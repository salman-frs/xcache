//! Each test sets a trap for the cache: a change that a naive cache would miss.
//! Tests need sh, gcc, go and python3 on PATH.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

struct Workspace {
    dir: tempfile::TempDir,
    store: tempfile::TempDir,
    root: PathBuf,
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
    report: Value,
}

impl Run {
    fn outcome(&self) -> &str {
        self.report["outcome"].as_str().unwrap_or("none")
    }

    fn reasons(&self) -> String {
        self.report["reasons"].to_string()
    }
}

impl Workspace {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        Self { dir, store: tempfile::tempdir().unwrap(), root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.path(relative)).unwrap()
    }

    fn run(&self, command: &[&str]) -> Run {
        self.run_with(command, |_| {})
    }

    fn sh(&self, script: &str) -> Run {
        self.run(&["sh", "-c", script])
    }

    fn run_with(&self, command: &[&str], configure: impl FnOnce(&mut Command)) -> Run {
        let report = self.dir.path().join("report.json");
        let _ = fs::remove_file(&report);
        let mut xcache = Command::new(env!("CARGO_BIN_EXE_xcache"));
        xcache.current_dir(&self.root).env("XCACHE_DIR", self.store.path()).args(["run", "--report"]).arg(&report);
        configure(&mut xcache);
        xcache.arg("--").args(command);
        let output = xcache.output().unwrap();
        let report = fs::read(&report).map(|bytes| serde_json::from_slice(&bytes).unwrap()).unwrap_or(Value::Null);
        Run {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            report,
        }
    }

    fn explain(&self, command: &[&str]) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_xcache"))
            .current_dir(&self.root)
            .env("XCACHE_DIR", self.store.path())
            .arg("explain")
            .arg("--")
            .args(command)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn compile(&self, tool: &[&str], source_name: &str, source: &str, binary: &str) -> PathBuf {
        let source_path = self.path(source_name);
        fs::write(&source_path, source).unwrap();
        let binary = self.path(binary);
        let status = Command::new(tool[0])
            .args(&tool[1..])
            .arg(&binary)
            .arg(&source_path)
            .current_dir(&self.root)
            .env("CGO_ENABLED", "0")
            .env("GOCACHE", self.dir.path().join("gocache"))
            .status()
            .unwrap_or_else(|error| panic!("{} is required for this test: {error}", tool[0]));
        assert!(status.success(), "compiling {source_name} failed");
        binary
    }
}

fn assert_outcome(run: &Run, expected: &str) {
    assert_eq!(run.outcome(), expected, "stderr: {}\nreport: {}", run.stderr, run.report);
}

#[test]
fn hit_restores_outputs_and_replays_output_and_status() {
    let ws = Workspace::new();
    ws.write("in.txt", "hello\n");
    let script = "tr a-z A-Z < in.txt > out.txt; echo stdout; echo stderr >&2";

    let first = ws.sh(script);
    assert_outcome(&first, "miss");
    fs::remove_file(ws.path("out.txt")).unwrap();

    let second = ws.sh(script);
    assert_outcome(&second, "hit");
    assert_eq!(ws.read("out.txt"), "HELLO\n");
    assert_eq!(second.stdout, "stdout\n");
    assert!(second.stderr.starts_with("stderr\n"));
    assert_eq!(second.status, 0);
}

#[test]
fn changed_content_misses() {
    let ws = Workspace::new();
    ws.write("in.txt", "one");
    assert_outcome(&ws.sh("cat in.txt > out.txt"), "miss");
    ws.write("in.txt", "two");
    assert_outcome(&ws.sh("cat in.txt > out.txt"), "miss");
    assert_eq!(ws.read("out.txt"), "two");
}

#[test]
fn a_new_header_that_shadows_an_old_one_misses() {
    let ws = Workspace::new();
    ws.write("b/config.h", "#define VALUE 1\n");
    ws.write("main.c", "#include \"config.h\"\nint value = VALUE;\n");
    fs::create_dir(ws.path("a")).unwrap();
    let compile = ["gcc", "-I", "a", "-I", "b", "-c", "main.c", "-o", "main.o"];

    assert_outcome(&ws.run(&compile), "miss");
    fs::remove_file(ws.path("main.o")).unwrap();
    assert_outcome(&ws.run(&compile), "hit");
    ws.write("a/config.h", "#define VALUE 2\n");
    fs::remove_file(ws.path("main.o")).unwrap();
    assert_outcome(&ws.run(&compile), "miss");
}

#[test]
fn whether_an_output_already_exists_is_an_input() {
    let ws = Workspace::new();
    ws.write("main.c", "int main(void) { return 0; }\n");
    let compile = ["gcc", "-c", "main.c", "-o", "main.o"];
    assert_outcome(&ws.run(&compile), "miss");
    assert_outcome(&ws.run(&compile), "miss");
    assert_outcome(&ws.run(&compile), "hit");
    fs::remove_file(ws.path("main.o")).unwrap();
    assert_outcome(&ws.run(&compile), "hit");
    assert!(ws.path("main.o").exists());
}

#[test]
fn a_new_file_in_a_listed_directory_misses() {
    let ws = Workspace::new();
    ws.write("tests/one.test", "");
    assert_outcome(&ws.sh("ls tests > found.txt"), "miss");
    assert_outcome(&ws.sh("ls tests > found.txt"), "hit");
    ws.write("tests/two.test", "");
    assert_outcome(&ws.sh("ls tests > found.txt"), "miss");
    assert_eq!(ws.read("found.txt"), "one.test\ntwo.test\n");
}

#[test]
fn files_the_command_creates_in_a_listed_directory_do_not_prevent_hits() {
    let ws = Workspace::new();
    ws.write("dist/keep", "");
    let script = "rm -f dist/manifest && echo x > dist/bundle && ls dist > dist/manifest";
    assert_outcome(&ws.sh(script), "miss");
    fs::remove_file(ws.path("dist/bundle")).unwrap();
    fs::remove_file(ws.path("dist/manifest")).unwrap();
    assert_outcome(&ws.sh(script), "hit");
    assert_eq!(ws.read("dist/manifest"), "bundle\nkeep\nmanifest\n");
}

#[test]
fn environment_changes_miss_and_volatile_variables_are_hidden() {
    let ws = Workspace::new();
    let script = "echo \"$MODE $GITHUB_SHA\" > out.txt";
    assert_outcome(
        &ws.run_with(&["sh", "-c", script], |c| {
            c.env("MODE", "debug").env("GITHUB_SHA", "a");
        }),
        "miss",
    );
    assert_outcome(
        &ws.run_with(&["sh", "-c", script], |c| {
            c.env("MODE", "debug").env("GITHUB_SHA", "b");
        }),
        "hit",
    );
    assert_eq!(ws.read("out.txt"), "debug \n");
    assert_outcome(
        &ws.run_with(&["sh", "-c", script], |c| {
            c.env("MODE", "release").env("GITHUB_SHA", "b");
        }),
        "miss",
    );
}

#[test]
fn stdin_is_not_an_input() {
    let ws = Workspace::new();
    let run = |input: &str| {
        let report = ws.dir.path().join("stdin-report.json");
        let mut child = Command::new(env!("CARGO_BIN_EXE_xcache"))
            .current_dir(&ws.root)
            .env("XCACHE_DIR", ws.store.path())
            .args(["run", "--report"])
            .arg(&report)
            .args(["--", "sh", "-c", "cat > out.txt"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        child.wait().unwrap();
        serde_json::from_slice::<Value>(&fs::read(&report).unwrap()).unwrap()["outcome"].clone()
    };
    assert_eq!(run("first"), "miss");
    assert_eq!(run("second"), "hit");
    assert_eq!(ws.read("out.txt"), "");
}

#[test]
fn failing_commands_are_not_cached() {
    let ws = Workspace::new();
    let first = ws.sh("echo partial > out.txt; exit 3");
    assert_eq!(first.status, 3);
    assert_outcome(&first, "not_cached");
    assert_outcome(&ws.sh("echo partial > out.txt; exit 3"), "not_cached");
}

#[test]
fn network_access_is_not_cached() {
    let ws = Workspace::new();
    let script =
        "import socket\ns = socket.socket()\ns.settimeout(0.2)\ntry: s.connect(('192.0.2.1', 9))\nexcept OSError: pass";
    let run = ws.run(&["python3", "-c", script]);
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains("network access to 192.0.2.1:9"), "{}", run.reasons());
}

#[test]
fn talking_to_its_own_local_server_is_cacheable() {
    let ws = Workspace::new();
    let script = "import socket\nserver = socket.create_server(('127.0.0.1', 0))\nclient = socket.create_connection(server.getsockname())\nprint('connected')";
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    assert_outcome(&ws.run(&["python3", "-c", script]), "hit");
}

#[test]
fn talking_to_a_service_it_did_not_start_is_not_cached() {
    let ws = Workspace::new();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let script = format!("import socket\nsocket.create_connection(('127.0.0.1', {port}))");
    let run = ws.run(&["python3", "-c", &script]);
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains(&format!("port {port}")), "{}", run.reasons());

    let socket_path = ws.path("service.sock");
    let _unix = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let script = format!("import socket\ns = socket.socket(socket.AF_UNIX)\ns.connect('{}')", socket_path.display());
    assert_outcome(&ws.run(&["python3", "-c", &script]), "not_cached");
}

#[test]
fn processes_left_running_are_terminated_and_not_cached() {
    let ws = Workspace::new();
    let started = Instant::now();
    let run = ws.sh("sleep 30 & echo started");
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains("left processes running"), "{}", run.reasons());
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn statically_linked_programs_are_traced() {
    let ws = Workspace::new();
    let program = r#"package main
import "os"
func main() {
	data, err := os.ReadFile("input.txt")
	if err != nil { panic(err) }
	if err := os.WriteFile("output.txt", append(data, '!'), 0o644); err != nil { panic(err) }
}"#;
    let binary = ws.compile(&["go", "build", "-o"], "main.go", program, "copy");
    let binary = binary.to_str().unwrap();
    ws.write("input.txt", "a");
    assert_outcome(&ws.run(&[binary]), "miss");
    assert_outcome(&ws.run(&[binary]), "hit");
    ws.write("input.txt", "b");
    assert_outcome(&ws.run(&[binary]), "miss");
    assert_eq!(ws.read("output.txt"), "b!");
}

#[test]
fn io_uring_is_refused_so_runtimes_fall_back_to_traceable_calls() {
    let ws = Workspace::new();
    let program = r#"#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    char params[120];
    memset(params, 0, sizeof params);
    long fd = syscall(SYS_io_uring_setup, 4, params);
    printf("%s\n", fd < 0 && errno == ENOSYS ? "refused" : "allowed");
    return 0;
}"#;
    let binary = ws.compile(&["gcc", "-o"], "uring.c", program, "uring");
    let run = ws.run(&[binary.to_str().unwrap()]);
    assert_eq!(run.stdout, "refused\n");
}

#[test]
fn rewriting_a_file_in_place_depends_on_its_original_content() {
    let ws = Workspace::new();
    let script = "f = open('data.txt', 'r+')\ntext = f.read()\nf.seek(0)\nf.write(text.upper())";
    ws.write("data.txt", "abc");
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    assert_eq!(ws.read("data.txt"), "ABC");

    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    ws.write("data.txt", "abc");
    assert_outcome(&ws.run(&["python3", "-c", script]), "hit");
    assert_eq!(ws.read("data.txt"), "ABC");
}

#[test]
fn appending_depends_on_existing_content() {
    let ws = Workspace::new();
    ws.write("log.txt", "start\n");
    assert_outcome(&ws.sh("echo line >> log.txt"), "miss");
    assert_outcome(&ws.sh("echo line >> log.txt"), "miss");
    assert_eq!(ws.read("log.txt"), "start\nline\nline\n");
    ws.write("log.txt", "start\n");
    assert_outcome(&ws.sh("echo line >> log.txt"), "hit");
    assert_eq!(ws.read("log.txt"), "start\nline\n");
}

#[test]
fn retargeting_a_symlink_misses() {
    let ws = Workspace::new();
    ws.write("a.txt", "a");
    ws.write("b.txt", "b");
    symlink("a.txt", ws.path("current")).unwrap();
    assert_outcome(&ws.sh("cat current > out.txt"), "miss");
    assert_outcome(&ws.sh("cat current > out.txt"), "hit");
    fs::remove_file(ws.path("current")).unwrap();
    symlink("b.txt", ws.path("current")).unwrap();
    assert_outcome(&ws.sh("cat current > out.txt"), "miss");
    assert_eq!(ws.read("out.txt"), "b");
}

#[test]
fn paths_that_are_not_utf8_are_cached_and_restored() {
    let ws = Workspace::new();
    let script = "printf data > \"$(printf 'caf\\351')\"";
    assert_outcome(&ws.sh(script), "miss");
    let name = OsStr::from_bytes(b"caf\xe9");
    fs::remove_file(ws.root.join(name)).unwrap();
    assert_outcome(&ws.sh(script), "hit");
    assert_eq!(fs::read(ws.root.join(name)).unwrap(), b"data");
}

#[test]
fn deletions_are_replayed() {
    let ws = Workspace::new();
    ws.write("stale.txt", "old");
    assert_outcome(&ws.sh("rm stale.txt"), "miss");
    ws.write("stale.txt", "old");
    assert_outcome(&ws.sh("rm stale.txt"), "hit");
    assert!(!ws.path("stale.txt").exists());
}

#[test]
fn directories_built_then_renamed_are_restored_whole() {
    let ws = Workspace::new();
    let script = "rm -rf final && mkdir staging && echo x > staging/a && mkdir staging/sub && echo y > staging/sub/b && mv staging final";
    assert_outcome(&ws.sh(script), "miss");
    fs::remove_dir_all(ws.path("final")).unwrap();
    assert_outcome(&ws.sh(script), "hit");
    assert_eq!(ws.read("final/a"), "x\n");
    assert_eq!(ws.read("final/sub/b"), "y\n");
    assert!(!ws.path("staging").exists());
}

#[test]
fn renaming_a_directory_it_did_not_create_is_not_cached() {
    let ws = Workspace::new();
    ws.write("build/out", "x");
    let run = ws.sh("mv build dist");
    assert_outcome(&run, "not_cached");
}

#[test]
fn shadow_mode_confirms_hits_and_catches_nondeterminism() {
    let ws = Workspace::new();
    ws.write("in.txt", "x");
    let deterministic = ["sh", "-c", "cat in.txt > out.txt"];
    assert_outcome(&ws.run(&deterministic), "miss");
    let confirmed = ws.run_with(&deterministic, |c| {
        c.arg("--shadow");
    });
    assert_eq!(confirmed.report["shadow"], "correct", "{}", confirmed.report);

    let clock = ["sh", "-c", "date +%s%N > stamp.txt"];
    assert_outcome(&ws.run(&clock), "miss");
    let caught = ws.run_with(&clock, |c| {
        c.arg("--shadow");
    });
    assert_eq!(caught.report["shadow"], "nondeterministic", "{}", caught.report);
}

#[test]
fn a_same_size_edit_behind_a_modification_time_check_misses() {
    let ws = Workspace::new();
    ws.write("main.c", "int v = 1;\n");
    ws.write("main.o", "int v = 1;\n");
    let set_age = |name: &str, seconds_ago: u64| {
        let file = fs::File::options().write(true).open(ws.path(name)).unwrap();
        file.set_modified(std::time::SystemTime::now() - Duration::from_secs(seconds_ago)).unwrap();
    };
    set_age("main.c", 200);
    set_age("main.o", 100);
    let make = "if [ main.c -nt main.o ]; then cp main.c main.o; fi";
    assert_outcome(&ws.sh(make), "miss");
    assert_outcome(&ws.sh(make), "hit");

    ws.write("main.c", "int v = 2;\n");
    assert_outcome(&ws.sh(make), "miss");
    assert_eq!(ws.read("main.o"), "int v = 2;\n");
}

#[test]
fn fresh_clones_of_the_same_commit_hit_although_their_git_index_differs() {
    let ws = Workspace::new();
    let git = |dir: &str, args: &[&str]| {
        let status = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(args)
            .current_dir(ws.path(dir))
            .output()
            .unwrap()
            .status;
        assert!(status.success(), "git {args:?}");
    };
    ws.write("origin/a.txt", "a");
    git("origin", &["init", "-q"]);
    git("origin", &["add", "a.txt"]);
    git("origin", &["commit", "-q", "-m", "a"]);
    let fresh_clone = || {
        let _ = fs::remove_dir_all(ws.path("src"));
        git(".", &["clone", "-q", "--no-local", "origin", "src"]);
    };
    let list_staged = || {
        ws.run_with(&["git", "ls-files", "--stage"], |c| {
            c.current_dir(ws.path("src"));
        })
    };

    fresh_clone();
    assert_outcome(&list_staged(), "miss");
    fresh_clone();
    assert_outcome(&list_staged(), "hit");

    ws.write("src/a.txt", "b");
    git("src", &["add", "a.txt"]);
    let staged_change = list_staged();
    assert_outcome(&staged_change, "miss");
    assert!(staged_change.stdout.contains("63d8dbd40c23542e740659a7168a0ce3138ea748"), "{}", staged_change.stdout);
}

#[test]
fn shadow_mode_leaves_what_a_hit_would_so_later_commands_see_the_same_files() {
    let ws = Workspace::new();
    let stamp = ["sh", "-c", "date +%s%N > stamp.txt"];
    let copy = ["sh", "-c", "cat stamp.txt > copy.txt"];
    assert_outcome(&ws.run(&stamp), "miss");
    assert_outcome(&ws.run(&copy), "miss");
    let cached_stamp = ws.read("stamp.txt");

    let shadowed = ws.run_with(&stamp, |c| {
        c.arg("--shadow");
    });
    assert_eq!(shadowed.report["shadow"], "nondeterministic", "{}", shadowed.report);
    assert_eq!(ws.read("stamp.txt"), cached_stamp);

    let downstream = ws.run_with(&copy, |c| {
        c.arg("--shadow");
    });
    assert_eq!(downstream.report["shadow"], "correct", "{}", downstream.report);
}

#[test]
fn shadow_mode_removes_files_only_the_fresh_run_created() {
    let ws = Workspace::new();
    let script = "mkdir -p out && touch out/$(date +%s%N)";
    assert_outcome(&ws.sh(script), "miss");
    let cached: Vec<_> = fs::read_dir(ws.path("out")).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    fs::remove_dir_all(ws.path("out")).unwrap();

    let shadowed = ws.run_with(&["sh", "-c", script], |c| {
        c.arg("--shadow");
    });
    assert_eq!(shadowed.report["shadow"], "nondeterministic", "{}", shadowed.report);
    let left: Vec<_> = fs::read_dir(ws.path("out")).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(left, cached);
}

#[test]
fn a_fresh_failure_with_the_same_inputs_is_nondeterministic_not_a_false_hit() {
    let ws = Workspace::new();
    let counter = ws.store.path().join("runs");
    fs::write(&counter, "0").unwrap();
    let flaky = format!("n=$(cat {0}); echo $((n + 1)) > {0}; test $n -eq 0", counter.display());
    assert_outcome(&ws.sh(&flaky), "miss");

    let shadowed = ws.run_with(&["sh", "-c", &flaky], |c| {
        c.arg("--shadow");
    });
    assert_eq!(shadowed.report["shadow"], "nondeterministic", "{}", shadowed.report);
    assert_eq!(shadowed.status, 0);
}

#[test]
fn unknown_commands_exit_127() {
    let ws = Workspace::new();
    let run = ws.run(&["definitely-not-a-command"]);
    assert_eq!(run.status, 127);
    assert!(run.stderr.contains("No such file"), "{}", run.stderr);
}

#[test]
fn creating_namespaces_is_not_cached() {
    let ws = Workspace::new();
    let run = ws.run(&["unshare", "--user", "true"]);
    assert!(run.reasons().contains("namespaces"), "{}", run.reasons());
}

#[test]
fn explain_names_the_changed_input() {
    let ws = Workspace::new();
    ws.write("in.txt", "one");
    ws.sh("cat in.txt > out.txt");
    ws.write("in.txt", "two!");
    let explanation = ws.explain(&["sh", "-c", "cat in.txt > out.txt"]);
    assert!(explanation.contains(&format!("{} changed", ws.path("in.txt").display())), "{explanation}");
}

#[test]
fn the_cache_directory_itself_is_never_an_input_or_output() {
    let ws = Workspace::new();
    let store = ws.store.path().to_str().unwrap().to_owned();
    let script = format!("ls {store} > /dev/null; echo done > out.txt");
    assert_outcome(&ws.sh(&script), "miss");
    assert_outcome(&ws.sh(&script), "hit");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn system_calls_through_the_32_bit_abi_are_not_cached() {
    let ws = Workspace::new();
    let program = r#"int main(void) {
    long pid;
    __asm__ volatile ("int $0x80" : "=a"(pid) : "a"(20));
    return pid > 0 ? 0 : 1;
}"#;
    let binary = ws.compile(&["gcc", "-o"], "legacy.c", program, "legacy");
    let run = ws.run(&[binary.to_str().unwrap()]);
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains("foreign ABI"), "{}", run.reasons());
}

#[test]
fn sources_read_through_parent_of_a_created_directory_are_inputs() {
    let ws = Workspace::new();
    ws.write("main.c", "one");
    let script = "rm -rf build && mkdir build && cd build && cat ../main.c > app";
    assert_outcome(&ws.sh(script), "miss");
    ws.write("main.c", "two");
    assert_outcome(&ws.sh(script), "miss");
    assert_eq!(ws.read("build/app"), "two");
}

#[test]
fn writing_through_a_symlink_restores_the_target() {
    let ws = Workspace::new();
    ws.write("target.txt", "old\n");
    symlink("target.txt", ws.path("link")).unwrap();
    assert_outcome(&ws.sh("echo new >> link"), "miss");
    ws.write("target.txt", "old\n");
    assert_outcome(&ws.sh("echo new >> link"), "hit");
    assert_eq!(ws.read("target.txt"), "old\nnew\n");
}

#[test]
fn hard_link_sources_are_read_by_content() {
    let ws = Workspace::new();
    ws.write("a", "1111");
    assert_outcome(&ws.run(&["ln", "a", "b"]), "miss");
    fs::remove_file(ws.path("b")).unwrap();
    ws.write("a", "2222");
    assert_outcome(&ws.run(&["ln", "a", "b"]), "miss");
}

#[test]
fn permission_changes_on_inputs_miss() {
    use std::os::unix::fs::PermissionsExt;
    let ws = Workspace::new();
    ws.write("a", "data");
    assert_outcome(&ws.run(&["cp", "a", "b"]), "miss");
    fs::remove_file(ws.path("b")).unwrap();
    fs::set_permissions(ws.path("a"), fs::Permissions::from_mode(0o600)).unwrap();
    assert_outcome(&ws.run(&["cp", "a", "b"]), "miss");
    assert_eq!(fs::metadata(ws.path("b")).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn chmod_on_a_directory_keeps_its_listing_an_input() {
    let ws = Workspace::new();
    ws.write("src/one", "");
    assert_outcome(&ws.sh("chmod 755 src && ls src > out.txt"), "miss");
    ws.write("src/two", "");
    assert_outcome(&ws.sh("chmod 755 src && ls src > out.txt"), "miss");
    assert_eq!(ws.read("out.txt"), "one\ntwo\n");
}

#[test]
fn read_only_opens_that_create_files_are_outputs() {
    let ws = Workspace::new();
    let script = "import os\nos.close(os.open('build.lock', os.O_RDONLY | os.O_CREAT))";
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    fs::remove_file(ws.path("build.lock")).unwrap();
    assert_outcome(&ws.run(&["python3", "-c", script]), "hit");
    assert!(ws.path("build.lock").exists());
}

#[test]
fn reads_through_proc_self_are_inputs() {
    let ws = Workspace::new();
    ws.write("in.txt", "one");
    assert_outcome(&ws.sh("cat /proc/self/cwd/in.txt > out.txt"), "miss");
    ws.write("in.txt", "two");
    assert_outcome(&ws.sh("cat /proc/self/cwd/in.txt > out.txt"), "miss");
    assert_eq!(ws.read("out.txt"), "two");
}

#[test]
fn accepting_a_connection_from_outside_is_not_cached() {
    let ws = Workspace::new();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let client = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let script = format!("import socket\ns = socket.create_server(('127.0.0.1', {port}))\ns.accept()");
    let run = ws.run(&["python3", "-c", &script]);
    client.join().unwrap();
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains("accepted a connection"), "{}", run.reasons());
}

#[test]
fn accepting_its_own_client_is_cacheable() {
    let ws = Workspace::new();
    let script = "import socket\ns = socket.create_server(('127.0.0.1', 0))\nc = socket.create_connection(s.getsockname())\ns.accept()";
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    assert_outcome(&ws.run(&["python3", "-c", script]), "hit");
}
