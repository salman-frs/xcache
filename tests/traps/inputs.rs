use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command;
use std::time::Duration;

use crate::support::{Workspace, assert_outcome};

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
fn a_file_read_through_dev_fd_is_an_input() {
    let ws = Workspace::new();
    ws.write("dir/in.txt", "one");
    let script = "exec 3<dir; cat /dev/fd/3/in.txt > out.txt";
    assert_outcome(&ws.sh(script), "miss");
    assert_outcome(&ws.sh(script), "hit");
    ws.write("dir/in.txt", "two");
    assert_outcome(&ws.sh(script), "miss");
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
fn touching_an_input_is_not_a_change_by_another_process() {
    let ws = Workspace::new();
    ws.write("in.txt", "one");
    let script = "cat in.txt > out.txt && touch -c -d @1000000000 in.txt";
    assert_outcome(&ws.sh(script), "miss");
    ws.write("in.txt", "two");
    assert_outcome(&ws.sh(script), "miss");
    assert_eq!(ws.read("out.txt"), "two");
}

#[test]
fn replacing_a_link_to_dev_null_misses() {
    let ws = Workspace::new();
    symlink("/dev/null", ws.path("settings")).unwrap();
    assert_outcome(&ws.sh("cat settings > out.txt"), "miss");
    fs::remove_file(ws.path("settings")).unwrap();
    ws.write("settings", "verbose");
    assert_outcome(&ws.sh("cat settings > out.txt"), "miss");
    assert_eq!(ws.read("out.txt"), "verbose");
}

#[test]
fn checking_a_file_it_may_not_read_still_sees_its_size() {
    use std::os::unix::fs::PermissionsExt;
    let ws = Workspace::new();
    let secret = ws.path("secret");
    let script = "if [ -s secret ]; then echo nonempty; else echo empty; fi > out.txt";
    fs::write(&secret, "").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
    assert_outcome(&ws.sh(script), "miss");

    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&secret, "x").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
    assert_outcome(&ws.sh(script), "miss");
    assert_eq!(ws.read("out.txt"), "nonempty\n");
}

#[test]
fn a_same_size_edit_behind_a_modification_time_check_misses() {
    let ws = Workspace::new();
    ws.write("main.c", "int v = 1;\n");
    ws.write("main.o", "int v = 1;\n");
    ws.set_age("main.c", 200);
    ws.set_age("main.o", 100);
    let make = "if [ main.c -nt main.o ]; then cp main.c main.o; fi";
    assert_outcome(&ws.sh(make), "miss");
    assert_outcome(&ws.sh(make), "hit");

    ws.write("main.c", "int v = 2;\n");
    assert_outcome(&ws.sh(make), "miss");
    assert_eq!(ws.read("main.o"), "int v = 2;\n");
}

#[test]
fn fresh_clones_of_the_same_commit_hit_although_git_bookkeeping_differs() {
    let ws = Workspace::new();
    let git_as = |user: &str, dir: &str, args: &[&str]| {
        let status = Command::new("git")
            .args(["-c", &format!("user.name={user}"), "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(args)
            .current_dir(ws.path(dir))
            .output()
            .unwrap()
            .status;
        assert!(status.success(), "git {args:?}");
    };
    let git = |dir: &str, args: &[&str]| git_as("t", dir, args);
    ws.write("origin/a.txt", "a");
    git("origin", &["init", "-q"]);
    git("origin", &["add", "a.txt"]);
    git("origin", &["commit", "-q", "-m", "a"]);
    let fresh_clone = |user: &str| {
        let _ = fs::remove_dir_all(ws.path("src"));
        git_as(user, ".", &["clone", "-q", "--no-local", "origin", "src"]);
        git_as(user, "src", &["checkout", "-q", "--detach"]);
    };
    let status = || {
        ws.run_with(&["git", "status"], |c| {
            c.current_dir(ws.path("src"));
        })
    };

    fresh_clone("runner");
    assert_outcome(&status(), "miss");
    std::thread::sleep(Duration::from_secs(1));
    fresh_clone("another runner");
    let again = status();
    assert_outcome(&again, "hit");
    assert!(again.stdout.contains("HEAD detached"), "{}", again.stdout);

    ws.write("src/a.txt", "b");
    git("src", &["add", "a.txt"]);
    let staged_change = status();
    assert_outcome(&staged_change, "miss");
    assert!(staged_change.stdout.contains("modified:   a.txt"), "{}", staged_change.stdout);
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
fn reads_through_proc_self_are_inputs() {
    let ws = Workspace::new();
    ws.write("in.txt", "one");
    assert_outcome(&ws.sh("cat /proc/self/cwd/in.txt > out.txt"), "miss");
    ws.write("in.txt", "two");
    assert_outcome(&ws.sh("cat /proc/self/cwd/in.txt > out.txt"), "miss");
    assert_eq!(ws.read("out.txt"), "two");
}

#[test]
fn relative_paths_follow_every_change_of_directory() {
    let ws = Workspace::new();
    ws.write("in.txt", "decoy");
    ws.write("by-name/in.txt", "a");
    ws.write("by-descriptor/in.txt", "b");
    let script = "import os\n\
        os.chdir('by-name'); first = open('in.txt').read()\n\
        os.fchdir(os.open('../by-descriptor', os.O_RDONLY)); second = open('in.txt').read()\n\
        print(first + second)";
    let command = ["python3", "-c", script];

    assert_outcome(&ws.run(&command), "miss");
    assert_outcome(&ws.run(&command), "hit");
    ws.write("in.txt", "another decoy");
    assert_outcome(&ws.run(&command), "hit");
    for (changed, printed) in [("by-descriptor/in.txt", "aB\n"), ("by-name/in.txt", "AB\n")] {
        ws.write(changed, &ws.read(changed).to_uppercase());
        let run = ws.run(&command);
        assert_outcome(&run, "miss");
        assert_eq!(run.stdout, printed);
    }
}
