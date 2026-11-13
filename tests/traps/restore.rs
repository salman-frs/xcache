use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::time::Duration;

use crate::support::{Workspace, assert_outcome};

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
fn a_file_written_through_dev_fd_is_restored() {
    let ws = Workspace::new();
    ws.write("out.txt", "old");
    let script = "exec 3<out.txt; echo new > /dev/fd/3";
    assert_outcome(&ws.sh(script), "miss");
    assert_eq!(ws.read("out.txt"), "new\n");

    ws.write("out.txt", "old");
    assert_outcome(&ws.sh(script), "hit");
    assert_eq!(ws.read("out.txt"), "new\n");
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
fn restored_outputs_are_newer_than_the_checkout_they_are_restored_into() {
    let ws = Workspace::new();
    ws.write("main.c", "int v;\n");
    let build = "cp main.c main.o && sleep 2";
    let up_to_date = "if [ main.c -nt main.o ]; then echo stale; else echo fresh; fi";
    assert_outcome(&ws.sh(build), "miss");

    fs::remove_file(ws.path("main.o")).unwrap();
    ws.write("main.c", "int v;\n");
    assert_outcome(&ws.sh(build), "hit");
    assert_eq!(ws.sh(up_to_date).stdout, "fresh\n");
}

#[test]
fn a_modification_time_the_command_chose_is_restored() {
    let ws = Workspace::new();
    let script = "touch -d @1000000000 stamp";
    assert_outcome(&ws.sh(script), "miss");
    fs::remove_file(ws.path("stamp")).unwrap();
    assert_outcome(&ws.sh(script), "hit");
    let modified = fs::metadata(ws.path("stamp")).unwrap().modified().unwrap();
    assert_eq!(modified, std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000));
}

#[test]
fn a_time_chosen_within_the_run_is_restored_relative_to_it() {
    let ws = Workspace::new();
    ws.write("main.c", "int v;\n");
    let build = "start=$(date +%s.%N); sleep 1; cp main.c main.o; touch -d @$start main.o.d";
    let up_to_date = "if [ main.c -nt main.o.d ]; then echo stale; else echo fresh; fi";
    assert_outcome(&ws.sh(build), "miss");

    fs::remove_file(ws.path("main.o")).unwrap();
    fs::remove_file(ws.path("main.o.d")).unwrap();
    ws.write("main.c", "int v;\n");
    assert_outcome(&ws.sh(build), "hit");
    assert_eq!(ws.sh(up_to_date).stdout, "fresh\n");
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
fn read_only_opens_that_create_files_are_outputs() {
    let ws = Workspace::new();
    let script = "import os\nos.close(os.open('build.lock', os.O_RDONLY | os.O_CREAT))";
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    fs::remove_file(ws.path("build.lock")).unwrap();
    assert_outcome(&ws.run(&["python3", "-c", script]), "hit");
    assert!(ws.path("build.lock").exists());
}
