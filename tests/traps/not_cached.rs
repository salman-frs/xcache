use std::time::{Duration, Instant};

use crate::support::{Workspace, assert_outcome};

#[test]
fn failing_commands_are_not_cached() {
    let ws = Workspace::new();
    let first = ws.sh("echo partial > out.txt; exit 3");
    assert_eq!(first.status, 3);
    assert_outcome(&first, "not_cached");
    assert_outcome(&ws.sh("echo partial > out.txt; exit 3"), "not_cached");
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
fn renaming_a_directory_it_did_not_create_is_not_cached() {
    let ws = Workspace::new();
    ws.write("build/out", "x");
    let run = ws.sh("mv build dist");
    assert_outcome(&run, "not_cached");
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
