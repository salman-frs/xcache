use crate::support::{Workspace, assert_outcome};

#[test]
fn real_time_signals_reach_the_command() {
    let ws = Workspace::new();
    let script = "import os, signal\nsignal.signal(signal.SIGRTMIN, lambda *_: print('handled'))\nos.kill(os.getpid(), signal.SIGRTMIN)";
    let run = ws.run(&["python3", "-c", script]);
    assert_eq!(run.stdout, "handled\n", "{}", run.stderr);
    assert_outcome(&run, "miss");
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
