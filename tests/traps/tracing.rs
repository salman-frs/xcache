use std::io;
use std::os::unix::process::CommandExt;

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

#[test]
fn signals_do_not_make_reads_fail() {
    let ws = Workspace::new();
    let program = r#"#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
static void ignore(int signal) { (void)signal; }
int main(void) {
    struct sigaction action = { .sa_handler = ignore };
    sigaction(SIGALRM, &action, NULL);
    struct itimerval every_50us = { { 0, 50 }, { 0, 50 } };
    setitimer(ITIMER_REAL, &every_50us, NULL);
    struct stat st;
    for (int i = 0; i < 2000; i++) {
        int fd = open("input.txt", O_RDONLY);
        if (fd < 0 || close(fd) != 0 || stat("input.txt", &st) != 0) {
            printf("failed: %s\n", strerror(errno));
            return 1;
        }
    }
    printf("ok\n");
    return 0;
}"#;
    let binary = ws.compile(&["gcc", "-o"], "reads.c", program, "reads");
    ws.write("input.txt", "a");
    let run = ws.run(&[binary.to_str().unwrap()]);
    assert_eq!(run.stdout, "ok\n", "{}", run.stderr);
    assert_outcome(&run, "miss");
}

#[test]
fn a_signal_still_interrupts_opening_a_fifo() {
    let ws = Workspace::new();
    let program = r#"#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
static int alarms;
static void count(int signal) { (void)signal; if (++alarms == 10) _exit(3); }
int main(void) {
    mkfifo("pipe", 0600);
    struct sigaction action = { .sa_handler = count };
    sigaction(SIGALRM, &action, NULL);
    struct itimerval every_100ms = { { 0, 100000 }, { 0, 100000 } };
    setitimer(ITIMER_REAL, &every_100ms, NULL);
    int fd = open("pipe", O_RDONLY);
    printf("%s\n", fd < 0 && errno == EINTR ? "interrupted" : "opened");
    return 0;
}"#;
    let binary = ws.compile(&["gcc", "-o"], "fifo.c", program, "fifo");
    let run = ws.run(&[binary.to_str().unwrap()]);
    assert_eq!(run.stdout, "interrupted\n", "{}", run.stderr);
}

#[test]
fn commands_are_traced_where_copying_descriptors_is_refused() {
    let ws = Workspace::new();
    ws.write("input.txt", "a");
    let run = || {
        ws.run_with(&["cat", "input.txt"], |xcache| {
            // SAFETY: the closure makes two system calls and allocates nothing.
            unsafe { xcache.pre_exec(|| refuse(libc::SYS_pidfd_getfd)) };
        })
    };
    assert_outcome(&run(), "miss");
    assert_outcome(&run(), "hit");
    ws.write("input.txt", "b");
    let changed = run();
    assert_outcome(&changed, "miss");
    assert_eq!(changed.stdout, "b");
}

/// Makes a system call fail with EPERM from here on, as Docker's default
/// seccomp profile does for pidfd_getfd.
fn refuse(nr: libc::c_long) -> io::Result<()> {
    const ALLOW: u32 = 0x7fff_0000;
    const FAIL: u32 = 0x0005_0000;
    let instruction = |code: u32, jt: u8, k: u32| libc::sock_filter { code: code as u16, jt, jf: 0, k };
    let filter = [
        instruction(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0),
        instruction(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 1, nr as u32),
        instruction(libc::BPF_RET | libc::BPF_K, 0, ALLOW),
        instruction(libc::BPF_RET | libc::BPF_K, 0, FAIL | libc::EPERM as u32),
    ];
    let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr().cast_mut() };
    // SAFETY: the kernel copies the program, which outlives both calls.
    let installed = unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) == 0
    };
    if installed { Ok(()) } else { Err(io::Error::last_os_error()) }
}
