//! Signals on their way to the command. Each stops in the tracer before its
//! handler runs.

use nix::sys::ptrace;
use nix::unistd::Pid;

use super::syscalls::{self, Call};
use super::{NO_SIGNAL, Tracer, resume, tracee};

const ERESTARTSYS: i64 = -512;

/// Signals that interrupted a call while it waited for the supervisor, held
/// back until the call has run again. Delivered right away, one whose handler
/// lacks SA_RESTART makes the call fail with EINTR, as no local read does.
pub(super) struct HeldSignals {
    signals: Vec<libc::siginfo_t>,
    rerun: Rerun,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rerun {
    Restarting,
    Running,
    Resent,
}

impl HeldSignals {
    pub(super) fn are_waiting(&self) -> bool {
        self.rerun != Rerun::Resent
    }
}

impl Tracer<'_, '_> {
    pub(super) fn signal_stop(&mut self, pid: Pid, signal: i32) {
        let supervised = self.supervised;
        let tracee = self.tracees.entry(pid).or_default();
        if signal == libc::SIGSTOP && !tracee.attached {
            tracee.attached = true;
            resume(pid, NO_SIGNAL);
            return;
        }
        if let Some(held) = &mut tracee.held
            && held.rerun == Rerun::Resent
            && let Some(index) = held.signals.iter().position(|info| info.si_signo == signal)
        {
            let _ = ptrace::setsiginfo(pid, &held.signals.remove(index));
            if held.signals.is_empty() {
                tracee.held = None;
            }
            resume(pid, signal);
            return;
        }
        let is_group_stop = matches!(signal, libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU)
            && ptrace::getsiginfo(pid).is_err();
        if supervised
            && !is_group_stop
            && !is_synchronous(signal)
            && interrupted_before_supervisor(self.directories, pid)
            && let Ok(info) = ptrace::getsiginfo(pid)
        {
            let held = tracee.held.get_or_insert(HeldSignals { signals: Vec::new(), rerun: Rerun::Restarting });
            // A standard signal is pending at most once, so a second one replaces the first.
            if signal < libc::SIGRTMIN() {
                held.signals.retain(|held| held.si_signo != signal);
            }
            held.signals.push(info);
            held.rerun = Rerun::Restarting;
            if ptrace::syscall(pid, None).is_err() {
                self.tracees.remove(&pid);
            }
            return;
        }
        let signal = if is_group_stop { NO_SIGNAL } else { signal };
        if tracee.held.as_ref().is_some_and(HeldSignals::are_waiting) {
            // SAFETY: PTRACE_SYSCALL takes no address and the signal to deliver as data.
            unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid.as_raw(), 0, signal as libc::c_long) };
        } else {
            resume(pid, signal);
        }
    }

    /// A syscall stop is the end of a call that waits for its result, or a
    /// step in rerunning a call that held signals interrupted.
    pub(super) fn syscall_stop(&mut self, pid: Pid) {
        let Some(tracee) = self.tracees.get_mut(&pid) else {
            return self.syscall_exit(pid);
        };
        match tracee.held.as_ref().map(|held| held.rerun) {
            Some(Rerun::Restarting) => self.continue_rerun(pid, Rerun::Running),
            Some(Rerun::Running) if tracee::syscall_result(pid).is_ok_and(|result| result == ERESTARTSYS) => {
                self.continue_rerun(pid, Rerun::Restarting);
            }
            Some(Rerun::Running) => self.resend_held_signals(pid),
            // The thread is back in its own code, so what was resent has
            // been delivered, or merged with a signal that was pending.
            Some(Rerun::Resent) | None => {
                tracee.held = None;
                self.syscall_exit(pid);
            }
        }
    }

    fn continue_rerun(&mut self, pid: Pid, rerun: Rerun) {
        if let Some(held) = self.tracees.get_mut(&pid).and_then(|tracee| tracee.held.as_mut()) {
            held.rerun = rerun;
        }
        if ptrace::syscall(pid, None).is_err() {
            self.tracees.remove(&pid);
        }
    }

    pub(super) fn resend_held_signals(&mut self, pid: Pid) {
        if let Some(held) = self.tracees.get_mut(&pid).and_then(|tracee| tracee.held.as_mut()) {
            held.rerun = Rerun::Resent;
            for info in &held.signals {
                // SAFETY: tkill takes a thread ID and a signal number.
                unsafe { libc::syscall(libc::SYS_tkill, pid.as_raw(), info.si_signo) };
            }
        }
        resume(pid, NO_SIGNAL);
    }
}

/// Signals caused by the instruction the thread was running.
fn is_synchronous(signal: i32) -> bool {
    matches!(signal, libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE | libc::SIGTRAP | libc::SIGSYS)
}

/// Whether the thread will rerun a call the supervisor was to see, which the
/// signal must have interrupted before the call ran. Opening a FIFO or a
/// device can block in the call itself, where a signal should interrupt it.
fn interrupted_before_supervisor(directories: &super::WorkingDirectories, pid: Pid) -> bool {
    let Some((nr, args)) = tracee::restartable_call(pid) else {
        return false;
    };
    if !syscalls::is_observed(nr, args) {
        return false;
    }
    match syscalls::decode(nr, args) {
        Some(Call::Open { dirfd, path, .. }) => tracee::read_c_string(pid, path)
            .and_then(|raw| tracee::resolve_at(directories, pid, dirfd, &raw))
            .and_then(|path| std::fs::metadata(path).ok())
            .is_none_or(|meta| meta.is_file() || meta.is_dir()),
        _ => true,
    }
}
