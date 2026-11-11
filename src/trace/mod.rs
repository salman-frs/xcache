mod filter;
mod handle;
pub(crate) mod net;
mod spawn;
mod syscalls;
mod tracee;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::sys::ptrace::{self, Event, Options};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use crate::invocation::Invocation;
use crate::observe::Access;
use crate::record::{Mutation, Recorder, Recording};
use crate::stdio;
use net::Destination;
use spawn::SetupFailure;

const LEFTOVER_PROCESSES: &str = "left processes running after it exited (they were terminated)";
const NO_SIGNAL: i32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

impl Exit {
    pub fn code(self) -> i32 {
        match self {
            Exit::Code(code) => code,
            Exit::Signal(signal) => 128 + signal,
        }
    }
}

pub struct Traced {
    pub exit: Exit,
    pub recording: Recording,
    pub stdio: Vec<u8>,
    pub command_time: Duration,
    pub hashing_time: Duration,
}

pub enum Outcome {
    Ran(Traced),
    ExecFailed {
        errno: i32,
    },
    /// Tracing is not permitted here; the command has not run.
    Unavailable {
        reason: String,
    },
}

pub fn run(invocation: &Invocation, recorder: Recorder) -> Result<Outcome> {
    let started = Instant::now();
    let spawn::Child { pid, stdout, stderr, setup } = spawn::spawn(invocation)?;
    let output = stdio::capture(stdout, stderr);

    let mut tracer = Tracer::new(pid, recorder);
    let attached = tracer.attach()?;
    if attached {
        tracer.run_until_all_exit()?;
    }
    let stdio = output.join().map_err(|_| anyhow::anyhow!("output pump panicked"))??;
    let failure = setup.failure();

    if attached && tracer.exec_seen {
        let command_time = started.elapsed();
        let recording = tracer.recorder.finish();
        return Ok(Outcome::Ran(Traced {
            exit: tracer.root_exit.unwrap_or(Exit::Signal(libc::SIGKILL)),
            recording,
            stdio,
            command_time,
            hashing_time: started.elapsed() - command_time,
        }));
    }
    Ok(match failure {
        Some((SetupFailure::Exec, errno)) => Outcome::ExecFailed { errno },
        Some((stage, errno)) => {
            Outcome::Unavailable { reason: format!("{stage:?} failed: {}", io::Error::from_raw_os_error(errno)) }
        }
        None => Outcome::Unavailable { reason: "the traced process exited before exec".into() },
    })
}

#[derive(Default)]
struct Tracee {
    attached: bool,
    pending: Option<Pending>,
}

enum Pending {
    Exec(PathBuf),
    Mutations(Vec<Mutation>),
    Rename { from: Mutation, to: Mutation },
    UntracedChild,
    Accept,
    Connect { fd: i32, destination: Destination },
    Bind { socket: PathBuf, mutation: Option<Mutation> },
}

enum Resume {
    Continue,
    UntilExit(Pending),
}

struct Tracer<'h> {
    root: Pid,
    recorder: Recorder<'h>,
    tracees: HashMap<Pid, Tracee>,
    root_exit: Option<Exit>,
    exec_seen: bool,
    untraced_children: Vec<Pid>,
    opened_connections: HashSet<SocketAddr>,
    known_listeners: net::KnownListeners,
    /// Sockets the command bound, by device and inode, which renames and links
    /// to them keep.
    bound_sockets: HashSet<(u64, u64)>,
}

impl<'h> Tracer<'h> {
    fn new(root: Pid, recorder: Recorder<'h>) -> Self {
        Self {
            root,
            recorder,
            tracees: HashMap::new(),
            root_exit: None,
            exec_seen: false,
            untraced_children: Vec::new(),
            opened_connections: HashSet::new(),
            known_listeners: net::KnownListeners::new(),
            bound_sockets: HashSet::new(),
        }
    }

    /// Returns false if the child exited before stopping, so tracing could not be set up.
    fn attach(&mut self) -> Result<bool> {
        match wait_for(Some(self.root)).context("waiting for the command to start")? {
            Stop::Signal(_, libc::SIGSTOP) => {}
            _ => return Ok(false),
        }
        let options = Options::PTRACE_O_TRACESYSGOOD
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEEXEC
            | Options::PTRACE_O_TRACESECCOMP
            | Options::PTRACE_O_EXITKILL;
        ptrace::setoptions(self.root, options).context("PTRACE_SETOPTIONS")?;
        self.tracees.insert(self.root, Tracee { attached: true, pending: None });
        ptrace::cont(self.root, None).context("resuming the command")?;
        Ok(true)
    }

    fn run_until_all_exit(&mut self) -> Result<()> {
        loop {
            let stop = match wait_for(None) {
                Ok(stop) => stop,
                Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
                Err(error) => return Err(error).context("waitpid"),
            };
            if self.outlives_root(&stop) {
                continue;
            }
            match stop {
                Stop::Exited(pid, code) => self.exited(pid, Exit::Code(code)),
                Stop::Killed(pid, signal) => self.exited(pid, Exit::Signal(signal)),
                Stop::Event(pid, event) => self.ptrace_event(pid, event),
                Stop::Syscall(pid) => self.syscall_exit(pid),
                Stop::Signal(pid, signal) => self.signal_stop(pid, signal),
            }
        }
    }

    fn exited(&mut self, pid: Pid, exit: Exit) {
        if let Some(pending @ (Pending::Mutations(_) | Pending::Rename { .. })) =
            self.tracees.remove(&pid).and_then(|tracee| tracee.pending)
        {
            // The syscall may have completed without an exit stop (exit_group or
            // a sibling's execve); capture records whatever really happened.
            self.complete(pending, 0, pid);
        }
        if pid != self.root {
            return;
        }
        self.root_exit = Some(exit);
        let mut leftovers: Vec<Pid> = self.tracees.keys().copied().filter(|pid| is_running(*pid)).collect();
        leftovers.extend(self.untraced_children.iter().copied().filter(|pid| is_running(*pid)));
        if !leftovers.is_empty() {
            self.recorder.taint(LEFTOVER_PROCESSES);
            for pid in leftovers {
                let _ = signal::kill(pid, Signal::SIGKILL);
            }
        }
    }

    /// A process first seen after the command exited is a leftover too: its
    /// fork event was still queued when the leftovers were terminated.
    fn outlives_root(&mut self, stop: &Stop) -> bool {
        let still_running = match *stop {
            Stop::Exited(..) | Stop::Killed(..) => None,
            Stop::Event(pid, _) | Stop::Syscall(pid) | Stop::Signal(pid, _) => Some(pid),
        };
        let (Some(pid), Some(_)) = (still_running, self.root_exit) else {
            return false;
        };
        self.recorder.taint(LEFTOVER_PROCESSES);
        let _ = signal::kill(pid, Signal::SIGKILL);
        resume(pid, NO_SIGNAL);
        true
    }

    fn signal_stop(&mut self, pid: Pid, signal: i32) {
        let tracee = self.tracees.entry(pid).or_default();
        if signal == libc::SIGSTOP && !tracee.attached {
            tracee.attached = true;
            resume(pid, NO_SIGNAL);
            return;
        }
        let is_group_stop = matches!(signal, libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU)
            && ptrace::getsiginfo(pid).is_err();
        resume(pid, if is_group_stop { NO_SIGNAL } else { signal });
    }

    fn ptrace_event(&mut self, pid: Pid, event: i32) {
        match event {
            e if e == Event::PTRACE_EVENT_SECCOMP as i32 => {
                let resume_mode = self.syscall_entry(pid);
                match resume_mode {
                    Resume::Continue => resume(pid, NO_SIGNAL),
                    Resume::UntilExit(pending) => {
                        self.tracees.entry(pid).or_default().pending = Some(pending);
                        if ptrace::syscall(pid, None).is_err() {
                            self.tracees.remove(&pid);
                        }
                    }
                }
            }
            e if e == Event::PTRACE_EVENT_FORK as i32
                || e == Event::PTRACE_EVENT_VFORK as i32
                || e == Event::PTRACE_EVENT_CLONE as i32 =>
            {
                if let Ok(child) = ptrace::getevent(pid) {
                    self.tracees.entry(Pid::from_raw(child as i32)).or_default();
                }
                resume(pid, NO_SIGNAL);
            }
            e if e == Event::PTRACE_EVENT_EXEC as i32 => {
                self.exec_seen = true;
                let former = ptrace::getevent(pid).map(|tid| Pid::from_raw(tid as i32)).unwrap_or(pid);
                let pending = self.tracees.get_mut(&former).and_then(|tracee| tracee.pending.take());
                if former != pid {
                    self.tracees.remove(&former);
                }
                self.tracees.entry(pid).or_default().attached = true;
                if let Some(Pending::Exec(path)) = pending {
                    self.recorder.observe(Access::Read, &path);
                }
                for file in tracee::mapped_files(pid) {
                    self.recorder.observe(Access::Read, &file);
                }
                resume(pid, NO_SIGNAL);
            }
            _ => resume(pid, NO_SIGNAL),
        }
    }

    fn syscall_exit(&mut self, pid: Pid) {
        let pending = self.tracees.get_mut(&pid).and_then(|tracee| tracee.pending.take());
        if let (Some(pending), Ok(result)) = (pending, tracee::syscall_result(pid)) {
            self.complete(pending, result, pid);
        }
        resume(pid, NO_SIGNAL);
    }

    fn complete(&mut self, pending: Pending, result: i64, pid: Pid) {
        let succeeded = result >= 0;
        match pending {
            Pending::Exec(path) => self.recorder.observe(Access::Read, &path),
            Pending::Mutations(mutations) if succeeded => {
                for mutation in mutations {
                    self.recorder.mutated(mutation);
                }
            }
            Pending::Rename { from, to } if succeeded => self.recorder.renamed(from, to),
            Pending::UntracedChild if result > 0 => self.untraced_children.push(Pid::from_raw(result as i32)),
            Pending::Accept if result >= 0 => {
                let tracees: Vec<Pid> = self.tracees.keys().copied().collect();
                if let Some(reason) =
                    net::accepted_from_outside(pid, result as i32, &tracees, &mut self.opened_connections)
                {
                    self.recorder.taint(reason);
                }
            }
            Pending::Connect { fd, destination } => self.connected(pid, fd, &destination, result),
            Pending::Bind { socket, mutation } if succeeded => {
                if let Some(mutation) = mutation {
                    self.recorder.mutated(mutation);
                }
                if let Ok(meta) = std::fs::metadata(&socket) {
                    self.bound_sockets.insert((meta.dev(), meta.ino()));
                }
            }
            Pending::Mutations(_)
            | Pending::Rename { .. }
            | Pending::UntracedChild
            | Pending::Accept
            | Pending::Bind { .. } => {}
        }
    }
}

fn is_running(pid: Pid) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let state = stat.rsplit_once(") ").and_then(|(_, rest)| rest.chars().next());
    !matches!(state, Some('Z' | 'X') | None)
}

/// What waitpid reported. Signals stay numbers, because nix has no names for
/// the real-time signals that glibc and the JVM send between their threads.
enum Stop {
    Exited(Pid, i32),
    Killed(Pid, i32),
    Event(Pid, i32),
    Syscall(Pid),
    Signal(Pid, i32),
}

fn wait_for(pid: Option<Pid>) -> io::Result<Stop> {
    let mut status = 0;
    // SAFETY: waitpid writes the status of one child into `status`.
    let waited = unsafe { libc::waitpid(pid.map_or(-1, Pid::as_raw), &mut status, libc::__WALL) };
    if waited < 0 {
        return Err(io::Error::last_os_error());
    }
    let pid = Pid::from_raw(waited);
    Ok(if libc::WIFEXITED(status) {
        Stop::Exited(pid, libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Stop::Killed(pid, libc::WTERMSIG(status))
    } else if libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
        Stop::Syscall(pid)
    } else if status >> 16 != 0 {
        Stop::Event(pid, status >> 16)
    } else {
        Stop::Signal(pid, libc::WSTOPSIG(status))
    })
}

fn resume(pid: Pid, signal: i32) {
    // SAFETY: PTRACE_CONT takes no address and the signal to deliver as data.
    unsafe {
        libc::ptrace(libc::PTRACE_CONT, pid.as_raw(), std::ptr::null_mut::<libc::c_void>(), signal as libc::c_long)
    };
}
