mod filter;
pub(crate) mod net;
mod syscalls;
mod tracee;

use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::sys::ptrace::{self, Event, Options};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use crate::invocation::Invocation;
use crate::observe::Access;
use crate::record::{Effect, Mutation, Recorder, Recording};
use filter::Filter;
use net::Destination;
use syscalls::Call;

const NAMESPACE_FLAGS: u64 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET) as u64;
const O_TMPFILE: u64 = libc::O_TMPFILE as u64;
const CLONE_UNTRACED: u64 = libc::CLONE_UNTRACED as u64;
const RESOLVE_IN_ROOT: u64 = 0x10;
const STATUS_FD: RawFd = 3;
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

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum SetupFailure {
    Ptrace = 1,
    Seccomp = 2,
    Exec = 3,
}

impl SetupFailure {
    fn from_byte(byte: u8) -> Option<Self> {
        [Self::Ptrace, Self::Seccomp, Self::Exec].into_iter().find(|stage| *stage as u8 == byte)
    }
}

pub fn run(invocation: &Invocation, recorder: Recorder) -> Result<Outcome> {
    let started = Instant::now();
    let child = ChildSetup::prepare(invocation)?;
    let (stdout_read, stdout_write) = pipe()?;
    let (stderr_read, stderr_write) = pipe()?;
    let (status_read, status_write) = pipe()?;
    let dev_null = high_fd(File::open("/dev/null")?.into())?;

    // SAFETY: xcache is single-threaded here, and the child only calls
    // async-signal-safe functions before exec.
    let pid = match unsafe { libc::fork() } {
        -1 => return Err(io::Error::last_os_error()).context("fork"),
        0 => unsafe {
            child.exec(
                dev_null.as_raw_fd(),
                stdout_write.as_raw_fd(),
                stderr_write.as_raw_fd(),
                status_write.as_raw_fd(),
            )
        },
        pid => Pid::from_raw(pid),
    };
    drop((stdout_write, stderr_write, status_write, dev_null));
    let output = spawn_output_pump(stdout_read, stderr_read);

    let mut tracer = Tracer::new(pid, recorder);
    let attached = tracer.attach()?;
    if attached {
        tracer.run_until_all_exit()?;
    }
    let stdio = output.join().map_err(|_| anyhow::anyhow!("output pump panicked"))??;
    let failure = read_setup_failure(status_read);

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

struct ChildSetup {
    candidates: Vec<CString>,
    _strings: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
    filter: Filter,
}

impl ChildSetup {
    fn prepare(invocation: &Invocation) -> Result<Self> {
        let c_string = |bytes: &[u8]| CString::new(bytes).context("argument contains a NUL byte");
        let program = invocation.argv.first().context("empty command")?;
        let candidates = program_candidates(program.as_bytes(), invocation.path_var())
            .into_iter()
            .map(|candidate| c_string(&candidate))
            .collect::<Result<_>>()?;
        let args: Vec<CString> = invocation.argv.iter().map(|arg| c_string(arg.as_bytes())).collect::<Result<_>>()?;
        let vars: Vec<CString> = invocation
            .env
            .iter()
            .map(|(name, value)| c_string(&[name.as_bytes(), b"=", value.as_bytes()].concat()))
            .collect::<Result<_>>()?;
        let null_terminated = |strings: &[CString]| {
            strings.iter().map(|string| string.as_ptr()).chain([std::ptr::null()]).collect::<Vec<_>>()
        };
        let (argv, envp) = (null_terminated(&args), null_terminated(&vars));
        Ok(Self {
            candidates,
            _strings: args.into_iter().chain(vars).collect(),
            argv,
            envp,
            filter: Filter::new(&syscalls::traced(), &syscalls::refused()),
        })
    }

    /// Runs in the forked child. Allocates nothing.
    unsafe fn exec(&self, stdin: RawFd, stdout: RawFd, stderr: RawFd, status: RawFd) -> ! {
        unsafe {
            libc::dup2(stdin, 0);
            libc::dup2(stdout, 1);
            libc::dup2(stderr, 2);
            libc::dup2(status, STATUS_FD);
            libc::fcntl(STATUS_FD, libc::F_SETFD, libc::FD_CLOEXEC);
            close_from(STATUS_FD + 1);

            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 {
                fail(SetupFailure::Ptrace);
            }
            libc::raise(libc::SIGSTOP);

            let program = self.filter.program();
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &program) != 0
            {
                fail(SetupFailure::Seccomp);
            }

            let mut errno = libc::ENOENT;
            for candidate in &self.candidates {
                libc::execve(candidate.as_ptr(), self.argv.as_ptr(), self.envp.as_ptr());
                let attempt = *libc::__errno_location();
                if attempt != libc::ENOENT && attempt != libc::ENOTDIR {
                    errno = attempt;
                }
            }
            *libc::__errno_location() = errno;
            fail(SetupFailure::Exec)
        }
    }
}

unsafe fn close_from(first: RawFd) {
    unsafe {
        if libc::syscall(libc::SYS_close_range, first as libc::c_uint, libc::c_uint::MAX, 0) != 0 {
            for fd in first..65536 {
                libc::close(fd);
            }
        }
    }
}

unsafe fn fail(stage: SetupFailure) -> ! {
    unsafe {
        let errno = *libc::__errno_location();
        let mut message = [0u8; 5];
        message[0] = stage as u8;
        message[1..].copy_from_slice(&errno.to_le_bytes());
        libc::write(STATUS_FD, message.as_ptr().cast(), message.len());
        libc::_exit(if errno == libc::ENOENT { 127 } else { 126 });
    }
}

fn read_setup_failure(status: OwnedFd) -> Option<(SetupFailure, i32)> {
    let mut message = Vec::new();
    File::from(status).read_to_end(&mut message).ok()?;
    let stage = SetupFailure::from_byte(*message.first()?)?;
    let errno = i32::from_le_bytes(message.get(1..5)?.try_into().ok()?);
    Some((stage, errno))
}

fn program_candidates(program: &[u8], path_var: Option<&OsStr>) -> Vec<Vec<u8>> {
    if program.contains(&b'/') {
        return vec![program.to_vec()];
    }
    let path_var = path_var.map_or(b"/usr/local/bin:/usr/bin:/bin".as_slice(), OsStr::as_bytes);
    path_var
        .split(|&byte| byte == b':')
        .map(|dir| {
            let dir = if dir.is_empty() { b".".as_slice() } else { dir };
            [dir, b"/", program].concat()
        })
        .collect()
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills both descriptors on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are owned here.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    Ok((high_fd(read)?, high_fd(write)?))
}

/// Moves a descriptor above the range the child rewires (0-3), so dup2 in the
/// child never overwrites a descriptor it still has to duplicate.
fn high_fd(fd: OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC returns a new descriptor that we take ownership of.
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

const STDOUT: u8 = 1;
const STDERR: u8 = 2;

fn spawn_output_pump(stdout: OwnedFd, stderr: OwnedFd) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut streams = [(stdout, STDOUT, true), (stderr, STDERR, true)];
        let mut frames = Vec::new();
        let mut buffer = vec![0u8; 64 * 1024];
        while streams.iter().any(|(_, _, open)| *open) {
            let mut pollfds: Vec<libc::pollfd> = streams
                .iter()
                .map(|(fd, _, open)| libc::pollfd {
                    fd: if *open { fd.as_raw_fd() } else { -1 },
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            // SAFETY: pollfds is a valid array of the given length.
            if unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, -1) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            for (stream, pollfd) in streams.iter_mut().zip(&pollfds) {
                if pollfd.revents == 0 {
                    continue;
                }
                // SAFETY: reading into a buffer we own from a descriptor we own.
                let read = unsafe { libc::read(stream.0.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if read <= 0 {
                    stream.2 = false;
                    continue;
                }
                let chunk = &buffer[..read as usize];
                if stream.1 == STDOUT {
                    io::stdout().write_all(chunk).and_then(|()| io::stdout().flush())?;
                } else {
                    io::stderr().write_all(chunk)?;
                }
                push_frame(&mut frames, stream.1, chunk);
            }
        }
        Ok(frames)
    })
}

fn push_frame(frames: &mut Vec<u8>, stream: u8, chunk: &[u8]) {
    frames.push(stream);
    frames.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    frames.extend_from_slice(chunk);
}

pub fn replay_output(frames: &[u8]) -> io::Result<()> {
    let mut rest = frames;
    while let [stream, a, b, c, d, tail @ ..] = rest {
        let length = u32::from_le_bytes([*a, *b, *c, *d]) as usize;
        let chunk = tail.get(..length).ok_or_else(|| io::Error::other("truncated output record"))?;
        if *stream == STDOUT {
            io::stdout().write_all(chunk)?;
        } else {
            io::stderr().write_all(chunk)?;
        }
        rest = &tail[length..];
    }
    io::stdout().flush()
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

    fn syscall_entry(&mut self, pid: Pid) -> Resume {
        let Ok(stop) = tracee::seccomp_stop(pid) else {
            return Resume::Continue;
        };
        if stop.arch != filter::NATIVE_AUDIT_ARCH || stop.ret_data == filter::FOREIGN_ABI {
            self.recorder.taint("issues system calls through a foreign ABI");
            return Resume::Continue;
        }
        let Some(call) = syscalls::decode(stop.nr, stop.args) else {
            return Resume::Continue;
        };
        self.handle(pid, call).unwrap_or(Resume::Continue)
    }

    fn handle(&mut self, pid: Pid, call: Call) -> Option<Resume> {
        let path = |dirfd: i32, address: u64| -> Option<PathBuf> {
            tracee::resolve(pid, dirfd, &tracee::read_c_string(pid, address)?)
        };
        let path_or_fd = |dirfd: i32, address: u64, flags: u64| -> Option<PathBuf> {
            let raw = tracee::read_c_string(pid, address)?;
            if raw.is_empty() && flags & libc::AT_EMPTY_PATH as u64 != 0 {
                tracee::fd_path(pid, dirfd)
            } else {
                tracee::resolve(pid, dirfd, &raw)
            }
        };

        let resume = match call {
            Call::Open { dirfd, path: address, flags } => self.open(path(dirfd, address)?, flags),
            Call::OpenHow { dirfd, path: address, how } => {
                let how = tracee::read_exact(pid, how, 24)?;
                let field = |index: usize| u64::from_ne_bytes(how[index * 8..index * 8 + 8].try_into().unwrap());
                if field(2) & RESOLVE_IN_ROOT != 0 {
                    self.recorder.taint("resolves paths inside another root (RESOLVE_IN_ROOT)");
                }
                self.open(path(dirfd, address)?, field(0))
            }
            Call::Exec { dirfd, path: address, flags } => {
                Resume::UntilExit(Pending::Exec(path_or_fd(dirfd, address, flags)?))
            }
            Call::Probe { dirfd, path: address, flags, access } => {
                let raw = tracee::read_c_string(pid, address)?;
                if raw.is_empty() && flags & libc::AT_EMPTY_PATH as u64 != 0 {
                    return Some(Resume::Continue);
                }
                let access = if flags & libc::AT_SYMLINK_NOFOLLOW as u64 != 0 { Access::Lstat } else { access };
                self.recorder.observe(access, &tracee::resolve(pid, dirfd, &raw)?);
                Resume::Continue
            }
            Call::List { fd } => {
                self.recorder.observe(Access::List, &tracee::fd_path(pid, fd)?);
                Resume::Continue
            }
            Call::Unlink { dirfd, path: address, flags } => {
                let effect = if flags & libc::AT_REMOVEDIR as u64 != 0 { Effect::RemoveDir } else { Effect::Remove };
                self.mutate(&[(path(dirfd, address)?, effect)])
            }
            Call::Rename { old_dirfd, old, new_dirfd, new, flags } => {
                if flags & libc::RENAME_EXCHANGE as u64 != 0 {
                    self.recorder.taint("swaps paths with RENAME_EXCHANGE");
                    return Some(Resume::Continue);
                }
                let (old, new) = (path(old_dirfd, old)?, path(new_dirfd, new)?);
                let from = self.recorder.before_mutation(&old, Effect::RenameFrom);
                let to = self.recorder.before_mutation(&new, Effect::RenameTo);
                match (from, to) {
                    (Some(from), Some(to)) => Resume::UntilExit(Pending::Rename { from, to }),
                    (from, to) => Resume::UntilExit(Pending::Mutations(from.into_iter().chain(to).collect())),
                }
            }
            Call::MakeNode { dirfd, path: address } => self.mutate(&[(path(dirfd, address)?, Effect::MakeNode)]),
            Call::Link { old_dirfd, old, new_dirfd, new, flags } => {
                let source = path_or_fd(old_dirfd, old, flags)?;
                self.recorder.before_link(&source);
                self.mutate(&[(path(new_dirfd, new)?, Effect::MakeLink)])
            }
            Call::Symlink { new_dirfd, new } => self.mutate(&[(path(new_dirfd, new)?, Effect::MakeLink)]),
            Call::Chmod { dirfd, path: address } => self.mutate(&[(path(dirfd, address)?, Effect::Chmod)]),
            Call::ChmodFd { fd } => self.mutate(&[(tracee::fd_path(pid, fd)?, Effect::Chmod)]),
            Call::SetTimes { dirfd, path: address, flags, times, timespecs } => {
                let target = if address == 0 { tracee::fd_path(pid, dirfd)? } else { path(dirfd, address)? };
                let follows_symlinks = flags & libc::AT_SYMLINK_NOFOLLOW as u64 == 0;
                if follows_symlinks && sets_a_modification_time(pid, times, timespecs) {
                    self.mutate(&[(target, Effect::SetTimes)])
                } else {
                    self.recorder.before_times_change(&target, follows_symlinks);
                    Resume::Continue
                }
            }
            Call::Truncate { path: address, length } => {
                let effect = if length == 0 { Effect::TruncateToZero } else { Effect::Modify };
                self.mutate(&[(path(libc::AT_FDCWD, address)?, effect)])
            }
            Call::Connect { fd, addr, len } => match net::read_sockaddr(pid, addr, len) {
                Some(destination) => Resume::UntilExit(Pending::Connect { fd, destination }),
                None => Resume::Continue,
            },
            Call::SendTo { addr, len } => {
                self.check_peer(pid, addr, len);
                Resume::Continue
            }
            Call::SendMsg { msg } => {
                self.check_message_peer(pid, msg);
                Resume::Continue
            }
            Call::SendMmsg { msgs, count } => {
                const MMSGHDR_SIZE: u64 = std::mem::size_of::<libc::mmsghdr>() as u64;
                for index in 0..count.min(1024) {
                    self.check_message_peer(pid, msgs + index * MMSGHDR_SIZE);
                }
                Resume::Continue
            }
            Call::Unshare { flags } => {
                self.check_namespaces(flags);
                Resume::Continue
            }
            Call::Clone { flags } => self.clone(flags),
            Call::Clone3 { args } => self.clone(u64::from_ne_bytes(tracee::read_exact(pid, args, 8)?.try_into().ok()?)),
            Call::Accept => Resume::UntilExit(Pending::Accept),
            Call::Bind { addr, len } => match net::read_sockaddr(pid, addr, len) {
                Some(Destination::UnixPath(path)) => {
                    let socket = tracee::resolve(pid, libc::AT_FDCWD, &path)?;
                    let mutation = self.recorder.before_mutation(&socket, Effect::MakeNode);
                    Resume::UntilExit(Pending::Bind { socket, mutation })
                }
                _ => Resume::Continue,
            },
            Call::Unsupported(reason) => {
                self.recorder.taint(reason);
                Resume::Continue
            }
        };
        Some(resume)
    }

    fn clone(&mut self, flags: u64) -> Resume {
        self.check_namespaces(flags);
        if flags & CLONE_UNTRACED == 0 {
            return Resume::Continue;
        }
        self.recorder.taint("starts a process that cannot be traced (CLONE_UNTRACED)");
        Resume::UntilExit(Pending::UntracedChild)
    }

    fn open(&mut self, path: PathBuf, flags: u64) -> Resume {
        let has = |flag: i32| flags & flag as u64 != 0;
        if has(libc::O_PATH) {
            self.recorder.observe(if has(libc::O_NOFOLLOW) { Access::Lstat } else { Access::Stat }, &path);
            return Resume::Continue;
        }
        if flags & O_TMPFILE == O_TMPFILE {
            return Resume::Continue;
        }
        let writes =
            flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64 || has(libc::O_TRUNC) || has(libc::O_CREAT);
        if !writes {
            self.recorder.observe(Access::Read, &path);
            if has(libc::O_NOFOLLOW) {
                self.recorder.observe(Access::Lstat, &path);
            }
            return Resume::Continue;
        }
        let effect = match (has(libc::O_CREAT), has(libc::O_EXCL), has(libc::O_TRUNC)) {
            (true, true, _) => Effect::CreateExclusive,
            (true, false, true) => Effect::Create,
            _ => Effect::Modify,
        };
        self.mutate(&[(path, effect)])
    }

    fn mutate(&mut self, targets: &[(PathBuf, Effect)]) -> Resume {
        let mutations: Vec<Mutation> =
            targets.iter().filter_map(|(path, effect)| self.recorder.before_mutation(path, *effect)).collect();
        if mutations.is_empty() { Resume::Continue } else { Resume::UntilExit(Pending::Mutations(mutations)) }
    }

    /// A connection that reached nothing is an input: no file at a socket path,
    /// or nothing bound to a loopback port. glibc connects datagram sockets,
    /// without sending, to sort the addresses getaddrinfo returns.
    fn connected(&mut self, pid: Pid, fd: i32, destination: &Destination, result: i64) {
        let errno = -result as i32;
        if let Destination::Loopback { .. } = destination
            && errno != libc::ECONNREFUSED
            && let Some(local) = net::local_address(pid, fd)
        {
            self.opened_connections.insert(local);
        }
        match destination {
            Destination::UnixPath(path) if matches!(errno, libc::ENOENT | libc::ENOTDIR) => {
                if let Some(path) = tracee::resolve(pid, libc::AT_FDCWD, path) {
                    self.recorder.observe(Access::Stat, &path);
                }
            }
            Destination::Loopback { port: 0, .. } => {}
            Destination::Loopback { ip, port } if errno == libc::ECONNREFUSED => {
                self.recorder.observe(Access::Listen, &net::port_key(false, SocketAddr::new(*ip, *port)));
            }
            Destination::Loopback { ip, port } if net::datagram_to_nobody(pid, fd, *port) => {
                self.recorder.observe(Access::Listen, &net::port_key(true, SocketAddr::new(*ip, *port)));
            }
            _ => self.check_destination(pid, destination),
        }
    }

    fn check_peer(&mut self, pid: Pid, address: u64, length: u64) {
        if let Some(destination) = net::read_sockaddr(pid, address, length) {
            self.check_destination(pid, &destination);
        }
    }

    fn check_destination(&mut self, pid: Pid, destination: &Destination) {
        if let Destination::UnixPath(path) = destination
            && let Some(meta) = tracee::resolve(pid, libc::AT_FDCWD, path).and_then(|path| std::fs::metadata(path).ok())
            && self.bound_sockets.contains(&(meta.dev(), meta.ino()))
        {
            return;
        }
        let tracees: Vec<Pid> = self.tracees.keys().copied().collect();
        if let Some(reason) = net::external_peer(pid, destination, &tracees, &mut self.known_listeners) {
            self.recorder.taint(reason);
        }
    }

    fn check_message_peer(&mut self, pid: Pid, header: u64) {
        let Some(bytes) = tracee::read_exact(pid, header, 16) else {
            return;
        };
        let name = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        let name_length = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        self.check_peer(pid, name, u64::from(name_length));
    }

    fn check_namespaces(&mut self, flags: u64) {
        if flags & NAMESPACE_FLAGS != 0 {
            self.recorder.taint("creates Linux namespaces");
        }
    }
}

/// Whether a utime call sets a chosen modification time, as `touch -d` and
/// `cp -p` do, rather than the current time or none.
fn sets_a_modification_time(pid: Pid, times: u64, timespecs: bool) -> bool {
    const TIMESPEC_SIZE: u64 = 16;
    if times == 0 {
        return false;
    }
    if !timespecs {
        return true;
    }
    tracee::read_exact(pid, times + TIMESPEC_SIZE, TIMESPEC_SIZE as usize).is_some_and(|modified| {
        let nanoseconds = i64::from_ne_bytes(modified[8..16].try_into().unwrap());
        nanoseconds != libc::UTIME_NOW && nanoseconds != libc::UTIME_OMIT
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_lookup_follows_path_order() {
        let candidates = program_candidates(b"cc", Some(OsStr::new("/a::/b")));
        assert_eq!(candidates, vec![b"/a/cc".to_vec(), b"./cc".to_vec(), b"/b/cc".to_vec()]);
        assert_eq!(program_candidates(b"./run.sh", None), vec![b"./run.sh".to_vec()]);
    }

    #[test]
    fn output_frames_round_trip() {
        let mut frames = Vec::new();
        push_frame(&mut frames, STDOUT, b"out");
        push_frame(&mut frames, STDERR, b"err");
        assert_eq!(frames.len(), 2 * 5 + 6);
        replay_output(&frames).unwrap();
    }
}
