use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result};
use nix::unistd::Pid;

use super::filter::{Filter, Observer};
use super::syscalls;
use crate::invocation::Invocation;

const STATUS_FD: RawFd = 3;
/// Where the child keeps its seccomp listener until exec, for the tracer to copy.
pub const LISTENER_FD: RawFd = 4;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum SetupFailure {
    Ptrace = 1,
    Seccomp = 2,
    Exec = 3,
}

impl SetupFailure {
    fn from_byte(byte: u8) -> Option<Self> {
        [Self::Ptrace, Self::Seccomp, Self::Exec].into_iter().find(|stage| *stage as u8 == byte)
    }
}

/// A forked child that stops itself before exec, waiting for the tracer.
pub struct Child {
    pub pid: Pid,
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
    pub setup: SetupStatus,
}

/// Where the child reports a failure to set up tracing or to exec.
pub struct SetupStatus(OwnedFd);

impl SetupStatus {
    /// Blocks until the child has exec'd or exited, so call it once tracing is over.
    pub fn failure(self) -> Option<(SetupFailure, i32)> {
        let mut message = Vec::new();
        File::from(self.0).read_to_end(&mut message).ok()?;
        let stage = SetupFailure::from_byte(*message.first()?)?;
        let errno = i32::from_le_bytes(message.get(1..5)?.try_into().ok()?);
        Some((stage, errno))
    }
}

/// With `notify`, the child asks for a seccomp listener and leaves it at
/// LISTENER_FD if the kernel gives it one.
pub fn spawn(invocation: &Invocation, notify: bool) -> Result<Child> {
    let setup = ChildSetup::prepare(invocation, notify)?;
    let (stdout, stdout_write) = pipe()?;
    let (stderr, stderr_write) = pipe()?;
    let (status, status_write) = pipe()?;
    let dev_null = high_fd(File::open("/dev/null")?.into())?;

    // SAFETY: xcache is single-threaded here, and the child only calls
    // async-signal-safe functions before exec.
    let pid = match unsafe { libc::fork() } {
        -1 => return Err(io::Error::last_os_error()).context("fork"),
        // SAFETY: this is the forked child, which execs or exits without returning.
        0 => unsafe {
            setup.exec(
                dev_null.as_raw_fd(),
                stdout_write.as_raw_fd(),
                stderr_write.as_raw_fd(),
                status_write.as_raw_fd(),
            )
        },
        pid => Pid::from_raw(pid),
    };
    Ok(Child { pid, stdout, stderr, setup: SetupStatus(status) })
}

struct ChildSetup {
    candidates: Vec<CString>,
    _strings: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
    tracing: Filter,
    /// Shows the supervisor the calls that are only observed.
    notifying: Option<Filter>,
}

impl ChildSetup {
    fn prepare(invocation: &Invocation, notify: bool) -> Result<Self> {
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
            tracing: Filter::new(&syscalls::rules(), Observer::Tracer),
            notifying: notify.then(|| Filter::new(&syscalls::rules(), Observer::Supervisor)),
        })
    }

    /// Runs in the forked child. Allocates nothing.
    unsafe fn exec(&self, stdin: RawFd, stdout: RawFd, stderr: RawFd, status: RawFd) -> ! {
        // SAFETY: plain system calls on descriptors and pointers prepared before the fork.
        unsafe {
            libc::dup2(stdin, 0);
            libc::dup2(stdout, 1);
            libc::dup2(stderr, 2);
            libc::dup2(status, STATUS_FD);
            libc::fcntl(STATUS_FD, libc::F_SETFD, libc::FD_CLOEXEC);
            close_from(STATUS_FD + 1);

            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || !self.install_filter() {
                fail(SetupFailure::Seccomp);
            }
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 {
                fail(SetupFailure::Ptrace);
            }
            libc::raise(libc::SIGSTOP);

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

    /// Installs the notifying filter if the kernel gives it a listener, and the
    /// tracing filter otherwise. A listener is refused to a process that
    /// already runs under one.
    unsafe fn install_filter(&self) -> bool {
        const NEW_LISTENER: libc::c_ulong = libc::SECCOMP_FILTER_FLAG_NEW_LISTENER;
        // Since Linux 5.19: no signal interrupts a call the supervisor has received.
        const WAIT_KILLABLE_RECV: libc::c_ulong = libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
        let install = |filter: &Filter, flags: libc::c_ulong| {
            let program = filter.program();
            // SAFETY: the kernel copies the program, which outlives the call.
            unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, flags, &program) }
        };
        if let Some(notifying) = &self.notifying {
            for flags in [NEW_LISTENER | WAIT_KILLABLE_RECV, NEW_LISTENER] {
                let listener = install(notifying, flags) as RawFd;
                if listener == LISTENER_FD {
                    return true;
                }
                if listener >= 0 {
                    // SAFETY: dup3 and close take descriptors this process owns.
                    return unsafe {
                        libc::dup3(listener, LISTENER_FD, libc::O_CLOEXEC) == LISTENER_FD && libc::close(listener) == 0
                    };
                }
            }
        }
        install(&self.tracing, 0) == 0
    }
}

unsafe fn close_from(first: RawFd) {
    // SAFETY: close_range and close take no pointers.
    unsafe {
        if libc::syscall(libc::SYS_close_range, first as libc::c_uint, libc::c_uint::MAX, 0) != 0 {
            for fd in first..65536 {
                libc::close(fd);
            }
        }
    }
}

unsafe fn fail(stage: SetupFailure) -> ! {
    // SAFETY: errno is thread-local and the message is a local buffer.
    unsafe {
        let errno = *libc::__errno_location();
        let mut message = [0u8; 5];
        message[0] = stage as u8;
        message[1..].copy_from_slice(&errno.to_le_bytes());
        libc::write(STATUS_FD, message.as_ptr().cast(), message.len());
        libc::_exit(if errno == libc::ENOENT { 127 } else { 126 });
    }
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

pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
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
    // SAFETY: F_DUPFD_CLOEXEC takes no pointers.
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl just returned this new descriptor, and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
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
}
