use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use nix::unistd::{Pid, getpid};

use super::tracee;

const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP: libc::c_ulong = 1;

/// Whether a supervisor can see calls here and let them continue.
pub fn available() -> bool {
    can_copy_descriptors() && notification_sizes_match()
}

/// Whether pidfd_getfd, which takes the listener out of the child, works. It
/// came in Linux 5.6, after SECCOMP_USER_NOTIF_FLAG_CONTINUE, and Docker's
/// default seccomp profile refuses it.
fn can_copy_descriptors() -> bool {
    let me = getpid();
    tracee::process_descriptor(me).is_ok_and(|any_open| tracee::copy_descriptor(me, any_open.as_raw_fd()).is_ok())
}

fn notification_sizes_match() -> bool {
    let mut sizes = libc::seccomp_notif_sizes { seccomp_notif: 0, seccomp_notif_resp: 0, seccomp_data: 0 };
    // SAFETY: the kernel fills the three sizes.
    let result = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_GET_NOTIF_SIZES, 0, &mut sizes) };
    result == 0
        && usize::from(sizes.seccomp_notif) == size_of::<libc::seccomp_notif>()
        && usize::from(sizes.seccomp_notif_resp) == size_of::<libc::seccomp_notif_resp>()
        && usize::from(sizes.seccomp_data) == size_of::<libc::seccomp_data>()
}

pub struct Notification {
    id: u64,
    /// Whether the caller was last seen on the CPU the supervisor is on.
    caller_is_here: bool,
    pub pid: Pid,
    pub nr: u64,
    pub args: [u64; 6],
}

/// The file descriptor the kernel delivers notifications on. Since Linux 6.6
/// it can wake a caller on the supervisor's CPU, which would move a caller
/// from another CPU there, so only callers met on this CPU are woken that way.
pub struct Listener {
    fd: OwnedFd,
    /// Whether the kernel wakes on one CPU now, or None if it cannot.
    wakes_on_one_cpu: Option<bool>,
    cpu: i32,
    cpu_of_caller: HashMap<Pid, i32>,
}

struct Ready {
    notification: bool,
    closed: bool,
}

impl Listener {
    /// Copies the listener out of a stopped child, which keeps it at `fd`.
    /// None if the child has none there, because the kernel refused one.
    pub fn take_from(child: Pid, fd: RawFd) -> io::Result<Option<Self>> {
        let fd = match tracee::copy_descriptor(child, fd) {
            Ok(fd) => fd,
            Err(error) if error.raw_os_error() == Some(libc::EBADF) => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut listener = Self { fd, wakes_on_one_cpu: None, cpu: -1, cpu_of_caller: HashMap::new() };
        listener.wakes_on_one_cpu = listener.set_flags(SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP).then_some(true);
        Ok(Some(listener))
    }

    /// Waits for the next notification, or for `stop` to be closed (None).
    pub fn next(&mut self, stop: &OwnedFd) -> io::Result<Option<Notification>> {
        self.wake_on_one_cpu(true);
        loop {
            let ready = self.poll(stop)?;
            if ready.notification {
                match self.receive() {
                    Ok(notification) => return Ok(Some(notification)),
                    // The caller was killed or interrupted before it was received.
                    Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EINTR)) => continue,
                    Err(error) => return Err(error),
                }
            }
            if ready.closed {
                return Ok(None);
            }
        }
    }

    fn poll(&self, stop: &OwnedFd) -> io::Result<Ready> {
        loop {
            let mut fds =
                [self.fd.as_raw_fd(), stop.as_raw_fd()].map(|fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 });
            // SAFETY: fds is a valid array of two pollfds.
            if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } >= 0 {
                let [listener, stop] = fds.map(|fd| fd.revents);
                return Ok(Ready {
                    notification: listener & libc::POLLIN != 0,
                    closed: stop != 0 || listener & libc::POLLHUP != 0,
                });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn wake_on_one_cpu(&mut self, wanted: bool) {
        if self.wakes_on_one_cpu.is_some_and(|current| current != wanted) {
            self.set_flags(if wanted { SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP } else { 0 });
            self.wakes_on_one_cpu = Some(wanted);
        }
    }

    fn set_flags(&self, flags: libc::c_ulong) -> bool {
        // SAFETY: the flags are passed by value; kernels before 6.6 refuse the call.
        unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_SET_FLAGS, flags) == 0 }
    }

    fn receive(&mut self) -> io::Result<Notification> {
        // SAFETY: seccomp_notif is plain data, and the kernel requires it zeroed.
        let mut raw: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: the kernel writes one seccomp_notif, whose size was checked in available().
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_RECV, &mut raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let pid = Pid::from_raw(raw.pid as i32);
        let caller_is_here = self.wakes_on_one_cpu.is_some() && self.met_here(pid);
        Ok(Notification { id: raw.id, caller_is_here, pid, nr: raw.data.nr as u64, args: raw.data.args })
    }

    /// The supervisor only changes CPU when a caller wakes it on its own.
    fn met_here(&mut self, caller: Pid) -> bool {
        // SAFETY: sched_getcpu takes no arguments.
        let here = unsafe { libc::sched_getcpu() };
        if here != self.cpu {
            self.cpu = here;
            self.cpu_of_caller.insert(caller, here);
        }
        self.cpu_of_caller.get(&caller) == Some(&here)
    }

    /// Lets the call run as it would without xcache.
    pub fn resume(&mut self, notification: &Notification) {
        self.wake_on_one_cpu(notification.caller_is_here);
        let response =
            libc::seccomp_notif_resp { id: notification.id, val: 0, error: 0, flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE };
        // SAFETY: the kernel reads one seccomp_notif_resp. If the caller is
        // gone, ENOENT is all there is to it.
        unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_SEND, &response) };
    }
}
