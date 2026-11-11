//! What each traced system call records when it starts, and what it leaves
//! pending until it returns.

use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use nix::unistd::Pid;

use super::net::{self, Destination};
use super::syscalls::{self, Call};
use super::{Pending, Resume, Tracer, filter, tracee};
use crate::observe::Access;
use crate::record::{Effect, Mutation};

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

impl Tracer<'_> {
    pub(super) fn syscall_entry(&mut self, pid: Pid) -> Resume {
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
    pub(super) fn connected(&mut self, pid: Pid, fd: i32, destination: &Destination, result: i64) {
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
