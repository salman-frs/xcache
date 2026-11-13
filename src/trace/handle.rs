//! What each traced system call records when it starts, and what it leaves
//! pending until it returns.

use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::unistd::Pid;

use super::net::{self, Destination};
use super::supervise::{self, Opening};
use super::syscalls::{self, CLONE_UNTRACED, Call, NAMESPACE_FLAGS};
use super::{Pending, Resume, Tracer, filter, tracee};
use crate::observe::Access;
use crate::record::{Effect, Mutation};

const RESOLVE_IN_ROOT: u64 = 0x10;

impl Tracer<'_, '_> {
    pub(super) fn syscall_entry(&mut self, pid: Pid) -> Resume {
        let Ok(stop) = tracee::seccomp_stop(pid) else {
            return Resume::Continue;
        };
        if stop.arch != filter::NATIVE_AUDIT_ARCH || stop.ret_data == filter::FOREIGN_ABI {
            self.recorder().taint("issues system calls through a foreign ABI");
            return Resume::Continue;
        }
        let Some(call) = syscalls::decode(stop.nr, stop.args) else {
            return Resume::Continue;
        };
        self.handle(pid, call).unwrap_or(Resume::Continue)
    }

    fn handle(&mut self, pid: Pid, call: Call) -> Option<Resume> {
        if let Some(observed) = supervise::observations(self.directories, pid, call) {
            let mut recorder = self.recorder();
            for (access, path) in observed {
                recorder.observe(access, &path);
            }
            return Some(Resume::Continue);
        }
        let resume = match call {
            Call::Open { dirfd, path: address, flags } => {
                let path = tracee::path_at(self.directories, pid, dirfd, address)?;
                self.open(path, flags)
            }
            Call::OpenHow { dirfd, path: address, how } => {
                let how = tracee::read_exact(pid, how, 24)?;
                let field = |index: usize| u64::from_ne_bytes(how[index * 8..index * 8 + 8].try_into().unwrap());
                if field(2) & RESOLVE_IN_ROOT != 0 {
                    self.recorder().taint("resolves paths inside another root (RESOLVE_IN_ROOT)");
                }
                let path = tracee::path_at(self.directories, pid, dirfd, address)?;
                self.open(path, field(0))
            }
            Call::ChangeDirectory { path: address } => {
                let path = tracee::path_at(self.directories, pid, libc::AT_FDCWD, address)?;
                self.recorder().observe(Access::Stat, &path);
                self.directories.may_have_changed();
                Resume::UntilExit(Pending::DirectoryChange)
            }
            Call::ChangeDirectoryToDescriptor => {
                self.directories.may_have_changed();
                Resume::UntilExit(Pending::DirectoryChange)
            }
            Call::Unlink { dirfd, path: address, flags } => {
                let effect = if flags & libc::AT_REMOVEDIR as u64 != 0 { Effect::RemoveDir } else { Effect::Remove };
                self.mutate_at(pid, dirfd, address, effect)?
            }
            Call::Rename { old_dirfd, old, new_dirfd, new, flags } => {
                if flags & libc::RENAME_EXCHANGE as u64 != 0 {
                    self.recorder().taint("swaps paths with RENAME_EXCHANGE");
                    return Some(Resume::Continue);
                }
                let (old, new) = (
                    tracee::path_at(self.directories, pid, old_dirfd, old)?,
                    tracee::path_at(self.directories, pid, new_dirfd, new)?,
                );
                let mut recorder = self.recorder();
                let from = recorder.before_mutation(&old, Effect::RenameFrom);
                let to = recorder.before_mutation(&new, Effect::RenameTo);
                drop(recorder);
                // Only moving a directory renames the working directories under it.
                let renames_directories = from.as_ref().is_none_or(Mutation::is_of_a_directory);
                if renames_directories {
                    self.directories.may_have_changed();
                }
                Resume::UntilExit(Pending::Rename { from, to, renames_directories })
            }
            Call::MakeNode { dirfd, path: address } => self.mutate_at(pid, dirfd, address, Effect::MakeNode)?,
            Call::Link { old_dirfd, old, new_dirfd, new, flags } => {
                let source = tracee::path_or_descriptor(self.directories, pid, old_dirfd, old, flags)?;
                self.recorder().before_link(&source);
                self.mutate_at(pid, new_dirfd, new, Effect::MakeLink)?
            }
            Call::Symlink { new_dirfd, new } => self.mutate_at(pid, new_dirfd, new, Effect::MakeLink)?,
            Call::Chmod { dirfd, path: address } => self.mutate_at(pid, dirfd, address, Effect::Chmod)?,
            Call::ChmodFd { fd } => self.mutate(&tracee::fd_path(pid, fd)?, Effect::Chmod),
            Call::SetTimes { dirfd, path: address, flags, times, timespecs } => {
                let target = if address == 0 {
                    tracee::fd_path(pid, dirfd)?
                } else {
                    tracee::path_at(self.directories, pid, dirfd, address)?
                };
                let follows_symlinks = flags & libc::AT_SYMLINK_NOFOLLOW as u64 == 0;
                if follows_symlinks && sets_a_modification_time(pid, times, timespecs) {
                    self.mutate(&target, Effect::SetTimes)
                } else {
                    self.recorder().before_times_change(&target, follows_symlinks);
                    Resume::Continue
                }
            }
            Call::Truncate { path: address, length } => {
                let effect = if length == 0 { Effect::TruncateToZero } else { Effect::Modify };
                self.mutate_at(pid, libc::AT_FDCWD, address, effect)?
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
            Call::Bind { fd, addr, len } => match net::read_sockaddr(pid, addr, len) {
                Some(Destination::Loopback { .. }) => Resume::UntilExit(Pending::BindPort { fd }),
                Some(Destination::UnixPath(path)) => {
                    let socket = tracee::resolve_at(self.directories, pid, libc::AT_FDCWD, &path)?;
                    let mutation = self.recorder().before_mutation(&socket, Effect::MakeNode);
                    Resume::UntilExit(Pending::Bind { socket, mutation })
                }
                _ => Resume::Continue,
            },
            Call::Unsupported(reason) => {
                self.recorder().taint(reason);
                Resume::Continue
            }
            Call::Exec { .. } | Call::Probe { .. } | Call::List { .. } => Resume::Continue,
        };
        Some(resume)
    }

    fn clone(&mut self, flags: u64) -> Resume {
        self.check_namespaces(flags);
        if flags & CLONE_UNTRACED == 0 {
            return Resume::Continue;
        }
        self.recorder().taint("starts a process that cannot be traced (CLONE_UNTRACED)");
        Resume::UntilExit(Pending::UntracedChild)
    }

    fn open(&mut self, path: PathBuf, flags: u64) -> Resume {
        match supervise::opening(flags) {
            Opening::Writes(effect) => self.mutate(&path, effect),
            Opening::Reads(_) | Opening::Temporary => Resume::Continue,
        }
    }

    fn mutate_at(&mut self, pid: Pid, dirfd: i32, address: u64, effect: Effect) -> Option<Resume> {
        let path = tracee::path_at(self.directories, pid, dirfd, address)?;
        Some(self.mutate(&path, effect))
    }

    fn mutate(&mut self, path: &Path, effect: Effect) -> Resume {
        match self.recorder().before_mutation(path, effect) {
            Some(mutation) => Resume::UntilExit(Pending::Mutation(mutation)),
            None => Resume::Continue,
        }
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
                if let Some(path) = tracee::resolve_at(self.directories, pid, libc::AT_FDCWD, path) {
                    self.recorder().observe(Access::Stat, &path);
                }
            }
            Destination::Loopback { port: 0, .. } => {}
            Destination::Loopback { ip, port } if errno == libc::ECONNREFUSED => {
                self.recorder().observe(Access::Listen, &net::port_key(false, SocketAddr::new(*ip, *port)));
            }
            Destination::Loopback { ip, port } if net::datagram_to_nobody(pid, fd, *port) => {
                self.recorder().observe(Access::Listen, &net::port_key(true, SocketAddr::new(*ip, *port)));
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
            && let Some(meta) = tracee::resolve_at(self.directories, pid, libc::AT_FDCWD, path)
                .and_then(|path| std::fs::metadata(path).ok())
            && self.bound_sockets.contains(&(meta.dev(), meta.ino()))
        {
            return;
        }
        let tracees: Vec<Pid> = self.tracees.keys().copied().collect();
        if let Some(reason) = net::external_peer(pid, destination, &tracees, &mut self.known_listeners) {
            self.recorder().taint(reason);
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
            self.recorder().taint("creates Linux namespaces");
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
