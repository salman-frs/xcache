//! The calls that only look at the filesystem: what each records, and the
//! supervisor thread that records them when the kernel offers a listener.

use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Mutex;

use nix::unistd::Pid;

use super::directories::WorkingDirectories;
use super::notify::Listener;
use super::syscalls::{self, Call};
use super::tracee;
use crate::observe::Access;
use crate::record::{Effect, Recorder};
use crate::sync::lock;

const O_TMPFILE: u64 = libc::O_TMPFILE as u64;

/// Records the calls the filter shows the supervisor and lets each run, until
/// `all_exited` is closed.
pub fn supervise(
    mut listener: Listener,
    all_exited: &OwnedFd,
    recorder: &Mutex<Recorder>,
    directories: &WorkingDirectories,
) -> io::Result<()> {
    while let Some(call) = listener.next(all_exited)? {
        let observed =
            syscalls::decode(call.nr, call.args).and_then(|decoded| observations(directories, call.pid, decoded));
        if let Some(observed) = observed
            && !observed.is_empty()
        {
            let mut recorder = lock(recorder);
            for (access, path) in observed {
                recorder.observe(access, &path);
            }
        }
        listener.resume(&call);
    }
    Ok(())
}

/// What a call that changes nothing looks at, or None for any other call.
/// Paths are resolved while the caller waits, because its working directory
/// and descriptors can change once it runs.
pub fn observations(directories: &WorkingDirectories, pid: Pid, call: Call) -> Option<Vec<(Access, PathBuf)>> {
    let each = |accesses: &[Access], path: Option<PathBuf>| -> Vec<(Access, PathBuf)> {
        let Some(path) = path else {
            return Vec::new();
        };
        accesses.iter().map(|&access| (access, path.clone())).collect()
    };
    let observed = match call {
        Call::Open { dirfd, path: address, flags } => match opening(flags) {
            Opening::Reads(accesses) => each(accesses, tracee::path_at(directories, pid, dirfd, address)),
            Opening::Temporary => Vec::new(),
            Opening::Writes(_) => return None,
        },
        Call::Probe { dirfd, path: address, flags, access } => match tracee::read_c_string(pid, address) {
            Some(raw) if raw.is_empty() && flags & libc::AT_EMPTY_PATH as u64 != 0 => Vec::new(),
            Some(raw) => {
                let access = if flags & libc::AT_SYMLINK_NOFOLLOW as u64 != 0 { Access::Lstat } else { access };
                each(&[access], tracee::resolve_at(directories, pid, dirfd, &raw))
            }
            None => Vec::new(),
        },
        Call::List { fd } => each(&[Access::List], tracee::fd_path(pid, fd)),
        Call::Exec { dirfd, path: address, flags } => {
            each(&[Access::Read], tracee::path_or_descriptor(directories, pid, dirfd, address, flags))
        }
        _ => return None,
    };
    Some(observed)
}

pub enum Opening {
    Reads(&'static [Access]),
    /// An unnamed file (O_TMPFILE), which only the command can see.
    Temporary,
    Writes(Effect),
}

pub fn opening(flags: u64) -> Opening {
    let has = |flag: i32| flags & flag as u64 != 0;
    if has(libc::O_PATH) {
        return Opening::Reads(if has(libc::O_NOFOLLOW) { &[Access::Lstat] } else { &[Access::Stat] });
    }
    if flags & O_TMPFILE == O_TMPFILE {
        return Opening::Temporary;
    }
    let writes = flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64 || has(libc::O_TRUNC) || has(libc::O_CREAT);
    if !writes {
        return Opening::Reads(if has(libc::O_NOFOLLOW) { &[Access::Read, Access::Lstat] } else { &[Access::Read] });
    }
    Opening::Writes(match (has(libc::O_CREAT), has(libc::O_EXCL), has(libc::O_TRUNC)) {
        (true, true, _) => Effect::CreateExclusive,
        (true, false, true) => Effect::Create,
        _ => Effect::Modify,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::syscalls::Rule;

    #[test]
    fn calls_the_supervisor_sees_change_nothing() {
        let me = nix::unistd::getpid();
        let directories = WorkingDirectories::new();
        let opening_without_writing = [0, libc::O_PATH | libc::O_NOFOLLOW, libc::O_DIRECTORY, libc::O_TMPFILE];
        for (nr, rule) in syscalls::rules() {
            let argument_sets: Vec<[u64; 6]> = match rule {
                Rule::Observe => vec![[0; 6]],
                Rule::ObserveReading { flags, writing } => opening_without_writing
                    .iter()
                    .filter(|&&opening| opening as u32 & writing == 0)
                    .map(|&opening| {
                        let mut args = [0; 6];
                        args[flags] = opening as u64;
                        args
                    })
                    .collect(),
                Rule::Trace | Rule::TraceFlagged { .. } | Rule::Refuse => continue,
            };
            for args in argument_sets {
                let call = syscalls::decode(nr as u64, args).unwrap();
                assert!(observations(&directories, me, call).is_some(), "{call:?}");
            }
        }
    }
}
