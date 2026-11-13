use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use nix::unistd::Pid;

use super::tracee;
use crate::sync::lock;

/// The working directories of the traced processes, which their relative
/// paths start from. Each is read once, and again after any call that can
/// change what a working directory is called.
pub struct WorkingDirectories {
    changes: AtomicU64,
    known: Mutex<HashMap<Pid, (u64, PathBuf)>>,
}

impl WorkingDirectories {
    pub fn new() -> Self {
        Self { changes: AtomicU64::new(0), known: Mutex::new(HashMap::new()) }
    }

    pub fn of(&self, pid: Pid) -> Option<PathBuf> {
        let as_of = self.changes.load(Ordering::Acquire);
        let mut known = lock(&self.known);
        if let Some((read_as_of, directory)) = known.get(&pid)
            && *read_as_of == as_of
        {
            return Some(directory.clone());
        }
        let directory = tracee::working_directory(pid)?;
        known.insert(pid, (as_of, directory.clone()));
        Some(directory)
    }

    /// Call when a chdir, fchdir or rename starts and when it has returned, so
    /// nothing read in between is kept.
    pub fn may_have_changed(&self) {
        self.changes.fetch_add(1, Ordering::Release);
    }

    /// Call when a process has exited, because its ID can be given to another.
    pub fn forget(&self, pid: Pid) {
        lock(&self.known).remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_read_again_after_a_change() {
        let directories = WorkingDirectories::new();
        let pid = nix::unistd::getpid();
        let actual = std::env::current_dir().unwrap();
        assert_eq!(directories.of(pid), Some(actual.clone()));

        lock(&directories.known).insert(pid, (0, PathBuf::from("/stale")));
        assert_eq!(directories.of(pid), Some(PathBuf::from("/stale")));
        directories.may_have_changed();
        assert_eq!(directories.of(pid), Some(actual));
    }
}
