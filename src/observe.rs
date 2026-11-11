use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, FileType};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::digest::{ContentHasher, Digest};
use crate::git;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Stat,
    Lstat,
    List,
    Writable,
    /// Whether anything is bound to a loopback address, named like `tcp:127.0.0.1:8080`.
    Listen,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum State {
    Missing,
    File {
        size: u64,
        mode: u32,
        /// None when the command only checked a file it may not read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<Digest>,
    },
    Dir {
        #[serde(with = "crate::path_serde")]
        real_path: PathBuf,
        mode: u32,
    },
    Listing {
        #[serde(with = "crate::path_serde")]
        real_path: PathBuf,
        entries: Digest,
    },
    Symlink {
        #[serde(with = "crate::path_serde")]
        target: PathBuf,
    },
    Writable {
        parent_is_dir: bool,
        is_dir: bool,
    },
    Special {
        kind: SpecialKind,
    },
    Error {
        errno: i32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialKind {
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Special,
}

impl EntryKind {
    pub fn of(file_type: FileType) -> Self {
        if file_type.is_symlink() {
            Self::Symlink
        } else if file_type.is_dir() {
            Self::Dir
        } else if file_type.is_file() {
            Self::File
        } else {
            Self::Special
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::File => b'f',
            Self::Dir => b'd',
            Self::Symlink => b'l',
            Self::Special => b's',
        }
    }
}

pub type Listing = BTreeMap<OsString, EntryKind>;

pub fn probe(access: Access, path: &Path, hasher: &mut ContentHasher) -> State {
    match access {
        Access::Read => match fs::metadata(path) {
            Ok(meta) => describe(access, path, &meta, hasher),
            Err(error) => from_error(&error),
        },
        Access::Stat => match fs::metadata(path) {
            Ok(meta) => describe(access, path, &meta, hasher),
            Err(error) => from_error(&error),
        },
        Access::Lstat => match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => match fs::read_link(path) {
                Ok(target) => State::Symlink { target },
                Err(error) => from_error(&error),
            },
            Ok(meta) => describe(access, path, &meta, hasher),
            Err(error) => from_error(&error),
        },
        Access::List => match read_listing(path) {
            Ok(listing) => listing_state(path, &listing),
            Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => probe(Access::Stat, path, hasher),
            Err(error) => from_error(&error),
        },
        Access::Writable => {
            State::Writable { parent_is_dir: path.parent().is_some_and(Path::is_dir), is_dir: path.is_dir() }
        }
        Access::Listen => match crate::trace::net::is_bound(path) {
            Some(true) => State::Special { kind: SpecialKind::Socket },
            Some(false) => State::Missing,
            None => State::Error { errno: libc::EINVAL },
        },
    }
}

/// Whether a file recorded as `state` still has the same type, size and
/// permissions, which is cheaper to check than its content.
pub fn file_metadata_matches(access: Access, path: &Path, state: &State) -> bool {
    let State::File { size, mode, .. } = state else {
        return false;
    };
    let meta = if access == Access::Lstat { fs::symlink_metadata(path) } else { fs::metadata(path) };
    meta.is_ok_and(|meta| meta.is_file() && recorded_size(path, &meta) == *size && permission_bits(&meta) == *mode)
}

/// Git's bookkeeping files are compared by a digest that leaves out what
/// differs between checkouts, which changes their size too.
fn recorded_size(path: &Path, meta: &fs::Metadata) -> u64 {
    if git::is_bookkeeping(path) { 0 } else { meta.len() }
}

pub fn read_listing(dir: &Path) -> io::Result<Listing> {
    fs::read_dir(dir)?
        .map(|entry| {
            let entry = entry?;
            Ok((entry.file_name(), EntryKind::of(entry.file_type()?)))
        })
        .collect()
}

pub fn listing_state(dir: &Path, listing: &Listing) -> State {
    let mut hasher = blake3::Hasher::new();
    for (name, kind) in listing {
        hasher.update(&[kind.tag()]);
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
    }
    State::Listing {
        real_path: fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf()),
        entries: Digest::of_hasher(&hasher),
    }
}

/// Files are described by content even when the command only checked their
/// metadata: tools such as make and git compare modification times, and content
/// is what those times stand for, without changing on every checkout.
fn describe(access: Access, path: &Path, meta: &fs::Metadata, hasher: &mut ContentHasher) -> State {
    let file_type = meta.file_type();
    if file_type.is_file() {
        let content = match hasher.hash_file(path) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied && access != Access::Read => None,
            Err(error) => return from_error(&error),
        };
        State::File { size: recorded_size(path, meta), mode: permission_bits(meta), content }
    } else if file_type.is_dir() {
        match fs::canonicalize(path) {
            Ok(real_path) => State::Dir { real_path, mode: permission_bits(meta) },
            Err(error) => from_error(&error),
        }
    } else {
        State::Special { kind: special_kind(file_type) }
    }
}

pub fn permission_bits(meta: &fs::Metadata) -> u32 {
    meta.permissions().mode() & 0o7777
}

fn special_kind(file_type: FileType) -> SpecialKind {
    if file_type.is_fifo() {
        SpecialKind::Fifo
    } else if file_type.is_socket() {
        SpecialKind::Socket
    } else if file_type.is_char_device() {
        SpecialKind::CharDevice
    } else {
        SpecialKind::BlockDevice
    }
}

fn from_error(error: &io::Error) -> State {
    match error.raw_os_error() {
        Some(libc::ENOENT) => State::Missing,
        Some(errno) => State::Error { errno },
        None => State::Error { errno: libc::EIO },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn probe_now(access: Access, path: &Path) -> State {
        probe(access, path, &mut ContentHasher::in_memory())
    }

    #[test]
    fn metadata_checks_see_content_changes_of_the_same_size() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a");
        fs::write(&file, b"one").unwrap();
        let before: Vec<State> = [Access::Read, Access::Stat, Access::Lstat].map(|a| probe_now(a, &file)).into();

        fs::write(&file, b"two").unwrap();
        for (access, state) in [Access::Read, Access::Stat, Access::Lstat].into_iter().zip(before) {
            assert_ne!(probe_now(access, &file), state, "{access:?}");
        }
    }

    #[test]
    fn lstat_sees_symlink_targets() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), b"x").unwrap();
        fs::write(dir.path().join("b"), b"x").unwrap();
        let link = dir.path().join("link");
        symlink("a", &link).unwrap();
        let before = (probe_now(Access::Lstat, &link), probe_now(Access::Read, &link));

        fs::remove_file(&link).unwrap();
        symlink("b", &link).unwrap();
        assert_ne!(probe_now(Access::Lstat, &link), before.0);
        assert_eq!(probe_now(Access::Read, &link), before.1);
    }

    #[test]
    fn listing_changes_when_an_entry_is_added() {
        let dir = tempfile::tempdir().unwrap();
        let before = probe_now(Access::List, dir.path());
        fs::write(dir.path().join("new"), b"").unwrap();
        assert_ne!(probe_now(Access::List, dir.path()), before);
    }

    #[test]
    fn missing_paths_and_not_a_directory_are_distinct() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("file"), b"").unwrap();
        assert_eq!(probe_now(Access::Stat, &dir.path().join("absent")), State::Missing);
        assert_eq!(probe_now(Access::Stat, &dir.path().join("file/child")), State::Error { errno: libc::ENOTDIR });
    }
}
