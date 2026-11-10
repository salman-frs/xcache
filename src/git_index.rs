//! Git's index stores the stat data (times, inode, size) of every tracked file
//! next to its object ID, so two checkouts of the same commit have different
//! index files. The digest here covers what the index says about the tree and
//! leaves out that stat cache. A command that relies on the stat cache compares
//! it with the work tree, whose files xcache records by content.

use std::ffi::OsStr;
use std::path::Path;

use crate::digest::Digest;

const SIGNATURE: &[u8] = b"DIRC";
const HEADER_LEN: usize = 12;
const STAT_LEN: usize = 40;
const MODE_RANGE: std::ops::Range<usize> = 24..28;
const OID_LEN: usize = 20;
const CHECKSUM_LEN: usize = 20;
const EXTENDED_FLAG: u16 = 0x4000;
const NAME_LENGTH_MASK: u16 = 0x0fff;
const STAT_EXTENSIONS: [&[u8]; 4] = [b"UNTR", b"FSMN", b"EOIE", b"IEOT"];

pub fn is_index(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new("index"))
        && path.ancestors().skip(1).any(|dir| dir.file_name() == Some(OsStr::new(".git")))
}

/// Returns None for anything that does not parse as a SHA-1 index of version
/// 2 to 4, so the caller can fall back to hashing the raw bytes.
pub fn digest(bytes: &[u8]) -> Option<Digest> {
    let mut reader = Reader { bytes, offset: 0 };
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xcache-git-index-v1");

    let header = reader.take(HEADER_LEN)?;
    let version = u32::from_be_bytes(header[4..8].try_into().ok()?);
    let count = u32::from_be_bytes(header[8..12].try_into().ok()?);
    if &header[..4] != SIGNATURE || !(2..=4).contains(&version) {
        return None;
    }
    hasher.update(header);

    let mut path: Vec<u8> = Vec::new();
    for _ in 0..count {
        let start = reader.offset;
        let stat = reader.take(STAT_LEN)?;
        let oid = reader.take(OID_LEN)?;
        let flags_bytes = reader.take(2)?;
        let flags = u16::from_be_bytes([flags_bytes[0], flags_bytes[1]]);
        let extended_flags = if version >= 3 && flags & EXTENDED_FLAG != 0 { reader.take(2)? } else { &[] };
        if version == 4 {
            let shared_prefix = path.len().checked_sub(reader.varint()?)?;
            path.truncate(shared_prefix);
            path.extend_from_slice(reader.until_nul()?);
        } else {
            path = reader.until_nul()?.to_vec();
            let padded_end = start + ((reader.offset - 1 - start + 8) & !7);
            let padding = reader.take(padded_end.checked_sub(reader.offset)?)?;
            if padding.iter().any(|&byte| byte != 0) {
                return None;
            }
        }
        if usize::from(flags & NAME_LENGTH_MASK) != path.len().min(usize::from(NAME_LENGTH_MASK)) {
            return None;
        }
        hasher.update(&stat[MODE_RANGE]);
        hasher.update(oid);
        hasher.update(flags_bytes);
        hasher.update(extended_flags);
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(&path);
    }

    while reader.remaining() > CHECKSUM_LEN {
        let signature = reader.take(4)?;
        let length = u32::from_be_bytes(reader.take(4)?.try_into().ok()?) as usize;
        let data = reader.take(length)?;
        if !STAT_EXTENSIONS.contains(&signature) {
            hasher.update(signature);
            hasher.update(&(length as u64).to_le_bytes());
            hasher.update(data);
        }
    }
    (reader.remaining() == CHECKSUM_LEN).then(|| Digest::of_hasher(&hasher))
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let taken = self.bytes.get(self.offset..self.offset.checked_add(length)?)?;
        self.offset += length;
        Some(taken)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    /// Consumes a NUL-terminated string and returns it without the NUL.
    fn until_nul(&mut self) -> Option<&'a [u8]> {
        let length = self.bytes.get(self.offset..)?.iter().position(|&byte| byte == 0)?;
        let text = self.take(length)?;
        self.take(1)?;
        Some(text)
    }

    /// Git's offset encoding: each continuation byte adds one before shifting.
    fn varint(&mut self) -> Option<usize> {
        let mut byte = self.take(1)?[0];
        let mut value = usize::from(byte & 0x7f);
        while byte & 0x80 != 0 {
            byte = self.take(1)?[0];
            value = value.checked_add(1)?.checked_mul(128)? + usize::from(byte & 0x7f);
        }
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    fn index_of(dir: &Path) -> Vec<u8> {
        fs::read(dir.join(".git/index")).unwrap()
    }

    fn repository_with(version: &str, files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        git(dir.path(), &["config", "index.version", version]);
        for (name, content) in files {
            let path = dir.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        git(dir.path(), &["add", "-A"]);
        dir
    }

    #[test]
    fn checkouts_of_the_same_tree_have_the_same_digest() {
        for version in ["2", "3", "4"] {
            let files = [("a.txt", "a"), ("dir/b.txt", "b"), ("dir/longer-name.txt", "c")];
            let one = repository_with(version, &files);
            std::thread::sleep(std::time::Duration::from_millis(10));
            let two = repository_with(version, &files);
            let (one, two) = (index_of(one.path()), index_of(two.path()));
            assert_ne!(one, two, "the raw indexes should differ in their stat data");
            assert!(digest(&one).is_some(), "version {version} should parse");
            assert_eq!(digest(&one), digest(&two), "version {version}");
        }
    }

    #[test]
    fn staged_content_changes_the_digest() {
        let one = repository_with("2", &[("a.txt", "one")]);
        let two = repository_with("2", &[("a.txt", "two")]);
        assert_ne!(digest(&index_of(one.path())), digest(&index_of(two.path())));
    }

    #[test]
    fn anything_else_is_not_parsed() {
        assert_eq!(digest(b"not an index"), None);
        let index = index_of(repository_with("2", &[("a.txt", "a")]).path());
        assert_eq!(digest(&index[..index.len() - 1]), None);
    }

    #[test]
    fn only_index_files_inside_git_directories_qualify() {
        assert!(is_index(Path::new("/src/.git/index")));
        assert!(is_index(Path::new("/src/.git/worktrees/feature/index")));
        assert!(!is_index(Path::new("/src/index")));
        assert!(!is_index(Path::new("/src/.git/indexes")));
    }
}
