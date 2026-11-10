//! Git keeps bookkeeping about each checkout next to the repository: the index
//! stores the stat data (times, inode, size) of every tracked file, and the
//! reflogs record who moved HEAD and when. Two checkouts of the same commit
//! differ there, and cargo and `go build` read both. The digests here leave
//! that bookkeeping out. A command that relies on the index's stat data
//! compares it with the work tree, whose files xcache records by content.

use std::ffi::OsStr;
use std::path::{Component, Path};

use crate::digest::Digest;

const SIGNATURE: &[u8] = b"DIRC";
const HEADER_LEN: usize = 12;
const STAT_LEN: usize = 40;
const MODE_RANGE: std::ops::Range<usize> = 24..28;
const OID_LEN: usize = 20;
const CHECKSUM_LEN: usize = 20;
const EXTENDED_FLAG: u16 = 0x4000;
const NAME_LENGTH_MASK: u16 = 0x0fff;
/// Offsets into the index itself, which follow from the entries. The untracked
/// cache stays in: git trusts its listings while directory times match.
const DERIVED_EXTENSIONS: [&[u8]; 2] = [b"EOIE", b"IEOT"];

enum Bookkeeping {
    Index,
    Reflog,
}

fn bookkeeping(path: &Path) -> Option<Bookkeeping> {
    let is = |component: &Component, name: &str| *component == Component::Normal(OsStr::new(name));
    let mut components = path.components().skip_while(|component| !is(component, ".git"));
    components.next()?;
    let inside_git_dir: Vec<Component> = components.collect();
    match inside_git_dir.as_slice() {
        [.., last] if is(last, "index") => Some(Bookkeeping::Index),
        components if components.iter().any(|component| is(component, "logs")) => Some(Bookkeeping::Reflog),
        _ => None,
    }
}

pub fn is_bookkeeping(path: &Path) -> bool {
    bookkeeping(path).is_some()
}

/// None for a file that is not an index or reflog, or does not parse as one;
/// the caller then hashes it as it is.
pub fn digest(path: &Path, bytes: &[u8]) -> Option<Digest> {
    match bookkeeping(path)? {
        Bookkeeping::Index => index_digest(bytes),
        Bookkeeping::Reflog => reflog_digest(bytes),
    }
}

/// Keeps each entry's old and new object IDs and message, and leaves out the
/// identity, which names the machine when no user is configured, and the time.
fn reflog_digest(bytes: &[u8]) -> Option<Digest> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xcache-git-reflog-v1");
    for line in bytes.split_inclusive(|&byte| byte == b'\n') {
        let tab = line.iter().position(|&byte| byte == b'\t')?;
        let (header, message) = line.split_at(tab);
        let mut fields = header.splitn(3, |&byte| byte == b' ');
        let (old, new) = (fields.next()?, fields.next()?);
        if !is_object_id(old) || !is_object_id(new) {
            return None;
        }
        for field in [old, new, message] {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
    }
    Some(Digest::of_hasher(&hasher))
}

fn is_object_id(field: &[u8]) -> bool {
    matches!(field.len(), 40 | 64) && field.iter().all(u8::is_ascii_hexdigit)
}

/// Returns None for anything that is not a SHA-1 index of version 2 to 4.
fn index_digest(bytes: &[u8]) -> Option<Digest> {
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
        if !DERIVED_EXTENSIONS.contains(&signature) {
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

    fn index_digest_of(dir: &Path) -> Option<Digest> {
        digest(&dir.join(".git/index"), &index_of(dir))
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
            assert!(index_digest(&one).is_some(), "version {version} should parse");
            assert_eq!(index_digest(&one), index_digest(&two), "version {version}");
        }
    }

    #[test]
    fn staged_content_changes_the_digest() {
        let one = repository_with("2", &[("a.txt", "one")]);
        let two = repository_with("2", &[("a.txt", "two")]);
        assert_ne!(index_digest_of(one.path()), index_digest_of(two.path()));
    }

    #[test]
    fn anything_else_is_not_parsed() {
        assert_eq!(index_digest(b"not an index"), None);
        let index = index_of(repository_with("2", &[("a.txt", "a")]).path());
        assert_eq!(index_digest(&index[..index.len() - 1]), None);
        assert_eq!(reflog_digest(b"not a reflog\n"), None);
    }

    #[test]
    fn reflogs_differ_only_in_who_moved_head_and_when() {
        let oid = |c: char| c.to_string().repeat(40);
        let entry = |who: &str, when: &str| {
            format!("{} {} {who} {when}\tcheckout: moving from main to {}\n", oid('0'), oid('a'), oid('a'))
        };
        let here = entry("runner <runner@fv-az1.internal>", "1794328357 +0000");
        let there = entry("runner <runner@fv-az2.internal>", "1794329999 +0700");
        assert_eq!(reflog_digest(here.as_bytes()), reflog_digest(there.as_bytes()));
        let elsewhere = here.replace("to aaaa", "to bbbb");
        assert_ne!(reflog_digest(here.as_bytes()), reflog_digest(elsewhere.as_bytes()));
    }

    #[test]
    fn only_bookkeeping_inside_git_directories_qualifies() {
        let index = index_of(repository_with("2", &[("a.txt", "a")]).path());
        assert!(digest(Path::new("/src/.git/index"), &index).is_some());
        assert!(digest(Path::new("/src/.git/worktrees/feature/index"), &index).is_some());
        assert!(digest(Path::new("/src/index"), &index).is_none());
        assert!(digest(Path::new("/src/.git/logs/HEAD"), b"").is_some());
        assert!(digest(Path::new("/src/.git/HEAD"), b"ref: refs/heads/main\n").is_none());
        assert!(digest(Path::new("/src/logs/HEAD"), b"").is_none());
    }
}
