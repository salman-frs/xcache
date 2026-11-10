use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::observe::{Access, State};

const FORMAT: u32 = 2;
const ENTRIES_PER_COMMAND: usize = 16;
const COMPRESSION_LEVEL: i32 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Input {
    pub access: Access,
    #[serde(with = "crate::path_serde")]
    pub path: PathBuf,
    pub state: State,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    #[serde(with = "crate::path_serde")]
    pub path: PathBuf,
    pub state: OutputState,
    /// How long before the end of the run this was last modified, so restoring
    /// can keep the order of modification times, which make and cargo compare.
    #[serde(default)]
    pub age_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutputState {
    Deleted,
    Dir {
        mode: u32,
    },
    File {
        mode: u32,
        size: u64,
        content: Digest,
    },
    /// Another name for an output earlier in path order.
    HardLink {
        #[serde(with = "crate::path_serde")]
        target: PathBuf,
    },
    Symlink {
        #[serde(with = "crate::path_serde")]
        target: PathBuf,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResult {
    pub exit_code: i32,
    pub stdio: Digest,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub format: u32,
    pub command: String,
    pub created_at: u64,
    pub last_used_at: u64,
    pub duration_ms: u64,
    pub inputs: Vec<Input>,
    pub result: RunResult,
}

impl Entry {
    pub fn new(command: String, duration_ms: u64, inputs: Vec<Input>, result: RunResult) -> Self {
        let now = unix_now();
        Self { format: FORMAT, command, created_at: now, last_used_at: now, duration_ms, inputs, result }
    }

    fn blobs(&self) -> impl Iterator<Item = Digest> + '_ {
        let outputs = self.result.outputs.iter().filter_map(|output| match output.state {
            OutputState::File { content, .. } => Some(content),
            _ => None,
        });
        std::iter::once(self.result.stdio).chain(outputs)
    }
}

pub struct Store {
    root: PathBuf,
}

#[derive(Debug, Default)]
pub struct GcStats {
    pub entries_removed: usize,
    pub blobs_removed: usize,
    pub bytes_kept: u64,
}

impl Store {
    pub fn open(root: PathBuf) -> io::Result<Self> {
        for dir in ["cas", "ac", "tmp", "stat-cache"] {
            fs::create_dir_all(root.join(dir))?;
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Remembered digests are keyed by device and inode, which only identify a
    /// file within one boot of one machine, and a cache directory can be copied
    /// to another machine (for example by a CI cache step).
    pub fn stat_cache_path(&self) -> Option<PathBuf> {
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        Some(self.root.join("stat-cache").join(boot.trim()))
    }

    pub fn put_bytes(&self, bytes: &[u8]) -> io::Result<Digest> {
        self.put_reader(bytes).map(|(digest, _)| digest)
    }

    pub fn put_file(&self, path: &Path) -> io::Result<(Digest, u64)> {
        self.put_reader(BufReader::new(File::open(path)?))
    }

    fn put_reader(&self, mut reader: impl Read) -> io::Result<(Digest, u64)> {
        let tmp = self.tmp_path();
        let mut encoder = zstd::Encoder::new(File::create(&tmp)?, COMPRESSION_LEVEL)?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0; 256 * 1024];
        let mut size = 0;
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    let _ = fs::remove_file(&tmp);
                    return Err(error);
                }
            };
            hasher.update(&buffer[..read]);
            encoder.write_all(&buffer[..read])?;
            size += read as u64;
        }
        encoder.finish()?;

        let digest = Digest::of_hasher(&hasher);
        let blob = self.blob_path(digest);
        if blob.exists() {
            fs::remove_file(&tmp)?;
        } else {
            fs::create_dir_all(blob.parent().unwrap())?;
            fs::rename(&tmp, &blob)?;
        }
        Ok((digest, size))
    }

    pub fn read_blob(&self, digest: Digest) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.copy_blob_to(digest, &mut bytes)?;
        Ok(bytes)
    }

    /// Blobs are not fsynced when written, so every read checks the content
    /// against its digest instead of trusting what is on disk.
    pub fn copy_blob_to(&self, digest: Digest, dest: &mut impl Write) -> io::Result<()> {
        let mut decoder = zstd::Decoder::new(File::open(self.blob_path(digest))?)?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0; 256 * 1024];
        loop {
            let read = decoder.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            dest.write_all(&buffer[..read])?;
        }
        if Digest::of_hasher(&hasher) != digest {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("cached blob {digest} is corrupt")));
        }
        Ok(())
    }

    pub fn entries(&self, fingerprint: Digest) -> io::Result<Vec<Entry>> {
        let path = self.entries_path(fingerprint);
        match File::open(&path) {
            Ok(file) => {
                let entries: Vec<Entry> = serde_json::from_reader(zstd::Decoder::new(file)?)?;
                Ok(entries.into_iter().filter(|entry| entry.format == FORMAT).collect())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    pub fn record(&self, fingerprint: Digest, entry: Entry) -> io::Result<()> {
        let _lock = self.lock()?;
        let mut entries = self.entries(fingerprint).unwrap_or_default();
        entries.retain(|existing| !same_inputs(existing, &entry));
        entries.insert(0, entry);
        entries.truncate(ENTRIES_PER_COMMAND);
        self.write_entries(fingerprint, &entries)
    }

    pub fn remove(&self, fingerprint: Digest, entry: &Entry) -> io::Result<()> {
        let _lock = self.lock()?;
        let mut entries = self.entries(fingerprint)?;
        entries.retain(|existing| !same_inputs(existing, entry));
        self.write_entries(fingerprint, &entries)
    }

    pub fn mark_used(&self, fingerprint: Digest, created_at: u64) -> io::Result<()> {
        let _lock = self.lock()?;
        let mut entries = self.entries(fingerprint)?;
        let Some(entry) = entries.iter_mut().find(|entry| entry.created_at == created_at) else {
            return Ok(());
        };
        entry.last_used_at = unix_now();
        self.write_entries(fingerprint, &entries)
    }

    pub fn gc(&self, max_bytes: u64) -> io::Result<GcStats> {
        let _lock = self.lock()?;
        let mut stats = GcStats::default();

        let mut commands = Vec::new();
        for file in fs::read_dir(self.root.join("ac"))? {
            let path = file?.path();
            let Some(fingerprint) = path.file_stem().and_then(|stem| Digest::from_hex(&stem.to_string_lossy())) else {
                continue;
            };
            commands.push((fingerprint, self.entries(fingerprint).unwrap_or_default()));
        }

        let mut by_recency: Vec<(u64, usize, usize)> = Vec::new();
        for (command, (_, entries)) in commands.iter().enumerate() {
            for (index, entry) in entries.iter().enumerate() {
                by_recency.push((entry.last_used_at, command, index));
            }
        }
        by_recency.sort_by_key(|&(last_used_at, ..)| std::cmp::Reverse(last_used_at));

        let mut kept_blobs = HashSet::new();
        let mut keep: HashSet<(usize, usize)> = HashSet::new();
        for (_, command, index) in by_recency {
            let entry = &commands[command].1[index];
            let new_bytes: u64 = entry
                .blobs()
                .filter(|blob| !kept_blobs.contains(blob))
                .collect::<HashSet<_>>()
                .into_iter()
                .map(|blob| fs::metadata(self.blob_path(blob)).map_or(0, |meta| meta.len()))
                .sum();
            if stats.bytes_kept + new_bytes > max_bytes {
                stats.entries_removed += 1;
                continue;
            }
            stats.bytes_kept += new_bytes;
            kept_blobs.extend(entry.blobs());
            keep.insert((command, index));
        }

        for (command, (fingerprint, entries)) in commands.iter().enumerate() {
            let kept: Vec<Entry> = entries
                .iter()
                .enumerate()
                .filter(|(index, _)| keep.contains(&(command, *index)))
                .map(|(_, entry)| entry.clone())
                .collect();
            if kept.is_empty() {
                fs::remove_file(self.entries_path(*fingerprint))?;
            } else if kept.len() != entries.len() {
                self.write_entries(*fingerprint, &kept)?;
            }
        }

        let current_stat_cache = self.stat_cache_path();
        for stat_cache in fs::read_dir(self.root.join("stat-cache"))? {
            let path = stat_cache?.path();
            if Some(&path) != current_stat_cache.as_ref() {
                fs::remove_file(path)?;
            }
        }

        for shard in fs::read_dir(self.root.join("cas"))? {
            for blob in fs::read_dir(shard?.path())? {
                let path = blob?.path();
                let shard_name = path.parent().and_then(Path::file_name).unwrap_or_default();
                let hex = format!(
                    "{}{}",
                    shard_name.to_string_lossy(),
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
                if Digest::from_hex(&hex).is_none_or(|digest| !kept_blobs.contains(&digest)) {
                    fs::remove_file(&path)?;
                    stats.blobs_removed += 1;
                }
            }
        }
        Ok(stats)
    }

    fn write_entries(&self, fingerprint: Digest, entries: &[Entry]) -> io::Result<()> {
        let json = serde_json::to_vec(entries)?;
        let compressed = zstd::encode_all(json.as_slice(), COMPRESSION_LEVEL)?;
        write_atomically(&self.entries_path(fingerprint), &compressed)
    }

    fn lock(&self) -> io::Result<File> {
        let file = File::options().create(true).truncate(false).write(true).open(self.root.join("lock"))?;
        // SAFETY: flock on a valid descriptor; released when the file is dropped.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }

    fn blob_path(&self, digest: Digest) -> PathBuf {
        let hex = digest.to_hex();
        self.root.join("cas").join(&hex[..2]).join(&hex[2..])
    }

    fn entries_path(&self, fingerprint: Digest) -> PathBuf {
        self.root.join("ac").join(format!("{fingerprint}.zst"))
    }

    fn tmp_path(&self) -> PathBuf {
        self.root.join("tmp").join(unique_name())
    }
}

fn same_inputs(a: &Entry, b: &Entry) -> bool {
    a.inputs.len() == b.inputs.len()
        && a.inputs.iter().zip(&b.inputs).all(|(a, b)| a.access == b.access && a.path == b.path && a.state == b.state)
}

pub fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".{}", unique_name()));
    let mut file = File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

pub fn unique_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.subsec_nanos());
    format!("xcache-{}-{}-{nanos}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed))
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(store: &Store, payload: &[u8], last_used_at: u64) -> Entry {
        let content = store.put_bytes(payload).unwrap();
        let output = Output {
            path: "/out".into(),
            state: OutputState::File { mode: 0o644, size: payload.len() as u64, content },
            age_ns: 0,
        };
        let result = RunResult { exit_code: 0, stdio: store.put_bytes(b"").unwrap(), outputs: vec![output] };
        let inputs =
            vec![Input { access: Access::Read, path: format!("/in-{last_used_at}").into(), state: State::Missing }];
        Entry { last_used_at, ..Entry::new("cmd".into(), 1, inputs, result) }
    }

    #[test]
    fn blobs_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_path_buf()).unwrap();
        let digest = store.put_bytes(b"hello").unwrap();
        assert_eq!(digest, Digest::of_bytes(b"hello"));
        assert_eq!(store.read_blob(digest).unwrap(), b"hello");
    }

    #[test]
    fn corrupt_blobs_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_path_buf()).unwrap();
        let digest = store.put_bytes(b"hello").unwrap();
        let corrupt = zstd::encode_all(&b"HELLO"[..], 0).unwrap();
        fs::write(store.blob_path(digest), corrupt).unwrap();
        assert_eq!(store.read_blob(digest).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn newest_entry_comes_first_and_duplicates_are_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_path_buf()).unwrap();
        let fingerprint = Digest::of_bytes(b"command");
        store.record(fingerprint, entry(&store, b"a", 1)).unwrap();
        store.record(fingerprint, entry(&store, b"b", 2)).unwrap();
        store.record(fingerprint, entry(&store, b"c", 1)).unwrap();

        let entries = store.entries(fingerprint).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].inputs[0].path, PathBuf::from("/in-1"));
    }

    #[test]
    fn gc_keeps_recent_entries_within_budget() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_path_buf()).unwrap();
        let old = Digest::of_bytes(b"old");
        let new = Digest::of_bytes(b"new");
        store.record(old, entry(&store, &[1; 4096], 10)).unwrap();
        store.record(new, entry(&store, &[2; 4096], 20)).unwrap();
        let one_entry_budget =
            fs::metadata(store.blob_path(store.entries(new).unwrap()[0].result.outputs[0].state.content()))
                .unwrap()
                .len()
                + fs::metadata(store.blob_path(Digest::of_bytes(b""))).unwrap().len();

        let stats = store.gc(one_entry_budget).unwrap();
        assert_eq!(stats.entries_removed, 1);
        assert!(store.entries(old).unwrap().is_empty());
        assert_eq!(store.entries(new).unwrap().len(), 1);
        assert!(store.read_blob(Digest::of_bytes(&[1; 4096])).is_err());
    }

    impl OutputState {
        fn content(&self) -> Digest {
            match self {
                OutputState::File { content, .. } => *content,
                _ => panic!("not a file"),
            }
        }
    }
}
