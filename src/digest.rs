use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::git;
use crate::sync::{available_cpus, lock, on_all_cpus};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Large files are hashed on all CPUs, a chunk at a time.
    pub fn of_file(mut file: &File, size: u64) -> io::Result<Self> {
        let mut hasher = blake3::Hasher::new();
        if size < PARALLEL_HASHING_MIN {
            hasher.update_reader(file)?;
            return Ok(Self::of_hasher(&hasher));
        }
        let mut chunk = vec![0; PARALLEL_HASHING_CHUNK];
        loop {
            let filled = read_up_to(&mut file, &mut chunk)?;
            if filled == 0 {
                break;
            }
            hasher.update_rayon(&chunk[..filled]);
        }
        Ok(Self::of_hasher(&hasher))
    }

    pub fn of_hasher(hasher: &blake3::Hasher) -> Self {
        Self(*hasher.finalize().as_bytes())
    }

    pub fn to_hex(self) -> String {
        blake3::Hash::from_bytes(self.0).to_hex().to_string()
    }

    pub fn from_hex(hex: &str) -> Option<Self> {
        blake3::Hash::from_hex(hex).ok().map(|hash| Self(*hash.as_bytes()))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", &self.to_hex()[..12])
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        Digest::from_hex(&hex).ok_or_else(|| serde::de::Error::custom("invalid digest"))
    }
}

pub struct ContentHasher {
    cache_path: Option<PathBuf>,
    known: HashMap<FileKey, Known>,
    dirty: bool,
    early: Option<EarlyHashing>,
}

/// Threads that hash files while the command still runs, at the lowest
/// priority, so the command keeps the CPUs it can use.
struct EarlyHashing {
    batch: Vec<PathBuf>,
    batch_size: u64,
    batches: Sender<Vec<PathBuf>>,
    hashed: Receiver<(FileKey, Known)>,
}

impl EarlyHashing {
    fn start() -> Self {
        let (batches, queue) = mpsc::channel::<Vec<PathBuf>>();
        let (results, hashed) = mpsc::channel();
        let queue = Arc::new(Mutex::new(queue));
        for _ in 0..available_cpus() {
            let (queue, results) = (Arc::clone(&queue), results.clone());
            let hash_batches = move || {
                // SAFETY: setpriority takes no pointers; on Linux it applies to the calling thread.
                unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 19) };
                loop {
                    let Ok(batch) = lock(&queue).recv() else {
                        break;
                    };
                    for path in batch {
                        let learned = digest_of(&path, &HashMap::new()).ok().and_then(|(_, learned)| learned);
                        if let Some(learned) = learned
                            && results.send(learned).is_err()
                        {
                            return;
                        }
                    }
                }
            };
            // Without the thread, the files wait for `prefetch`.
            let _ = thread::Builder::new().name("xcache-hash".into()).spawn(hash_batches);
        }
        Self { batch: Vec::new(), batch_size: 0, batches, hashed }
    }

    /// Waking a hashing thread delays the caller by more than a small file
    /// takes to hash, so files are handed over a batch at a time.
    fn add(&mut self, path: &Path, size: u64) {
        self.batch.push(path.to_path_buf());
        self.batch_size += size;
        if self.batch.len() >= EARLY_BATCH_FILES || self.batch_size >= EARLY_BATCH_BYTES {
            self.batch_size = 0;
            let _ = self.batches.send(std::mem::take(&mut self.batch));
        }
    }
}

type FileKey = (u64, u64);

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

#[derive(Clone, Copy)]
struct Known {
    stamp: Stamp,
    digest: Digest,
    /// Unsettled digests are only trusted within this process.
    settled: bool,
}

const EARLY_BATCH_FILES: usize = 32;
const EARLY_BATCH_BYTES: u64 = 1 << 20;
const PARALLEL_HASHING_MIN: u64 = 4 << 20;
const PARALLEL_HASHING_CHUNK: usize = 4 << 20;
const CACHE_MAGIC: &[u8] = b"xcache-stat-v2\n";
const RECORD_LEN: usize = 8 * 7 + 32;
const MAX_KNOWN: usize = 500_000;
// Matches git's "racy" guard: a file touched within the timestamp granularity
// of being hashed may change again without its stamp changing.
const SETTLE_TIME: Duration = Duration::from_secs(2);

impl Stamp {
    fn of(meta: &fs::Metadata) -> Self {
        Self { size: meta.size(), mtime: (meta.mtime(), meta.mtime_nsec()), ctime: (meta.ctime(), meta.ctime_nsec()) }
    }

    fn is_settled(&self) -> bool {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        let horizon = now.saturating_sub(SETTLE_TIME).as_secs() as i64;
        self.mtime.0 < horizon && self.ctime.0 < horizon
    }
}

impl ContentHasher {
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self { cache_path: None, known: HashMap::new(), dirty: false, early: None }
    }

    pub fn load(cache_path: Option<PathBuf>) -> Self {
        let known = cache_path.as_ref().and_then(|path| fs::read(path).ok()).map(|bytes| parse_cache(&bytes));
        Self { cache_path, known: known.unwrap_or_default(), dirty: false, early: None }
    }

    /// Has a file hashed before its digest is asked for, unless it is known
    /// already. `meta` is the file's metadata.
    pub fn hash_early(&mut self, path: &Path, meta: &fs::Metadata) {
        if self.known.get(&(meta.dev(), meta.ino())).is_some_and(|known| known.stamp == Stamp::of(meta)) {
            return;
        }
        self.early.get_or_insert_with(EarlyHashing::start).add(path, meta.len());
    }

    fn remember_what_was_hashed_early(&mut self) {
        let hashed: Vec<(FileKey, Known)> = self.early.iter().flat_map(|early| early.hashed.try_iter()).collect();
        for learned in hashed {
            self.remember(Some(learned));
        }
    }

    pub fn hash_file(&mut self, path: &Path) -> io::Result<Digest> {
        self.remember_what_was_hashed_early();
        let (digest, learned) = digest_of(path, &self.known)?;
        self.remember(learned);
        Ok(digest)
    }

    /// Hashes files on all CPUs, so the `hash_file` calls that follow are lookups.
    pub fn prefetch(&mut self, paths: &[&Path]) {
        self.remember_what_was_hashed_early();
        let mut paths = paths.to_vec();
        paths.sort_unstable();
        paths.dedup();
        let known = &self.known;
        let learned = on_all_cpus(&paths, |path| digest_of(path, known).ok().and_then(|(_, learned)| learned));
        for learned in learned {
            self.remember(learned);
        }
    }

    fn remember(&mut self, learned: Option<(FileKey, Known)>) {
        if let Some((key, known)) = learned {
            self.dirty |= known.settled;
            self.known.insert(key, known);
        }
    }

    pub fn save(&mut self) -> io::Result<()> {
        let Some(cache_path) = &self.cache_path else {
            return Ok(());
        };
        if !self.dirty {
            return Ok(());
        }
        if self.known.len() > MAX_KNOWN {
            self.known.clear();
        }
        let mut bytes = Vec::with_capacity(CACHE_MAGIC.len() + self.known.len() * RECORD_LEN);
        bytes.extend_from_slice(CACHE_MAGIC);
        for (&(dev, ino), known) in self.known.iter().filter(|(_, known)| known.settled) {
            let Stamp { size, mtime, ctime } = known.stamp;
            for field in [dev, ino, size] {
                bytes.extend_from_slice(&field.to_le_bytes());
            }
            for field in [mtime.0, mtime.1, ctime.0, ctime.1] {
                bytes.extend_from_slice(&field.to_le_bytes());
            }
            bytes.extend_from_slice(&known.digest.0);
        }
        crate::store::write_atomically(cache_path, &bytes)?;
        self.dirty = false;
        Ok(())
    }
}

fn read_up_to(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// The digest of a file, and what to remember about it if it had to be hashed.
fn digest_of(path: &Path, known: &HashMap<FileKey, Known>) -> io::Result<(Digest, Option<(FileKey, Known)>)> {
    let file = File::open(path)?;
    let before = file.metadata()?;
    let key = (before.dev(), before.ino());
    let stamp = Stamp::of(&before);
    if let Some(known) = known.get(&key)
        && known.stamp == stamp
    {
        return Ok((known.digest, None));
    }

    let digest = if git::is_bookkeeping(path) {
        let mut bytes = Vec::new();
        (&file).read_to_end(&mut bytes)?;
        git::digest(path, &bytes).unwrap_or_else(|| Digest::of_bytes(&bytes))
    } else {
        Digest::of_file(&file, before.len())?
    };
    let unchanged_while_hashing = Stamp::of(&file.metadata()?) == stamp;
    let learned = unchanged_while_hashing.then(|| (key, Known { stamp, digest, settled: stamp.is_settled() }));
    Ok((digest, learned))
}

fn parse_cache(bytes: &[u8]) -> HashMap<FileKey, Known> {
    let Some(records) = bytes.strip_prefix(CACHE_MAGIC) else {
        return HashMap::new();
    };
    let field = |record: &[u8], index: usize| -> [u8; 8] { record[index * 8..index * 8 + 8].try_into().unwrap() };
    let (records, _) = records.as_chunks::<RECORD_LEN>();
    records
        .iter()
        .map(|record| {
            let unsigned = |index| u64::from_le_bytes(field(record, index));
            let signed = |index| i64::from_le_bytes(field(record, index));
            let stamp = Stamp { size: unsigned(2), mtime: (signed(3), signed(4)), ctime: (signed(5), signed(6)) };
            let digest = Digest(record[56..].try_into().unwrap());
            ((unsigned(0), unsigned(1)), Known { stamp, digest, settled: true })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_round_trips_through_hex() {
        let digest = Digest::of_bytes(b"xcache");
        assert_eq!(Digest::from_hex(&digest.to_hex()), Some(digest));
    }

    #[test]
    fn stat_cache_survives_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("stat-cache");
        let stamp = Stamp { size: 7, mtime: (1, 2), ctime: (3, 4) };
        let digest = Digest::of_bytes(b"content");

        let mut hasher = ContentHasher::load(Some(cache.clone()));
        hasher.known.insert((10, 20), Known { stamp, digest, settled: true });
        hasher.dirty = true;
        hasher.save().unwrap();

        let reloaded = ContentHasher::load(Some(cache));
        let known = reloaded.known[&(10, 20)];
        assert!(known.stamp == stamp);
        assert_eq!(known.digest, digest);
    }

    #[test]
    fn recently_modified_files_are_not_saved() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("input");
        fs::write(&file, b"content").unwrap();

        let mut hasher = ContentHasher::in_memory();
        assert_eq!(hasher.hash_file(&file).unwrap(), Digest::of_bytes(b"content"));
        assert!(hasher.known.values().all(|known| !known.settled));
        assert!(!hasher.dirty);
    }

    #[test]
    fn large_files_hash_the_same_in_parallel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large");
        let content: Vec<u8> = (0..PARALLEL_HASHING_CHUNK as u64 * 2 + 12345).map(|i| (i % 251) as u8).collect();
        fs::write(&path, &content).unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(Digest::of_file(&file, content.len() as u64).unwrap(), Digest::of_bytes(&content));
    }

    #[test]
    fn prefetched_digests_match_hashing_one_file_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<PathBuf> = (0..20).map(|index| dir.path().join(format!("file{index}"))).collect();
        for (index, path) in paths.iter().enumerate() {
            fs::write(path, vec![index as u8; index * 1000]).unwrap();
        }
        let mut hasher = ContentHasher::in_memory();
        hasher.prefetch(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>());
        assert_eq!(hasher.known.len(), paths.len());
        for (index, path) in paths.iter().enumerate() {
            assert_eq!(hasher.hash_file(path).unwrap(), Digest::of_bytes(&vec![index as u8; index * 1000]));
        }
    }
}
