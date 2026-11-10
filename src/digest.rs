use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    #[cfg(test)]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    pub fn of_reader(reader: impl Read) -> io::Result<Self> {
        let mut hasher = blake3::Hasher::new();
        hasher.update_reader(reader)?;
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
    known: HashMap<(u64, u64), Known>,
    dirty: bool,
}

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
}

const CACHE_MAGIC: &[u8] = b"xcache-stat-v1\n";
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
        Self { cache_path: None, known: HashMap::new(), dirty: false }
    }

    pub fn load(cache_path: Option<PathBuf>) -> Self {
        let known = cache_path.as_ref().and_then(|path| fs::read(path).ok()).map(|bytes| parse_cache(&bytes));
        Self { cache_path, known: known.unwrap_or_default(), dirty: false }
    }

    pub fn hash_file(&mut self, path: &Path) -> io::Result<Digest> {
        let file = File::open(path)?;
        let before = file.metadata()?;
        let key = (before.dev(), before.ino());
        let stamp = Stamp::of(&before);
        if let Some(known) = self.known.get(&key)
            && known.stamp == stamp
        {
            return Ok(known.digest);
        }

        let digest = Digest::of_reader(&file)?;
        let unchanged_while_hashing = Stamp::of(&file.metadata()?) == stamp;
        if unchanged_while_hashing && stamp.is_settled() {
            self.known.insert(key, Known { stamp, digest });
            self.dirty = true;
        }
        Ok(digest)
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
        for (&(dev, ino), known) in &self.known {
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

fn parse_cache(bytes: &[u8]) -> HashMap<(u64, u64), Known> {
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
            ((unsigned(0), unsigned(1)), Known { stamp, digest })
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
        hasher.known.insert((10, 20), Known { stamp, digest });
        hasher.dirty = true;
        hasher.save().unwrap();

        let reloaded = ContentHasher::load(Some(cache));
        let known = reloaded.known[&(10, 20)];
        assert!(known.stamp == stamp);
        assert_eq!(known.digest, digest);
    }

    #[test]
    fn recently_modified_files_are_not_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("input");
        fs::write(&file, b"content").unwrap();

        let mut hasher = ContentHasher::in_memory();
        assert_eq!(hasher.hash_file(&file).unwrap(), Digest::of_bytes(b"content"));
        assert!(hasher.known.is_empty());
    }
}
