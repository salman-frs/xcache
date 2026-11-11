//! Paths are bytes on Linux. A path that is valid UTF-8 is stored as a string
//! and any other as an array of bytes, so cache entries stay readable without
//! losing paths that tests create on purpose.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    match path.to_str() {
        Some(text) => serializer.serialize_str(text),
        None => serializer.collect_seq(path.as_os_str().as_bytes()),
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Stored {
        Text(String),
        Bytes(Vec<u8>),
    }
    Ok(match Stored::deserialize(deserializer)? {
        Stored::Text(text) => PathBuf::from(text),
        Stored::Bytes(bytes) => PathBuf::from(OsString::from_vec(bytes)),
    })
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Named {
        #[serde(with = "super")]
        path: PathBuf,
    }

    #[test]
    fn paths_round_trip_whether_or_not_they_are_utf8() {
        for bytes in [b"/src/main.c".as_slice(), b"/tmp/caf\xe9"] {
            let named = Named { path: PathBuf::from(OsString::from_vec(bytes.to_vec())) };
            let json = serde_json::to_string(&named).unwrap();
            assert_eq!(serde_json::from_str::<Named>(&json).unwrap(), named);
        }
        assert_eq!(serde_json::to_string(&Named { path: "/a".into() }).unwrap(), r#"{"path":"/a"}"#);
    }
}
