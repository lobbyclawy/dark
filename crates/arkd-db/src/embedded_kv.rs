//! Embedded key-value store using sled (issue #243)
//!
//! Provides a Badger-equivalent embedded KV store for Rust.
//! Go arkd uses Badger for local state; this uses sled as the Rust equivalent.

use std::path::Path;

/// Embedded key-value store backed by sled.
///
/// Intended as the Rust counterpart to Go arkd's Badger-backed stores.
pub struct SledKvStore {
    db: sled::Db,
}

impl SledKvStore {
    /// Open (or create) an embedded KV store at the given path.
    ///
    /// # Errors
    /// Returns an error if sled cannot open/create the database.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Get a value by key.
    // TODO(#243): replace with production KV store
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, sled::Error> {
        Ok(self.db.get(key)?.map(|v| v.to_vec()))
    }

    /// Set a key-value pair.
    // TODO(#243): replace with production KV store
    pub fn set(&self, key: &[u8], value: &[u8]) -> Result<(), sled::Error> {
        self.db.insert(key, value)?;
        Ok(())
    }

    /// Delete a key.
    // TODO(#243): replace with production KV store
    pub fn delete(&self, key: &[u8]) -> Result<(), sled::Error> {
        self.db.remove(key)?;
        Ok(())
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &[u8]) -> Result<bool, sled::Error> {
        self.db.contains_key(key)
    }

    /// Scan all keys with the given prefix and return (key, value) pairs.
    #[allow(clippy::type_complexity)]
    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, sled::Error> {
        let mut result = Vec::new();
        for item in self.db.scan_prefix(prefix) {
            let (k, v) = item?;
            result.push((k.to_vec(), v.to_vec()));
        }
        Ok(result)
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), sled::Error> {
        self.db.flush().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sled_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = SledKvStore::open(dir.path()).unwrap();

        assert_eq!(store.get(b"k1").unwrap(), None);

        store.set(b"k1", b"v1").unwrap();
        assert_eq!(store.get(b"k1").unwrap(), Some(b"v1".to_vec()));
        assert!(store.contains(b"k1").unwrap());

        store.delete(b"k1").unwrap();
        assert_eq!(store.get(b"k1").unwrap(), None);
    }
}
