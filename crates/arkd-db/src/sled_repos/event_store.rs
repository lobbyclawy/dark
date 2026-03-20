//! Sled-backed implementation of `arkd_core::ports::EventStore`.
//!
//! Events are stored with keys: `evt::{aggregate_id}::{sequence}` where
//! sequence is a zero-padded monotonic counter per aggregate.

use crate::embedded_kv::SledKvStore;
use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::EventStore;
use async_trait::async_trait;
use std::sync::Arc;

/// Sled-backed event store for aggregate event persistence.
pub struct SledEventStore {
    store: Arc<SledKvStore>,
}

impl SledEventStore {
    /// Create a new sled-backed event store.
    pub fn new(store: Arc<SledKvStore>) -> Self {
        Self { store }
    }

    fn event_prefix(aggregate_id: &str) -> Vec<u8> {
        format!("evt::{}::", aggregate_id).into_bytes()
    }

    fn event_key(aggregate_id: &str, seq: u64) -> Vec<u8> {
        format!("evt::{}::{:020}", aggregate_id, seq).into_bytes()
    }

    fn counter_key(aggregate_id: &str) -> Vec<u8> {
        format!("evt_seq::{}", aggregate_id).into_bytes()
    }
}

#[async_trait]
impl EventStore for SledEventStore {
    async fn append_event(&self, aggregate_id: &str, event: &[u8]) -> ArkResult<()> {
        // Read current sequence, increment, store event
        let counter_key = Self::counter_key(aggregate_id);
        let seq = match self
            .store
            .get(&counter_key)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?
        {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| ArkError::DatabaseError("corrupt sequence counter".into()))?;
                u64::from_be_bytes(arr)
            }
            None => 0,
        };

        let next_seq = seq + 1;
        let event_key = Self::event_key(aggregate_id, next_seq);

        self.store
            .set(&event_key, event)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        self.store
            .set(&counter_key, &next_seq.to_be_bytes())
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn load_events(&self, aggregate_id: &str) -> ArkResult<Vec<Vec<u8>>> {
        let prefix = Self::event_prefix(aggregate_id);
        let entries = self
            .store
            .scan_prefix(&prefix)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(entries.into_iter().map(|(_, v)| v).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Arc<SledKvStore> {
        let dir = tempfile::tempdir().unwrap();
        Arc::new(SledKvStore::open(dir.path()).unwrap())
    }

    #[tokio::test]
    async fn test_append_and_load_events() {
        let store = SledEventStore::new(make_store());

        store.append_event("agg-1", b"event-a").await.unwrap();
        store.append_event("agg-1", b"event-b").await.unwrap();
        store.append_event("agg-2", b"event-c").await.unwrap();

        let events = store.load_events("agg-1").await.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], b"event-a");
        assert_eq!(events[1], b"event-b");

        let events2 = store.load_events("agg-2").await.unwrap();
        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0], b"event-c");
    }

    #[tokio::test]
    async fn test_load_empty_aggregate() {
        let store = SledEventStore::new(make_store());
        let events = store.load_events("nonexistent").await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_event_ordering() {
        let store = SledEventStore::new(make_store());

        for i in 0..10 {
            store
                .append_event("agg", format!("event-{i}").as_bytes())
                .await
                .unwrap();
        }

        let events = store.load_events("agg").await.unwrap();
        assert_eq!(events.len(), 10);
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(ev, format!("event-{i}").as_bytes());
        }
    }
}
