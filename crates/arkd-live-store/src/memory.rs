//! In-memory implementation of [`LiveStore`] for dev/test.

use std::collections::HashMap;
use std::sync::Arc;

use arkd_core::error::ArkResult;
use arkd_core::ports::LiveStore;
use async_trait::async_trait;
use tokio::sync::RwLock;

/// In-memory ephemeral live-store.
///
/// TTL is ignored — entries persist until explicitly deleted or the process exits.
/// Suitable for development and testing only.
#[derive(Debug, Clone, Default)]
pub struct InMemoryLiveStore {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl InMemoryLiveStore {
    /// Create a new empty in-memory live-store.
    pub fn new() -> Self {
        Self::default()
    }

    fn intent_key(round_id: &str, intent_id: &str) -> String {
        format!("intents:{round_id}:{intent_id}")
    }

    fn nonce_key(session_id: &str, pubkey: &str) -> String {
        format!("nonces:{session_id}:{pubkey}")
    }

    fn partial_sig_key(session_id: &str, pubkey: &str) -> String {
        format!("partial_sigs:{session_id}:{pubkey}")
    }
}

#[async_trait]
impl LiveStore for InMemoryLiveStore {
    async fn set_intent(
        &self,
        round_id: &str,
        intent_id: &str,
        data: &[u8],
        _ttl_secs: u64, // TTL ignored in memory impl
    ) -> ArkResult<()> {
        let key = Self::intent_key(round_id, intent_id);
        self.data.write().await.insert(key, data.to_vec());
        Ok(())
    }

    async fn get_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<Option<Vec<u8>>> {
        let key = Self::intent_key(round_id, intent_id);
        Ok(self.data.read().await.get(&key).cloned())
    }

    async fn list_intents(&self, round_id: &str) -> ArkResult<Vec<String>> {
        let prefix = format!("intents:{round_id}:");
        let guard = self.data.read().await;
        let ids: Vec<String> = guard
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(ids)
    }

    async fn delete_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<()> {
        let key = Self::intent_key(round_id, intent_id);
        self.data.write().await.remove(&key);
        Ok(())
    }

    async fn set_nonce(
        &self,
        session_id: &str,
        pubkey: &str,
        nonce: &[u8],
        _ttl_secs: u64,
    ) -> ArkResult<()> {
        let key = Self::nonce_key(session_id, pubkey);
        self.data.write().await.insert(key, nonce.to_vec());
        Ok(())
    }

    async fn get_nonce(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>> {
        let key = Self::nonce_key(session_id, pubkey);
        Ok(self.data.read().await.get(&key).cloned())
    }

    async fn list_nonces(&self, session_id: &str) -> ArkResult<Vec<String>> {
        let prefix = format!("nonces:{session_id}:");
        let guard = self.data.read().await;
        let ids: Vec<String> = guard
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(ids)
    }

    async fn set_partial_sig(
        &self,
        session_id: &str,
        pubkey: &str,
        sig: &[u8],
        _ttl_secs: u64,
    ) -> ArkResult<()> {
        let key = Self::partial_sig_key(session_id, pubkey);
        self.data.write().await.insert(key, sig.to_vec());
        Ok(())
    }

    async fn get_partial_sig(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>> {
        let key = Self::partial_sig_key(session_id, pubkey);
        Ok(self.data.read().await.get(&key).cloned())
    }

    async fn list_partial_sigs(&self, session_id: &str) -> ArkResult<Vec<String>> {
        let prefix = format!("partial_sigs:{session_id}:");
        let guard = self.data.read().await;
        let ids: Vec<String> = guard
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_set_get_intent() {
        let store = InMemoryLiveStore::new();
        let data = b"test-intent-data";
        store
            .set_intent("round-1", "intent-a", data, 300)
            .await
            .unwrap();
        let got = store.get_intent("round-1", "intent-a").await.unwrap();
        assert_eq!(got, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_memory_list_intents() {
        let store = InMemoryLiveStore::new();
        store
            .set_intent("round-1", "intent-a", b"a", 300)
            .await
            .unwrap();
        store
            .set_intent("round-1", "intent-b", b"b", 300)
            .await
            .unwrap();
        // Different round — should not appear
        store
            .set_intent("round-2", "intent-c", b"c", 300)
            .await
            .unwrap();
        let mut ids = store.list_intents("round-1").await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["intent-a", "intent-b"]);
    }

    #[tokio::test]
    async fn test_memory_delete_intent() {
        let store = InMemoryLiveStore::new();
        store
            .set_intent("round-1", "intent-a", b"data", 300)
            .await
            .unwrap();
        store.delete_intent("round-1", "intent-a").await.unwrap();
        let got = store.get_intent("round-1", "intent-a").await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn test_memory_nonce_roundtrip() {
        let store = InMemoryLiveStore::new();
        let nonce = b"random-nonce-bytes";
        store
            .set_nonce("session-1", "pk-abc", nonce, 120)
            .await
            .unwrap();
        let got = store.get_nonce("session-1", "pk-abc").await.unwrap();
        assert_eq!(got, Some(nonce.to_vec()));

        let keys = store.list_nonces("session-1").await.unwrap();
        assert_eq!(keys, vec!["pk-abc"]);
    }

    #[tokio::test]
    async fn test_memory_partial_sig_roundtrip() {
        let store = InMemoryLiveStore::new();
        let sig = b"partial-sig-bytes";
        store
            .set_partial_sig("session-1", "pk-xyz", sig, 120)
            .await
            .unwrap();
        let got = store.get_partial_sig("session-1", "pk-xyz").await.unwrap();
        assert_eq!(got, Some(sig.to_vec()));

        let keys = store.list_partial_sigs("session-1").await.unwrap();
        assert_eq!(keys, vec!["pk-xyz"]);
    }

    #[tokio::test]
    async fn test_memory_get_nonexistent_returns_none() {
        let store = InMemoryLiveStore::new();
        assert_eq!(store.get_intent("x", "y").await.unwrap(), None);
        assert_eq!(store.get_nonce("x", "y").await.unwrap(), None);
        assert_eq!(store.get_partial_sig("x", "y").await.unwrap(), None);
    }
}
