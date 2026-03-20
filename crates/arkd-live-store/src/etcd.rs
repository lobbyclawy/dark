//! etcd-backed implementation of [`LiveStore`] for clustered deployments.

use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::LiveStore;
use async_trait::async_trait;
use etcd_client::{Client, GetOptions, PutOptions};

/// etcd-backed ephemeral live-store.
///
/// Uses `etcd_client::Client` for async gRPC communication with etcd.
/// Keys are set with TTL via etcd leases so they auto-expire after a round
/// completes or times out.
#[derive(Clone)]
pub struct EtcdLiveStore {
    client: Client,
}

impl EtcdLiveStore {
    /// Connect to etcd at the given URL (e.g. `http://127.0.0.1:2379`).
    pub async fn new(url: &str) -> ArkResult<Self> {
        let client = Client::connect([url], None)
            .await
            .map_err(|e| ArkError::Internal(format!("etcd connect: {e}")))?;
        Ok(Self { client })
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

    /// Helper: PUT key value with a lease-based TTL.
    async fn put_with_ttl(&self, key: &str, value: &[u8], ttl_secs: u64) -> ArkResult<()> {
        let mut client = self.client.clone();

        // Create a lease with the requested TTL.
        let lease = client
            .lease_grant(ttl_secs as i64, None)
            .await
            .map_err(|e| ArkError::Internal(format!("etcd lease_grant: {e}")))?;

        let opts = PutOptions::new().with_lease(lease.id());
        client
            .put(key, value, Some(opts))
            .await
            .map_err(|e| ArkError::Internal(format!("etcd PUT: {e}")))?;
        Ok(())
    }

    /// Helper: GET key → Option<Vec<u8>>
    async fn get_bytes(&self, key: &str) -> ArkResult<Option<Vec<u8>>> {
        let mut client = self.client.clone();
        let resp = client
            .get(key, None)
            .await
            .map_err(|e| ArkError::Internal(format!("etcd GET: {e}")))?;

        Ok(resp.kvs().first().map(|kv| kv.value().to_vec()))
    }

    /// Helper: GET with prefix → extract suffix after last ':' from each key.
    async fn list_keys_suffix(&self, prefix: &str) -> ArkResult<Vec<String>> {
        let mut client = self.client.clone();
        let opts = GetOptions::new().with_prefix();
        let resp = client
            .get(prefix, Some(opts))
            .await
            .map_err(|e| ArkError::Internal(format!("etcd GET prefix: {e}")))?;

        let suffixes = resp
            .kvs()
            .iter()
            .filter_map(|kv| {
                let key = kv.key_str().ok()?;
                key.rsplit(':').next().map(String::from)
            })
            .collect();
        Ok(suffixes)
    }

    /// Helper: DELETE key
    async fn delete_key(&self, key: &str) -> ArkResult<()> {
        let mut client = self.client.clone();
        client
            .delete(key, None)
            .await
            .map_err(|e| ArkError::Internal(format!("etcd DELETE: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl LiveStore for EtcdLiveStore {
    async fn set_intent(
        &self,
        round_id: &str,
        intent_id: &str,
        data: &[u8],
        ttl_secs: u64,
    ) -> ArkResult<()> {
        self.put_with_ttl(&Self::intent_key(round_id, intent_id), data, ttl_secs)
            .await
    }

    async fn get_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<Option<Vec<u8>>> {
        self.get_bytes(&Self::intent_key(round_id, intent_id)).await
    }

    async fn list_intents(&self, round_id: &str) -> ArkResult<Vec<String>> {
        self.list_keys_suffix(&format!("intents:{round_id}:")).await
    }

    async fn delete_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<()> {
        self.delete_key(&Self::intent_key(round_id, intent_id))
            .await
    }

    async fn set_nonce(
        &self,
        session_id: &str,
        pubkey: &str,
        nonce: &[u8],
        ttl_secs: u64,
    ) -> ArkResult<()> {
        self.put_with_ttl(&Self::nonce_key(session_id, pubkey), nonce, ttl_secs)
            .await
    }

    async fn get_nonce(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>> {
        self.get_bytes(&Self::nonce_key(session_id, pubkey)).await
    }

    async fn list_nonces(&self, session_id: &str) -> ArkResult<Vec<String>> {
        self.list_keys_suffix(&format!("nonces:{session_id}:"))
            .await
    }

    async fn set_partial_sig(
        &self,
        session_id: &str,
        pubkey: &str,
        sig: &[u8],
        ttl_secs: u64,
    ) -> ArkResult<()> {
        self.put_with_ttl(&Self::partial_sig_key(session_id, pubkey), sig, ttl_secs)
            .await
    }

    async fn get_partial_sig(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>> {
        self.get_bytes(&Self::partial_sig_key(session_id, pubkey))
            .await
    }

    async fn list_partial_sigs(&self, session_id: &str) -> ArkResult<Vec<String>> {
        self.list_keys_suffix(&format!("partial_sigs:{session_id}:"))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// etcd integration tests require a live etcd instance.
    /// Run with: `cargo test --features etcd -- --ignored`
    #[tokio::test]
    #[ignore = "requires a live etcd instance at http://127.0.0.1:2379"]
    async fn test_etcd_intent_roundtrip() {
        let store = EtcdLiveStore::new("http://127.0.0.1:2379")
            .await
            .expect("etcd connection failed");
        let data = b"etcd-test-data";
        store.set_intent("r1", "i1", data, 60).await.unwrap();
        let got = store.get_intent("r1", "i1").await.unwrap();
        assert_eq!(got, Some(data.to_vec()));
        store.delete_intent("r1", "i1").await.unwrap();
        let gone = store.get_intent("r1", "i1").await.unwrap();
        assert_eq!(gone, None);
    }

    #[tokio::test]
    #[ignore = "requires a live etcd instance at http://127.0.0.1:2379"]
    async fn test_etcd_nonce_roundtrip() {
        let store = EtcdLiveStore::new("http://127.0.0.1:2379")
            .await
            .expect("etcd connection failed");
        let nonce = b"nonce-bytes";
        store.set_nonce("s1", "pk1", nonce, 60).await.unwrap();
        let got = store.get_nonce("s1", "pk1").await.unwrap();
        assert_eq!(got, Some(nonce.to_vec()));
        let keys = store.list_nonces("s1").await.unwrap();
        assert!(keys.contains(&"pk1".to_string()));
    }

    #[tokio::test]
    #[ignore = "requires a live etcd instance at http://127.0.0.1:2379"]
    async fn test_etcd_partial_sig_roundtrip() {
        let store = EtcdLiveStore::new("http://127.0.0.1:2379")
            .await
            .expect("etcd connection failed");
        let sig = b"partial-sig-bytes";
        store.set_partial_sig("s1", "pk1", sig, 60).await.unwrap();
        let got = store.get_partial_sig("s1", "pk1").await.unwrap();
        assert_eq!(got, Some(sig.to_vec()));
        let keys = store.list_partial_sigs("s1").await.unwrap();
        assert!(keys.contains(&"pk1".to_string()));
    }

    #[tokio::test]
    #[ignore = "requires a live etcd instance at http://127.0.0.1:2379"]
    async fn test_etcd_list_intents() {
        let store = EtcdLiveStore::new("http://127.0.0.1:2379")
            .await
            .expect("etcd connection failed");
        // Clean up first
        store.delete_intent("list-r1", "a").await.ok();
        store.delete_intent("list-r1", "b").await.ok();

        store.set_intent("list-r1", "a", b"d1", 60).await.unwrap();
        store.set_intent("list-r1", "b", b"d2", 60).await.unwrap();
        let mut ids = store.list_intents("list-r1").await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["a".to_string(), "b".to_string()]);

        // Cleanup
        store.delete_intent("list-r1", "a").await.unwrap();
        store.delete_intent("list-r1", "b").await.unwrap();
    }
}
