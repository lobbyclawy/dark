//! Redis-backed implementation of [`LiveStore`] for production use.

use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::LiveStore;
use async_trait::async_trait;
use redis::AsyncCommands;

/// Redis-backed ephemeral live-store.
///
/// Uses `redis::aio::ConnectionManager` for automatic reconnection.
/// Keys are set with TTL so they auto-expire after a round completes or times out.
#[derive(Clone)]
pub struct RedisLiveStore {
    conn: redis::aio::ConnectionManager,
}

impl RedisLiveStore {
    /// Connect to Redis at the given URL (e.g. `redis://127.0.0.1:6379`).
    pub async fn new(url: &str) -> ArkResult<Self> {
        let client =
            redis::Client::open(url).map_err(|e| ArkError::Internal(format!("Redis: {e}")))?;
        let conn = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(|e| ArkError::Internal(format!("Redis connect: {e}")))?;
        Ok(Self { conn })
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

    /// Helper: SET key value EX ttl
    async fn set_ex(&self, key: &str, value: &[u8], ttl_secs: u64) -> ArkResult<()> {
        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(key, value, ttl_secs)
            .await
            .map_err(|e| ArkError::Internal(format!("Redis SET: {e}")))?;
        Ok(())
    }

    /// Helper: GET key
    async fn get_bytes(&self, key: &str) -> ArkResult<Option<Vec<u8>>> {
        let mut conn = self.conn.clone();
        let val: Option<Vec<u8>> = conn
            .get(key)
            .await
            .map_err(|e| ArkError::Internal(format!("Redis GET: {e}")))?;
        Ok(val)
    }

    /// Helper: KEYS pattern → extract suffix after last ':'
    async fn list_keys_suffix(&self, pattern: &str) -> ArkResult<Vec<String>> {
        let mut conn = self.conn.clone();
        let keys: Vec<String> = conn
            .keys(pattern)
            .await
            .map_err(|e| ArkError::Internal(format!("Redis KEYS: {e}")))?;
        let suffixes = keys
            .into_iter()
            .filter_map(|k| k.rsplit(':').next().map(String::from))
            .collect();
        Ok(suffixes)
    }
}

#[async_trait]
impl LiveStore for RedisLiveStore {
    async fn set_intent(
        &self,
        round_id: &str,
        intent_id: &str,
        data: &[u8],
        ttl_secs: u64,
    ) -> ArkResult<()> {
        self.set_ex(&Self::intent_key(round_id, intent_id), data, ttl_secs)
            .await
    }

    async fn get_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<Option<Vec<u8>>> {
        self.get_bytes(&Self::intent_key(round_id, intent_id)).await
    }

    async fn list_intents(&self, round_id: &str) -> ArkResult<Vec<String>> {
        self.list_keys_suffix(&format!("intents:{round_id}:*"))
            .await
    }

    async fn delete_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<()> {
        let mut conn = self.conn.clone();
        conn.del::<_, ()>(Self::intent_key(round_id, intent_id))
            .await
            .map_err(|e| ArkError::Internal(format!("Redis DEL: {e}")))?;
        Ok(())
    }

    async fn set_nonce(
        &self,
        session_id: &str,
        pubkey: &str,
        nonce: &[u8],
        ttl_secs: u64,
    ) -> ArkResult<()> {
        self.set_ex(&Self::nonce_key(session_id, pubkey), nonce, ttl_secs)
            .await
    }

    async fn get_nonce(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>> {
        self.get_bytes(&Self::nonce_key(session_id, pubkey)).await
    }

    async fn list_nonces(&self, session_id: &str) -> ArkResult<Vec<String>> {
        self.list_keys_suffix(&format!("nonces:{session_id}:*"))
            .await
    }

    async fn set_partial_sig(
        &self,
        session_id: &str,
        pubkey: &str,
        sig: &[u8],
        ttl_secs: u64,
    ) -> ArkResult<()> {
        self.set_ex(&Self::partial_sig_key(session_id, pubkey), sig, ttl_secs)
            .await
    }

    async fn get_partial_sig(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>> {
        self.get_bytes(&Self::partial_sig_key(session_id, pubkey))
            .await
    }

    async fn list_partial_sigs(&self, session_id: &str) -> ArkResult<Vec<String>> {
        self.list_keys_suffix(&format!("partial_sigs:{session_id}:*"))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Redis integration tests require a live Redis instance.
    /// Run with: `cargo test --features redis -- --ignored`
    #[tokio::test]
    #[ignore = "requires a live Redis instance at redis://127.0.0.1:6379"]
    async fn test_redis_intent_roundtrip() {
        let store = RedisLiveStore::new("redis://127.0.0.1:6379")
            .await
            .expect("Redis connection failed");
        let data = b"redis-test-data";
        store.set_intent("r1", "i1", data, 60).await.unwrap();
        let got = store.get_intent("r1", "i1").await.unwrap();
        assert_eq!(got, Some(data.to_vec()));
        store.delete_intent("r1", "i1").await.unwrap();
    }
}
