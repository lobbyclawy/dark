//! Cache service implementations
//!
//! Provides:
//! - `RedisCacheService` — backed by Redis via the `redis` crate
//! - `InMemoryCacheService` — in-process fallback using `tokio::sync::RwLock`
//!
//! Both implement `arkd_core::ports::CacheService`.

use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::CacheService;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

// ─── Redis cache ────────────────────────────────────────────────────────────

/// Redis-backed cache service
pub struct RedisCacheService {
    client: redis::Client,
}

impl RedisCacheService {
    /// Connect to Redis
    pub fn new(url: &str) -> ArkResult<Self> {
        info!(url = %url, "Connecting to Redis cache");
        let client = redis::Client::open(url).map_err(|e| ArkError::CacheError(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl CacheService for RedisCacheService {
    async fn set(&self, key: &str, value: &[u8], ttl_seconds: Option<u64>) -> ArkResult<()> {
        debug!(key = %key, "Redis SET");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| ArkError::CacheError(e.to_string()))?;

        if let Some(ttl) = ttl_seconds {
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("EX")
                .arg(ttl)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| ArkError::CacheError(e.to_string()))?;
        } else {
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| ArkError::CacheError(e.to_string()))?;
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> ArkResult<Option<Vec<u8>>> {
        debug!(key = %key, "Redis GET");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| ArkError::CacheError(e.to_string()))?;

        let result: Option<Vec<u8>> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(|e| ArkError::CacheError(e.to_string()))?;

        Ok(result)
    }

    async fn delete(&self, key: &str) -> ArkResult<bool> {
        debug!(key = %key, "Redis DEL");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| ArkError::CacheError(e.to_string()))?;

        let deleted: i64 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(|e| ArkError::CacheError(e.to_string()))?;

        Ok(deleted > 0)
    }
}

// ─── In-memory cache ────────────────────────────────────────────────────────

/// Entry with optional expiry
struct CacheEntry {
    value: Vec<u8>,
    expires_at: Option<std::time::Instant>,
}

/// In-memory cache service (for testing or when Redis is unavailable)
#[derive(Clone)]
pub struct InMemoryCacheService {
    store: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl InMemoryCacheService {
    /// Create a new in-memory cache
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryCacheService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheService for InMemoryCacheService {
    async fn set(&self, key: &str, value: &[u8], ttl_seconds: Option<u64>) -> ArkResult<()> {
        debug!(key = %key, "InMemory SET");
        let expires_at =
            ttl_seconds.map(|ttl| std::time::Instant::now() + std::time::Duration::from_secs(ttl));
        let entry = CacheEntry {
            value: value.to_vec(),
            expires_at,
        };
        let mut store = self.store.write().await;
        store.insert(key.to_string(), entry);
        Ok(())
    }

    async fn get(&self, key: &str) -> ArkResult<Option<Vec<u8>>> {
        debug!(key = %key, "InMemory GET");
        let store = self.store.read().await;
        match store.get(key) {
            Some(entry) => {
                // Check expiry
                if let Some(expires_at) = entry.expires_at {
                    if std::time::Instant::now() >= expires_at {
                        drop(store);
                        // Lazily remove expired key
                        self.store.write().await.remove(key);
                        return Ok(None);
                    }
                }
                Ok(Some(entry.value.clone()))
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, key: &str) -> ArkResult<bool> {
        debug!(key = %key, "InMemory DEL");
        let mut store = self.store.write().await;
        Ok(store.remove(key).is_some())
    }
}

/// Cache key helpers
pub mod keys {
    /// Round state cache key
    pub fn round_state(round_id: &str) -> String {
        format!("round:{}:state", round_id)
    }

    /// Active participants cache key
    pub fn active_participants(round_id: &str) -> String {
        format!("round:{}:participants", round_id)
    }

    /// VTXO cache key
    pub fn vtxo(vtxo_id: &str) -> String {
        format!("vtxo:{}", vtxo_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_keys() {
        assert_eq!(keys::round_state("abc"), "round:abc:state");
        assert_eq!(keys::vtxo("xyz"), "vtxo:xyz");
    }

    #[tokio::test]
    async fn test_in_memory_set_get() {
        let cache = InMemoryCacheService::new();
        cache.set("key1", b"value1", None).await.unwrap();
        let result = cache.get("key1").await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_in_memory_get_nonexistent() {
        let cache = InMemoryCacheService::new();
        let result = cache.get("nope").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_delete() {
        let cache = InMemoryCacheService::new();
        cache.set("key1", b"value1", None).await.unwrap();
        assert!(cache.delete("key1").await.unwrap());
        assert!(!cache.delete("key1").await.unwrap());
        assert!(cache.get("key1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_in_memory_overwrite() {
        let cache = InMemoryCacheService::new();
        cache.set("key1", b"v1", None).await.unwrap();
        cache.set("key1", b"v2", None).await.unwrap();
        assert_eq!(cache.get("key1").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn test_in_memory_ttl_expired() {
        let cache = InMemoryCacheService::new();
        // Set with 0-second TTL (expires immediately)
        {
            let entry = CacheEntry {
                value: b"expired".to_vec(),
                expires_at: Some(std::time::Instant::now() - std::time::Duration::from_secs(1)),
            };
            cache
                .store
                .write()
                .await
                .insert("expired-key".to_string(), entry);
        }
        let result = cache.get("expired-key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_binary_data() {
        let cache = InMemoryCacheService::new();
        let binary = vec![0u8, 1, 2, 255, 254, 253];
        cache.set("bin", &binary, None).await.unwrap();
        assert_eq!(cache.get("bin").await.unwrap(), Some(binary));
    }
}
