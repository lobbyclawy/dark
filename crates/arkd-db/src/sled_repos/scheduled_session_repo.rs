//! Sled-backed implementation of `arkd_core::ports::ScheduledSessionRepository`.
//!
//! Stores a singleton config under key `sched_session::config`.

use crate::embedded_kv::SledKvStore;
use arkd_core::domain::ScheduledSessionConfig;
use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::ScheduledSessionRepository;
use async_trait::async_trait;
use std::sync::Arc;

const CONFIG_KEY: &[u8] = b"sched_session::config";

/// Sled-backed scheduled-session config repository (singleton).
pub struct SledScheduledSessionRepository {
    store: Arc<SledKvStore>,
}

impl SledScheduledSessionRepository {
    /// Create a new sled-backed scheduled-session repository.
    pub fn new(store: Arc<SledKvStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ScheduledSessionRepository for SledScheduledSessionRepository {
    async fn get(&self) -> ArkResult<Option<ScheduledSessionConfig>> {
        match self
            .store
            .get(CONFIG_KEY)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?
        {
            Some(bytes) => {
                let config: ScheduledSessionConfig = serde_json::from_slice(&bytes)
                    .map_err(|e| ArkError::DatabaseError(format!("deserialize config: {e}")))?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    async fn upsert(&self, config: ScheduledSessionConfig) -> ArkResult<()> {
        let data = serde_json::to_vec(&config)
            .map_err(|e| ArkError::DatabaseError(format!("serialize config: {e}")))?;
        self.store
            .set(CONFIG_KEY, &data)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn clear(&self) -> ArkResult<()> {
        self.store
            .delete(CONFIG_KEY)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        Ok(())
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
    async fn test_get_returns_none_when_empty() {
        let repo = SledScheduledSessionRepository::new(make_store());
        let result = repo.get().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_upsert_and_get() {
        let repo = SledScheduledSessionRepository::new(make_store());
        let config = ScheduledSessionConfig::new(10, 30, 128);
        repo.upsert(config.clone()).await.unwrap();

        let found = repo.get().await.unwrap().unwrap();
        assert_eq!(found, config);
    }

    #[tokio::test]
    async fn test_upsert_overwrites() {
        let repo = SledScheduledSessionRepository::new(make_store());

        repo.upsert(ScheduledSessionConfig::new(10, 30, 128))
            .await
            .unwrap();
        repo.upsert(ScheduledSessionConfig::new(20, 60, 256))
            .await
            .unwrap();

        let found = repo.get().await.unwrap().unwrap();
        assert_eq!(found.round_interval_secs, 20);
        assert_eq!(found.round_lifetime_secs, 60);
        assert_eq!(found.max_intents_per_round, 256);
    }

    #[tokio::test]
    async fn test_clear() {
        let repo = SledScheduledSessionRepository::new(make_store());
        repo.upsert(ScheduledSessionConfig::new(10, 30, 128))
            .await
            .unwrap();

        repo.clear().await.unwrap();
        let result = repo.get().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_clear_when_empty_is_ok() {
        let repo = SledScheduledSessionRepository::new(make_store());
        repo.clear().await.unwrap();
    }
}
