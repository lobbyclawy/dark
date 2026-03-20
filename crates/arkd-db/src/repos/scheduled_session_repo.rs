//! Scheduled-session config repository — SQLite implementation of
//! `arkd_core::ports::ScheduledSessionRepository`

use arkd_core::domain::ScheduledSessionConfig;
use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::ScheduledSessionRepository;
use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::debug;

/// SQLite-backed scheduled-session config repository (singleton row).
pub struct SqliteScheduledSessionRepository {
    pool: SqlitePool,
}

impl SqliteScheduledSessionRepository {
    /// Create a new repository backed by the given SQLite pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ScheduledSessionRepository for SqliteScheduledSessionRepository {
    async fn get(&self) -> ArkResult<Option<ScheduledSessionConfig>> {
        debug!("Getting scheduled session config");

        let row = sqlx::query_as::<_, ScheduledSessionRow>(
            "SELECT round_interval_secs, round_lifetime_secs, max_intents_per_round \
             FROM scheduled_session_config WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| r.into_config()))
    }

    async fn upsert(&self, config: ScheduledSessionConfig) -> ArkResult<()> {
        debug!(
            interval = config.round_interval_secs,
            lifetime = config.round_lifetime_secs,
            max_intents = config.max_intents_per_round,
            "Upserting scheduled session config"
        );

        sqlx::query(
            "INSERT INTO scheduled_session_config (id, round_interval_secs, round_lifetime_secs, max_intents_per_round) \
             VALUES (1, ?1, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET \
                 round_interval_secs = excluded.round_interval_secs, \
                 round_lifetime_secs = excluded.round_lifetime_secs, \
                 max_intents_per_round = excluded.max_intents_per_round",
        )
        .bind(config.round_interval_secs as i32)
        .bind(config.round_lifetime_secs as i32)
        .bind(config.max_intents_per_round as i32)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn clear(&self) -> ArkResult<()> {
        debug!("Clearing scheduled session config");

        sqlx::query("DELETE FROM scheduled_session_config WHERE id = 1")
            .execute(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ScheduledSessionRow {
    round_interval_secs: i32,
    round_lifetime_secs: i32,
    max_intents_per_round: i32,
}

impl ScheduledSessionRow {
    fn into_config(self) -> ScheduledSessionConfig {
        ScheduledSessionConfig {
            round_interval_secs: self.round_interval_secs as u32,
            round_lifetime_secs: self.round_lifetime_secs as u32,
            max_intents_per_round: self.max_intents_per_round as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn setup() -> (Database, SqliteScheduledSessionRepository) {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = SqliteScheduledSessionRepository::new(db.sqlite_pool().unwrap().clone());
        (db, repo)
    }

    #[tokio::test]
    async fn test_get_returns_none_when_empty() {
        let (_db, repo) = setup().await;
        let result = repo.get().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_upsert_and_get() {
        let (_db, repo) = setup().await;
        let config = ScheduledSessionConfig::new(10, 30, 128);
        repo.upsert(config.clone()).await.unwrap();

        let found = repo.get().await.unwrap().unwrap();
        assert_eq!(found, config);
    }

    #[tokio::test]
    async fn test_upsert_overwrites() {
        let (_db, repo) = setup().await;

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
        let (_db, repo) = setup().await;
        repo.upsert(ScheduledSessionConfig::new(10, 30, 128))
            .await
            .unwrap();

        repo.clear().await.unwrap();
        let result = repo.get().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_clear_when_empty_is_ok() {
        let (_db, repo) = setup().await;
        // Should not error even when nothing to delete
        repo.clear().await.unwrap();
    }
}
