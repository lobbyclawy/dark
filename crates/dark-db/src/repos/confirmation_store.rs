//! Confirmation store — SQLite implementation of `dark_core::ports::ConfirmationStore`

use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::ConfirmationStore;
use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::debug;

/// SQLite-backed confirmation store
pub struct SqliteConfirmationStore {
    pool: SqlitePool,
}

impl SqliteConfirmationStore {
    /// Create a new store backed by the given SQLite pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ConfirmationStore for SqliteConfirmationStore {
    async fn init(&self, round_id: &str, intent_ids: Vec<String>) -> ArkResult<()> {
        debug!(round_id = %round_id, count = intent_ids.len(), "Initializing confirmation store");

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        // Clear any existing entries for this round
        sqlx::query("DELETE FROM confirmations WHERE round_id = ?1")
            .bind(round_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        // Insert all intent IDs as unconfirmed
        for intent_id in &intent_ids {
            sqlx::query(
                "INSERT INTO confirmations (round_id, intent_id, confirmed) VALUES (?1, ?2, FALSE)",
            )
            .bind(round_id)
            .bind(intent_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn confirm(&self, round_id: &str, intent_id: &str) -> ArkResult<()> {
        debug!(round_id = %round_id, intent_id = %intent_id, "Confirming intent");

        sqlx::query(
            "UPDATE confirmations SET confirmed = TRUE WHERE round_id = ?1 AND intent_id = ?2",
        )
        .bind(round_id)
        .bind(intent_id)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn all_confirmed(&self, round_id: &str) -> ArkResult<bool> {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM confirmations WHERE round_id = ?1 AND confirmed = FALSE",
        )
        .bind(round_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(row.0 == 0)
    }

    async fn get_confirmed(&self, round_id: &str) -> ArkResult<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT intent_id FROM confirmations WHERE round_id = ?1 AND confirmed = TRUE",
        )
        .bind(round_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn get_pending(&self, round_id: &str) -> ArkResult<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT intent_id FROM confirmations WHERE round_id = ?1 AND confirmed = FALSE",
        )
        .bind(round_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn setup() -> (Database, SqliteConfirmationStore) {
        let db = Database::connect_in_memory().await.unwrap();
        let store = SqliteConfirmationStore::new(db.sqlite_pool().unwrap().clone());
        (db, store)
    }

    #[tokio::test]
    async fn test_init_and_confirm() {
        let (_db, store) = setup().await;

        let intents = vec!["i1".into(), "i2".into(), "i3".into()];
        store.init("round-1", intents).await.unwrap();

        // Initially nothing confirmed
        assert!(!store.all_confirmed("round-1").await.unwrap());
        assert_eq!(store.get_pending("round-1").await.unwrap().len(), 3);
        assert_eq!(store.get_confirmed("round-1").await.unwrap().len(), 0);

        // Confirm one
        store.confirm("round-1", "i1").await.unwrap();
        assert!(!store.all_confirmed("round-1").await.unwrap());
        assert_eq!(store.get_confirmed("round-1").await.unwrap().len(), 1);
        assert_eq!(store.get_pending("round-1").await.unwrap().len(), 2);

        // Confirm all
        store.confirm("round-1", "i2").await.unwrap();
        store.confirm("round-1", "i3").await.unwrap();
        assert!(store.all_confirmed("round-1").await.unwrap());
        assert_eq!(store.get_confirmed("round-1").await.unwrap().len(), 3);
        assert_eq!(store.get_pending("round-1").await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_empty_round_all_confirmed() {
        let (_db, store) = setup().await;
        // No entries → all_confirmed returns true (vacuous truth)
        assert!(store.all_confirmed("nonexistent").await.unwrap());
    }

    #[tokio::test]
    async fn test_reinit_clears_old() {
        let (_db, store) = setup().await;

        store
            .init("round-1", vec!["i1".into(), "i2".into()])
            .await
            .unwrap();
        store.confirm("round-1", "i1").await.unwrap();

        // Re-init resets
        store
            .init("round-1", vec!["i3".into(), "i4".into()])
            .await
            .unwrap();
        assert!(!store.all_confirmed("round-1").await.unwrap());
        assert_eq!(store.get_pending("round-1").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_multiple_rounds_isolated() {
        let (_db, store) = setup().await;

        store.init("r1", vec!["i1".into()]).await.unwrap();
        store.init("r2", vec!["i2".into()]).await.unwrap();

        store.confirm("r1", "i1").await.unwrap();

        assert!(store.all_confirmed("r1").await.unwrap());
        assert!(!store.all_confirmed("r2").await.unwrap());
    }
}
