//! Checkpoint repository — SQLite implementation of `dark_core::ports::CheckpointRepository`

use dark_core::domain::CheckpointTx;
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::CheckpointRepository;
use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::debug;

/// SQLite-backed checkpoint repository
pub struct SqliteCheckpointRepository {
    pool: SqlitePool,
}

impl SqliteCheckpointRepository {
    /// Create a new repository backed by the given SQLite pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CheckpointRepository for SqliteCheckpointRepository {
    async fn store_checkpoint(&self, checkpoint: CheckpointTx) -> ArkResult<()> {
        debug!(id = %checkpoint.id, "Storing checkpoint");

        sqlx::query(
            r#"
            INSERT INTO checkpoints (id, offchain_tx_id, tapscript, exit_delay, created_at, swept)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(id) DO UPDATE SET
                offchain_tx_id = excluded.offchain_tx_id,
                tapscript = excluded.tapscript,
                exit_delay = excluded.exit_delay,
                swept = excluded.swept
            "#,
        )
        .bind(&checkpoint.id)
        .bind(&checkpoint.offchain_tx_id)
        .bind(&checkpoint.tapscript)
        .bind(checkpoint.exit_delay as i32)
        .bind(checkpoint.created_at as i64)
        .bind(checkpoint.swept)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_checkpoint(&self, id: &str) -> ArkResult<Option<CheckpointTx>> {
        debug!(id = %id, "Getting checkpoint");

        let row = sqlx::query_as::<_, CheckpointRow>(
            r#"
            SELECT id, offchain_tx_id, tapscript, exit_delay, created_at, swept
            FROM checkpoints
            WHERE id = ?1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| r.into_checkpoint()))
    }

    async fn list_pending(&self) -> ArkResult<Vec<CheckpointTx>> {
        debug!("Listing pending checkpoints");

        let rows = sqlx::query_as::<_, CheckpointRow>(
            r#"
            SELECT id, offchain_tx_id, tapscript, exit_delay, created_at, swept
            FROM checkpoints
            WHERE swept = FALSE
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_checkpoint()).collect())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct CheckpointRow {
    id: String,
    offchain_tx_id: String,
    tapscript: String,
    exit_delay: i32,
    created_at: i64,
    swept: bool,
}

impl CheckpointRow {
    fn into_checkpoint(self) -> CheckpointTx {
        CheckpointTx {
            id: self.id,
            offchain_tx_id: self.offchain_tx_id,
            tapscript: self.tapscript,
            exit_delay: self.exit_delay as u32,
            created_at: self.created_at as u64,
            swept: self.swept,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn setup() -> (Database, SqliteCheckpointRepository) {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = SqliteCheckpointRepository::new(db.sqlite_pool().unwrap().clone());
        (db, repo)
    }

    #[tokio::test]
    async fn test_store_and_get_checkpoint() {
        let (_db, repo) = setup().await;

        let cp = CheckpointTx::new("offchain-tx-1".into(), "tapscript-hex".into(), 144);
        let id = cp.id.clone();
        repo.store_checkpoint(cp).await.unwrap();

        let found = repo.get_checkpoint(&id).await.unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.offchain_tx_id, "offchain-tx-1");
        assert_eq!(found.tapscript, "tapscript-hex");
        assert_eq!(found.exit_delay, 144);
        assert!(!found.swept);
    }

    #[tokio::test]
    async fn test_get_checkpoint_not_found() {
        let (_db, repo) = setup().await;
        let found = repo.get_checkpoint("nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_list_pending_checkpoints() {
        let (_db, repo) = setup().await;

        let cp1 = CheckpointTx::new("tx-1".into(), "script-1".into(), 100);
        let mut cp2 = CheckpointTx::new("tx-2".into(), "script-2".into(), 200);
        cp2.mark_swept();
        let cp3 = CheckpointTx::new("tx-3".into(), "script-3".into(), 144);

        repo.store_checkpoint(cp1).await.unwrap();
        repo.store_checkpoint(cp2).await.unwrap();
        repo.store_checkpoint(cp3).await.unwrap();

        let pending = repo.list_pending().await.unwrap();
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn test_upsert_checkpoint() {
        let (_db, repo) = setup().await;

        let cp = CheckpointTx::new("tx-1".into(), "script-1".into(), 100);
        let id = cp.id.clone();
        repo.store_checkpoint(cp).await.unwrap();

        let mut cp2 = CheckpointTx::new("tx-1-updated".into(), "script-1-new".into(), 200);
        cp2.id = id.clone();
        cp2.mark_swept();
        repo.store_checkpoint(cp2).await.unwrap();

        let found = repo.get_checkpoint(&id).await.unwrap().unwrap();
        assert_eq!(found.offchain_tx_id, "tx-1-updated");
        assert!(found.swept);
    }
}
