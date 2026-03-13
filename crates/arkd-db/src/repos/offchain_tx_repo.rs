//! Offchain transaction repository — SQLite implementation

use arkd_core::domain::{OffchainTx, OffchainTxStage, VtxoInput, VtxoOutput};
use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::OffchainTxRepository;
use async_trait::async_trait;
use sqlx::SqlitePool;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// SQLite-backed offchain transaction repository
pub struct SqliteOffchainTxRepository {
    pool: SqlitePool,
}

impl SqliteOffchainTxRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    #[allow(clippy::type_complexity)]
    fn row_to_offchain_tx(row: OffchainTxRow) -> ArkResult<OffchainTx> {
        let (id, stage, inputs_json, outputs_json, txid, rejection_reason, created_at, updated_at) =
            row;
        let inputs: Vec<VtxoInput> = serde_json::from_str(&inputs_json)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        let outputs: Vec<VtxoOutput> = serde_json::from_str(&outputs_json)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let stage = match stage.as_str() {
            "Requested" => OffchainTxStage::Requested,
            "Accepted" => OffchainTxStage::Accepted {
                accepted_at: updated_at as u64,
            },
            "Finalized" => OffchainTxStage::Finalized {
                txid: txid.unwrap_or_default(),
                finalized_at: updated_at as u64,
            },
            "Rejected" => OffchainTxStage::Rejected {
                reason: rejection_reason.unwrap_or_default(),
            },
            other => {
                return Err(ArkError::DatabaseError(format!(
                    "Unknown offchain tx stage: {other}"
                )));
            }
        };

        Ok(OffchainTx {
            id,
            inputs,
            outputs,
            stage,
            created_at: created_at as u64,
            updated_at: updated_at as u64,
        })
    }
}

type OffchainTxRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
    i64,
);

#[async_trait]
impl OffchainTxRepository for SqliteOffchainTxRepository {
    async fn create(&self, tx: &OffchainTx) -> ArkResult<()> {
        debug!(id = %tx.id, "Creating offchain tx");

        let inputs_json = serde_json::to_string(&tx.inputs)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        let outputs_json = serde_json::to_string(&tx.outputs)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        let stage_str = tx.stage.to_string();
        let created_at = tx.created_at as i64;
        let updated_at = tx.updated_at as i64;

        sqlx::query(
            "INSERT INTO offchain_txs (id, stage, inputs_json, outputs_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&tx.id)
        .bind(&stage_str)
        .bind(&inputs_json)
        .bind(&outputs_json)
        .bind(created_at)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, id: &str) -> ArkResult<Option<OffchainTx>> {
        debug!(id = %id, "Getting offchain tx");

        let row = sqlx::query_as::<_, OffchainTxRow>(
            "SELECT id, stage, inputs_json, outputs_json, txid, rejection_reason, created_at, updated_at FROM offchain_txs WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(Self::row_to_offchain_tx(row)?)),
            None => Ok(None),
        }
    }

    async fn get_pending(&self) -> ArkResult<Vec<OffchainTx>> {
        debug!("Getting pending offchain txs");

        let rows = sqlx::query_as::<_, OffchainTxRow>(
            "SELECT id, stage, inputs_json, outputs_json, txid, rejection_reason, created_at, updated_at FROM offchain_txs WHERE stage IN ('Requested', 'Accepted') ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        rows.into_iter().map(Self::row_to_offchain_tx).collect()
    }

    async fn update_stage(&self, id: &str, stage: &OffchainTxStage) -> ArkResult<()> {
        debug!(id = %id, stage = %stage, "Updating offchain tx stage");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let stage_str = stage.to_string();
        let (txid, rejection_reason): (Option<String>, Option<String>) = match stage {
            OffchainTxStage::Finalized { txid, .. } => (Some(txid.clone()), None),
            OffchainTxStage::Rejected { reason } => (None, Some(reason.clone())),
            _ => (None, None),
        };

        let result = sqlx::query(
            "UPDATE offchain_txs SET stage = ?1, txid = COALESCE(?2, txid), rejection_reason = COALESCE(?3, rejection_reason), updated_at = ?4 WHERE id = ?5",
        )
        .bind(&stage_str)
        .bind(&txid)
        .bind(&rejection_reason)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ArkError::Internal(format!(
                "Offchain tx {id} not found for stage update"
            )));
        }

        Ok(())
    }
}

impl SqliteOffchainTxRepository {
    /// List offchain transactions that reference a specific VTXO (not part of the trait).
    pub async fn list_by_vtxo(&self, vtxo_id: &str) -> ArkResult<Vec<OffchainTx>> {
        debug!(vtxo_id = %vtxo_id, "Listing offchain txs by VTXO");

        let pattern = format!("%\"{vtxo_id}\"%");
        let rows = sqlx::query_as::<_, OffchainTxRow>(
            "SELECT id, stage, inputs_json, outputs_json, txid, rejection_reason, created_at, updated_at FROM offchain_txs WHERE inputs_json LIKE ?1 ORDER BY created_at ASC",
        )
        .bind(&pattern)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        rows.into_iter().map(Self::row_to_offchain_tx).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn setup() -> (Database, SqliteOffchainTxRepository) {
        let db = Database::connect_in_memory().await.unwrap();
        let pool = db.sqlite_pool().unwrap().clone();
        let repo = SqliteOffchainTxRepository::new(pool);
        (db, repo)
    }

    fn make_test_tx() -> OffchainTx {
        OffchainTx::new(
            vec![VtxoInput {
                vtxo_id: "abc123:0".to_string(),
                signed_tx: vec![1, 2, 3],
            }],
            vec![VtxoOutput {
                pubkey: "02deadbeef".to_string(),
                amount_sats: 10_000,
            }],
        )
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let (_db, repo) = setup().await;
        let tx = make_test_tx();
        let id = tx.id.clone();
        repo.create(&tx).await.unwrap();
        let fetched = repo.get(&id).await.unwrap().unwrap();
        assert_eq!(fetched.id, id);
        assert_eq!(fetched.stage, OffchainTxStage::Requested);
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let (_db, repo) = setup().await;
        assert!(repo.get("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_pending() {
        let (_db, repo) = setup().await;
        let tx = make_test_tx();
        repo.create(&tx).await.unwrap();
        assert_eq!(repo.get_pending().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_update_stage() {
        let (_db, repo) = setup().await;
        let tx = make_test_tx();
        let id = tx.id.clone();
        repo.create(&tx).await.unwrap();

        let stage = OffchainTxStage::Finalized {
            txid: "finaltxid".to_string(),
            finalized_at: 12345,
        };
        repo.update_stage(&id, &stage).await.unwrap();
        assert!(repo.get(&id).await.unwrap().unwrap().is_finalized());
        assert!(repo.get_pending().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_by_vtxo() {
        let (_db, repo) = setup().await;
        let tx = make_test_tx();
        repo.create(&tx).await.unwrap();
        assert_eq!(repo.list_by_vtxo("abc123:0").await.unwrap().len(), 1);
        assert!(repo.list_by_vtxo("nonexistent:0").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_update_stage_not_found() {
        let (_db, repo) = setup().await;
        assert!(repo
            .update_stage("nonexistent", &OffchainTxStage::Requested)
            .await
            .is_err());
    }
}
