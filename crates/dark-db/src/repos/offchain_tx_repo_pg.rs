//! Offchain transaction repository — PostgreSQL implementation

use async_trait::async_trait;
use dark_core::domain::{OffchainTx, OffchainTxStage, VtxoInput, VtxoOutput};
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::OffchainTxRepository;
use sqlx::PgPool;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// PostgreSQL-backed offchain transaction repository
pub struct PgOffchainTxRepository {
    pool: PgPool,
}

impl PgOffchainTxRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::type_complexity)]
    fn row_to_offchain_tx(row: PgOffchainTxRow) -> ArkResult<OffchainTx> {
        let (
            id,
            stage,
            inputs_json,
            outputs_json,
            txid,
            rejection_reason,
            created_at,
            updated_at,
            signed_ark_tx,
            checkpoint_txs_json,
        ) = row;
        let inputs: Vec<VtxoInput> = serde_json::from_str(&inputs_json)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        let outputs: Vec<VtxoOutput> = serde_json::from_str(&outputs_json)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        let checkpoint_txs: Vec<String> =
            serde_json::from_str(&checkpoint_txs_json).unwrap_or_default();

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
            signed_ark_tx,
            checkpoint_txs,
        })
    }
}

type PgOffchainTxRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
    i64,
    String,
    String,
);

#[async_trait]
impl OffchainTxRepository for PgOffchainTxRepository {
    async fn create(&self, tx: &OffchainTx) -> ArkResult<()> {
        debug!(id = %tx.id, "Creating offchain tx (PG)");

        let inputs_json = serde_json::to_string(&tx.inputs)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        let outputs_json = serde_json::to_string(&tx.outputs)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        let checkpoint_txs_json = serde_json::to_string(&tx.checkpoint_txs)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        let stage_str = tx.stage.to_string();
        let created_at = tx.created_at as i64;
        let updated_at = tx.updated_at as i64;

        sqlx::query(
            "INSERT INTO offchain_txs (id, stage, inputs_json, outputs_json, created_at, updated_at, signed_ark_tx, checkpoint_txs_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&tx.id)
        .bind(&stage_str)
        .bind(&inputs_json)
        .bind(&outputs_json)
        .bind(created_at)
        .bind(updated_at)
        .bind(&tx.signed_ark_tx)
        .bind(&checkpoint_txs_json)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, id: &str) -> ArkResult<Option<OffchainTx>> {
        debug!(id = %id, "Getting offchain tx (PG)");

        let row = sqlx::query_as::<_, PgOffchainTxRow>(
            "SELECT id, stage, inputs_json, outputs_json, txid, rejection_reason, created_at, updated_at, COALESCE(signed_ark_tx, '') as signed_ark_tx, COALESCE(checkpoint_txs_json, '[]') as checkpoint_txs_json FROM offchain_txs WHERE id = $1",
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

    async fn get_all_finalized(&self) -> ArkResult<Vec<OffchainTx>> {
        debug!("Getting all finalized offchain txs (PG)");

        let rows = sqlx::query_as::<_, PgOffchainTxRow>(
            "SELECT id, stage, inputs_json, outputs_json, txid, rejection_reason, created_at, updated_at, COALESCE(signed_ark_tx, '') as signed_ark_tx, COALESCE(checkpoint_txs_json, '[]') as checkpoint_txs_json FROM offchain_txs WHERE stage = 'Finalized' ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        rows.into_iter().map(Self::row_to_offchain_tx).collect()
    }

    async fn get_pending(&self) -> ArkResult<Vec<OffchainTx>> {
        debug!("Getting pending offchain txs (PG)");

        let rows = sqlx::query_as::<_, PgOffchainTxRow>(
            "SELECT id, stage, inputs_json, outputs_json, txid, rejection_reason, created_at, updated_at, COALESCE(signed_ark_tx, '') as signed_ark_tx, COALESCE(checkpoint_txs_json, '[]') as checkpoint_txs_json FROM offchain_txs WHERE stage IN ('Requested', 'Accepted') ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        rows.into_iter().map(Self::row_to_offchain_tx).collect()
    }

    async fn update_stage(&self, id: &str, stage: &OffchainTxStage) -> ArkResult<()> {
        debug!(id = %id, stage = %stage, "Updating offchain tx stage (PG)");

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
            "UPDATE offchain_txs SET stage = $1, txid = COALESCE($2, txid), rejection_reason = COALESCE($3, rejection_reason), updated_at = $4 WHERE id = $5",
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

    async fn set_signed_ark_tx(&self, id: &str, signed_ark_tx: &str) -> ArkResult<()> {
        sqlx::query("UPDATE offchain_txs SET signed_ark_tx = $1 WHERE id = $2")
            .bind(signed_ark_tx)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn set_checkpoint_txs(&self, id: &str, checkpoint_txs: &[String]) -> ArkResult<()> {
        let json = serde_json::to_string(checkpoint_txs)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        sqlx::query("UPDATE offchain_txs SET checkpoint_txs_json = $1 WHERE id = $2")
            .bind(&json)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

impl PgOffchainTxRepository {
    /// List offchain transactions that reference a specific VTXO (not part of the trait).
    pub async fn list_by_vtxo(&self, vtxo_id: &str) -> ArkResult<Vec<OffchainTx>> {
        debug!(vtxo_id = %vtxo_id, "Listing offchain txs by VTXO (PG)");

        let pattern = format!("%\"{vtxo_id}\"%");
        let rows = sqlx::query_as::<_, PgOffchainTxRow>(
            "SELECT id, stage, inputs_json, outputs_json, txid, rejection_reason, created_at, updated_at, COALESCE(signed_ark_tx, '') as signed_ark_tx, COALESCE(checkpoint_txs_json, '[]') as checkpoint_txs_json FROM offchain_txs WHERE inputs_json LIKE $1 ORDER BY created_at ASC",
        )
        .bind(&pattern)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        rows.into_iter().map(Self::row_to_offchain_tx).collect()
    }
}
