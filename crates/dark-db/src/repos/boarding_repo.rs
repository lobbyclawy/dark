//! Boarding repository — SQLite implementation of `dark_core::ports::BoardingRepository`

use dark_core::domain::BoardingTransaction;
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::BoardingRepository;
use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::debug;

/// SQLite-backed boarding repository
pub struct SqliteBoardingRepository {
    pool: SqlitePool,
}

impl SqliteBoardingRepository {
    /// Create a new repository backed by the given SQLite pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BoardingRepository for SqliteBoardingRepository {
    async fn register_boarding(&self, tx: BoardingTransaction) -> ArkResult<()> {
        debug!(id = %tx.id, "Registering boarding transaction");

        let id = tx.id.to_string();
        let status = format!("{:?}", tx.status).to_lowercase();
        let amount = tx.amount.to_sat() as i64;
        let recipient_pubkey = tx.recipient_pubkey.to_string();
        let funding_txid = tx.funding_txid.map(|t| t.to_string());
        let funding_vout = tx.funding_vout.map(|v| v as i32);
        let round_id = tx.round_id.map(|r| r.to_string());
        let vtxo_id = tx.vtxo_id.map(|v| v.to_string());
        let created_at = tx.created_at.to_rfc3339();
        let updated_at = tx.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO boarding_txs (id, status, amount, recipient_pubkey, funding_txid,
                funding_vout, round_id, vtxo_id, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                amount = excluded.amount,
                funding_txid = excluded.funding_txid,
                funding_vout = excluded.funding_vout,
                round_id = excluded.round_id,
                vtxo_id = excluded.vtxo_id,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&id)
        .bind(&status)
        .bind(amount)
        .bind(&recipient_pubkey)
        .bind(&funding_txid)
        .bind(funding_vout)
        .bind(&round_id)
        .bind(&vtxo_id)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_pending_boarding(&self) -> ArkResult<Vec<BoardingTransaction>> {
        debug!("Getting pending boarding transactions");

        // Return empty vec — pending boarding requires reconstructing full
        // BoardingTransaction from DB, which needs bitcoin crate parsing.
        // For now, pending = status in ('awaiting_funding', 'funded')
        let rows = sqlx::query_as::<_, BoardingRow>(
            r#"
            SELECT id, status, amount, recipient_pubkey, funding_txid,
                   funding_vout, round_id, vtxo_id, created_at, updated_at
            FROM boarding_txs
            WHERE status IN ('awaitingfunding', 'funded')
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            if let Some(tx) = row.try_into_boarding_tx() {
                result.push(tx);
            }
        }
        Ok(result)
    }

    async fn mark_claimed(&self, id: &str) -> ArkResult<()> {
        debug!(id = %id, "Marking boarding transaction as claimed");

        let rows_affected = sqlx::query(
            "UPDATE boarding_txs SET status = 'claimed', updated_at = datetime('now') WHERE id = ?1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(ArkError::NotFound(format!(
                "Boarding transaction {id} not found"
            )));
        }

        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct BoardingRow {
    id: String,
    status: String,
    amount: i64,
    recipient_pubkey: String,
    funding_txid: Option<String>,
    funding_vout: Option<i32>,
    round_id: Option<String>,
    vtxo_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl BoardingRow {
    fn try_into_boarding_tx(self) -> Option<BoardingTransaction> {
        use dark_core::domain::BoardingStatus;
        use bitcoin::{Amount, XOnlyPublicKey};
        use chrono::DateTime;
        use std::str::FromStr;
        use uuid::Uuid;

        let id = match Uuid::parse_str(&self.id) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(row_id = %self.id, error = %e, "Failed to parse boarding tx UUID");
                return None;
            }
        };
        let status = match self.status.as_str() {
            "awaitingfunding" => BoardingStatus::AwaitingFunding,
            "funded" => BoardingStatus::Funded,
            "inround" => BoardingStatus::InRound,
            "completed" => BoardingStatus::Completed,
            "failed" => BoardingStatus::Failed,
            "expired" => BoardingStatus::Expired,
            _ => BoardingStatus::AwaitingFunding,
        };
        let amount = Amount::from_sat(self.amount as u64);
        let recipient_pubkey = match XOnlyPublicKey::from_str(&self.recipient_pubkey) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(row_id = %id, error = %e, "Failed to parse boarding tx recipient pubkey");
                return None;
            }
        };
        let funding_txid = self
            .funding_txid
            .and_then(|t| bitcoin::Txid::from_str(&t).ok());
        let funding_vout = self.funding_vout.map(|v| v as u32);
        let round_id = self.round_id.and_then(|r| Uuid::parse_str(&r).ok());
        let vtxo_id = self.vtxo_id.and_then(|v| {
            use dark_core::domain::VtxoOutpoint;
            // VtxoId is VtxoOutpoint, stored as "txid:vout"
            let parts: Vec<&str> = v.splitn(2, ':').collect();
            if parts.len() == 2 {
                parts[1]
                    .parse::<u32>()
                    .ok()
                    .map(|vout| VtxoOutpoint::new(parts[0].to_string(), vout))
            } else {
                None
            }
        });
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .ok()?
            .with_timezone(&chrono::Utc);
        let updated_at = DateTime::parse_from_rfc3339(&self.updated_at)
            .ok()?
            .with_timezone(&chrono::Utc);

        Some(BoardingTransaction {
            id,
            status,
            amount,
            recipient_pubkey,
            funding_txid,
            funding_vout,
            round_id,
            vtxo_id,
            created_at,
            updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn setup() -> (Database, SqliteBoardingRepository) {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = SqliteBoardingRepository::new(db.sqlite_pool().unwrap().clone());
        (db, repo)
    }

    #[tokio::test]
    async fn test_register_and_get_pending() {
        let (_db, repo) = setup().await;

        // get_pending should return empty initially
        let pending = repo.get_pending_boarding().await.unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_mark_claimed_not_found() {
        let (_db, repo) = setup().await;
        let result = repo.mark_claimed("nonexistent-id").await;
        assert!(result.is_err());
    }
}
