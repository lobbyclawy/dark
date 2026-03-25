//! Round repository — SQLite implementation of `dark_core::ports::RoundRepository`

use async_trait::async_trait;
use dark_core::domain::{
    ConfirmationStatus, ForfeitTx, Intent, Receiver, Round, RoundStage, RoundStats, Stage,
    TxTreeNode, Vtxo, VtxoOutpoint,
};
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::RoundRepository;
use sqlx::SqlitePool;
use std::collections::HashMap;
use tracing::debug;

/// SQLite-backed round repository
pub struct SqliteRoundRepository {
    pool: SqlitePool,
}

impl SqliteRoundRepository {
    /// Create a new repository backed by the given SQLite pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoundRepository for SqliteRoundRepository {
    async fn add_or_update_round(&self, round: &Round) -> ArkResult<()> {
        debug!(round_id = %round.id, "Upserting round");

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let stage_code = match round.stage.code {
            RoundStage::Undefined => 0i32,
            RoundStage::Registration => 1,
            RoundStage::Finalization => 2,
        };

        // Upsert the round itself
        sqlx::query(
            r#"
            INSERT INTO rounds (id, starting_timestamp, ending_timestamp, stage_code,
                stage_ended, stage_failed, commitment_txid, commitment_tx,
                connector_address, version, swept, vtxo_tree_expiration, fail_reason)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            ON CONFLICT(id) DO UPDATE SET
                starting_timestamp = excluded.starting_timestamp,
                ending_timestamp = excluded.ending_timestamp,
                stage_code = excluded.stage_code,
                stage_ended = excluded.stage_ended,
                stage_failed = excluded.stage_failed,
                commitment_txid = excluded.commitment_txid,
                commitment_tx = excluded.commitment_tx,
                connector_address = excluded.connector_address,
                version = excluded.version,
                swept = excluded.swept,
                vtxo_tree_expiration = excluded.vtxo_tree_expiration,
                fail_reason = excluded.fail_reason
            "#,
        )
        .bind(&round.id)
        .bind(round.starting_timestamp)
        .bind(round.ending_timestamp)
        .bind(stage_code)
        .bind(round.stage.ended)
        .bind(round.stage.failed)
        .bind(&round.commitment_txid)
        .bind(&round.commitment_tx)
        .bind(&round.connector_address)
        .bind(round.version as i32)
        .bind(round.swept)
        .bind(round.vtxo_tree_expiration)
        .bind(&round.fail_reason)
        .execute(&mut *tx)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        // Delete existing child data for upsert (idempotent)
        for table in &["round_txs", "round_sweep_txs"] {
            sqlx::query(&format!("DELETE FROM {} WHERE round_id = ?1", table))
                .bind(&round.id)
                .execute(&mut *tx)
                .await
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }

        // Delete intents and their receivers/vtxo_intents
        let intent_ids: Vec<String> =
            sqlx::query_as::<_, (String,)>("SELECT id FROM intents WHERE round_id = ?1")
                .bind(&round.id)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?
                .into_iter()
                .map(|r| r.0)
                .collect();

        for iid in &intent_ids {
            sqlx::query("DELETE FROM intent_receivers WHERE intent_id = ?1")
                .bind(iid)
                .execute(&mut *tx)
                .await
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
            sqlx::query("DELETE FROM vtxo_intents WHERE intent_id = ?1")
                .bind(iid)
                .execute(&mut *tx)
                .await
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }
        sqlx::query("DELETE FROM intents WHERE round_id = ?1")
            .bind(&round.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        // Insert forfeit txs
        for (pos, ftx) in round.forfeit_txs.iter().enumerate() {
            sqlx::query(
                "INSERT INTO round_txs (round_id, txid, tx, type, position) VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&round.id)
            .bind(&ftx.txid)
            .bind(&ftx.tx)
            .bind("forfeit")
            .bind(pos as i32)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }

        // Insert VTXO tree nodes
        for (pos, node) in round.vtxo_tree.iter().enumerate() {
            let children_json =
                serde_json::to_string(&node.children).unwrap_or_else(|_| "{}".to_string());
            sqlx::query(
                "INSERT INTO round_txs (round_id, txid, tx, type, position, children) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&round.id)
            .bind(&node.txid)
            .bind(&node.tx)
            .bind("vtxo_tree")
            .bind(pos as i32)
            .bind(&children_json)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }

        // Insert connector tree nodes
        for (pos, node) in round.connectors.iter().enumerate() {
            let children_json =
                serde_json::to_string(&node.children).unwrap_or_else(|_| "{}".to_string());
            sqlx::query(
                "INSERT INTO round_txs (round_id, txid, tx, type, position, children) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&round.id)
            .bind(&node.txid)
            .bind(&node.tx)
            .bind("connector")
            .bind(pos as i32)
            .bind(&children_json)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }

        // Insert sweep transactions
        for (stxid, stx) in &round.sweep_txs {
            sqlx::query("INSERT INTO round_sweep_txs (round_id, txid, tx) VALUES (?1, ?2, ?3)")
                .bind(&round.id)
                .bind(stxid)
                .bind(stx)
                .execute(&mut *tx)
                .await
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }

        // Insert intents
        for intent in round.intents.values() {
            let conf_status = match round.confirmation_status.get(&intent.id) {
                Some(ConfirmationStatus::Confirmed { confirmed_at }) => {
                    format!("confirmed:{confirmed_at}")
                }
                Some(ConfirmationStatus::TimedOut) => "timed_out".to_string(),
                _ => "pending".to_string(),
            };

            sqlx::query(
                r#"
                INSERT INTO intents (id, round_id, proof, message, txid, leaf_tx_asset_packet, confirmation_status)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
            )
            .bind(&intent.id)
            .bind(&round.id)
            .bind(&intent.proof)
            .bind(&intent.message)
            .bind(&intent.txid)
            .bind(&intent.leaf_tx_asset_packet)
            .bind(&conf_status)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

            // Insert receivers
            for recv in &intent.receivers {
                sqlx::query(
                    r#"
                    INSERT INTO intent_receivers (intent_id, amount, onchain_address, pubkey)
                    VALUES (?1, ?2, ?3, ?4)
                    "#,
                )
                .bind(&intent.id)
                .bind(recv.amount as i64)
                .bind(&recv.onchain_address)
                .bind(&recv.pubkey)
                .execute(&mut *tx)
                .await
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
            }

            // Insert VTXO-intent associations (only for inputs that exist
            // in the vtxos table — boarding inputs are on-chain UTXOs and
            // don't have a corresponding VTXO row, so skip them to avoid
            // FOREIGN KEY constraint failures).
            for input in &intent.inputs {
                let vtxo_exists: bool = sqlx::query_scalar::<_, i32>(
                    "SELECT COUNT(*) FROM vtxos WHERE txid = ?1 AND vout = ?2",
                )
                .bind(&input.outpoint.txid)
                .bind(input.outpoint.vout as i32)
                .fetch_one(&mut *tx)
                .await
                .map(|c| c > 0)
                .unwrap_or(false);

                if vtxo_exists {
                    sqlx::query(
                        "INSERT INTO vtxo_intents (vtxo_txid, vtxo_vout, intent_id) VALUES (?1, ?2, ?3)",
                    )
                    .bind(&input.outpoint.txid)
                    .bind(input.outpoint.vout as i32)
                    .bind(&intent.id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
                }
            }
        }

        tx.commit()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_round_with_id(&self, id: &str) -> ArkResult<Option<Round>> {
        debug!(round_id = %id, "Fetching round");

        let row = sqlx::query_as::<_, RoundRow>(
            r#"
            SELECT id, starting_timestamp, ending_timestamp, stage_code,
                   stage_ended, stage_failed, commitment_txid, commitment_tx,
                   connector_address, version, swept, vtxo_tree_expiration, fail_reason
            FROM rounds WHERE id = ?1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        // Load round_txs
        let tx_rows = sqlx::query_as::<_, RoundTxRow>(
            "SELECT txid, tx, type, position, children FROM round_txs WHERE round_id = ?1 ORDER BY position",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut forfeit_txs = Vec::new();
        let mut vtxo_tree = Vec::new();
        let mut connectors = Vec::new();

        for tr in tx_rows {
            match tr.tx_type.as_str() {
                "forfeit" => {
                    forfeit_txs.push(ForfeitTx {
                        txid: tr.txid,
                        tx: tr.tx,
                    });
                }
                "vtxo_tree" => {
                    let children: HashMap<u32, String> =
                        serde_json::from_str(&tr.children).unwrap_or_default();
                    vtxo_tree.push(TxTreeNode {
                        txid: tr.txid,
                        tx: tr.tx,
                        children,
                    });
                }
                "connector" => {
                    let children: HashMap<u32, String> =
                        serde_json::from_str(&tr.children).unwrap_or_default();
                    connectors.push(TxTreeNode {
                        txid: tr.txid,
                        tx: tr.tx,
                        children,
                    });
                }
                _ => {}
            }
        }

        // Load sweep txs
        let sweep_rows = sqlx::query_as::<_, SweepTxRow>(
            "SELECT txid, tx FROM round_sweep_txs WHERE round_id = ?1",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let sweep_txs: HashMap<String, String> =
            sweep_rows.into_iter().map(|r| (r.txid, r.tx)).collect();

        // Load intents
        let intent_rows = sqlx::query_as::<_, IntentRow>(
            "SELECT id, proof, message, txid, leaf_tx_asset_packet, confirmation_status FROM intents WHERE round_id = ?1",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut intents = HashMap::new();
        let mut confirmation_status_map = HashMap::new();
        for irow in intent_rows {
            let receivers = sqlx::query_as::<_, ReceiverRow>(
                "SELECT amount, onchain_address, pubkey FROM intent_receivers WHERE intent_id = ?1",
            )
            .bind(&irow.id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

            // Load input vtxo outpoints for this intent
            let input_rows = sqlx::query_as::<_, VtxoIntentRow>(
                "SELECT vtxo_txid, vtxo_vout FROM vtxo_intents WHERE intent_id = ?1",
            )
            .bind(&irow.id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

            let inputs: Vec<Vtxo> = input_rows
                .into_iter()
                .map(|r| {
                    Vtxo::new(
                        VtxoOutpoint::new(r.vtxo_txid, r.vtxo_vout as u32),
                        0,
                        String::new(),
                    )
                })
                .collect();

            // Parse confirmation status
            let conf_status = parse_confirmation_status(&irow.confirmation_status);

            let intent = Intent {
                id: irow.id.clone(),
                inputs,
                receivers: receivers
                    .into_iter()
                    .map(|r| Receiver {
                        amount: r.amount as u64,
                        onchain_address: r.onchain_address,
                        pubkey: r.pubkey,
                    })
                    .collect(),
                proof: irow.proof,
                message: irow.message,
                txid: irow.txid,
                leaf_tx_asset_packet: irow.leaf_tx_asset_packet,
                cosigners_public_keys: Vec::new(),
                delegate_pubkey: None,
            };
            confirmation_status_map.insert(intent.id.clone(), conf_status);
            intents.insert(intent.id.clone(), intent);
        }

        let stage_code = match row.stage_code {
            1 => RoundStage::Registration,
            2 => RoundStage::Finalization,
            _ => RoundStage::Undefined,
        };

        let round = Round {
            id: row.id,
            starting_timestamp: row.starting_timestamp,
            ending_timestamp: row.ending_timestamp,
            stage: Stage {
                code: stage_code,
                ended: row.stage_ended,
                failed: row.stage_failed,
                entered_at: None, // Not stored in DB; only needed for runtime timeout tracking
            },
            intents,
            commitment_txid: row.commitment_txid,
            commitment_tx: row.commitment_tx,
            forfeit_txs,
            vtxo_tree,
            connectors,
            connector_address: row.connector_address,
            version: row.version as u32,
            swept: row.swept,
            vtxo_tree_expiration: row.vtxo_tree_expiration,
            sweep_txs,
            fail_reason: row.fail_reason,
            confirmation_status: confirmation_status_map,
            has_boarding_inputs: false, // Not persisted; only needed during live round processing
        };

        Ok(Some(round))
    }

    async fn get_round_stats(&self, commitment_txid: &str) -> ArkResult<Option<RoundStats>> {
        debug!(commitment_txid = %commitment_txid, "Getting round stats");

        let row = sqlx::query_as::<_, RoundRow>(
            r#"
            SELECT id, starting_timestamp, ending_timestamp, stage_code,
                   stage_ended, stage_failed, commitment_txid, commitment_tx,
                   connector_address, version, swept, vtxo_tree_expiration, fail_reason
            FROM rounds WHERE commitment_txid = ?1
            "#,
        )
        .bind(commitment_txid)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        // Count input/output vtxos via intents
        let intent_rows = sqlx::query_as::<_, IntentRow>(
            "SELECT id, proof, message, txid, leaf_tx_asset_packet, confirmation_status FROM intents WHERE round_id = ?1",
        )
        .bind(&row.id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut total_input_vtxos: i32 = 0;
        let mut total_output_vtxos: i32 = 0;
        let mut total_batch_amount: u64 = 0;

        for irow in &intent_rows {
            let input_count = sqlx::query_as::<_, (i32,)>(
                "SELECT COUNT(*) FROM vtxo_intents WHERE intent_id = ?1",
            )
            .bind(&irow.id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
            total_input_vtxos += input_count.0;

            let receivers = sqlx::query_as::<_, ReceiverRow>(
                "SELECT amount, onchain_address, pubkey FROM intent_receivers WHERE intent_id = ?1",
            )
            .bind(&irow.id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

            for r in &receivers {
                total_batch_amount += r.amount as u64;
                if r.onchain_address.is_empty() {
                    total_output_vtxos += 1;
                }
            }
        }

        // Count forfeit txs as a rough proxy for forfeit amount
        let forfeit_count = sqlx::query_as::<_, (i32,)>(
            "SELECT COUNT(*) FROM round_txs WHERE round_id = ?1 AND type = 'forfeit'",
        )
        .bind(&row.id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        let total_forfeit_amount = forfeit_count.0 as u64;

        Ok(Some(RoundStats {
            swept: row.swept,
            total_forfeit_amount,
            total_input_vtxos,
            total_batch_amount,
            total_output_vtxos,
            expires_at: row.vtxo_tree_expiration,
            started: row.starting_timestamp,
            ended: row.ending_timestamp,
        }))
    }

    async fn get_round_by_commitment_txid(&self, txid: &str) -> ArkResult<Option<Round>> {
        debug!(commitment_txid = %txid, "Fetching round by commitment txid");

        // Look up the round id by commitment_txid, then delegate to get_round_with_id
        // which already loads all associated data (forfeit txs, vtxo tree, etc.).
        let maybe_id =
            sqlx::query_scalar::<_, String>("SELECT id FROM rounds WHERE commitment_txid = ?1")
                .bind(txid)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        match maybe_id {
            Some(id) => self.get_round_with_id(&id).await,
            None => Ok(None),
        }
    }

    async fn confirm_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<()> {
        debug!(round_id = %round_id, intent_id = %intent_id, "Confirming intent");

        let now = chrono::Utc::now().timestamp() as u64;
        let status = format!("confirmed:{now}");

        let result = sqlx::query(
            "UPDATE intents SET confirmation_status = ?1 WHERE round_id = ?2 AND id = ?3 AND confirmation_status = 'pending'",
        )
        .bind(&status)
        .bind(round_id)
        .bind(intent_id)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ArkError::Internal(format!(
                "Intent {intent_id} not found or not pending in round {round_id}"
            )));
        }

        Ok(())
    }

    async fn get_pending_confirmations(&self, round_id: &str) -> ArkResult<Vec<String>> {
        debug!(round_id = %round_id, "Getting pending confirmations");

        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT id FROM intents WHERE round_id = ?1 AND confirmation_status = 'pending'",
        )
        .bind(round_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_rounds(&self, offset: u32, limit: u32) -> ArkResult<Vec<Round>> {
        debug!(offset, limit, "Listing rounds with pagination");

        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT id FROM rounds
            ORDER BY starting_timestamp DESC
            LIMIT ?1 OFFSET ?2
            "#,
        )
        .bind(limit as i32)
        .bind(offset as i32)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut rounds = Vec::with_capacity(rows.len());
        for (id,) in rows {
            if let Some(round) = self.get_round_with_id(&id).await? {
                rounds.push(round);
            }
        }

        Ok(rounds)
    }

    async fn count_rounds(&self) -> ArkResult<u64> {
        debug!("Counting total rounds");

        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM rounds")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(count as u64)
    }
}

// ─── Row types ──────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct RoundRow {
    id: String,
    starting_timestamp: i64,
    ending_timestamp: i64,
    stage_code: i32,
    stage_ended: bool,
    stage_failed: bool,
    commitment_txid: String,
    commitment_tx: String,
    connector_address: String,
    version: i32,
    swept: bool,
    vtxo_tree_expiration: i64,
    fail_reason: String,
}

#[derive(Debug, sqlx::FromRow)]
struct RoundTxRow {
    txid: String,
    tx: String,
    #[sqlx(rename = "type")]
    tx_type: String,
    #[allow(dead_code)]
    position: i32,
    children: String,
}

#[derive(Debug, sqlx::FromRow)]
struct SweepTxRow {
    txid: String,
    tx: String,
}

#[derive(Debug, sqlx::FromRow)]
struct IntentRow {
    id: String,
    proof: String,
    message: String,
    txid: String,
    leaf_tx_asset_packet: String,
    confirmation_status: String,
}

/// Parse the confirmation_status string from the DB into a ConfirmationStatus enum
fn parse_confirmation_status(s: &str) -> ConfirmationStatus {
    if s.starts_with("confirmed:") {
        let ts_str = s.strip_prefix("confirmed:").unwrap_or("0");
        let ts = ts_str.parse::<u64>().unwrap_or(0);
        ConfirmationStatus::Confirmed { confirmed_at: ts }
    } else if s == "timed_out" {
        ConfirmationStatus::TimedOut
    } else {
        ConfirmationStatus::Pending
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ReceiverRow {
    amount: i64,
    onchain_address: String,
    pubkey: String,
}

#[derive(Debug, sqlx::FromRow)]
struct VtxoIntentRow {
    vtxo_txid: String,
    vtxo_vout: i32,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use dark_core::domain::{ForfeitTx, TxTreeNode};

    async fn setup() -> (Database, SqliteRoundRepository) {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = SqliteRoundRepository::new(db.sqlite_pool().unwrap().clone());
        (db, repo)
    }

    fn make_round(id: &str) -> Round {
        let mut round = Round::new();
        round.id = id.to_string();
        round.starting_timestamp = 1700000000;
        round
    }

    #[tokio::test]
    async fn test_add_and_get_round() {
        let (_db, repo) = setup().await;

        let mut round = make_round("round-1");
        round.start_registration().unwrap();
        round.commitment_txid = "ctxid-1".to_string();
        round.connector_address = "bc1qaddr".to_string();

        repo.add_or_update_round(&round).await.unwrap();

        let fetched = repo.get_round_with_id("round-1").await.unwrap().unwrap();
        assert_eq!(fetched.id, "round-1");
        assert_eq!(fetched.commitment_txid, "ctxid-1");
        assert_eq!(fetched.connector_address, "bc1qaddr");
        assert_eq!(fetched.stage.code, RoundStage::Registration);
        assert!(!fetched.stage.ended);
    }

    #[tokio::test]
    async fn test_round_not_found() {
        let (_db, repo) = setup().await;

        let result = repo.get_round_with_id("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_round_upsert() {
        let (_db, repo) = setup().await;

        let mut round = make_round("round-u");
        round.start_registration().unwrap();
        repo.add_or_update_round(&round).await.unwrap();

        // Update the round
        round.start_finalization().unwrap();
        round.commitment_txid = "updated-txid".to_string();
        repo.add_or_update_round(&round).await.unwrap();

        let fetched = repo.get_round_with_id("round-u").await.unwrap().unwrap();
        assert_eq!(fetched.stage.code, RoundStage::Finalization);
        assert_eq!(fetched.commitment_txid, "updated-txid");
    }

    #[tokio::test]
    async fn test_round_with_forfeit_txs() {
        let (_db, repo) = setup().await;

        let mut round = make_round("round-f");
        round.start_registration().unwrap();
        round.forfeit_txs = vec![
            ForfeitTx {
                txid: "ftx1".to_string(),
                tx: "raw1".to_string(),
            },
            ForfeitTx {
                txid: "ftx2".to_string(),
                tx: "raw2".to_string(),
            },
        ];
        repo.add_or_update_round(&round).await.unwrap();

        let fetched = repo.get_round_with_id("round-f").await.unwrap().unwrap();
        assert_eq!(fetched.forfeit_txs.len(), 2);
        assert_eq!(fetched.forfeit_txs[0].txid, "ftx1");
    }

    #[tokio::test]
    async fn test_round_with_vtxo_tree() {
        let (_db, repo) = setup().await;

        let mut round = make_round("round-t");
        round.start_registration().unwrap();
        let mut children = HashMap::new();
        children.insert(0, "child-txid".to_string());
        round.vtxo_tree = vec![TxTreeNode {
            txid: "tree-root".to_string(),
            tx: "psbt-data".to_string(),
            children,
        }];
        repo.add_or_update_round(&round).await.unwrap();

        let fetched = repo.get_round_with_id("round-t").await.unwrap().unwrap();
        assert_eq!(fetched.vtxo_tree.len(), 1);
        assert_eq!(fetched.vtxo_tree[0].txid, "tree-root");
        assert_eq!(fetched.vtxo_tree[0].children.get(&0).unwrap(), "child-txid");
    }

    #[tokio::test]
    async fn test_round_with_sweep_txs() {
        let (_db, repo) = setup().await;

        let mut round = make_round("round-s");
        round.start_registration().unwrap();
        round
            .sweep_txs
            .insert("sweep-txid".to_string(), "sweep-raw".to_string());
        repo.add_or_update_round(&round).await.unwrap();

        let fetched = repo.get_round_with_id("round-s").await.unwrap().unwrap();
        assert_eq!(fetched.sweep_txs.len(), 1);
        assert_eq!(fetched.sweep_txs.get("sweep-txid").unwrap(), "sweep-raw");
    }

    #[tokio::test]
    async fn test_round_with_intents() {
        let (_db, repo) = setup().await;

        let mut round = make_round("round-i");
        round.start_registration().unwrap();

        let intent = Intent {
            id: "intent-1".to_string(),
            inputs: vec![],
            receivers: vec![
                Receiver::offchain(50_000, "pk_recv".to_string()),
                Receiver::onchain(30_000, "bc1qaddr".to_string()),
            ],
            proof: "proof-data".to_string(),
            message: "msg".to_string(),
            txid: "proof-txid".to_string(),
            leaf_tx_asset_packet: String::new(),
            cosigners_public_keys: Vec::new(),
            delegate_pubkey: None,
        };
        round.intents.insert(intent.id.clone(), intent);

        repo.add_or_update_round(&round).await.unwrap();

        let fetched = repo.get_round_with_id("round-i").await.unwrap().unwrap();
        assert_eq!(fetched.intents.len(), 1);
        let fi = fetched.intents.get("intent-1").unwrap();
        assert_eq!(fi.receivers.len(), 2);
        assert_eq!(fi.proof, "proof-data");
    }

    #[tokio::test]
    async fn test_round_failed() {
        let (_db, repo) = setup().await;

        let mut round = make_round("round-fail");
        round.start_registration().unwrap();
        round.fail("insufficient liquidity".to_string());
        repo.add_or_update_round(&round).await.unwrap();

        let fetched = repo.get_round_with_id("round-fail").await.unwrap().unwrap();
        assert!(fetched.stage.failed);
        assert_eq!(fetched.fail_reason, "insufficient liquidity");
    }

    #[tokio::test]
    async fn test_get_round_stats() {
        let (_db, repo) = setup().await;

        let mut round = make_round("round-stats");
        round.start_registration().unwrap();
        // Override the timestamp set by start_registration() to a deterministic value
        round.starting_timestamp = 1700000000;
        round.commitment_txid = "stats-ctxid".to_string();
        round.vtxo_tree_expiration = 1700604800;

        let intent = Intent {
            id: "si-1".to_string(),
            inputs: vec![],
            receivers: vec![Receiver::offchain(100_000, "pk1".to_string())],
            proof: "p".to_string(),
            message: "m".to_string(),
            txid: "t".to_string(),
            leaf_tx_asset_packet: String::new(),
            cosigners_public_keys: Vec::new(),
            delegate_pubkey: None,
        };
        round.intents.insert(intent.id.clone(), intent);

        repo.add_or_update_round(&round).await.unwrap();

        let stats = repo.get_round_stats("stats-ctxid").await.unwrap().unwrap();
        assert_eq!(stats.expires_at, 1700604800);
        assert_eq!(stats.started, 1700000000);
        assert_eq!(stats.total_output_vtxos, 1);
        assert_eq!(stats.total_batch_amount, 100_000);
    }

    #[tokio::test]
    async fn test_get_round_stats_not_found() {
        let (_db, repo) = setup().await;

        let result = repo.get_round_stats("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_rounds_pagination() {
        let (_db, repo) = setup().await;

        // Create several rounds with different timestamps.
        // Set timestamp AFTER start_registration() since it overwrites starting_timestamp.
        for i in 0..5 {
            let mut round = make_round(&format!("round-{i}"));
            round.start_registration().unwrap();
            round.starting_timestamp = 1700000000 + (i as i64 * 100);
            repo.add_or_update_round(&round).await.unwrap();
        }

        // List first 2 rounds (should be the newest)
        let page1 = repo.list_rounds(0, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].id, "round-4"); // newest first
        assert_eq!(page1[1].id, "round-3");

        // List next 2 rounds
        let page2 = repo.list_rounds(2, 2).await.unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].id, "round-2");
        assert_eq!(page2[1].id, "round-1");

        // List remaining
        let page3 = repo.list_rounds(4, 2).await.unwrap();
        assert_eq!(page3.len(), 1);
        assert_eq!(page3[0].id, "round-0");
    }

    #[tokio::test]
    async fn test_count_rounds() {
        let (_db, repo) = setup().await;

        // Initially no rounds
        let count = repo.count_rounds().await.unwrap();
        assert_eq!(count, 0);

        // Add some rounds
        for i in 0..3 {
            let mut round = make_round(&format!("round-{i}"));
            round.start_registration().unwrap();
            repo.add_or_update_round(&round).await.unwrap();
        }

        let count = repo.count_rounds().await.unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_list_rounds_empty() {
        let (_db, repo) = setup().await;

        let rounds = repo.list_rounds(0, 10).await.unwrap();
        assert!(rounds.is_empty());
    }
}
