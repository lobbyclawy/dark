//! VTXO repository — SQLite implementation of `dark_core::ports::VtxoRepository`

use async_trait::async_trait;
use dark_core::domain::{Vtxo, VtxoOutpoint};
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::VtxoRepository;
use sqlx::SqlitePool;
use tracing::debug;
use tracing::info;

/// SQLite-backed VTXO repository
pub struct SqliteVtxoRepository {
    pool: SqlitePool,
}

impl SqliteVtxoRepository {
    /// Create a new repository backed by the given SQLite pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl VtxoRepository for SqliteVtxoRepository {
    async fn add_vtxos(&self, vtxos: &[Vtxo]) -> ArkResult<()> {
        debug!(count = vtxos.len(), "Adding VTXOs");

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        for vtxo in vtxos {
            let settled_by = if vtxo.settled_by.is_empty() {
                None
            } else {
                Some(vtxo.settled_by.as_str())
            };
            let spent_by = if vtxo.spent_by.is_empty() {
                None
            } else {
                Some(vtxo.spent_by.as_str())
            };
            let ark_txid = if vtxo.ark_txid.is_empty() {
                None
            } else {
                Some(vtxo.ark_txid.as_str())
            };

            sqlx::query(
                r#"
                INSERT INTO vtxos (txid, vout, pubkey, amount, root_commitment_txid,
                    settled_by, spent_by, ark_txid, spent, unrolled, swept,
                    preconfirmed, expires_at, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                ON CONFLICT(txid, vout) DO UPDATE SET
                    pubkey = excluded.pubkey,
                    amount = excluded.amount,
                    root_commitment_txid = excluded.root_commitment_txid,
                    settled_by = excluded.settled_by,
                    spent_by = excluded.spent_by,
                    ark_txid = excluded.ark_txid,
                    spent = excluded.spent,
                    unrolled = excluded.unrolled,
                    swept = excluded.swept,
                    preconfirmed = excluded.preconfirmed,
                    expires_at = excluded.expires_at
                "#,
            )
            .bind(&vtxo.outpoint.txid)
            .bind(vtxo.outpoint.vout as i32)
            .bind(&vtxo.pubkey)
            .bind(vtxo.amount as i64)
            .bind(&vtxo.root_commitment_txid)
            .bind(settled_by)
            .bind(spent_by)
            .bind(ark_txid)
            .bind(vtxo.spent)
            .bind(vtxo.unrolled)
            .bind(vtxo.swept)
            .bind(vtxo.preconfirmed)
            .bind(vtxo.expires_at)
            .bind(vtxo.created_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

            // Insert commitment txids
            // First remove old ones for upsert semantics
            sqlx::query(
                "DELETE FROM vtxo_commitment_txids WHERE vtxo_txid = ?1 AND vtxo_vout = ?2",
            )
            .bind(&vtxo.outpoint.txid)
            .bind(vtxo.outpoint.vout as i32)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

            for (pos, ctxid) in vtxo.commitment_txids.iter().enumerate() {
                sqlx::query(
                    r#"
                    INSERT INTO vtxo_commitment_txids (vtxo_txid, vtxo_vout, commitment_txid, position)
                    VALUES (?1, ?2, ?3, ?4)
                    "#,
                )
                .bind(&vtxo.outpoint.txid)
                .bind(vtxo.outpoint.vout as i32)
                .bind(ctxid)
                .bind(pos as i32)
                .execute(&mut *tx)
                .await
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_vtxos(&self, outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
        debug!(count = outpoints.len(), "Getting VTXOs by outpoints");

        let mut result = Vec::with_capacity(outpoints.len());

        for op in outpoints {
            let row = sqlx::query_as::<_, VtxoRow>(
                r#"
                SELECT txid, vout, pubkey, amount, root_commitment_txid,
                       settled_by, spent_by, ark_txid, spent, unrolled, swept,
                       preconfirmed, expires_at, created_at
                FROM vtxos
                WHERE txid = ?1 AND vout = ?2
                "#,
            )
            .bind(&op.txid)
            .bind(op.vout as i32)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

            if let Some(row) = row {
                let commitment_txids = self.get_commitment_txids(&op.txid, op.vout).await?;
                result.push(row.into_vtxo(commitment_txids));
            }
        }

        Ok(result)
    }

    async fn get_all_vtxos_for_pubkey(&self, pubkey: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
        info!(pubkey = %pubkey, "Getting all VTXOs for pubkey");

        // Debug: count total vtxos in DB
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vtxos")
            .fetch_one(&self.pool)
            .await
            .unwrap_or((0,));
        info!(total_vtxos = total.0, "Total VTXOs in database");

        // Debug: list all pubkeys in DB
        let all_pks: Vec<(String,)> = sqlx::query_as("SELECT DISTINCT pubkey FROM vtxos")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
        let pk_list: Vec<&str> = all_pks.iter().map(|r| r.0.as_str()).collect();
        info!(stored_pubkeys = ?pk_list, "Pubkeys in VTXO store");

        let rows = sqlx::query_as::<_, VtxoRow>(
            r#"
            SELECT txid, vout, pubkey, amount, root_commitment_txid,
                   settled_by, spent_by, ark_txid, spent, unrolled, swept,
                   preconfirmed, expires_at, created_at
            FROM vtxos
            WHERE pubkey = ?1 AND unrolled = FALSE
            "#,
        )
        .bind(pubkey)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut spendable = Vec::new();
        let mut spent = Vec::new();

        for row in rows {
            let commitment_txids = self
                .get_commitment_txids(&row.txid, row.vout as u32)
                .await?;
            let vtxo = row.into_vtxo(commitment_txids);
            if vtxo.spent || vtxo.swept {
                spent.push(vtxo);
            } else {
                spendable.push(vtxo);
            }
        }

        Ok((spendable, spent))
    }

    async fn spend_vtxos(&self, spent: &[(VtxoOutpoint, String)], ark_txid: &str) -> ArkResult<()> {
        debug!(count = spent.len(), ark_txid = %ark_txid, "Spending VTXOs");

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        for (outpoint, spent_by) in spent {
            let rows_affected = sqlx::query(
                r#"
                UPDATE vtxos
                SET spent = TRUE, spent_by = ?1, ark_txid = ?2
                WHERE txid = ?3 AND vout = ?4
                "#,
            )
            .bind(spent_by)
            .bind(ark_txid)
            .bind(&outpoint.txid)
            .bind(outpoint.vout as i32)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?
            .rows_affected();

            if rows_affected == 0 {
                return Err(ArkError::VtxoNotFound(outpoint.to_string()));
            }
        }

        tx.commit()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn find_expired_vtxos(&self, before_timestamp: i64) -> ArkResult<Vec<Vtxo>> {
        debug!(before_timestamp, "Finding expired VTXOs for sweep");

        let rows = sqlx::query_as::<_, VtxoRow>(
            r#"
            SELECT txid, vout, pubkey, amount, root_commitment_txid,
                   settled_by, spent_by, ark_txid, spent, unrolled, swept,
                   preconfirmed, expires_at, created_at
            FROM vtxos
            WHERE expires_at > 0
              AND expires_at < ?1
              AND spent = FALSE
              AND swept = FALSE
              AND unrolled = FALSE
            "#,
        )
        .bind(before_timestamp)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut vtxos = Vec::with_capacity(rows.len());
        for row in rows {
            let commitment_txids = self
                .get_commitment_txids(&row.txid, row.vout as u32)
                .await?;
            vtxos.push(row.into_vtxo(commitment_txids));
        }

        Ok(vtxos)
    }

    async fn list_all(&self) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
        debug!("Listing all VTXOs");

        let rows = sqlx::query_as::<_, VtxoRow>(
            r#"
            SELECT txid, vout, pubkey, amount, root_commitment_txid,
                   settled_by, spent_by, ark_txid, spent, unrolled, swept,
                   preconfirmed, expires_at, created_at
            FROM vtxos
            WHERE unrolled = FALSE
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut spendable = Vec::new();
        let mut spent = Vec::new();

        for row in rows {
            let commitment_txids = self
                .get_commitment_txids(&row.txid, row.vout as u32)
                .await?;
            let vtxo = row.into_vtxo(commitment_txids);
            if vtxo.spent || vtxo.swept {
                spent.push(vtxo);
            } else {
                spendable.push(vtxo);
            }
        }

        Ok((spendable, spent))
    }
}

impl SqliteVtxoRepository {
    /// Fetch the commitment txid chain for a VTXO
    async fn get_commitment_txids(&self, txid: &str, vout: u32) -> ArkResult<Vec<String>> {
        let rows = sqlx::query_as::<_, CommitmentTxidRow>(
            r#"
            SELECT commitment_txid, position
            FROM vtxo_commitment_txids
            WHERE vtxo_txid = ?1 AND vtxo_vout = ?2
            ORDER BY position ASC
            "#,
        )
        .bind(txid)
        .bind(vout as i32)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.commitment_txid).collect())
    }
}

/// Row type for reading VTXOs from the database
#[derive(Debug, sqlx::FromRow)]
struct VtxoRow {
    txid: String,
    vout: i32,
    pubkey: String,
    amount: i64,
    root_commitment_txid: String,
    settled_by: Option<String>,
    spent_by: Option<String>,
    ark_txid: Option<String>,
    spent: bool,
    unrolled: bool,
    swept: bool,
    preconfirmed: bool,
    expires_at: i64,
    created_at: i64,
}

impl VtxoRow {
    fn into_vtxo(self, commitment_txids: Vec<String>) -> Vtxo {
        Vtxo {
            outpoint: VtxoOutpoint::new(self.txid, self.vout as u32),
            amount: self.amount as u64,
            pubkey: self.pubkey,
            commitment_txids,
            root_commitment_txid: self.root_commitment_txid,
            settled_by: self.settled_by.unwrap_or_default(),
            spent_by: self.spent_by.unwrap_or_default(),
            ark_txid: self.ark_txid.unwrap_or_default(),
            spent: self.spent,
            unrolled: self.unrolled,
            swept: self.swept,
            preconfirmed: self.preconfirmed,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct CommitmentTxidRow {
    commitment_txid: String,
    #[allow(dead_code)]
    position: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn setup() -> (Database, SqliteVtxoRepository) {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = SqliteVtxoRepository::new(db.sqlite_pool().unwrap().clone());
        (db, repo)
    }

    fn make_vtxo(txid: &str, vout: u32, pubkey: &str, amount: u64) -> Vtxo {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new(txid.to_string(), vout),
            amount,
            pubkey.to_string(),
        );
        vtxo.expires_at = 1700000000;
        vtxo.created_at = 1699000000;
        vtxo
    }

    #[tokio::test]
    async fn test_add_and_get_vtxos() {
        let (_db, repo) = setup().await;

        let vtxo = make_vtxo("abc123", 0, "pubkey1", 100_000);
        repo.add_vtxos(std::slice::from_ref(&vtxo)).await.unwrap();

        let outpoints = vec![VtxoOutpoint::new("abc123".to_string(), 0)];
        let result = repo.get_vtxos(&outpoints).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].amount, 100_000);
        assert_eq!(result[0].pubkey, "pubkey1");
        assert_eq!(result[0].expires_at, 1700000000);
    }

    #[tokio::test]
    async fn test_add_vtxos_with_commitment_chain() {
        let (_db, repo) = setup().await;

        let mut vtxo = make_vtxo("tx1", 0, "pk1", 50_000);
        vtxo.commitment_txids = vec!["ctxid1".to_string(), "ctxid2".to_string()];
        vtxo.root_commitment_txid = "ctxid1".to_string();
        repo.add_vtxos(&[vtxo]).await.unwrap();

        let result = repo
            .get_vtxos(&[VtxoOutpoint::new("tx1".to_string(), 0)])
            .await
            .unwrap();
        assert_eq!(result[0].commitment_txids.len(), 2);
        assert_eq!(result[0].commitment_txids[0], "ctxid1");
        assert_eq!(result[0].commitment_txids[1], "ctxid2");
    }

    #[tokio::test]
    async fn test_upsert_vtxos() {
        let (_db, repo) = setup().await;

        let vtxo = make_vtxo("tx1", 0, "pk1", 50_000);
        repo.add_vtxos(&[vtxo]).await.unwrap();

        // Upsert with changed amount
        let mut vtxo2 = make_vtxo("tx1", 0, "pk1", 75_000);
        vtxo2.preconfirmed = true;
        repo.add_vtxos(&[vtxo2]).await.unwrap();

        let result = repo
            .get_vtxos(&[VtxoOutpoint::new("tx1".to_string(), 0)])
            .await
            .unwrap();
        assert_eq!(result[0].amount, 75_000);
        assert!(result[0].preconfirmed);
    }

    #[tokio::test]
    async fn test_get_vtxos_nonexistent() {
        let (_db, repo) = setup().await;

        let result = repo
            .get_vtxos(&[VtxoOutpoint::new("nonexistent".to_string(), 0)])
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_get_all_vtxos_for_pubkey() {
        let (_db, repo) = setup().await;

        let v1 = make_vtxo("tx1", 0, "pk_alice", 100_000);
        let v2 = make_vtxo("tx2", 0, "pk_alice", 200_000);
        let mut v3 = make_vtxo("tx3", 0, "pk_alice", 50_000);
        v3.spent = true;
        v3.spent_by = "forfeit_tx".to_string();
        let v4 = make_vtxo("tx4", 0, "pk_bob", 300_000);

        repo.add_vtxos(&[v1, v2, v3, v4]).await.unwrap();

        let (spendable, spent) = repo.get_all_vtxos_for_pubkey("pk_alice").await.unwrap();
        assert_eq!(spendable.len(), 2);
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0].outpoint.txid, "tx3");
    }

    #[tokio::test]
    async fn test_spend_vtxos() {
        let (_db, repo) = setup().await;

        let v1 = make_vtxo("tx1", 0, "pk1", 100_000);
        let v2 = make_vtxo("tx2", 1, "pk1", 200_000);
        repo.add_vtxos(&[v1, v2]).await.unwrap();

        let spend_list = vec![
            (
                VtxoOutpoint::new("tx1".to_string(), 0),
                "forfeit1".to_string(),
            ),
            (
                VtxoOutpoint::new("tx2".to_string(), 1),
                "forfeit2".to_string(),
            ),
        ];
        repo.spend_vtxos(&spend_list, "ark_tx_abc").await.unwrap();

        let result = repo
            .get_vtxos(&[
                VtxoOutpoint::new("tx1".to_string(), 0),
                VtxoOutpoint::new("tx2".to_string(), 1),
            ])
            .await
            .unwrap();

        assert!(result[0].spent);
        assert_eq!(result[0].spent_by, "forfeit1");
        assert_eq!(result[0].ark_txid, "ark_tx_abc");
        assert!(result[1].spent);
    }

    #[tokio::test]
    async fn test_spend_vtxo_not_found() {
        let (_db, repo) = setup().await;

        let result = repo
            .spend_vtxos(
                &[(
                    VtxoOutpoint::new("nonexistent".to_string(), 0),
                    "x".to_string(),
                )],
                "ark",
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_swept_vtxos_appear_in_spent() {
        let (_db, repo) = setup().await;

        let mut v1 = make_vtxo("tx1", 0, "pk1", 100_000);
        v1.swept = true;
        repo.add_vtxos(&[v1]).await.unwrap();

        let (spendable, spent) = repo.get_all_vtxos_for_pubkey("pk1").await.unwrap();
        assert_eq!(spendable.len(), 0);
        assert_eq!(spent.len(), 1);
    }

    #[tokio::test]
    async fn test_multiple_vtxos_same_tx() {
        let (_db, repo) = setup().await;

        let v1 = make_vtxo("tx1", 0, "pk1", 50_000);
        let v2 = make_vtxo("tx1", 1, "pk1", 60_000);
        repo.add_vtxos(&[v1, v2]).await.unwrap();

        let result = repo
            .get_vtxos(&[
                VtxoOutpoint::new("tx1".to_string(), 0),
                VtxoOutpoint::new("tx1".to_string(), 1),
            ])
            .await
            .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].amount, 50_000);
        assert_eq!(result[1].amount, 60_000);
    }

    #[tokio::test]
    async fn test_list_all_vtxos() {
        let (_db, repo) = setup().await;

        // Add VTXOs for different pubkeys
        let v1 = make_vtxo("tx1", 0, "pk_alice", 100_000);
        let v2 = make_vtxo("tx2", 0, "pk_bob", 200_000);
        let mut v3 = make_vtxo("tx3", 0, "pk_alice", 50_000);
        v3.spent = true;
        v3.spent_by = "forfeit_tx".to_string();

        repo.add_vtxos(&[v1, v2, v3]).await.unwrap();

        let (spendable, spent) = repo.list_all().await.unwrap();

        // Should have 2 spendable (alice + bob) and 1 spent (alice)
        assert_eq!(spendable.len(), 2);
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0].outpoint.txid, "tx3");

        // Total amount in spendable
        let total: u64 = spendable.iter().map(|v| v.amount).sum();
        assert_eq!(total, 300_000);
    }

    #[tokio::test]
    async fn test_list_all_excludes_unrolled() {
        let (_db, repo) = setup().await;

        let v1 = make_vtxo("tx1", 0, "pk1", 100_000);
        let mut v2 = make_vtxo("tx2", 0, "pk1", 50_000);
        v2.unrolled = true;

        repo.add_vtxos(&[v1, v2]).await.unwrap();

        let (spendable, spent) = repo.list_all().await.unwrap();

        // Only v1 should be returned (v2 is unrolled)
        assert_eq!(spendable.len(), 1);
        assert_eq!(spent.len(), 0);
        assert_eq!(spendable[0].outpoint.txid, "tx1");
    }
}
