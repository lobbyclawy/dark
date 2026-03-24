//! VTXO repository — PostgreSQL implementation of `dark_core::ports::VtxoRepository`

use async_trait::async_trait;
use dark_core::domain::{Vtxo, VtxoOutpoint};
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::VtxoRepository;
use sqlx::PgPool;
use tracing::debug;

/// PostgreSQL-backed VTXO repository
pub struct PgVtxoRepository {
    pool: PgPool,
}

impl PgVtxoRepository {
    /// Create a new repository backed by the given PostgreSQL pool
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl VtxoRepository for PgVtxoRepository {
    async fn add_vtxos(&self, vtxos: &[Vtxo]) -> ArkResult<()> {
        debug!(count = vtxos.len(), "Adding VTXOs (PG)");

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
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                ON CONFLICT(txid, vout) DO UPDATE SET
                    pubkey = EXCLUDED.pubkey,
                    amount = EXCLUDED.amount,
                    root_commitment_txid = EXCLUDED.root_commitment_txid,
                    settled_by = EXCLUDED.settled_by,
                    spent_by = EXCLUDED.spent_by,
                    ark_txid = EXCLUDED.ark_txid,
                    spent = EXCLUDED.spent,
                    unrolled = EXCLUDED.unrolled,
                    swept = EXCLUDED.swept,
                    preconfirmed = EXCLUDED.preconfirmed,
                    expires_at = EXCLUDED.expires_at
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
            sqlx::query(
                "DELETE FROM vtxo_commitment_txids WHERE vtxo_txid = $1 AND vtxo_vout = $2",
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
                    VALUES ($1, $2, $3, $4)
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
        debug!(count = outpoints.len(), "Getting VTXOs by outpoints (PG)");

        let mut result = Vec::with_capacity(outpoints.len());

        for op in outpoints {
            let row = sqlx::query_as::<_, PgVtxoRow>(
                r#"
                SELECT txid, vout, pubkey, amount, root_commitment_txid,
                       settled_by, spent_by, ark_txid, spent, unrolled, swept,
                       preconfirmed, expires_at, created_at
                FROM vtxos
                WHERE txid = $1 AND vout = $2
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
        debug!(pubkey = %pubkey, "Getting all VTXOs for pubkey (PG)");

        let rows = sqlx::query_as::<_, PgVtxoRow>(
            r#"
            SELECT txid, vout, pubkey, amount, root_commitment_txid,
                   settled_by, spent_by, ark_txid, spent, unrolled, swept,
                   preconfirmed, expires_at, created_at
            FROM vtxos
            WHERE pubkey = $1 AND unrolled = FALSE
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
        debug!(count = spent.len(), ark_txid = %ark_txid, "Spending VTXOs (PG)");

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        for (outpoint, spent_by) in spent {
            let rows_affected = sqlx::query(
                r#"
                UPDATE vtxos
                SET spent = TRUE, spent_by = $1, ark_txid = $2
                WHERE txid = $3 AND vout = $4
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
        debug!(before_timestamp, "Finding expired VTXOs for sweep (PG)");

        let rows = sqlx::query_as::<_, PgVtxoRow>(
            r#"
            SELECT txid, vout, pubkey, amount, root_commitment_txid,
                   settled_by, spent_by, ark_txid, spent, unrolled, swept,
                   preconfirmed, expires_at, created_at
            FROM vtxos
            WHERE expires_at > 0
              AND expires_at < $1
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
        debug!("Listing all VTXOs (PG)");

        let rows = sqlx::query_as::<_, PgVtxoRow>(
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

impl PgVtxoRepository {
    /// Fetch the commitment txid chain for a VTXO
    async fn get_commitment_txids(&self, txid: &str, vout: u32) -> ArkResult<Vec<String>> {
        let rows = sqlx::query_as::<_, PgCommitmentTxidRow>(
            r#"
            SELECT commitment_txid, position
            FROM vtxo_commitment_txids
            WHERE vtxo_txid = $1 AND vtxo_vout = $2
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
struct PgVtxoRow {
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

impl PgVtxoRow {
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
            assets: vec![],
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct PgCommitmentTxidRow {
    commitment_txid: String,
    #[allow(dead_code)]
    position: i32,
}
