//! SQLite-backed `NullifierStore` (issue #534).
//!
//! Persists confidential-VTXO nullifiers in the dedicated `nullifiers`
//! table introduced by migration 009. The PRIMARY KEY constraint on the
//! `nullifier` column enforces uniqueness, so duplicate inserts come
//! back as `Ok(false)` rather than dirtying the round-commit
//! transaction.

use async_trait::async_trait;
use dark_core::error::{ArkError, ArkResult};
use dark_live_store::nullifier_set::{Nullifier, NullifierStore, NULLIFIER_LEN};
use sqlx::Row;
use sqlx::SqlitePool;
use tracing::debug;

/// SQLite implementation of `NullifierStore`.
pub struct SqliteNullifierStore {
    pool: SqlitePool,
}

impl SqliteNullifierStore {
    /// Wrap an existing pool. The caller owns migration execution; this
    /// constructor does not validate that table `nullifiers` exists.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NullifierStore for SqliteNullifierStore {
    async fn load_all(&self) -> ArkResult<Vec<Nullifier>> {
        let rows = sqlx::query("SELECT nullifier FROM nullifiers")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: Vec<u8> = row
                .try_get::<Vec<u8>, _>(0)
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
            if bytes.len() != NULLIFIER_LEN {
                return Err(ArkError::DatabaseError(format!(
                    "nullifier column has unexpected length {} (expected {NULLIFIER_LEN})",
                    bytes.len()
                )));
            }
            let mut n = [0u8; NULLIFIER_LEN];
            n.copy_from_slice(&bytes);
            out.push(n);
        }
        debug!(count = out.len(), "SqliteNullifierStore::load_all");
        Ok(out)
    }

    async fn persist_batch(
        &self,
        nullifiers: &[Nullifier],
        round_id: Option<&str>,
    ) -> ArkResult<Vec<bool>> {
        if nullifiers.is_empty() {
            return Ok(Vec::new());
        }

        // Single transaction so the whole batch is atomic w.r.t. the
        // round commit caller.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut results = Vec::with_capacity(nullifiers.len());
        for n in nullifiers {
            // INSERT ... ON CONFLICT DO NOTHING + RETURNING gives us a
            // row only when a fresh insert happened; that's our
            // "newly inserted" signal.
            let row_opt = sqlx::query(
                r#"
                INSERT INTO nullifiers (nullifier, round_id)
                VALUES (?1, ?2)
                ON CONFLICT(nullifier) DO NOTHING
                RETURNING 1 AS inserted
                "#,
            )
            .bind(&n[..])
            .bind(round_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
            results.push(row_opt.is_some());
        }

        tx.commit()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        Ok(results)
    }

    async fn count(&self) -> ArkResult<usize> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nullifiers")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        Ok(row.0 as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Database;
    use dark_live_store::nullifier_set::NullifierSet;
    use std::sync::Arc;

    async fn fresh_store() -> SqliteNullifierStore {
        let db = Database::connect_in_memory().await.unwrap();
        SqliteNullifierStore::new(db.sqlite_pool().unwrap().clone())
    }

    fn make_nullifier(b: u8) -> Nullifier {
        let mut n = [0u8; NULLIFIER_LEN];
        n[0] = b;
        n[31] = b.wrapping_add(1);
        n
    }

    #[tokio::test]
    async fn empty_store_load_all_returns_empty() {
        let store = fresh_store().await;
        assert!(store.load_all().await.unwrap().is_empty());
        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn persist_batch_returns_per_slot_status() {
        let store = fresh_store().await;
        let a = make_nullifier(1);
        let b = make_nullifier(2);

        let res = store.persist_batch(&[a, b], Some("r1")).await.unwrap();
        assert_eq!(res, vec![true, true]);
        assert_eq!(store.count().await.unwrap(), 2);

        // Re-insert the same nullifiers — both must report false.
        let res2 = store.persist_batch(&[a, b], Some("r2")).await.unwrap();
        assert_eq!(res2, vec![false, false]);
        assert_eq!(store.count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn load_all_after_persist_round_trips() {
        let store = fresh_store().await;
        let inputs: Vec<Nullifier> = (0..32u8).map(make_nullifier).collect();
        store.persist_batch(&inputs, Some("r1")).await.unwrap();

        let mut got = store.load_all().await.unwrap();
        let mut want = inputs.clone();
        got.sort();
        want.sort();
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn nullifier_set_crash_recovery_with_sqlite() {
        // End-to-end check using the real SQLite-backed store: write
        // through one NullifierSet, drop it, restart with
        // load_from_db, see the same state.
        let db = Database::connect_in_memory().await.unwrap();
        let pool = db.sqlite_pool().unwrap().clone();

        let nullifiers: Vec<Nullifier> = (0..8u8).map(make_nullifier).collect();

        {
            let store: Arc<dyn NullifierStore> = Arc::new(SqliteNullifierStore::new(pool.clone()));
            let set = NullifierSet::new(Arc::clone(&store));
            set.batch_insert(&nullifiers, Some("round-A"))
                .await
                .unwrap();
            assert_eq!(set.len().await, 8);
        }

        let store: Arc<dyn NullifierStore> = Arc::new(SqliteNullifierStore::new(pool));
        let recovered = NullifierSet::load_from_db(store).await.unwrap();
        assert_eq!(recovered.len().await, 8);
        for n in &nullifiers {
            assert!(recovered.contains(n).await);
        }
    }
}
