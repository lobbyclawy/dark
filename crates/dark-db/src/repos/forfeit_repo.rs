//! Forfeit repository — SQLite implementation of `dark_core::ports::ForfeitRepository`

use dark_core::domain::ForfeitRecord;
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::ForfeitRepository;
use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::debug;

/// SQLite-backed forfeit repository
pub struct SqliteForfeitRepository {
    pool: SqlitePool,
}

impl SqliteForfeitRepository {
    /// Create a new repository backed by the given SQLite pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ForfeitRepository for SqliteForfeitRepository {
    async fn store_forfeit(&self, record: ForfeitRecord) -> ArkResult<()> {
        debug!(id = %record.id, round_id = %record.round_id, "Storing forfeit record");

        sqlx::query(
            r#"
            INSERT INTO forfeits (id, round_id, vtxo_id, tx_hex, submitted_at, validated)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(id) DO UPDATE SET
                validated = excluded.validated,
                tx_hex = excluded.tx_hex
            "#,
        )
        .bind(&record.id)
        .bind(&record.round_id)
        .bind(&record.vtxo_id)
        .bind(&record.tx_hex)
        .bind(record.submitted_at as i64)
        .bind(record.validated)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_forfeit(&self, id: &str) -> ArkResult<Option<ForfeitRecord>> {
        debug!(id = %id, "Getting forfeit record");

        let row = sqlx::query_as::<_, ForfeitRow>(
            r#"
            SELECT id, round_id, vtxo_id, tx_hex, submitted_at, validated
            FROM forfeits
            WHERE id = ?1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| r.into_record()))
    }

    async fn list_by_round(&self, round_id: &str) -> ArkResult<Vec<ForfeitRecord>> {
        debug!(round_id = %round_id, "Listing forfeits by round");

        let rows = sqlx::query_as::<_, ForfeitRow>(
            r#"
            SELECT id, round_id, vtxo_id, tx_hex, submitted_at, validated
            FROM forfeits
            WHERE round_id = ?1
            ORDER BY submitted_at ASC
            "#,
        )
        .bind(round_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_record()).collect())
    }

    async fn mark_validated(&self, id: &str) -> ArkResult<()> {
        debug!(id = %id, "Marking forfeit as validated");

        let rows_affected = sqlx::query("UPDATE forfeits SET validated = TRUE WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?
            .rows_affected();

        if rows_affected == 0 {
            return Err(ArkError::NotFound(format!("Forfeit {id} not found")));
        }

        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ForfeitRow {
    id: String,
    round_id: String,
    vtxo_id: String,
    tx_hex: String,
    submitted_at: i64,
    validated: bool,
}

impl ForfeitRow {
    fn into_record(self) -> ForfeitRecord {
        ForfeitRecord {
            id: self.id,
            round_id: self.round_id,
            vtxo_id: self.vtxo_id,
            tx_hex: self.tx_hex,
            submitted_at: self.submitted_at as u64,
            validated: self.validated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn setup() -> (Database, SqliteForfeitRepository) {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = SqliteForfeitRepository::new(db.sqlite_pool().unwrap().clone());
        (db, repo)
    }

    #[tokio::test]
    async fn test_store_and_get_forfeit() {
        let (_db, repo) = setup().await;

        let record = ForfeitRecord::new("round-1".into(), "vtxo-abc:0".into(), "deadbeef".into());
        let id = record.id.clone();
        repo.store_forfeit(record).await.unwrap();

        let found = repo.get_forfeit(&id).await.unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.round_id, "round-1");
        assert_eq!(found.vtxo_id, "vtxo-abc:0");
        assert_eq!(found.tx_hex, "deadbeef");
        assert!(!found.validated);
    }

    #[tokio::test]
    async fn test_get_forfeit_not_found() {
        let (_db, repo) = setup().await;
        let found = repo.get_forfeit("nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_list_by_round() {
        let (_db, repo) = setup().await;

        let r1 = ForfeitRecord::new("round-1".into(), "v1:0".into(), "tx1".into());
        let r2 = ForfeitRecord::new("round-1".into(), "v2:0".into(), "tx2".into());
        let r3 = ForfeitRecord::new("round-2".into(), "v3:0".into(), "tx3".into());

        repo.store_forfeit(r1).await.unwrap();
        repo.store_forfeit(r2).await.unwrap();
        repo.store_forfeit(r3).await.unwrap();

        let round1 = repo.list_by_round("round-1").await.unwrap();
        assert_eq!(round1.len(), 2);

        let round2 = repo.list_by_round("round-2").await.unwrap();
        assert_eq!(round2.len(), 1);
    }

    #[tokio::test]
    async fn test_mark_validated() {
        let (_db, repo) = setup().await;

        let record = ForfeitRecord::new("round-1".into(), "v1:0".into(), "tx1".into());
        let id = record.id.clone();
        repo.store_forfeit(record).await.unwrap();

        assert!(!repo.get_forfeit(&id).await.unwrap().unwrap().validated);

        repo.mark_validated(&id).await.unwrap();
        assert!(repo.get_forfeit(&id).await.unwrap().unwrap().validated);
    }

    #[tokio::test]
    async fn test_mark_validated_not_found() {
        let (_db, repo) = setup().await;
        let result = repo.mark_validated("nonexistent").await;
        assert!(result.is_err());
    }
}
