//! Conviction repository — SQLite implementation of `dark_core::ports::ConvictionRepository`

use async_trait::async_trait;
use dark_core::domain::{Conviction, ConvictionKind, CrimeType};
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::ConvictionRepository;
use sqlx::SqlitePool;
use tracing::debug;

/// SQLite-backed conviction repository
pub struct SqliteConvictionRepository {
    pool: SqlitePool,
}

impl SqliteConvictionRepository {
    /// Create a new repository backed by the given SQLite pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ConvictionRepository for SqliteConvictionRepository {
    async fn store(&self, conviction: Conviction) -> ArkResult<()> {
        debug!(id = %conviction.id, "Storing conviction");

        let kind = match conviction.kind {
            ConvictionKind::Unspecified => 0i32,
            ConvictionKind::Script => 1,
        };
        let crime_type = conviction.crime_type.to_string();

        sqlx::query(
            r#"
            INSERT INTO convictions (id, kind, created_at, expires_at, pardoned, script,
                crime_type, round_id, reason)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(id) DO UPDATE SET
                pardoned = excluded.pardoned,
                expires_at = excluded.expires_at
            "#,
        )
        .bind(&conviction.id)
        .bind(kind)
        .bind(conviction.created_at)
        .bind(conviction.expires_at)
        .bind(conviction.pardoned)
        .bind(&conviction.script)
        .bind(&crime_type)
        .bind(&conviction.round_id)
        .bind(&conviction.reason)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_by_ids(&self, ids: &[String]) -> ArkResult<Vec<Conviction>> {
        debug!(count = ids.len(), "Getting convictions by IDs");

        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            let row = sqlx::query_as::<_, ConvictionRow>(
                r#"
                SELECT id, kind, created_at, expires_at, pardoned, script,
                       crime_type, round_id, reason
                FROM convictions
                WHERE id = ?1
                "#,
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

            if let Some(row) = row {
                result.push(row.into_conviction());
            }
        }
        Ok(result)
    }

    async fn get_in_range(&self, from: i64, to: i64) -> ArkResult<Vec<Conviction>> {
        debug!(from, to, "Getting convictions in time range");

        let rows = sqlx::query_as::<_, ConvictionRow>(
            r#"
            SELECT id, kind, created_at, expires_at, pardoned, script,
                   crime_type, round_id, reason
            FROM convictions
            WHERE created_at >= ?1 AND created_at <= ?2
            ORDER BY created_at ASC
            "#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_conviction()).collect())
    }

    async fn get_by_round(&self, round_id: &str) -> ArkResult<Vec<Conviction>> {
        debug!(round_id = %round_id, "Getting convictions by round");

        let rows = sqlx::query_as::<_, ConvictionRow>(
            r#"
            SELECT id, kind, created_at, expires_at, pardoned, script,
                   crime_type, round_id, reason
            FROM convictions
            WHERE round_id = ?1
            ORDER BY created_at ASC
            "#,
        )
        .bind(round_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_conviction()).collect())
    }

    async fn get_active_by_script(&self, script: &str) -> ArkResult<Vec<Conviction>> {
        debug!(script = %script, "Getting active convictions for script");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let rows = sqlx::query_as::<_, ConvictionRow>(
            r#"
            SELECT id, kind, created_at, expires_at, pardoned, script,
                   crime_type, round_id, reason
            FROM convictions
            WHERE script = ?1
              AND pardoned = FALSE
              AND (expires_at = 0 OR expires_at > ?2)
            ORDER BY created_at ASC
            "#,
        )
        .bind(script)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_conviction()).collect())
    }

    async fn pardon(&self, id: &str) -> ArkResult<()> {
        debug!(id = %id, "Pardoning conviction");

        let rows_affected = sqlx::query("UPDATE convictions SET pardoned = TRUE WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?
            .rows_affected();

        if rows_affected == 0 {
            return Err(ArkError::NotFound(format!("Conviction {id} not found")));
        }

        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ConvictionRow {
    id: String,
    kind: i32,
    created_at: i64,
    expires_at: i64,
    pardoned: bool,
    script: String,
    crime_type: String,
    round_id: String,
    reason: String,
}

impl ConvictionRow {
    fn into_conviction(self) -> Conviction {
        let kind = match self.kind {
            1 => ConvictionKind::Script,
            _ => ConvictionKind::Unspecified,
        };
        let crime_type = match self.crime_type.as_str() {
            "musig2_nonce_submission" => CrimeType::Musig2NonceSubmission,
            "musig2_signature_submission" => CrimeType::Musig2SignatureSubmission,
            "musig2_invalid_signature" => CrimeType::Musig2InvalidSignature,
            "forfeit_submission" => CrimeType::ForfeitSubmission,
            "forfeit_invalid_signature" => CrimeType::ForfeitInvalidSignature,
            "boarding_input_submission" => CrimeType::BoardingInputSubmission,
            "manual_ban" => CrimeType::ManualBan,
            _ => CrimeType::Unspecified,
        };

        Conviction {
            id: self.id,
            kind,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pardoned: self.pardoned,
            script: self.script,
            crime_type,
            round_id: self.round_id,
            reason: self.reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn setup() -> (Database, SqliteConvictionRepository) {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = SqliteConvictionRepository::new(db.sqlite_pool().unwrap().clone());
        (db, repo)
    }

    #[tokio::test]
    async fn test_store_and_get_conviction() {
        let (_db, repo) = setup().await;

        let conv = Conviction::manual_ban("script-abc", "spamming", 3600);
        let id = conv.id.clone();
        repo.store(conv).await.unwrap();

        let found = repo.get_by_ids(std::slice::from_ref(&id)).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].script, "script-abc");
        assert_eq!(found[0].reason, "spamming");
        assert_eq!(found[0].crime_type, CrimeType::ManualBan);
    }

    #[tokio::test]
    async fn test_get_by_ids_not_found() {
        let (_db, repo) = setup().await;
        let found = repo.get_by_ids(&["nonexistent".into()]).await.unwrap();
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn test_get_by_round() {
        let (_db, repo) = setup().await;

        let mut c1 = Conviction::manual_ban("s1", "r1", 0);
        c1.round_id = "round-1".to_string();
        let mut c2 = Conviction::manual_ban("s2", "r2", 0);
        c2.round_id = "round-1".to_string();
        let mut c3 = Conviction::manual_ban("s3", "r3", 0);
        c3.round_id = "round-2".to_string();

        repo.store(c1).await.unwrap();
        repo.store(c2).await.unwrap();
        repo.store(c3).await.unwrap();

        let round1 = repo.get_by_round("round-1").await.unwrap();
        assert_eq!(round1.len(), 2);
    }

    #[tokio::test]
    async fn test_get_active_by_script() {
        let (_db, repo) = setup().await;

        // Active permanent ban
        let c1 = Conviction::manual_ban("script-x", "permanent ban", 0);
        repo.store(c1).await.unwrap();

        // Active time-limited ban (1 hour from now)
        let c2 = Conviction::manual_ban("script-x", "temp ban", 3600);
        repo.store(c2).await.unwrap();

        // Pardoned ban
        let mut c3 = Conviction::manual_ban("script-x", "pardoned", 0);
        c3.pardoned = true;
        repo.store(c3).await.unwrap();

        let active = repo.get_active_by_script("script-x").await.unwrap();
        assert_eq!(active.len(), 2); // permanent + temp, not pardoned
    }

    #[tokio::test]
    async fn test_pardon_conviction() {
        let (_db, repo) = setup().await;

        let conv = Conviction::manual_ban("script-y", "bad", 0);
        let id = conv.id.clone();
        repo.store(conv).await.unwrap();

        repo.pardon(&id).await.unwrap();

        let found = repo.get_by_ids(&[id]).await.unwrap();
        assert!(found[0].pardoned);
    }

    #[tokio::test]
    async fn test_pardon_not_found() {
        let (_db, repo) = setup().await;
        let result = repo.pardon("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_in_range() {
        let (_db, repo) = setup().await;

        let conv = Conviction::manual_ban("s1", "reason", 0);
        let created = conv.created_at;
        repo.store(conv).await.unwrap();

        let found = repo.get_in_range(created - 1, created + 1).await.unwrap();
        assert_eq!(found.len(), 1);

        let not_found = repo
            .get_in_range(created + 100, created + 200)
            .await
            .unwrap();
        assert!(not_found.is_empty());
    }
}
