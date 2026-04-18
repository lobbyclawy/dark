//! Signing session store — SQLite implementation of `dark_core::ports::SigningSessionStore`

use async_trait::async_trait;
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::SigningSessionStore;
use sqlx::SqlitePool;
use tracing::debug;

/// SQLite-backed signing session store
pub struct SqliteSigningSessionStore {
    pool: SqlitePool,
}

impl SqliteSigningSessionStore {
    /// Create a new store backed by the given SQLite pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

use dark_core::domain::{SigningSession, SigningSessionStatus};

#[async_trait]
impl SigningSessionStore for SqliteSigningSessionStore {
    async fn get_session(&self, session_id: &str) -> ArkResult<Option<SigningSession>> {
        let row = sqlx::query_as::<_, (i32,)>(
            "SELECT participant_count FROM signing_sessions WHERE session_id = ?1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let participant_count = match row {
            Some((count,)) => count as usize,
            None => return Ok(None),
        };

        let nonces = sqlx::query_as::<_, (String, Vec<u8>)>(
            "SELECT participant_id, nonce FROM signing_nonces WHERE session_id = ?1 ORDER BY participant_id",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let sigs = sqlx::query_as::<_, (String, Vec<u8>)>(
            "SELECT participant_id, signature FROM signing_signatures WHERE session_id = ?1 ORDER BY participant_id",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        // Check for combined_sig (stored in a separate column or table)
        let combined_sig = sqlx::query_as::<_, (Option<Vec<u8>>,)>(
            "SELECT combined_sig FROM signing_sessions WHERE session_id = ?1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?
        .and_then(|r| r.0);

        let status = if combined_sig.is_some() {
            SigningSessionStatus::Complete
        } else if nonces.len() >= participant_count {
            SigningSessionStatus::CollectingSignatures
        } else {
            SigningSessionStatus::CollectingNonces
        };

        Ok(Some(SigningSession {
            round_id: session_id.to_string(),
            participant_count,
            tree_nonces: nonces,
            tree_signatures: sigs,
            combined_sig,
            status,
        }))
    }

    async fn complete_session(&self, session_id: &str, combined_sig: Vec<u8>) -> ArkResult<()> {
        debug!(session_id = %session_id, "Completing signing session");

        sqlx::query("UPDATE signing_sessions SET combined_sig = ?1 WHERE session_id = ?2")
            .bind(&combined_sig)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn init_session(&self, session_id: &str, participant_count: usize) -> ArkResult<()> {
        debug!(session_id = %session_id, participant_count, "Initializing signing session");

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        // Clean up old data for this session
        sqlx::query("DELETE FROM signing_signatures WHERE session_id = ?1")
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        sqlx::query("DELETE FROM signing_nonces WHERE session_id = ?1")
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        sqlx::query("DELETE FROM signing_sessions WHERE session_id = ?1")
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        sqlx::query("INSERT INTO signing_sessions (session_id, participant_count) VALUES (?1, ?2)")
            .bind(session_id)
            .bind(participant_count as i32)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn add_nonce(
        &self,
        session_id: &str,
        participant_id: &str,
        nonce: Vec<u8>,
    ) -> ArkResult<()> {
        debug!(session_id = %session_id, participant_id = %participant_id, "Adding nonce");

        sqlx::query(
            r#"
            INSERT INTO signing_nonces (session_id, participant_id, nonce)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(session_id, participant_id) DO UPDATE SET nonce = excluded.nonce
            "#,
        )
        .bind(session_id)
        .bind(participant_id)
        .bind(&nonce)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn all_nonces_collected(&self, session_id: &str) -> ArkResult<bool> {
        let session = sqlx::query_as::<_, (i32,)>(
            "SELECT participant_count FROM signing_sessions WHERE session_id = ?1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let Some((expected,)) = session else {
            return Ok(false);
        };

        let actual = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM signing_nonces WHERE session_id = ?1",
        )
        .bind(session_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(actual.0 >= expected as i64)
    }

    async fn add_signature(
        &self,
        session_id: &str,
        participant_id: &str,
        sig: Vec<u8>,
    ) -> ArkResult<()> {
        debug!(session_id = %session_id, participant_id = %participant_id, "Adding signature");

        sqlx::query(
            r#"
            INSERT INTO signing_signatures (session_id, participant_id, signature)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(session_id, participant_id) DO UPDATE SET signature = excluded.signature
            "#,
        )
        .bind(session_id)
        .bind(participant_id)
        .bind(&sig)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn all_signatures_collected(&self, session_id: &str) -> ArkResult<bool> {
        let session = sqlx::query_as::<_, (i32,)>(
            "SELECT participant_count FROM signing_sessions WHERE session_id = ?1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let Some((expected,)) = session else {
            return Ok(false);
        };

        let actual = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM signing_signatures WHERE session_id = ?1",
        )
        .bind(session_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(actual.0 >= expected as i64)
    }

    async fn get_nonces(&self, session_id: &str) -> ArkResult<Vec<Vec<u8>>> {
        let rows = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT nonce FROM signing_nonces WHERE session_id = ?1 ORDER BY participant_id",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn get_signatures(&self, session_id: &str) -> ArkResult<Vec<Vec<u8>>> {
        let rows = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT signature FROM signing_signatures WHERE session_id = ?1 ORDER BY participant_id",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn setup() -> (Database, SqliteSigningSessionStore) {
        let db = Database::connect_in_memory().await.unwrap();
        let store = SqliteSigningSessionStore::new(db.sqlite_pool().unwrap().clone());
        (db, store)
    }

    #[tokio::test]
    async fn test_init_and_nonces() {
        let (_db, store) = setup().await;

        store.init_session("s1", 3).await.unwrap();

        assert!(!store.all_nonces_collected("s1").await.unwrap());

        store.add_nonce("s1", "p1", vec![1, 2, 3]).await.unwrap();
        store.add_nonce("s1", "p2", vec![4, 5, 6]).await.unwrap();
        assert!(!store.all_nonces_collected("s1").await.unwrap());

        store.add_nonce("s1", "p3", vec![7, 8, 9]).await.unwrap();
        assert!(store.all_nonces_collected("s1").await.unwrap());

        let nonces = store.get_nonces("s1").await.unwrap();
        assert_eq!(nonces.len(), 3);
    }

    #[tokio::test]
    async fn test_signatures() {
        let (_db, store) = setup().await;

        store.init_session("s1", 2).await.unwrap();

        assert!(!store.all_signatures_collected("s1").await.unwrap());

        store.add_signature("s1", "p1", vec![10, 20]).await.unwrap();
        assert!(!store.all_signatures_collected("s1").await.unwrap());

        store.add_signature("s1", "p2", vec![30, 40]).await.unwrap();
        assert!(store.all_signatures_collected("s1").await.unwrap());

        let sigs = store.get_signatures("s1").await.unwrap();
        assert_eq!(sigs.len(), 2);
    }

    #[tokio::test]
    async fn test_nonexistent_session() {
        let (_db, store) = setup().await;
        assert!(!store.all_nonces_collected("nope").await.unwrap());
        assert!(!store.all_signatures_collected("nope").await.unwrap());
    }

    #[tokio::test]
    async fn test_reinit_clears_old_data() {
        let (_db, store) = setup().await;

        store.init_session("s1", 1).await.unwrap();
        store.add_nonce("s1", "p1", vec![1, 2]).await.unwrap();
        assert!(store.all_nonces_collected("s1").await.unwrap());

        // Re-init resets
        store.init_session("s1", 2).await.unwrap();
        assert!(!store.all_nonces_collected("s1").await.unwrap());
        assert!(store.get_nonces("s1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_upsert_nonce() {
        let (_db, store) = setup().await;

        store.init_session("s1", 1).await.unwrap();
        store.add_nonce("s1", "p1", vec![1, 2]).await.unwrap();
        store.add_nonce("s1", "p1", vec![3, 4]).await.unwrap();

        let nonces = store.get_nonces("s1").await.unwrap();
        assert_eq!(nonces.len(), 1);
        assert_eq!(nonces[0], vec![3, 4]);
    }
}
