//! Scheduled-session config repository — PostgreSQL implementation of
//! `arkd_core::ports::ScheduledSessionRepository`

use arkd_core::domain::ScheduledSessionConfig;
use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::ScheduledSessionRepository;
use async_trait::async_trait;
use sqlx::PgPool;
use tracing::debug;

/// PostgreSQL-backed scheduled-session config repository (singleton row).
pub struct PgScheduledSessionRepository {
    pool: PgPool,
}

impl PgScheduledSessionRepository {
    /// Create a new repository backed by the given PostgreSQL pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ScheduledSessionRepository for PgScheduledSessionRepository {
    async fn get(&self) -> ArkResult<Option<ScheduledSessionConfig>> {
        debug!("Getting scheduled session config (pg)");

        let row = sqlx::query_as::<_, ScheduledSessionRow>(
            "SELECT round_interval_secs, round_lifetime_secs, max_intents_per_round \
             FROM scheduled_session_config WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| r.into_config()))
    }

    async fn upsert(&self, config: ScheduledSessionConfig) -> ArkResult<()> {
        debug!(
            interval = config.round_interval_secs,
            lifetime = config.round_lifetime_secs,
            max_intents = config.max_intents_per_round,
            "Upserting scheduled session config (pg)"
        );

        sqlx::query(
            "INSERT INTO scheduled_session_config (id, round_interval_secs, round_lifetime_secs, max_intents_per_round) \
             VALUES (1, $1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET \
                 round_interval_secs = EXCLUDED.round_interval_secs, \
                 round_lifetime_secs = EXCLUDED.round_lifetime_secs, \
                 max_intents_per_round = EXCLUDED.max_intents_per_round",
        )
        .bind(config.round_interval_secs as i32)
        .bind(config.round_lifetime_secs as i32)
        .bind(config.max_intents_per_round as i32)
        .execute(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn clear(&self) -> ArkResult<()> {
        debug!("Clearing scheduled session config (pg)");

        sqlx::query("DELETE FROM scheduled_session_config WHERE id = 1")
            .execute(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ScheduledSessionRow {
    round_interval_secs: i32,
    round_lifetime_secs: i32,
    max_intents_per_round: i32,
}

impl ScheduledSessionRow {
    fn into_config(self) -> ScheduledSessionConfig {
        ScheduledSessionConfig {
            round_interval_secs: self.round_interval_secs as u32,
            round_lifetime_secs: self.round_lifetime_secs as u32,
            max_intents_per_round: self.max_intents_per_round as u32,
        }
    }
}
