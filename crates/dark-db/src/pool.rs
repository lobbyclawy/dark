//! Database connection pool

use crate::config::DatabaseBackend;
use crate::{DatabaseConfig, DatabaseError, DatabaseResult};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;
use tracing::info;

/// Database connection wrapper supporting SQLite and PostgreSQL
pub struct Database {
    config: DatabaseConfig,
    sqlite_pool: Option<SqlitePool>,
}

impl Database {
    /// Connect to the database based on config
    pub async fn connect(config: DatabaseConfig) -> DatabaseResult<Self> {
        info!(
            backend = ?config.backend,
            url = %config.url,
            "Connecting to database"
        );

        match config.backend {
            DatabaseBackend::Sqlite => {
                let opts = SqliteConnectOptions::from_str(&config.url)
                    .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?
                    .create_if_missing(true)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                    .foreign_keys(true);

                // For in-memory SQLite databases, disable idle timeout to
                // prevent the pool from recycling the connection (which would
                // destroy the in-memory database and all its tables).
                let is_memory = config.url.contains(":memory:");
                let mut pool_opts = SqlitePoolOptions::new()
                    .max_connections(config.max_connections)
                    .min_connections(config.min_connections);
                if is_memory {
                    pool_opts = pool_opts.idle_timeout(None).max_lifetime(None);
                }
                let pool = pool_opts
                    .connect_with(opts)
                    .await
                    .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

                let db = Self {
                    config,
                    sqlite_pool: Some(pool),
                };

                if db.config.run_migrations {
                    db.run_migrations().await?;
                }

                Ok(db)
            }
            DatabaseBackend::Postgres => {
                // PostgreSQL support — for now return an error since we test with SQLite
                Err(DatabaseError::ConnectionError(
                    "PostgreSQL support not yet implemented; use SQLite for now".to_string(),
                ))
            }
        }
    }

    /// Connect to an in-memory SQLite database (for testing)
    pub async fn connect_in_memory() -> DatabaseResult<Self> {
        let config = DatabaseConfig {
            backend: DatabaseBackend::Sqlite,
            url: "sqlite::memory:".to_string(),
            max_connections: 1,
            min_connections: 1,
            connect_timeout_secs: 5,
            run_migrations: true,
            redis_url: None,
        };
        Self::connect(config).await
    }

    /// Get the SQLite pool.
    ///
    /// Returns an error if the database is not using a SQLite backend.
    pub fn sqlite_pool(&self) -> DatabaseResult<&SqlitePool> {
        self.sqlite_pool.as_ref().ok_or_else(|| {
            DatabaseError::ConnectionError("Not a SQLite database connection".to_string())
        })
    }

    /// Get configuration
    pub fn config(&self) -> &DatabaseConfig {
        &self.config
    }

    /// Check if connection is healthy
    pub async fn health_check(&self) -> DatabaseResult<bool> {
        if let Some(pool) = &self.sqlite_pool {
            sqlx::query("SELECT 1")
                .execute(pool)
                .await
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Run embedded migrations.
    ///
    /// Each migration file may contain multiple SQL statements separated by
    /// semicolons. We split them and execute each statement individually
    /// because `sqlx::query()` only processes the first statement in SQLite.
    pub async fn run_migrations(&self) -> DatabaseResult<()> {
        info!("Running database migrations");
        if let Some(pool) = &self.sqlite_pool {
            let migrations: &[&str] = &[
                include_str!("../migrations/001_initial.sql"),
                include_str!("../migrations/002_offchain_txs.sql"),
                include_str!("../migrations/003_noop_repos.sql"),
                include_str!("../migrations/004_signing_combined_sig.sql"),
                include_str!("../migrations/005_assets.sql"),
                include_str!("../migrations/006_scheduled_sessions.sql"),
                include_str!("../migrations/007_vtxo_assets.sql"),
            ];

            for (i, migration_sql) in migrations.iter().enumerate() {
                let migration_num = i + 1;
                // Split by semicolons and execute each non-empty statement.
                // Strip SQL comments (lines starting with --) before checking
                // if a fragment is empty.
                for stmt in migration_sql.split(';') {
                    let without_comments: String = stmt
                        .lines()
                        .filter(|line| !line.trim_start().starts_with("--"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    let trimmed = without_comments.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    sqlx::query(trimmed).execute(pool).await.map_err(|e| {
                        DatabaseError::MigrationError(format!(
                            "Migration {migration_num:03} failed: {e}"
                        ))
                    })?;
                }
            }
            info!("Migrations applied successfully (001-007)");
        }
        Ok(())
    }

    /// Close all connections
    pub async fn close(&self) {
        info!("Closing database connections");
        if let Some(pool) = &self.sqlite_pool {
            pool.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_connect_in_memory() {
        let db = Database::connect_in_memory().await.unwrap();
        assert!(db.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn test_database_config() {
        let db = Database::connect_in_memory().await.unwrap();
        assert_eq!(db.config().backend, DatabaseBackend::Sqlite);
    }
}
