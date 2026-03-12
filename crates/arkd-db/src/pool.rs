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

                let pool = SqlitePoolOptions::new()
                    .max_connections(config.max_connections)
                    .min_connections(config.min_connections)
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

    /// Get the SQLite pool (panics if not SQLite backend)
    pub fn sqlite_pool(&self) -> &SqlitePool {
        self.sqlite_pool
            .as_ref()
            .expect("Not a SQLite database connection")
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

    /// Run embedded migrations
    pub async fn run_migrations(&self) -> DatabaseResult<()> {
        info!("Running database migrations");
        if let Some(pool) = &self.sqlite_pool {
            let migration_sql = include_str!("../migrations/001_initial.sql");
            sqlx::query(migration_sql)
                .execute(pool)
                .await
                .map_err(|e| DatabaseError::MigrationError(e.to_string()))?;
            info!("Migrations applied successfully");
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
