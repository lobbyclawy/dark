//! PostgreSQL connection pool and migration runner
//!
//! # Usage
//!
//! ```rust,no_run
//! # #[cfg(feature = "postgres")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use dark_db::pool_postgres::{create_postgres_pool, run_postgres_migrations};
//!
//! let pool = create_postgres_pool("postgres://user:pass@localhost/dark").await?;
//! run_postgres_migrations(&pool).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Integration Testing
//!
//! To run integration tests against a real PostgreSQL instance:
//! ```bash
//! DATABASE_URL=postgres://user:pass@localhost/dark_test cargo test --features postgres
//! ```

use crate::{DatabaseError, DatabaseResult};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::info;

/// Create a PostgreSQL connection pool
///
/// Configures the pool with:
/// - max_connections: 10
/// - acquire_timeout: 30 seconds (prevents hanging on unreachable hosts)
pub async fn create_postgres_pool(url: &str) -> DatabaseResult<PgPool> {
    info!(url = %url, "Creating PostgreSQL connection pool");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(url)
        .await
        .map_err(|e| {
            DatabaseError::ConnectionError(format!("PostgreSQL connection failed: {e}"))
        })?;

    info!("PostgreSQL connection pool created successfully");
    Ok(pool)
}

/// Run PostgreSQL migrations
///
/// Executes embedded migration SQL files in order against the given pool.
pub async fn run_postgres_migrations(pool: &PgPool) -> DatabaseResult<()> {
    info!("Running PostgreSQL migrations");

    let migration_001 = include_str!("../migrations/pg/001_initial.sql");
    sqlx::query(migration_001)
        .execute(pool)
        .await
        .map_err(|e| DatabaseError::MigrationError(format!("PG migration 001 failed: {e}")))?;

    let migration_002 = include_str!("../migrations/pg/002_offchain_txs.sql");
    sqlx::query(migration_002)
        .execute(pool)
        .await
        .map_err(|e| DatabaseError::MigrationError(format!("PG migration 002 failed: {e}")))?;

    let migration_004 = include_str!("../migrations/pg/004_scheduled_sessions.sql");
    sqlx::query(migration_004)
        .execute(pool)
        .await
        .map_err(|e| DatabaseError::MigrationError(format!("PG migration 004 failed: {e}")))?;

    let migration_005 = include_str!("../migrations/pg/005_confidential_vtxos.sql");
    sqlx::query(migration_005)
        .execute(pool)
        .await
        .map_err(|e| DatabaseError::MigrationError(format!("PG migration 005 failed: {e}")))?;

    let migration_006 = include_str!("../migrations/pg/006_nullifiers.sql");
    sqlx::query(migration_006)
        .execute(pool)
        .await
        .map_err(|e| DatabaseError::MigrationError(format!("PG migration 006 failed: {e}")))?;

    info!("PostgreSQL migrations applied successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgres_feature_compiles() {
        // Verifies that the postgres feature gate works and PgPoolOptions is available
        let _opts = PgPoolOptions::new().max_connections(10);
    }

    #[test]
    fn test_migration_sql_embedded() {
        // Verify migration SQL files are properly embedded at compile time
        let sql_001 = include_str!("../migrations/pg/001_initial.sql");
        assert!(sql_001.contains("CREATE TABLE"));
        let sql_002 = include_str!("../migrations/pg/002_offchain_txs.sql");
        assert!(sql_002.contains("offchain_txs"));
        let sql_005 = include_str!("../migrations/pg/005_confidential_vtxos.sql");
        assert!(sql_005.contains("confidential_commitment"));
        assert!(sql_005.contains("confidential_nullifier"));
    }
}
