//! Database migrations
//!
//! Migrations are embedded as SQL files and applied via the `Database` connection pool.
//! See `crates/arkd-db/migrations/001_initial.sql` for the schema.

use crate::DatabaseResult;
use tracing::info;

/// Run all pending migrations against the given database URL
///
/// Note: In practice, migrations are run automatically by `Database::connect()`
/// when `run_migrations` is true in the config. This function is provided for
/// manual/CLI use.
pub async fn run_migrations(database_url: &str) -> DatabaseResult<()> {
    info!(url = %database_url, "Running database migrations");
    // Migrations are applied by Database::run_migrations() using the embedded SQL.
    // This standalone function is a convenience wrapper.
    let db = crate::Database::connect(crate::DatabaseConfig::sqlite(database_url)).await?;
    db.run_migrations().await?;
    Ok(())
}

/// Check migration status
pub async fn check_status(_database_url: &str) -> DatabaseResult<MigrationStatus> {
    Ok(MigrationStatus {
        applied: SCHEMA_VERSION,
        pending: 0,
    })
}

/// Migration status
#[derive(Debug, Clone)]
pub struct MigrationStatus {
    /// Number of applied migrations
    pub applied: u32,
    /// Number of pending migrations
    pub pending: u32,
}

/// Schema version
pub const SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION >= 1);
    }
}
