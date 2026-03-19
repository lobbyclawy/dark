//! # arkd-db
//!
//! Database layer for the Ark protocol server.
//!
//! Provides persistent storage for:
//!
//! - **Rounds**: Round state and history
//! - **VTXOs**: Virtual transaction outputs
//!
//! ## Supported Backends
//!
//! - **PostgreSQL**: Production database
//! - **SQLite**: Development and testing
//! - **Redis**: Caching layer (with in-memory fallback)

use thiserror::Error;

pub mod cache;
pub mod config;
pub mod embedded_kv;
pub mod migrations;
#[cfg(feature = "sqlite")]
pub mod pool;
#[cfg(feature = "postgres")]
pub mod pool_postgres;
pub mod repos;

pub use config::DatabaseConfig;
#[cfg(feature = "sqlite")]
pub use pool::Database;
#[cfg(feature = "sqlite")]
pub use repos::{
    SqliteAssetRepository, SqliteBoardingRepository, SqliteCheckpointRepository,
    SqliteConfirmationStore, SqliteConvictionRepository, SqliteForfeitRepository,
    SqliteOffchainTxRepository, SqliteRoundRepository, SqliteSigningSessionStore,
    SqliteVtxoRepository,
};

#[cfg(feature = "postgres")]
pub use pool_postgres::{create_postgres_pool, run_postgres_migrations};
#[cfg(feature = "postgres")]
pub use repos::{PgOffchainTxRepository, PgRoundRepository, PgVtxoRepository};

/// Database-specific errors
#[derive(Error, Debug)]
pub enum DatabaseError {
    /// Connection failed
    #[error("Database connection failed: {0}")]
    ConnectionError(String),

    /// Query failed
    #[error("Query failed: {0}")]
    QueryError(String),

    /// Record not found
    #[error("Record not found: {entity} with id {id}")]
    NotFound { entity: String, id: String },

    /// Constraint violation (duplicate, foreign key, etc.)
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    /// Migration failed
    #[error("Migration failed: {0}")]
    MigrationError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),
}

impl From<sqlx::Error> for DatabaseError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => DatabaseError::NotFound {
                entity: "record".to_string(),
                id: "unknown".to_string(),
            },
            sqlx::Error::Database(db_err) => {
                if db_err.is_unique_violation() || db_err.is_foreign_key_violation() {
                    DatabaseError::ConstraintViolation(db_err.to_string())
                } else {
                    DatabaseError::QueryError(db_err.to_string())
                }
            }
            _ => DatabaseError::QueryError(err.to_string()),
        }
    }
}

/// Result type for database operations
pub type DatabaseResult<T> = Result<T, DatabaseError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_error_from_sqlx() {
        let err = DatabaseError::from(sqlx::Error::RowNotFound);
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_database_error_display() {
        let err = DatabaseError::ConnectionError("timeout".to_string());
        assert!(err.to_string().contains("timeout"));

        let err = DatabaseError::CacheError("redis down".to_string());
        assert!(err.to_string().contains("redis down"));
    }

    #[test]
    fn test_all_database_error_variants() {
        let errors = vec![
            DatabaseError::ConnectionError("conn fail".to_string()),
            DatabaseError::QueryError("query fail".to_string()),
            DatabaseError::NotFound {
                entity: "vtxo".to_string(),
                id: "abc123".to_string(),
            },
            DatabaseError::ConstraintViolation("unique".to_string()),
            DatabaseError::MigrationError("migrate fail".to_string()),
            DatabaseError::SerializationError("ser fail".to_string()),
            DatabaseError::CacheError("cache fail".to_string()),
        ];

        for err in &errors {
            assert!(!err.to_string().is_empty());
            // Verify Debug is implemented
            let debug = format!("{:?}", err);
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_not_found_error_contains_details() {
        let err = DatabaseError::NotFound {
            entity: "round".to_string(),
            id: "abc-123".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("round"));
        assert!(display.contains("abc-123"));
    }

    #[test]
    fn test_database_result_type() {
        let ok_result: DatabaseResult<i32> = Ok(42);
        assert!(ok_result.is_ok());

        let err_result: DatabaseResult<i32> = Err(DatabaseError::QueryError("fail".to_string()));
        assert!(err_result.is_err());
    }
}
