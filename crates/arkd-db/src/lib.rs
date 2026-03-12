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
pub mod migrations;
pub mod pool;
pub mod repos;

pub use config::DatabaseConfig;
pub use pool::Database;

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
}
