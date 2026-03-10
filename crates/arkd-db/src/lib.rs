//! # arkd-db
//!
//! Database layer for the Ark protocol server.
//!
//! Provides persistent storage for:
//!
//! - **Rounds**: Round state and history
//! - **VTXOs**: Virtual transaction outputs
//! - **Participants**: User registrations
//! - **Exits**: Exit requests and history
//! - **Events**: Event sourcing log
//!
//! ## Supported Backends
//!
//! - **PostgreSQL**: Production database
//! - **SQLite**: Development and testing
//! - **Redis**: Caching layer
//!
//! ## Example
//!
//! ```rust,ignore
//! use arkd_db::{Database, DatabaseConfig};
//!
//! let config = DatabaseConfig::postgres("postgres://localhost/arkd");
//! let db = Database::connect(config).await?;
//!
//! let round = db.rounds().get_by_id("round-123").await?;
//! ```

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
                // Check for constraint violations
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
}
