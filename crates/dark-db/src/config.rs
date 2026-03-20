//! Database configuration

use serde::{Deserialize, Serialize};

/// Database backend type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseBackend {
    /// PostgreSQL (production)
    Postgres,
    /// SQLite (development/testing)
    Sqlite,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database backend
    pub backend: DatabaseBackend,

    /// Connection URL
    pub url: String,

    /// Maximum connections in pool
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Minimum connections in pool
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,

    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Run migrations on startup
    #[serde(default = "default_true")]
    pub run_migrations: bool,

    /// Redis URL (optional cache layer)
    pub redis_url: Option<String>,
}

fn default_max_connections() -> u32 {
    10
}

fn default_min_connections() -> u32 {
    1
}

fn default_connect_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

impl DatabaseConfig {
    /// Create a PostgreSQL configuration
    pub fn postgres(url: &str) -> Self {
        Self {
            backend: DatabaseBackend::Postgres,
            url: url.to_string(),
            max_connections: default_max_connections(),
            min_connections: default_min_connections(),
            connect_timeout_secs: default_connect_timeout(),
            run_migrations: true,
            redis_url: None,
        }
    }

    /// Create a SQLite configuration
    pub fn sqlite(path: &str) -> Self {
        Self {
            backend: DatabaseBackend::Sqlite,
            url: format!("sqlite://{}", path),
            max_connections: 1, // SQLite doesn't support concurrent writes
            min_connections: 1,
            connect_timeout_secs: default_connect_timeout(),
            run_migrations: true,
            redis_url: None,
        }
    }

    /// Enable Redis caching
    pub fn with_redis(mut self, redis_url: &str) -> Self {
        self.redis_url = Some(redis_url.to_string());
        self
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self::sqlite("./data/dark.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgres_config() {
        let config = DatabaseConfig::postgres("postgres://localhost/dark");
        assert_eq!(config.backend, DatabaseBackend::Postgres);
    }

    #[test]
    fn test_sqlite_config() {
        let config = DatabaseConfig::sqlite("test.db");
        assert_eq!(config.backend, DatabaseBackend::Sqlite);
    }
}
