//! # arkd-api
//!
//! gRPC and REST API layer for the Ark protocol server.
//!
//! This crate provides the external interface for:
//!
//! - **User API**: Round registration, exits, VTXO queries
//! - **Admin API**: Server management, monitoring
//!
//! ## Protocol Buffers
//!
//! The API is defined using Protocol Buffers (see `proto/` directory).
//! Generated Rust code is created at build time using `tonic-build`.
//!
//! ## Authentication
//!
//! Uses macaroons for authentication (compatible with original arkd).
//!
//! ## Example
//!
//! ```rust,ignore
//! use arkd_api::{Server, ServerConfig};
//!
//! let config = ServerConfig::default();
//! let server = Server::new(config, core_service).await?;
//! server.run().await?;
//! ```

use thiserror::Error;

pub mod auth;
pub mod config;
pub mod handlers;
pub mod server;

pub use config::ServerConfig;
pub use server::Server;

/// API-specific errors
#[derive(Error, Debug)]
pub enum ApiError {
    /// Server failed to start
    #[error("Server startup failed: {0}")]
    StartupError(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Internal server error
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Service unavailable
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Rate limited
    #[error("Rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u32 },
}

impl From<ApiError> for tonic::Status {
    fn from(err: ApiError) -> Self {
        match err {
            ApiError::AuthenticationError(_) => tonic::Status::unauthenticated(err.to_string()),
            ApiError::InvalidRequest(_) => tonic::Status::invalid_argument(err.to_string()),
            ApiError::ServiceUnavailable(_) => tonic::Status::unavailable(err.to_string()),
            ApiError::RateLimited { .. } => tonic::Status::resource_exhausted(err.to_string()),
            _ => tonic::Status::internal(err.to_string()),
        }
    }
}

/// Result type for API operations
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_to_status() {
        let err = ApiError::AuthenticationError("Invalid token".to_string());
        let status: tonic::Status = err.into();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }
}
