//! gRPC server implementation

use crate::{ApiResult, ServerConfig};
use tracing::info;

/// Ark protocol gRPC server
pub struct Server {
    config: ServerConfig,
}

impl Server {
    /// Create a new server instance
    pub fn new(config: ServerConfig) -> ApiResult<Self> {
        info!(grpc_addr = %config.grpc_addr, "Creating Ark API server");
        Ok(Self { config })
    }

    /// Get server configuration
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Run the server (blocking)
    pub async fn run(&self) -> ApiResult<()> {
        info!(
            grpc_addr = %self.config.grpc_addr,
            rest_addr = ?self.config.rest_addr,
            "Starting Ark API server"
        );

        // TODO: Implement gRPC server in issue #9
        // - Set up tonic server
        // - Register ArkService
        // - Register AdminService (if admin token configured)
        // - Optionally start REST gateway

        info!("Server placeholder - full implementation in issue #9");
        Ok(())
    }

    /// Graceful shutdown
    pub async fn shutdown(&self) -> ApiResult<()> {
        info!("Shutting down server");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = ServerConfig::default();
        let server = Server::new(config);
        assert!(server.is_ok());
    }
}
