//! gRPC server implementation

use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server as TonicServer;
use tracing::info;

use arkd_core::ports::RoundRepository;

use crate::grpc::admin_service::AdminGrpcService;
use crate::grpc::ark_service::ArkGrpcService;
use crate::proto::ark_v1::admin_service_server::AdminServiceServer;
use crate::proto::ark_v1::ark_service_server::ArkServiceServer;
use crate::{ApiResult, ServerConfig};

/// Ark protocol gRPC server.
///
/// Runs two tonic servers:
/// - **gRPC** on `0.0.0.0:7070` — user-facing `ArkService`
/// - **Admin** on `0.0.0.0:7071` — operator `AdminService`
///
/// Both support tonic-web for REST / browser clients.
/// A shared `CancellationToken` ensures both servers shut down together.
pub struct Server {
    config: ServerConfig,
    core: Arc<arkd_core::ArkService>,
    round_repo: Arc<dyn RoundRepository>,
    cancel: CancellationToken,
}

impl Server {
    /// Create a new server instance.
    pub fn new(
        config: ServerConfig,
        core: Arc<arkd_core::ArkService>,
        round_repo: Arc<dyn RoundRepository>,
    ) -> ApiResult<Self> {
        info!(grpc_addr = %config.grpc_addr, "Creating Ark API server");
        Ok(Self {
            config,
            core,
            round_repo,
            cancel: CancellationToken::new(),
        })
    }

    /// Get server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Run the server (blocking).
    ///
    /// Spawns both gRPC and admin servers and waits for them.
    /// If either server exits, the other is cancelled.
    pub async fn run(&self) -> ApiResult<()> {
        let grpc_handle = self.spawn_grpc_server()?;
        let admin_handle = self.spawn_admin_server()?;

        info!(
            grpc_addr = %self.config.grpc_addr,
            admin_addr = %self.config.admin_addr(),
            "Ark API servers started"
        );

        // Wait for either server — if one exits, cancel the other
        tokio::select! {
            res = grpc_handle => {
                self.cancel.cancel();
                res.map_err(|e| crate::ApiError::StartupError(format!("gRPC server panicked: {e}")))?
                    .map_err(crate::ApiError::TransportError)?;
            }
            res = admin_handle => {
                self.cancel.cancel();
                res.map_err(|e| crate::ApiError::StartupError(format!("Admin server panicked: {e}")))?
                    .map_err(crate::ApiError::TransportError)?;
            }
        }

        Ok(())
    }

    /// Spawn the user-facing gRPC server.
    fn spawn_grpc_server(&self) -> ApiResult<JoinHandle<Result<(), tonic::transport::Error>>> {
        let addr = self
            .config
            .grpc_addr
            .parse()
            .map_err(|e| crate::ApiError::StartupError(format!("Invalid gRPC address: {e}")))?;

        let ark_service = ArkGrpcService::new(Arc::clone(&self.core), Arc::clone(&self.round_repo));
        let svc = tonic_web::enable(ArkServiceServer::new(ark_service));
        let cancel = self.cancel.clone();

        info!(%addr, "Spawning gRPC server (ArkService)");

        Ok(tokio::spawn(async move {
            TonicServer::builder()
                .accept_http1(true) // Required for tonic-web
                .add_service(svc)
                .serve_with_shutdown(addr, cancel.cancelled())
                .await
        }))
    }

    /// Spawn the admin gRPC server on a separate port.
    fn spawn_admin_server(&self) -> ApiResult<JoinHandle<Result<(), tonic::transport::Error>>> {
        let addr_str = self.config.admin_addr();
        let addr = addr_str
            .parse()
            .map_err(|e| crate::ApiError::StartupError(format!("Invalid admin address: {e}")))?;

        let admin_service = AdminGrpcService::new(Arc::clone(&self.core));
        let svc = tonic_web::enable(AdminServiceServer::new(admin_service));
        let cancel = self.cancel.clone();

        info!(%addr, "Spawning admin gRPC server (AdminService)");

        Ok(tokio::spawn(async move {
            TonicServer::builder()
                .accept_http1(true)
                .add_service(svc)
                .serve_with_shutdown(addr, cancel.cancelled())
                .await
        }))
    }

    /// Graceful shutdown — cancels both servers.
    pub async fn shutdown(&self) -> ApiResult<()> {
        info!("Shutting down server");
        self.cancel.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_admin_addr() {
        let config = ServerConfig::default();
        // Admin addr should differ from grpc_addr
        assert_ne!(config.grpc_addr, config.admin_addr());
    }
}
