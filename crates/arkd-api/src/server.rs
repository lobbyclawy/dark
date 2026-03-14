//! gRPC server implementation

use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server as TonicServer;
use tracing::info;

use arkd_core::ports::{OffchainTxRepository, RoundRepository};

use crate::auth::Authenticator;
use crate::grpc::admin_service::AdminGrpcService;
use crate::grpc::ark_service::ArkGrpcService;
use crate::grpc::broker::SharedEventBroker;
use crate::grpc::middleware::AuthInterceptor;
use crate::grpc::wallet_service::WalletGrpcService;
use crate::proto::ark_v1::admin_service_server::AdminServiceServer;
use crate::proto::ark_v1::ark_service_server::ArkServiceServer;
use crate::proto::ark_v1::wallet_service_server::WalletServiceServer;
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
    broker: SharedEventBroker,
    offchain_tx_repo: Arc<dyn OffchainTxRepository>,
    authenticator: Arc<Authenticator>,
    cancel: CancellationToken,
}

impl Server {
    /// Create a new server instance.
    ///
    /// The authenticator is used for request authentication.
    /// Pass `None` to use a default authenticator (dev mode).
    pub fn new(
        config: ServerConfig,
        core: Arc<arkd_core::ArkService>,
        round_repo: Arc<dyn RoundRepository>,
        offchain_tx_repo: Arc<dyn OffchainTxRepository>,
        authenticator: Option<Arc<Authenticator>>,
    ) -> ApiResult<Self> {
        info!(grpc_addr = %config.grpc_addr, "Creating Ark API server");

        // Use provided authenticator or create default (dev mode)
        let authenticator = authenticator.unwrap_or_else(|| {
            if config.require_auth {
                tracing::warn!("require_auth = true but no authenticator provided — using insecure default key!");
            } else {
                info!("Using default authenticator (dev mode)");
            }
            Arc::new(Authenticator::new(vec![0u8; 32]))
        });

        let broker = Arc::new(crate::grpc::broker::EventBroker::new(256));

        Ok(Self {
            config,
            core,
            round_repo,
            broker,
            offchain_tx_repo,
            authenticator,
            cancel: CancellationToken::new(),
        })
    }

    /// Get server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the authenticator for creating tokens.
    pub fn authenticator(&self) -> &Arc<Authenticator> {
        &self.authenticator
    }

    /// Load TLS configuration if enabled.
    ///
    /// Returns `Some(ServerTlsConfig)` when `tls_enabled` is true and both
    /// cert/key paths are provided. Returns `None` for plaintext mode.
    async fn load_tls_config(&self) -> ApiResult<Option<tonic::transport::ServerTlsConfig>> {
        if !self.config.tls_enabled {
            return Ok(None);
        }

        let cert_path = self.config.tls_cert_path.as_deref().ok_or_else(|| {
            crate::ApiError::StartupError(
                "TLS enabled but tls_cert_path not configured".to_string(),
            )
        })?;
        let key_path = self.config.tls_key_path.as_deref().ok_or_else(|| {
            crate::ApiError::StartupError("TLS enabled but tls_key_path not configured".to_string())
        })?;

        let cert = tokio::fs::read(cert_path).await.map_err(|e| {
            crate::ApiError::StartupError(format!("Failed to read TLS cert {cert_path}: {e}"))
        })?;
        let key = tokio::fs::read(key_path).await.map_err(|e| {
            crate::ApiError::StartupError(format!("Failed to read TLS key {key_path}: {e}"))
        })?;

        let identity = tonic::transport::Identity::from_pem(cert, key);
        let tls_config = tonic::transport::ServerTlsConfig::new().identity(identity);

        info!("TLS configured with cert={cert_path} key={key_path}");
        Ok(Some(tls_config))
    }

    /// Run the server (blocking).
    ///
    /// Spawns both gRPC and admin servers and waits for them.
    /// If either server exits, the other is cancelled.
    pub async fn run(&self) -> ApiResult<()> {
        // Load TLS config once (before spawning tasks)
        let tls_config = self.load_tls_config().await?;

        let grpc_handle = self.spawn_grpc_server(tls_config.clone())?;
        let admin_handle = self.spawn_admin_server(tls_config)?;

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
    fn spawn_grpc_server(
        &self,
        tls_config: Option<tonic::transport::ServerTlsConfig>,
    ) -> ApiResult<JoinHandle<Result<(), tonic::transport::Error>>> {
        let addr = self
            .config
            .grpc_addr
            .parse()
            .map_err(|e| crate::ApiError::StartupError(format!("Invalid gRPC address: {e}")))?;

        let ark_service = ArkGrpcService::new(
            Arc::clone(&self.core),
            Arc::clone(&self.round_repo),
            Arc::clone(&self.broker),
            Arc::clone(&self.offchain_tx_repo),
        );

        // Create auth interceptor
        // In production, use AuthInterceptor::strict()
        // For dev/testing, use AuthInterceptor::permissive()
        let auth_interceptor =
            AuthInterceptor::new(Arc::clone(&self.authenticator), self.config.require_auth);

        // Wrap service with auth interceptor
        #[allow(clippy::result_large_err)] // tonic::Status is inherently large
        let svc = ArkServiceServer::with_interceptor(ark_service, move |req| {
            auth_interceptor.clone().authenticate(req)
        });
        let svc = tonic_web::enable(svc);
        let cancel = self.cancel.clone();

        let tls_enabled = tls_config.is_some();
        info!(%addr, require_auth = self.config.require_auth, tls = tls_enabled, "Spawning gRPC server (ArkService)");

        Ok(tokio::spawn(async move {
            let mut builder = TonicServer::builder();
            if let Some(tls) = tls_config {
                builder = builder.tls_config(tls).expect("invalid TLS configuration");
            }
            builder
                .accept_http1(true) // Required for tonic-web
                .add_service(svc)
                .serve_with_shutdown(addr, cancel.cancelled())
                .await
        }))
    }

    /// Spawn the admin gRPC server on a separate port.
    fn spawn_admin_server(
        &self,
        tls_config: Option<tonic::transport::ServerTlsConfig>,
    ) -> ApiResult<JoinHandle<Result<(), tonic::transport::Error>>> {
        let addr_str = self.config.admin_addr();
        let addr = addr_str
            .parse()
            .map_err(|e| crate::ApiError::StartupError(format!("Invalid admin address: {e}")))?;

        let admin_service = AdminGrpcService::new(Arc::clone(&self.core));
        let admin_svc = tonic_web::enable(AdminServiceServer::new(admin_service));

        let wallet_service = WalletGrpcService::new();
        let wallet_svc = tonic_web::enable(WalletServiceServer::new(wallet_service));

        let cancel = self.cancel.clone();

        let tls_enabled = tls_config.is_some();
        info!(%addr, tls = tls_enabled, "Spawning admin gRPC server (AdminService + WalletService)");

        Ok(tokio::spawn(async move {
            let mut builder = TonicServer::builder();
            if let Some(tls) = tls_config {
                builder = builder.tls_config(tls).expect("invalid TLS configuration");
            }
            builder
                .accept_http1(true)
                .add_service(admin_svc)
                .add_service(wallet_svc)
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

    #[test]
    fn test_server_config_tls_defaults_to_none() {
        let cfg = ServerConfig::default();
        assert!(!cfg.tls_enabled);
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
    }
}
