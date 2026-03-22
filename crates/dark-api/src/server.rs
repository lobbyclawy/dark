//! gRPC server implementation

use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server as TonicServer;
use tonic_reflection::server::Builder as ReflectionBuilder;
use tracing::info;

use dark_core::ports::{OffchainTxRepository, RoundRepository};
use dark_core::signer::SwappableSigner;

use crate::auth::Authenticator;
use crate::grpc::admin_service::AdminGrpcService;
use crate::grpc::ark_service::ArkGrpcService;
use crate::grpc::broker::{
    SharedEventBroker, SharedTransactionEventBroker, TransactionEventBroker,
};
use crate::grpc::indexer_service::{IndexerGrpcService, SubscriptionStore};
use crate::grpc::middleware::AuthInterceptor;
use crate::grpc::signer_manager_service::SignerManagerGrpcService;
use crate::grpc::wallet_service::WalletGrpcService;
use crate::proto::ark_v1::admin_service_server::AdminServiceServer;
use crate::proto::ark_v1::ark_service_server::ArkServiceServer;
use crate::proto::ark_v1::indexer_service_server::IndexerServiceServer;
use crate::proto::ark_v1::signer_manager_service_server::SignerManagerServiceServer;
use crate::proto::ark_v1::wallet_service_server::WalletServiceServer;
use crate::{ApiResult, ServerConfig};

/// Ark protocol gRPC server.
///
/// Runs two tonic servers:
/// - **gRPC** on `0.0.0.0:7070` — user-facing `ArkService`
/// - **Admin** on `0.0.0.0:7071` — operator `AdminService` + `SignerManagerService`
///
/// Both support tonic-web for REST / browser clients.
/// A shared `CancellationToken` ensures both servers shut down together.
pub struct Server {
    config: ServerConfig,
    core: Arc<dark_core::ArkService>,
    round_repo: Arc<dyn RoundRepository>,
    broker: SharedEventBroker,
    tx_broker: SharedTransactionEventBroker,
    offchain_tx_repo: Arc<dyn OffchainTxRepository>,
    authenticator: Arc<Authenticator>,
    swappable_signer: Option<Arc<SwappableSigner>>,
    subscriptions: SubscriptionStore,
    cancel: CancellationToken,
}

impl Server {
    /// Create a new server instance.
    ///
    /// The authenticator is used for request authentication.
    /// Pass `None` to use a default authenticator (dev mode).
    pub fn new(
        config: ServerConfig,
        core: Arc<dark_core::ArkService>,
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
        let tx_broker = Arc::new(TransactionEventBroker::new(256));

        Ok(Self {
            config,
            core,
            round_repo,
            broker,
            tx_broker,
            offchain_tx_repo,
            authenticator,
            swappable_signer: None,
            subscriptions: SubscriptionStore::default(),
            cancel: CancellationToken::new(),
        })
    }

    /// Set the swappable signer for the SignerManagerService.
    ///
    /// When set, the admin server will expose a `SignerManagerService` endpoint
    /// on port 7071 that allows runtime signer hot-swap via `LoadSigner` RPC.
    ///
    /// Must be called before [`Server::run()`].
    pub fn set_swappable_signer(&mut self, signer: Arc<SwappableSigner>) {
        self.swappable_signer = Some(signer);
    }

    /// Get server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the authenticator for creating tokens.
    pub fn authenticator(&self) -> &Arc<Authenticator> {
        &self.authenticator
    }

    /// Get the round event broker for publishing round lifecycle events.
    pub fn event_broker(&self) -> &SharedEventBroker {
        &self.broker
    }

    /// Get the transaction event broker for publishing transaction events.
    ///
    /// Use this to publish `TransactionEvent`s that will be streamed to clients
    /// via `GetTransactionsStream`. Events are filtered server-side based on
    /// the client's script filter.
    pub fn tx_event_broker(&self) -> &SharedTransactionEventBroker {
        &self.tx_broker
    }

    /// Load TLS configuration if enabled.
    ///
    /// Returns `Some(ServerTlsConfig)` when `tls_enabled` is true and both
    /// cert/key paths are provided. Returns `None` for plaintext mode.
    ///
    /// If `tls_enabled` is true but cert/key files don't exist, automatically
    /// generates a self-signed certificate using rcgen and writes it to the
    /// configured paths (defaulting to `~/.dark/tls.cert` and `~/.dark/tls.key`).
    async fn load_tls_config(&self) -> ApiResult<Option<tonic::transport::ServerTlsConfig>> {
        if !self.config.tls_enabled || self.config.no_tls {
            if self.config.no_tls {
                info!("TLS disabled via no_tls flag");
            }
            return Ok(None);
        }

        let default_dir = std::env::var("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(".dark");
        let cert_path = self
            .config
            .tls_cert_path
            .clone()
            .unwrap_or_else(|| default_dir.join("tls.cert").to_string_lossy().into_owned());
        let key_path = self
            .config
            .tls_key_path
            .clone()
            .unwrap_or_else(|| default_dir.join("tls.key").to_string_lossy().into_owned());

        // Auto-generate self-signed cert if files don't exist
        let cert_exists = tokio::fs::metadata(&cert_path).await.is_ok();
        let key_exists = tokio::fs::metadata(&key_path).await.is_ok();

        if !cert_exists || !key_exists {
            info!("TLS cert/key not found, generating self-signed certificate...");
            Self::generate_self_signed_cert(&cert_path, &key_path).await?;
            info!(cert = %cert_path, key = %key_path, "Self-signed TLS certificate generated");
        }

        let cert = tokio::fs::read(&cert_path).await.map_err(|e| {
            crate::ApiError::StartupError(format!("Failed to read TLS cert {cert_path}: {e}"))
        })?;
        let key = tokio::fs::read(&key_path).await.map_err(|e| {
            crate::ApiError::StartupError(format!("Failed to read TLS key {key_path}: {e}"))
        })?;

        let identity = tonic::transport::Identity::from_pem(cert, key);
        let tls_config = tonic::transport::ServerTlsConfig::new().identity(identity);

        info!("TLS configured with cert={cert_path} key={key_path}");
        Ok(Some(tls_config))
    }

    /// Generate a self-signed TLS certificate and write to the given paths.
    async fn generate_self_signed_cert(cert_path: &str, key_path: &str) -> ApiResult<()> {
        use std::path::Path;

        // Ensure parent directory exists
        if let Some(parent) = Path::new(cert_path).parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                crate::ApiError::StartupError(format!(
                    "Failed to create TLS directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        // Generate self-signed certificate using rcgen
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "0.0.0.0".to_string(),
        ])
        .map_err(|e| {
            crate::ApiError::StartupError(format!("Failed to generate self-signed cert: {e}"))
        })?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        tokio::fs::write(cert_path, cert_pem.as_bytes())
            .await
            .map_err(|e| {
                crate::ApiError::StartupError(format!(
                    "Failed to write TLS cert to {cert_path}: {e}"
                ))
            })?;
        tokio::fs::write(key_path, key_pem.as_bytes())
            .await
            .map_err(|e| {
                crate::ApiError::StartupError(format!("Failed to write TLS key to {key_path}: {e}"))
            })?;

        Ok(())
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

        // Bridge core ArkService domain events → gRPC EventBroker
        self.spawn_event_bridge();

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

    /// Spawn a background task that bridges core domain events to the gRPC EventBroker.
    /// This converts `ArkEvent`s (RoundStarted, RoundFinalized, etc.) into proto `RoundEvent`s
    /// so that `GetEventStream` clients receive batch lifecycle events.
    fn spawn_event_bridge(&self) {
        let broker = Arc::clone(&self.broker);
        let core = Arc::clone(&self.core);

        tokio::spawn(async move {
            let mut rx = match core.subscribe_events().await {
                Ok(rx) => rx,
                Err(e) => {
                    tracing::error!("Failed to subscribe to core events for broker bridge: {e}");
                    return;
                }
            };

            loop {
                match rx.recv().await {
                    Ok(event) => {
                        use crate::proto::ark_v1::*;

                        let round_event = match &event {
                            dark_core::domain::ArkEvent::BatchStarted {
                                round_id,
                                intent_ids,
                                ..
                            } => {
                                // Hash intent IDs (Go client expects SHA-256 hashes)
                                let hashes: Vec<String> = intent_ids
                                    .iter()
                                    .map(|id| {
                                        use std::collections::hash_map::DefaultHasher;
                                        use std::hash::{Hash, Hasher};
                                        let mut hasher = DefaultHasher::new();
                                        id.hash(&mut hasher);
                                        format!("{:016x}", hasher.finish())
                                    })
                                    .collect();

                                Some(RoundEvent {
                                    event: Some(round_event::Event::BatchStarted(
                                        BatchStartedEvent {
                                            id: round_id.clone(),
                                            intent_id_hashes: hashes,
                                            batch_expiry: 0,
                                        },
                                    )),
                                })
                            }
                            dark_core::domain::ArkEvent::RoundFinalized {
                                round_id,
                                commitment_tx,
                                ..
                            } => {
                                // Emit both BatchFinalization and BatchFinalized
                                broker.publish(RoundEvent {
                                    event: Some(round_event::Event::BatchFinalization(
                                        BatchFinalizationEvent {
                                            id: round_id.clone(),
                                            commitment_tx: commitment_tx.clone(),
                                        },
                                    )),
                                });

                                // Extract txid from commitment tx PSBT
                                let txid = hex::decode(commitment_tx)
                                    .ok()
                                    .and_then(|b| bitcoin::psbt::Psbt::deserialize(&b).ok())
                                    .map(|psbt| psbt.unsigned_tx.compute_txid().to_string())
                                    .unwrap_or_default();

                                Some(RoundEvent {
                                    event: Some(round_event::Event::BatchFinalized(
                                        BatchFinalizedEvent {
                                            id: round_id.clone(),
                                            commitment_txid: txid,
                                        },
                                    )),
                                })
                            }
                            dark_core::domain::ArkEvent::RoundFailed {
                                round_id, reason, ..
                            } => Some(RoundEvent {
                                event: Some(round_event::Event::BatchFailed(BatchFailedEvent {
                                    id: round_id.clone(),
                                    reason: reason.clone(),
                                })),
                            }),
                            dark_core::domain::ArkEvent::TreeTxReady {
                                round_id,
                                txid,
                                tx,
                                cosigners,
                            } => Some(RoundEvent {
                                event: Some(round_event::Event::TreeTx(TreeTxEvent {
                                    id: round_id.clone(),
                                    topic: cosigners.clone(),
                                    batch_index: 0, // vtxo tree
                                    txid: txid.clone(),
                                    tx: tx.clone(),
                                    children: std::collections::HashMap::new(),
                                })),
                            }),
                            dark_core::domain::ArkEvent::TreeSigningPhaseStarted {
                                round_id,
                                cosigners_pubkeys,
                                unsigned_commitment_tx,
                            } => Some(RoundEvent {
                                event: Some(round_event::Event::TreeSigningStarted(
                                    TreeSigningStartedEvent {
                                        id: round_id.clone(),
                                        cosigners_pubkeys: cosigners_pubkeys.clone(),
                                        unsigned_commitment_tx: unsigned_commitment_tx.clone(),
                                    },
                                )),
                            }),
                            dark_core::domain::ArkEvent::TreeNoncesForwarded {
                                round_id,
                                txid,
                                nonces_by_pubkey,
                            } => {
                                let topic: Vec<String> = nonces_by_pubkey.keys().cloned().collect();
                                Some(RoundEvent {
                                    event: Some(round_event::Event::TreeNonces(TreeNoncesEvent {
                                        id: round_id.clone(),
                                        topic,
                                        txid: txid.clone(),
                                        nonces: nonces_by_pubkey.clone(),
                                    })),
                                })
                            }
                            _ => None,
                        };

                        if let Some(event) = round_event {
                            let kind = match &event.event {
                                Some(round_event::Event::BatchStarted(_)) => "BatchStarted",
                                Some(round_event::Event::BatchFinalization(_)) => {
                                    "BatchFinalization"
                                }
                                Some(round_event::Event::BatchFinalized(_)) => "BatchFinalized",
                                Some(round_event::Event::BatchFailed(_)) => "BatchFailed",
                                Some(round_event::Event::TreeTx(_)) => "TreeTx",
                                Some(round_event::Event::TreeSigningStarted(_)) => {
                                    "TreeSigningStarted"
                                }
                                Some(round_event::Event::TreeNonces(_)) => "TreeNonces",
                                _ => "Other",
                            };
                            let subs = broker.publish(event);
                            tracing::info!(kind, subscribers = subs, "Event bridge → broker");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "Event bridge lagged — some events missed");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::info!("Event bus closed — stopping event bridge");
                        return;
                    }
                }
            }
        });
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
            Arc::clone(&self.tx_broker),
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

        let indexer_service =
            IndexerGrpcService::new(Arc::clone(&self.core), Arc::clone(&self.subscriptions));
        let indexer_svc = tonic_web::enable(IndexerServiceServer::new(indexer_service));

        // gRPC reflection service (enables grpcurl without -proto flag)
        let reflection_svc = ReflectionBuilder::configure()
            .register_encoded_file_descriptor_set(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/ark_descriptor.bin"
            )))
            .build_v1()
            .expect("failed to build reflection service");

        let cancel = self.cancel.clone();

        let tls_enabled = tls_config.is_some();
        info!(%addr, require_auth = self.config.require_auth, tls = tls_enabled, "Spawning gRPC server (ArkService + IndexerService + Reflection)");

        Ok(tokio::spawn(async move {
            let mut builder = TonicServer::builder();
            if let Some(tls) = tls_config {
                builder = builder.tls_config(tls).expect("invalid TLS configuration");
            }
            builder
                .accept_http1(true) // Required for tonic-web
                .add_service(svc)
                .add_service(indexer_svc)
                .add_service(reflection_svc)
                .serve_with_shutdown(addr, cancel.cancelled())
                .await
        }))
    }

    /// Spawn the admin gRPC + REST server on a separate port.
    ///
    /// The admin port serves both:
    /// - gRPC services (AdminService, WalletService, optionally SignerManagerService)
    /// - REST/JSON endpoints under `/v1/admin/...` for HTTP clients (e.g. Go e2e tests)
    ///
    /// REST handlers delegate directly to the same gRPC service implementations,
    /// so behavior is identical regardless of transport.
    fn spawn_admin_server(
        &self,
        tls_config: Option<tonic::transport::ServerTlsConfig>,
    ) -> ApiResult<JoinHandle<Result<(), tonic::transport::Error>>> {
        let addr_str = self.config.admin_addr();
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .map_err(|e| crate::ApiError::StartupError(format!("Invalid admin address: {e}")))?;

        // Create gRPC service implementations (shared with REST via Arc)
        let admin_service = Arc::new(AdminGrpcService::new_with_auth(
            Arc::clone(&self.core),
            Arc::clone(&self.authenticator),
        ));
        let wallet_service = Arc::new(WalletGrpcService::new(self.core.wallet()));

        // Wrap in tonic-web for gRPC
        let admin_svc = tonic_web::enable(AdminServiceServer::from_arc(Arc::clone(&admin_service)));
        let wallet_svc =
            tonic_web::enable(WalletServiceServer::from_arc(Arc::clone(&wallet_service)));

        // Build optional SignerManagerService (only if swappable_signer was configured)
        let signer_mgr_svc = self.swappable_signer.as_ref().map(|signer| {
            let signer_mgr = SignerManagerGrpcService::new(Arc::clone(signer));
            tonic_web::enable(SignerManagerServiceServer::new(signer_mgr))
        });

        // Build the REST router sharing the same service instances
        let rest_state = crate::rest::RestState {
            wallet_svc: wallet_service,
            admin_svc: admin_service,
        };
        let rest_router = crate::rest::build_rest_router(rest_state);

        let cancel = self.cancel.clone();

        let has_signer_mgr = signer_mgr_svc.is_some();
        let tls_enabled = tls_config.is_some();
        info!(
            %addr, tls = tls_enabled, signer_manager = has_signer_mgr,
            "Spawning admin server (gRPC + REST) (AdminService + WalletService{})",
            if has_signer_mgr { " + SignerManagerService" } else { "" }
        );

        Ok(tokio::spawn(async move {
            let mut builder = TonicServer::builder();
            if let Some(tls) = tls_config {
                builder = builder.tls_config(tls).expect("invalid TLS configuration");
            }
            let mut grpc_routes = builder
                .accept_http1(true)
                .add_service(admin_svc)
                .add_service(wallet_svc);

            // Conditionally add SignerManagerService
            if let Some(signer_svc) = signer_mgr_svc {
                grpc_routes = grpc_routes.add_service(signer_svc);
            }

            // Convert tonic router to axum and merge with REST routes.
            // gRPC paths (e.g. /ark.v1.AdminService/...) and REST paths
            // (e.g. /v1/admin/...) don't overlap, so merging is safe.
            #[allow(deprecated)] // into_router deprecated in favor of Routes::into_axum_router
            let grpc_axum = grpc_routes.into_router();
            let combined = grpc_axum.merge(rest_router);

            // Serve the combined router via axum
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("bind admin address");
            axum::serve(listener, combined)
                .with_graceful_shutdown(cancel.cancelled_owned())
                .await
                .expect("admin server error");

            Ok::<(), tonic::transport::Error>(())
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
