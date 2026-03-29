mod cli;
mod config;
mod profiling;
mod telemetry;

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;

use dark_core::{LocalSigner, LocalTxBuilder};

#[tokio::main]
async fn main() -> Result<()> {
    // --- CLI + Config ---
    let args = cli::Cli::parse();

    // Load file config early so telemetry can read otlp_endpoint
    let file_config = config::load_config(std::path::Path::new(&args.config))?;

    telemetry::init_telemetry(&telemetry::TelemetryConfig {
        otlp_endpoint: file_config.server.otlp_endpoint.clone(),
        service_name: "dark".to_string(),
        log_level: args.log_level.clone(),
    });

    info!("Starting dark v{}", env!("CARGO_PKG_VERSION"));

    // --- Continuous profiling (Pyroscope) ---
    let profiling_config = profiling::ProfilingConfig {
        pyroscope_url: file_config.server.pyroscope_url.clone(),
        pyroscope_app_name: file_config
            .server
            .pyroscope_app_name
            .clone()
            .unwrap_or_else(|| "dark".to_string()),
    };
    let _profiling_agent = profiling::start_pyroscope(&profiling_config);

    // Log deployment mode
    if file_config.is_light_mode() {
        info!(
            store = file_config.store_info(),
            "Starting in LIGHT mode (SQLite + in-memory live store)"
        );
    } else {
        info!(
            store = file_config.store_info(),
            "Starting in FULL mode (PostgreSQL + Redis)"
        );
    }

    // Apply file config to ServerConfig (CLI args override file config)
    let mut config = dark_api::ServerConfig::default();
    if let Some(addr) = args.grpc_addr.or(file_config.server.grpc_addr) {
        config.grpc_addr = addr;
    } else if let Some(port) = args.grpc_port {
        config.grpc_addr = format!("0.0.0.0:{}", port);
    }
    if let Some(port) = args.admin_port {
        config.admin_grpc_addr = Some(format!("0.0.0.0:{}", port));
    }
    if let Some(v) = file_config.server.rest_addr {
        config.rest_addr = Some(v);
    }
    if let Some(v) = file_config.server.require_auth {
        config.require_auth = v;
    }
    if let Some(v) = file_config.server.tls_cert_path {
        config.tls_cert_path = Some(v);
    }
    if let Some(v) = file_config.server.tls_key_path {
        config.tls_key_path = Some(v);
    }
    if let Some(v) = file_config.server.asp_key_hex {
        config.asp_key_hex = Some(v);
    }
    if let Some(v) = file_config.server.esplora_url {
        config.esplora_url = Some(v);
    }
    if let Some(v) = file_config.server.admin_token {
        config.admin_token = Some(v);
    }
    if let Some(v) = file_config.ark.round_duration_secs {
        config.round_duration_secs = v;
    }
    if let Some(v) = file_config.ark.round_interval_blocks {
        config.round_interval_blocks = v;
    }
    if let Some(v) = file_config.ark.allow_csv_block_type {
        config.allow_csv_block_type = v;
    }
    if let Some(v) = file_config.server.no_macaroons {
        config.no_macaroons = v;
    }
    if let Some(v) = file_config.server.no_tls {
        config.no_tls = v;
    }

    // Validate config before starting services
    if let Err(errors) = config.validate() {
        for e in &errors {
            tracing::error!("Config error: {}", e);
        }
        eprintln!(
            "Config validation failed with {} error(s). Exiting.",
            errors.len()
        );
        std::process::exit(1);
    }

    info!(
        grpc = %config.grpc_addr,
        require_auth = config.require_auth,
        esplora = ?config.esplora_url,
        round_secs = config.round_duration_secs,
        "Configuration loaded"
    );

    // --- Database ---
    let db = dark_db::Database::connect_in_memory()
        .await
        .map_err(|e| anyhow::anyhow!("DB init failed: {e}"))?;
    info!("Database ready (SQLite in-memory)");

    let sqlite_pool = db
        .sqlite_pool()
        .map_err(|e| anyhow::anyhow!("Failed to get SQLite pool: {e}"))?
        .clone();

    let round_repo = Arc::new(dark_db::SqliteRoundRepository::new(sqlite_pool.clone()));
    let vtxo_repo = Arc::new(dark_db::SqliteVtxoRepository::new(sqlite_pool.clone()));
    let forfeit_repo = Arc::new(dark_db::SqliteForfeitRepository::new(sqlite_pool.clone()));
    let signing_session_store =
        Arc::new(dark_db::SqliteSigningSessionStore::new(sqlite_pool.clone()));

    // Build the RepositoryIndexer so GetVtxos queries actually work
    let indexer = Arc::new(dark_core::RepositoryIndexer::new(
        vtxo_repo.clone() as Arc<dyn dark_core::ports::VtxoRepository>,
        round_repo.clone() as Arc<dyn dark_core::ports::RoundRepository>,
        forfeit_repo.clone() as Arc<dyn dark_core::ports::ForfeitRepository>,
    ));
    let offchain_tx_repo = Arc::new(dark_db::SqliteOffchainTxRepository::new(
        sqlite_pool.clone(),
    ));
    let asset_repo = Arc::new(dark_db::SqliteAssetRepository::new(sqlite_pool.clone()));
    // Run asset table migration
    asset_repo
        .run_migration()
        .await
        .map_err(|e| anyhow::anyhow!("Asset migration failed: {e}"))?;

    // --- Blockchain scanner ---
    let scanner: Arc<dyn dark_core::ports::BlockchainScanner> =
        if let Some(ref esplora_url) = config.esplora_url {
            info!(url = %esplora_url, "Starting EsploraScanner for on-chain monitoring");
            let scanner = Arc::new(dark_scanner::EsploraScanner::new(esplora_url, 30));
            Arc::clone(&scanner).start_polling();
            scanner
        } else {
            info!("No esplora_url configured — using NoopBlockchainScanner");
            Arc::new(dark_core::NoopBlockchainScanner::new())
        };

    // --- Wallet service ---
    // Use WalletServiceImpl (backed by WalletManager with BIP86 Taproot + file persistence)
    // when esplora_url is available. Falls back to StubWallet only when no esplora is configured.
    //
    // WalletManager auto-generates a mnemonic and derives descriptors on first start,
    // persisting state to a SQLite file. This enables real on-chain fee funding,
    // UTXO selection, and signing without requiring manual descriptor config.
    let wallet: Arc<dyn WalletService> = {
        let esplora_url = file_config
            .wallet
            .esplora_url
            .clone()
            .or_else(|| config.esplora_url.clone());

        if let Some(ref esplora) = esplora_url {
            let network = file_config.wallet.parse_network();
            let db_path = std::env::var("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".local/share/dark/wallet.db"))
                .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/dark-wallet.db"));

            info!(
                %esplora,
                ?network,
                db = %db_path.display(),
                "Initialising WalletManager (BIP86 Taproot, auto-generate mnemonic)"
            );

            let db_str = db_path.to_string_lossy().to_string();
            let wallet_config = match network {
                bitcoin::Network::Bitcoin => dark_wallet::WalletConfig::mainnet(&db_str),
                bitcoin::Network::Testnet => dark_wallet::WalletConfig::testnet(&db_str),
                _ => dark_wallet::WalletConfig::regtest(&db_str),
            }
            .with_esplora_url(esplora.clone());

            let manager = dark_wallet::WalletManager::new(wallet_config)
                .await
                .map_err(|e| anyhow::anyhow!("WalletManager init failed: {e}"))?;

            let wallet_svc = dark_wallet::WalletServiceImpl::new(Arc::new(manager));

            if let Err(e) = wallet_svc.sync().await {
                tracing::warn!("Initial wallet sync failed (non-fatal): {e}");
            }

            info!("WalletManager ready");
            Arc::new(wallet_svc)
        } else {
            info!("No esplora_url configured — using StubWallet (no on-chain ops)");
            Arc::new(StubWallet)
        }
    };

    // --- Core service ---

    // --- Fraud detector ---
    let _fraud_detector: Arc<dyn dark_core::ports::FraudDetector> =
        if let Some(ref esplora_url) = config.esplora_url {
            info!(url = %esplora_url, "Using EsploraFraudDetector for on-chain fraud detection");
            Arc::new(dark_scanner::EsploraFraudDetector::new(esplora_url))
        } else {
            info!("No esplora_url — using NoopFraudDetector");
            Arc::new(dark_core::NoopFraudDetector)
        };

    // --- Sweep service (wired with vtxo_repo/wallet/tx_builder later) ---
    let sweep_esplora_url = config.esplora_url.clone();

    // --- Nostr notifier (Issue #247) ---
    let notifier: Arc<dyn dark_core::ports::Notifier> =
        if let (Some(ref relay_url), Some(ref private_key)) = (
            &file_config.nostr.relay_url,
            &file_config.nostr.private_key_hex,
        ) {
            match dark_nostr::NostrNotifier::new(dark_nostr::NostrConfig::new(
                relay_url.clone(),
                private_key.clone(),
            )) {
                Ok(n) => {
                    info!(
                        relay = %relay_url,
                        pubkey = %n.pubkey(),
                        "Nostr notifier enabled for VTXO expiry notifications"
                    );
                    Arc::new(n)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to create Nostr notifier, using no-op");
                    Arc::new(dark_core::ports::NoopNotifier)
                }
            }
        } else {
            info!("Nostr notifier not configured — VTXO expiry notifications disabled");
            Arc::new(dark_core::ports::NoopNotifier)
        };

    // --- Alerts ---
    let alerts: Arc<dyn dark_core::Alerts> =
        if let Some(url) = file_config.server.alertmanager_url.as_deref() {
            info!(url, "Using Prometheus Alertmanager for operational alerts");
            Arc::new(dark_core::PrometheusAlertsManager::new(url))
        } else {
            Arc::new(dark_core::NoopAlerts)
        };

    // --- Core service (with stub impls for now) ---
    let exit_delay = file_config
        .ark
        .unilateral_exit_delay
        .unwrap_or(dark_core::DEFAULT_UNILATERAL_EXIT_DELAY);

    let ark_config = dark_core::ArkConfig {
        allow_csv_block_type: config.allow_csv_block_type,
        session_duration_secs: config.round_duration_secs,
        fee_program: dark_core::domain::FeeProgram {
            offchain_input_fee: file_config.fees.offchain_input_fee.unwrap_or(0),
            onchain_input_fee: file_config.fees.onchain_input_fee.unwrap_or(0),
            offchain_output_fee: file_config.fees.offchain_output_fee.unwrap_or(0),
            onchain_output_fee: file_config.fees.onchain_output_fee.unwrap_or(0),
            base_fee: file_config.fees.base_fee.unwrap_or(0),
        },
        unilateral_exit_delay: exit_delay,
        boarding_exit_delay: file_config
            .ark
            .boarding_exit_delay
            .unwrap_or(dark_core::DEFAULT_BOARDING_EXIT_DELAY),
        // Default vtxo_expiry_secs to unilateral_exit_delay so VTXOs become
        // sweepable as soon as the exit timelock elapses.
        vtxo_expiry_secs: file_config
            .ark
            .vtxo_expiry_secs
            .unwrap_or(exit_delay as i64),
        vtxo_expiry_blocks: file_config.ark.vtxo_expiry_blocks,
        ..Default::default()
    };

    // Build LocalSigner from config or generate random key for dev
    let signer: Arc<dyn SignerService> = if let Some(ref key_hex) = config.asp_key_hex {
        match LocalSigner::from_hex(key_hex) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::error!("Failed to parse asp_key_hex: {e}");
                std::process::exit(1);
            }
        }
    } else {
        info!("No asp_key_hex configured — generating random ASP key (dev mode)");
        Arc::new(LocalSigner::random())
    };

    // Pre-compute sweep service deps before wallet/ark_config are moved
    let sweep_service: Arc<dyn dark_core::ports::SweepService> =
        if let Some(ref esplora_url) = sweep_esplora_url {
            info!(url = %esplora_url, "Using EsploraSweepService for VTXO sweep monitoring");
            let sweep_tx_builder = Arc::new(
                LocalTxBuilder::new(&ark_config.network)
                    .with_csv_delay(ark_config.unilateral_exit_delay as u16),
            );
            Arc::new(
                dark_scanner::EsploraSweepService::new(esplora_url).with_deps(
                    vtxo_repo.clone(),
                    Arc::clone(&wallet),
                    sweep_tx_builder as Arc<dyn dark_core::ports::TxBuilder>,
                ),
            )
        } else {
            info!("No esplora_url — using NoopSweepService");
            Arc::new(dark_core::NoopSweepService)
        };

    let core = Arc::new(
        dark_core::ArkService::new(
            wallet,
            signer,
            vtxo_repo.clone(),
            Arc::new(
                LocalTxBuilder::new(&ark_config.network)
                    .with_csv_delay(ark_config.unilateral_exit_delay as u16),
            ),
            Arc::new(StubCache),
            Arc::new(dark_core::TokioBroadcastEventBus::new(
                dark_core::DEFAULT_EVENT_CHANNEL_CAPACITY,
            )),
            ark_config,
        )
        .with_scanner(scanner)
        .with_sweep_service(sweep_service)
        .with_asset_repo(asset_repo as Arc<dyn dark_core::ports::AssetRepository>)
        .with_notifier(notifier)
        .with_alerts(alerts)
        .with_indexer(indexer as Arc<dyn dark_core::ports::IndexerService>)
        .with_round_repo(round_repo.clone() as Arc<dyn dark_core::ports::RoundRepository>)
        .with_signing_session_store(
            signing_session_store as Arc<dyn dark_core::ports::SigningSessionStore>,
        ),
    );

    // --- Unlocker ---
    let unlocker: Option<Arc<dyn dark_core::ports::Unlocker>> = match file_config
        .server
        .unlocker_type
        .as_deref()
    {
        Some("env") => {
            info!("Using environment-based wallet unlocker (DARK_WALLET_PASS)");
            Some(Arc::new(dark_core::ports::EnvUnlocker))
        }
        Some("file") => {
            let path = file_config
                .server
                .unlocker_file_path
                .as_deref()
                .unwrap_or("~/.dark/wallet_password");
            info!(path = %path, "Using file-based wallet unlocker");
            Some(Arc::new(dark_core::ports::FileUnlocker::new(path)))
        }
        Some(other) => {
            tracing::warn!(unlocker_type = %other, "Unknown unlocker type, skipping auto-unlock");
            None
        }
        None => None,
    };
    let _ = unlocker; // Will be wired into wallet service when available

    // --- API server with integrated round loop ---
    // The server now manages the round loop internally via `run_with_scheduler`.
    // This ensures the event bridge subscribes BEFORE the scheduler fires its
    // first tick, preventing race conditions where BatchStarted events could be
    // missed by clients.
    info!(
        grpc = %config.grpc_addr,
        round_duration_secs = config.round_duration_secs,
        "Starting gRPC server with integrated round loop"
    );

    let round_duration_secs = config.round_duration_secs;
    let server = dark_api::Server::new(
        config,
        core,
        round_repo as Arc<dyn dark_core::ports::RoundRepository>,
        offchain_tx_repo as Arc<dyn dark_core::ports::OffchainTxRepository>,
        None,
    )?;

    server
        .run_with_scheduler(round_duration_secs)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))?;

    Ok(())
}

// ─── Stub implementations ───────────────────────────────────────────
// These mirror the mock impls from grpc_integration.rs.
// They will be replaced by real implementations as features are wired.

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;
use dark_core::domain::VtxoOutpoint;
use dark_core::error::ArkResult;
use dark_core::ports::*;

struct StubWallet;
#[async_trait]
impl WalletService for StubWallet {
    async fn status(&self) -> ArkResult<WalletStatus> {
        Ok(WalletStatus {
            initialized: true,
            unlocked: true,
            synced: true,
        })
    }
    async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap())
    }
    async fn derive_connector_address(&self) -> ArkResult<String> {
        Ok("tb1q_connector".to_string())
    }
    async fn sign_transaction(&self, partial_tx: &str, _extract_raw: bool) -> ArkResult<String> {
        Ok(partial_tx.to_string())
    }
    async fn select_utxos(
        &self,
        _amount: u64,
        _confirmed_only: bool,
    ) -> ArkResult<(Vec<TxInput>, u64)> {
        Ok((vec![], 0))
    }
    async fn broadcast_transaction(&self, _txs: Vec<String>) -> ArkResult<String> {
        Ok("txid".to_string())
    }
    async fn fee_rate(&self) -> ArkResult<u64> {
        Ok(1)
    }
    async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
        Ok(BlockTimestamp {
            height: 100,
            timestamp: 1_700_000_000,
        })
    }
    async fn get_dust_amount(&self) -> ArkResult<u64> {
        Ok(546)
    }
    async fn get_outpoint_status(&self, _outpoint: &VtxoOutpoint) -> ArkResult<bool> {
        Ok(false)
    }
    async fn gen_seed(&self) -> ArkResult<String> {
        Ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string())
    }
    async fn create_wallet(&self, _mnemonic: &str, _password: &str) -> ArkResult<()> {
        Ok(())
    }
    async fn restore_wallet(&self, _mnemonic: &str, _password: &str) -> ArkResult<()> {
        Ok(())
    }
    async fn unlock(&self, _password: &str) -> ArkResult<()> {
        Ok(())
    }
    async fn lock(&self) -> ArkResult<()> {
        Ok(())
    }
    async fn derive_address(&self) -> ArkResult<DerivedAddress> {
        Ok(DerivedAddress {
            address: "tb1qstub_address".to_string(),
            derivation_path: "m/84'/1'/0'/0/0".to_string(),
        })
    }
    async fn get_balance(&self) -> ArkResult<WalletBalance> {
        Ok(WalletBalance {
            confirmed: 0,
            unconfirmed: 0,
            locked: 0,
        })
    }
}

struct StubCache;
#[async_trait]
impl CacheService for StubCache {
    async fn set(&self, _key: &str, _value: &[u8], _ttl: Option<u64>) -> ArkResult<()> {
        Ok(())
    }
    async fn get(&self, _key: &str) -> ArkResult<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn delete(&self, _key: &str) -> ArkResult<bool> {
        Ok(false)
    }
}

// StubEvents replaced by dark_core::LoggingEventPublisher
