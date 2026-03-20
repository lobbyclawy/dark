mod cli;
mod config;
mod telemetry;

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;

use arkd_core::ports::TimeScheduler;
use arkd_scheduler::SimpleTimeScheduler;

#[tokio::main]
async fn main() -> Result<()> {
    // --- CLI + Config ---
    let args = cli::Cli::parse();

    // Load file config early so telemetry can read otlp_endpoint
    let file_config = config::load_config(std::path::Path::new(&args.config))?;

    telemetry::init_telemetry(&telemetry::TelemetryConfig {
        otlp_endpoint: file_config.server.otlp_endpoint.clone(),
        service_name: "arkd-rs".to_string(),
        log_level: args.log_level.clone(),
    });

    info!("Starting arkd-rs v{}", env!("CARGO_PKG_VERSION"));

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
    let mut config = arkd_api::ServerConfig::default();
    if let Some(addr) = args.grpc_addr.or(file_config.server.grpc_addr) {
        config.grpc_addr = addr;
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
    let db = arkd_db::Database::connect_in_memory()
        .await
        .map_err(|e| anyhow::anyhow!("DB init failed: {e}"))?;
    info!("Database ready (SQLite in-memory)");

    let sqlite_pool = db
        .sqlite_pool()
        .map_err(|e| anyhow::anyhow!("Failed to get SQLite pool: {e}"))?
        .clone();

    let round_repo = Arc::new(arkd_db::SqliteRoundRepository::new(sqlite_pool.clone()));
    let vtxo_repo = Arc::new(arkd_db::SqliteVtxoRepository::new(sqlite_pool.clone()));
    let offchain_tx_repo = Arc::new(arkd_db::SqliteOffchainTxRepository::new(
        sqlite_pool.clone(),
    ));
    let asset_repo = Arc::new(arkd_db::SqliteAssetRepository::new(sqlite_pool.clone()));
    // Run asset table migration
    asset_repo
        .run_migration()
        .await
        .map_err(|e| anyhow::anyhow!("Asset migration failed: {e}"))?;

    // --- Blockchain scanner ---
    let scanner: Arc<dyn arkd_core::ports::BlockchainScanner> =
        if let Some(ref esplora_url) = config.esplora_url {
            info!(url = %esplora_url, "Starting EsploraScanner for on-chain monitoring");
            let scanner = Arc::new(arkd_scanner::EsploraScanner::new(esplora_url, 30));
            Arc::clone(&scanner).start_polling();
            scanner
        } else {
            info!("No esplora_url configured — using NoopBlockchainScanner");
            Arc::new(arkd_core::NoopBlockchainScanner::new())
        };

    // --- Wallet service ---
    // Use BdkWalletService when wallet config is present, otherwise StubWallet.
    let wallet: Arc<dyn WalletService> = if file_config.wallet.is_configured() {
        let descriptor = file_config
            .wallet
            .descriptor
            .as_ref()
            .expect("wallet.descriptor checked by is_configured()");
        let change_descriptor = file_config
            .wallet
            .change_descriptor
            .as_deref()
            .unwrap_or(descriptor);
        let network = file_config.wallet.parse_network();
        let esplora_url = file_config
            .wallet
            .esplora_url
            .as_ref()
            .expect("wallet.esplora_url checked by is_configured()");

        info!(
            %esplora_url,
            ?network,
            "Initialising BDK wallet service"
        );

        let bdk_wallet =
            arkd_wallet::BdkWalletService::new(descriptor, change_descriptor, network, esplora_url)
                .await
                .map_err(|e| anyhow::anyhow!("BDK wallet init failed: {e}"))?;

        // TODO(#238): Initial sync could be slow on mainnet; consider async background sync.
        if let Err(e) = bdk_wallet.sync().await {
            tracing::warn!("Initial wallet sync failed (will retry): {e}");
        }

        info!("BDK wallet service ready");
        Arc::new(bdk_wallet)
    } else {
        info!("No [wallet] config — using StubWallet");
        Arc::new(StubWallet)
    };

    // --- Core service ---

    // --- Fraud detector ---
    let _fraud_detector: Arc<dyn arkd_core::ports::FraudDetector> =
        if let Some(ref esplora_url) = config.esplora_url {
            info!(url = %esplora_url, "Using EsploraFraudDetector for on-chain fraud detection");
            Arc::new(arkd_scanner::EsploraFraudDetector::new(esplora_url))
        } else {
            info!("No esplora_url — using NoopFraudDetector");
            Arc::new(arkd_core::NoopFraudDetector)
        };

    // --- Sweep service ---
    let sweep_service: Arc<dyn arkd_core::ports::SweepService> =
        if let Some(ref esplora_url) = config.esplora_url {
            info!(url = %esplora_url, "Using EsploraSweepService for VTXO sweep monitoring");
            Arc::new(arkd_scanner::EsploraSweepService::new(esplora_url))
        } else {
            info!("No esplora_url — using NoopSweepService");
            Arc::new(arkd_core::NoopSweepService)
        };

    // --- Nostr notifier (Issue #247) ---
    let notifier: Arc<dyn arkd_core::ports::Notifier> =
        if let (Some(ref relay_url), Some(ref private_key)) = (
            &file_config.nostr.relay_url,
            &file_config.nostr.private_key_hex,
        ) {
            match arkd_nostr::NostrNotifier::new(arkd_nostr::NostrConfig::new(
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
                    Arc::new(arkd_core::ports::NoopNotifier)
                }
            }
        } else {
            info!("Nostr notifier not configured — VTXO expiry notifications disabled");
            Arc::new(arkd_core::ports::NoopNotifier)
        };

    // --- Alerts ---
    let alerts: Arc<dyn arkd_core::Alerts> =
        if let Some(url) = file_config.server.alertmanager_url.as_deref() {
            info!(url, "Using Prometheus Alertmanager for operational alerts");
            Arc::new(arkd_core::PrometheusAlertsManager::new(url))
        } else {
            Arc::new(arkd_core::NoopAlerts)
        };

    // --- Core service (with stub impls for now) ---
    let ark_config = arkd_core::ArkConfig {
        allow_csv_block_type: config.allow_csv_block_type,
        fee_program: arkd_core::domain::FeeProgram {
            offchain_input_fee: file_config.fees.offchain_input_fee.unwrap_or(0),
            onchain_input_fee: file_config.fees.onchain_input_fee.unwrap_or(0),
            offchain_output_fee: file_config.fees.offchain_output_fee.unwrap_or(0),
            onchain_output_fee: file_config.fees.onchain_output_fee.unwrap_or(0),
            base_fee: file_config.fees.base_fee.unwrap_or(0),
        },
        ..Default::default()
    };

    let core = Arc::new(
        arkd_core::ArkService::new(
            wallet,
            Arc::new(StubSigner),
            vtxo_repo.clone(),
            Arc::new(StubTxBuilder),
            Arc::new(StubCache),
            Arc::new(arkd_core::TokioBroadcastEventBus::new(
                arkd_core::DEFAULT_EVENT_CHANNEL_CAPACITY,
            )),
            ark_config,
        )
        .with_scanner(scanner)
        .with_sweep_service(sweep_service)
        .with_asset_repo(asset_repo as Arc<dyn arkd_core::ports::AssetRepository>)
        .with_notifier(notifier)
        .with_alerts(alerts),
    );

    // --- Unlocker ---
    let unlocker: Option<Arc<dyn arkd_core::ports::Unlocker>> = match file_config
        .server
        .unlocker_type
        .as_deref()
    {
        Some("env") => {
            info!("Using environment-based wallet unlocker (ARKD_WALLET_PASS)");
            Some(Arc::new(arkd_core::ports::EnvUnlocker))
        }
        Some("file") => {
            let path = file_config
                .server
                .unlocker_file_path
                .as_deref()
                .unwrap_or("~/.arkd/wallet_password");
            info!(path = %path, "Using file-based wallet unlocker");
            Some(Arc::new(arkd_core::ports::FileUnlocker::new(path)))
        }
        Some(other) => {
            tracing::warn!(unlocker_type = %other, "Unknown unlocker type, skipping auto-unlock");
            None
        }
        None => None,
    };
    let _ = unlocker; // Will be wired into wallet service when available

    // --- API server ---
    info!(
        grpc = %config.grpc_addr,
        round_duration_secs = config.round_duration_secs,
        "Starting gRPC server"
    );

    // --- Round loop (auto-trigger rounds from scheduler) ---
    let scheduler = SimpleTimeScheduler;
    let tick_rx = scheduler
        .schedule(std::time::Duration::from_secs(config.round_duration_secs))
        .await
        .map_err(|e| anyhow::anyhow!("Scheduler error: {e}"))?;
    let _round_loop = arkd_core::spawn_round_loop(Arc::clone(&core), tick_rx);
    info!(
        interval_secs = config.round_duration_secs,
        "Round loop started"
    );

    let server = arkd_api::Server::new(
        config,
        core,
        round_repo as Arc<dyn arkd_core::ports::RoundRepository>,
        offchain_tx_repo as Arc<dyn arkd_core::ports::OffchainTxRepository>,
        None,
    )?;

    server
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))?;

    Ok(())
}

// ─── Stub implementations ───────────────────────────────────────────
// These mirror the mock impls from grpc_integration.rs.
// They will be replaced by real implementations as features are wired.

use arkd_core::domain::{Vtxo, VtxoOutpoint};
use arkd_core::error::ArkResult;
use arkd_core::ports::*;
use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

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
}

struct StubSigner;
#[async_trait]
impl SignerService for StubSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap())
    }
    async fn sign_transaction(&self, partial_tx: &str, _extract_raw: bool) -> ArkResult<String> {
        Ok(partial_tx.to_string())
    }
}

// StubVtxoRepo removed — now using SqliteVtxoRepository

struct StubTxBuilder;
#[async_trait]
impl arkd_core::ports::TxBuilder for StubTxBuilder {
    async fn build_commitment_tx(
        &self,
        _signer_pubkey: &XOnlyPublicKey,
        _intents: &[arkd_core::domain::Intent],
        _boarding_inputs: &[arkd_core::ports::BoardingInput],
    ) -> ArkResult<arkd_core::ports::CommitmentTxResult> {
        Ok(arkd_core::ports::CommitmentTxResult {
            commitment_tx: String::new(),
            vtxo_tree: vec![],
            connector_address: String::new(),
            connectors: vec![],
        })
    }
    async fn verify_forfeit_txs(
        &self,
        _vtxos: &[Vtxo],
        _connectors: &arkd_core::domain::FlatTxTree,
        _txs: &[String],
    ) -> ArkResult<Vec<arkd_core::ports::ValidForfeitTx>> {
        Ok(vec![])
    }
    async fn build_sweep_tx(
        &self,
        _inputs: &[arkd_core::ports::SweepInput],
    ) -> ArkResult<(String, String)> {
        Ok((String::new(), String::new()))
    }
    async fn get_sweepable_batch_outputs(
        &self,
        _vtxo_tree: &arkd_core::domain::FlatTxTree,
    ) -> ArkResult<Option<arkd_core::ports::SweepableOutput>> {
        Ok(None)
    }
    async fn finalize_and_extract(&self, _tx: &str) -> ArkResult<String> {
        Ok(String::new())
    }
    async fn verify_vtxo_tapscript_sigs(
        &self,
        _tx: &str,
        _must_include_signer: bool,
    ) -> ArkResult<bool> {
        Ok(true)
    }
    async fn verify_boarding_tapscript_sigs(
        &self,
        _signed_tx: &str,
        _commitment_tx: &str,
    ) -> ArkResult<std::collections::HashMap<u32, arkd_core::ports::SignedBoardingInput>> {
        Ok(std::collections::HashMap::new())
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

// StubEvents replaced by arkd_core::LoggingEventPublisher
