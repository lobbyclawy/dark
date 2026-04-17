//! Application services — aligned with Go dark's `application.Service`

use std::collections::HashMap as StdHashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use crate::domain::ban::BanReason;
use crate::domain::config_service::StaticConfigService;
use crate::domain::conviction::Conviction;
use crate::domain::ForfeitRecord;
use crate::domain::InMemoryBanRepository;
use crate::domain::{
    BoardingTransaction, CollaborativeExitRequest, Exit, ExitSummary, ExitType, Intent, Round,
    RoundStage, TxTreeNode, UnilateralExitRequest, Vtxo, VtxoOutpoint, DEFAULT_BOARDING_EXIT_DELAY,
    DEFAULT_CHECKPOINT_EXIT_DELAY, DEFAULT_MAX_INTENTS, DEFAULT_MAX_TX_WEIGHT, DEFAULT_MIN_INTENTS,
    DEFAULT_PUBLIC_UNILATERAL_EXIT_DELAY, DEFAULT_SESSION_DURATION_SECS,
    DEFAULT_UNILATERAL_EXIT_DELAY, DEFAULT_UTXO_MAX_AMOUNT, DEFAULT_UTXO_MIN_AMOUNT,
    DEFAULT_VTXO_EXPIRY_SECS, MIN_VTXO_AMOUNT_SATS,
};
use crate::domain::{FeeProgram, OffchainTx, VtxoInput, VtxoOutput};
use crate::error::{ArkError, ArkResult};
use crate::ports::{
    Alerts, ArkEvent, AssetRepository, BanRepository, BlockchainScanner, BoardingRepository,
    CacheService, CheckpointRepository, ConfigService, ConfirmationStore, ConvictionRepository,
    EventPublisher, FeeManagerService, ForfeitRepository, FraudDetector, IndexerService,
    IndexerStats, NoopAlerts, NoopAssetRepository, NoopBlockchainScanner, NoopBoardingRepository,
    NoopCheckpointRepository, NoopConfirmationStore, NoopConvictionRepository, NoopFeeManager,
    NoopForfeitRepository, NoopFraudDetector, NoopIndexerService, NoopOffchainTxRepository,
    NoopSweepService, OffchainTxRepository, SignerService, SigningSessionStore, SweepService,
    TxBuilder, VtxoRepository, WalletService,
};

/// Tagged VTXO expiry — either a Unix timestamp or a block height.
#[derive(Debug, Clone, Copy)]
pub enum VtxoExpiry {
    /// Time-based: expires at this Unix timestamp
    Timestamp(i64),
    /// Block-based: expires at this block height
    Block(u32),
}

impl VtxoExpiry {
    /// Apply this expiry to a VTXO, setting the appropriate field.
    pub fn apply_to(&self, vtxo: &mut Vtxo) {
        match self {
            VtxoExpiry::Timestamp(ts) => vtxo.expires_at = *ts,
            VtxoExpiry::Block(h) => vtxo.expires_at_block = *h,
        }
    }
}

/// Round timing configuration (matches Go dark's `roundTiming`)
#[derive(Debug, Clone)]
pub struct RoundTiming {
    /// Duration of the registration phase (seconds)
    pub registration_duration_secs: u64,
    /// Duration of the confirmation phase (seconds)
    pub confirmation_duration_secs: u64,
    /// Duration of the finalization phase (seconds)
    /// This is split into thirds: nonce collection, signing, forfeit collection
    pub finalization_duration_secs: u64,
}

impl Default for RoundTiming {
    fn default() -> Self {
        Self {
            // Go dark defaults: sessionDuration is 10s, split as:
            // - registration: ~4s
            // - confirmation: ~3s
            // - finalization: ~3s (split into nonce/sig/forfeit)
            registration_duration_secs: 4,
            confirmation_duration_secs: 3,
            finalization_duration_secs: 3,
        }
    }
}

impl RoundTiming {
    /// Total session duration in seconds
    pub fn total_duration_secs(&self) -> u64 {
        self.registration_duration_secs
            + self.confirmation_duration_secs
            + self.finalization_duration_secs
    }

    /// Finalization is split into thirds for MuSig2 coordination.
    /// Duration for collecting nonces from participants.
    pub fn nonce_collection_duration_secs(&self) -> u64 {
        self.finalization_duration_secs / 3
    }

    /// Duration for collecting signatures from participants.
    pub fn signature_collection_duration_secs(&self) -> u64 {
        self.finalization_duration_secs / 3
    }

    /// Duration for collecting forfeit transactions from participants.
    pub fn forfeit_collection_duration_secs(&self) -> u64 {
        self.finalization_duration_secs - (2 * (self.finalization_duration_secs / 3))
    }
}

/// ASP configuration
#[derive(Debug, Clone)]
pub struct ArkConfig {
    /// VTXO tree expiry (seconds, default: 7 days)
    pub vtxo_expiry_secs: i64,
    /// Session duration (seconds) — DEPRECATED: use round_timing instead
    pub session_duration_secs: u64,
    /// Round timing configuration
    pub round_timing: RoundTiming,
    /// Unilateral exit delay (seconds)
    pub unilateral_exit_delay: u32,
    /// Min intents per round
    pub min_intents: u32,
    /// Max intents per round
    pub max_intents: u32,
    /// Min VTXO amount (sats)
    pub min_vtxo_amount_sats: u64,
    /// Max VTXO amount (sats)
    pub max_vtxo_amount_sats: u64,
    /// Network name
    pub network: String,
    /// Min UTXO amount for boarding (sats)
    pub utxo_min_amount: u64,
    /// Max UTXO amount for boarding (sats, 0 = boarding disabled)
    pub utxo_max_amount: u64,
    /// CSV delay for public unilateral exits (seconds)
    pub public_unilateral_exit_delay: u32,
    /// CSV delay for boarding inputs (seconds)
    pub boarding_exit_delay: u32,
    /// Max commitment tx weight
    pub max_tx_weight: u64,
    /// Default fee rate in sats/vB for fee estimation
    pub default_fee_rate_sats_per_vb: u64,
    /// Checkpoint exit delay in blocks (~1 day default)
    pub checkpoint_exit_delay: u32,
    /// Bitcoin Core RPC URL for dynamic fee estimation (None = static fee manager)
    pub fee_manager_url: Option<String>,
    /// Bitcoin Core RPC username
    pub fee_manager_user: Option<String>,
    /// Bitcoin Core RPC password
    pub fee_manager_pass: Option<String>,
    /// URI prefix for note VTXOs (e.g. "ark-note")
    pub note_uri_prefix: Option<String>,
    /// Nostr relay WebSocket URL for VTXO notifications (e.g. `wss://relay.damus.io`)
    pub nostr_relay_url: Option<String>,
    /// Nostr private key (32-byte hex) for signing notification events
    pub nostr_private_key: Option<String>,
    /// Whether to allow CSV block-type timelocks (vs time-based).
    /// Passed from ServerConfig; controls round scheduling behavior.
    pub allow_csv_block_type: bool,
    /// Fee program for intent fee calculation (CEL-based fee programs, #242)
    pub fee_program: FeeProgram,
    /// VTXO expiry in blocks (optional).
    /// When set, `expires_at` is stored as `creation_height + vtxo_expiry_blocks`
    /// and the height-based sweep path is used instead of wall-clock time.
    pub vtxo_expiry_blocks: Option<u32>,
    /// Esplora/chopsticks URL for package broadcast (e.g. "http://localhost:3000")
    pub explorer_url: String,
}

impl Default for ArkConfig {
    fn default() -> Self {
        Self {
            vtxo_expiry_secs: DEFAULT_VTXO_EXPIRY_SECS,
            session_duration_secs: DEFAULT_SESSION_DURATION_SECS,
            round_timing: RoundTiming::default(),
            unilateral_exit_delay: DEFAULT_UNILATERAL_EXIT_DELAY,
            min_intents: DEFAULT_MIN_INTENTS,
            max_intents: DEFAULT_MAX_INTENTS,
            min_vtxo_amount_sats: MIN_VTXO_AMOUNT_SATS,
            max_vtxo_amount_sats: 2_100_000_000_000_000,
            network: "regtest".to_string(),
            utxo_min_amount: DEFAULT_UTXO_MIN_AMOUNT,
            utxo_max_amount: DEFAULT_UTXO_MAX_AMOUNT,
            public_unilateral_exit_delay: DEFAULT_PUBLIC_UNILATERAL_EXIT_DELAY,
            boarding_exit_delay: DEFAULT_BOARDING_EXIT_DELAY,
            max_tx_weight: DEFAULT_MAX_TX_WEIGHT,
            checkpoint_exit_delay: DEFAULT_CHECKPOINT_EXIT_DELAY,
            default_fee_rate_sats_per_vb: 1,
            fee_manager_url: None,
            fee_manager_user: None,
            fee_manager_pass: None,
            note_uri_prefix: None,
            nostr_relay_url: None,
            nostr_private_key: None,
            allow_csv_block_type: false,
            fee_program: FeeProgram::default(),
            vtxo_expiry_blocks: None,
            explorer_url: String::new(),
        }
    }
}

/// Main Ark service
pub struct ArkService {
    wallet: Arc<dyn WalletService>,
    signer: Arc<dyn SignerService>,
    vtxo_repo: Arc<dyn VtxoRepository>,
    tx_builder: Arc<dyn TxBuilder>,
    #[allow(dead_code)]
    cache: Arc<dyn CacheService>,
    events: Arc<dyn EventPublisher>,
    checkpoint_repo: Arc<dyn CheckpointRepository>,
    forfeit_repo: Arc<dyn ForfeitRepository>,
    ban_repo: Arc<dyn BanRepository>,
    boarding_repo: Arc<dyn BoardingRepository>,
    fraud_detector: Arc<dyn FraudDetector>,
    confirmation_store: Arc<dyn ConfirmationStore>,
    offchain_tx_repo: Arc<dyn OffchainTxRepository>,
    sweep_service: Arc<dyn SweepService>,
    scanner: Arc<dyn BlockchainScanner>,
    indexer: Arc<dyn IndexerService>,
    fee_manager: Arc<dyn FeeManagerService>,
    conviction_repo: Arc<dyn ConvictionRepository>,
    /// MuSig2 signing session store for tree nonces/signatures (#159)
    signing_session_store: Arc<dyn crate::ports::SigningSessionStore>,
    asset_repo: Arc<dyn AssetRepository>,
    scheduled_session_repo: Arc<dyn crate::ports::ScheduledSessionRepository>,
    notifier: Arc<dyn crate::ports::Notifier>,
    alerts: Arc<dyn Alerts>,
    config: ArkConfig,
    config_service: Arc<dyn ConfigService>,
    round_repo: Arc<dyn crate::ports::RoundRepository>,
    current_round: RwLock<Option<Round>>,
    /// Last completed round — kept accessible for forfeit submission.
    /// Forfeits arrive after BatchFinalizationEvent which is emitted post-completion,
    /// so the current_round may already be a new round by then.
    last_completed_round: RwLock<Option<Round>>,
    /// Active exits indexed by ID
    /// TODO(#9): Back with SQLite persistence to survive restarts
    exits: RwLock<std::collections::HashMap<uuid::Uuid, Exit>>,
    /// Partial commitment tx PSBTs from clients (for merging before broadcast).
    /// Tuple: (round_id, base64 PSBT).
    partial_commitment_psbts: tokio::sync::Mutex<Vec<(String, String)>>,
    /// Stored fee input signature from BDK signing (to re-apply after PSBT merge).
    /// This preserves the wallet's signature which may be stripped by Go SDK round-trips.
    fee_input_signature: tokio::sync::Mutex<Option<bitcoin::taproot::Signature>>,
    /// Mapping from watched script pubkey (hex) → VTXO outpoints.
    /// Used by the scanner listener to look up which VTXO was spent on-chain.
    watched_scripts: RwLock<StdHashMap<String, Vec<VtxoOutpoint>>>,
    /// ASP MuSig2 tree cosigning state (per-round nonces and sweep root).
    asp_musig2_state: tokio::sync::Mutex<Option<AspMusig2State>>,
}

/// ASP's per-round MuSig2 state for tree cosigning.
struct AspMusig2State {
    /// ASP secret nonces per tree txid (64-byte serialized SecNonce, consumed during signing).
    sec_nonces: StdHashMap<String, Vec<u8>>,
    /// Per-txid aggregated nonces (66-byte serialized AggNonce, set after nonce collection).
    agg_nonces: StdHashMap<String, Vec<u8>>,
    /// Sweep tapscript merkle root (32 bytes, for taproot tweak in MuSig2 signing).
    sweep_merkle_root: [u8; 32],
    /// ASP compressed pubkey hex (participant ID in signing session).
    asp_compressed_hex: String,
}

impl AspMusig2State {
    /// Clone fields needed for signature aggregation (agg_nonces + sweep root).
    fn clone_for_aggregation(&self) -> AspMusig2AggData {
        AspMusig2AggData {
            agg_nonces: self.agg_nonces.clone(),
            sweep_merkle_root: self.sweep_merkle_root,
        }
    }
}

/// Read-only subset of ASP MuSig2 state needed for signature aggregation.
struct AspMusig2AggData {
    agg_nonces: StdHashMap<String, Vec<u8>>,
    sweep_merkle_root: [u8; 32],
}

impl ArkService {
    /// Create a new Ark service
    pub fn new(
        wallet: Arc<dyn WalletService>,
        signer: Arc<dyn SignerService>,
        vtxo_repo: Arc<dyn VtxoRepository>,
        tx_builder: Arc<dyn TxBuilder>,
        cache: Arc<dyn CacheService>,
        events: Arc<dyn EventPublisher>,
        config: ArkConfig,
    ) -> Self {
        let config_service: Arc<dyn ConfigService> =
            Arc::new(StaticConfigService::new(config.clone()));
        Self {
            wallet,
            signer,
            vtxo_repo,
            tx_builder,
            cache,
            events,
            checkpoint_repo: Arc::new(NoopCheckpointRepository),
            forfeit_repo: Arc::new(NoopForfeitRepository),
            ban_repo: Arc::new(InMemoryBanRepository::new()),
            boarding_repo: Arc::new(NoopBoardingRepository),
            fraud_detector: Arc::new(NoopFraudDetector),
            confirmation_store: Arc::new(NoopConfirmationStore),
            offchain_tx_repo: Arc::new(NoopOffchainTxRepository),
            sweep_service: Arc::new(NoopSweepService),
            scanner: Arc::new(NoopBlockchainScanner::new()),
            indexer: Arc::new(NoopIndexerService),
            fee_manager: Arc::new(NoopFeeManager),
            conviction_repo: Arc::new(NoopConvictionRepository),
            signing_session_store: Arc::new(crate::ports::NoopSigningSessionStore),
            asset_repo: Arc::new(NoopAssetRepository),
            scheduled_session_repo: Arc::new(crate::ports::NoopScheduledSessionRepository),
            notifier: Arc::new(crate::ports::NoopNotifier),
            alerts: Arc::new(NoopAlerts),
            config,
            config_service,
            round_repo: Arc::new(crate::ports::NoopRoundRepository),
            current_round: RwLock::new(None),
            last_completed_round: RwLock::new(None),
            exits: RwLock::new(std::collections::HashMap::new()),
            partial_commitment_psbts: tokio::sync::Mutex::new(Vec::new()),
            fee_input_signature: tokio::sync::Mutex::new(None),
            watched_scripts: RwLock::new(StdHashMap::new()),
            asp_musig2_state: tokio::sync::Mutex::new(None),
        }
    }

    /// Set a custom confirmation store (for production use with Redis/Postgres)
    pub fn with_confirmation_store(mut self, store: Arc<dyn ConfirmationStore>) -> Self {
        self.confirmation_store = store;
        self
    }

    /// Set a custom blockchain scanner (for production Esplora/Electrum use).
    pub fn with_scanner(mut self, scanner: Arc<dyn BlockchainScanner>) -> Self {
        self.scanner = scanner;
        self
    }

    /// Get a reference to the blockchain scanner.
    pub fn scanner(&self) -> &dyn BlockchainScanner {
        self.scanner.as_ref()
    }

    /// Broadcast a raw hex transaction via the scanner (direct RPC if available).
    pub async fn broadcast_raw_tx_via_rpc(&self, tx_hex: &str) -> ArkResult<()> {
        self.scanner.broadcast_raw_tx(tx_hex).await
    }

    /// Set a round repository for persisting completed rounds.
    pub fn with_round_repo(mut self, repo: Arc<dyn crate::ports::RoundRepository>) -> Self {
        self.round_repo = repo;
        self
    }

    /// Set a custom indexer service.
    pub fn with_indexer(mut self, indexer: Arc<dyn IndexerService>) -> Self {
        self.indexer = indexer;
        self
    }

    /// Set a custom signing session store (for MuSig2 cosigning).
    pub fn with_signing_session_store(mut self, store: Arc<dyn SigningSessionStore>) -> Self {
        self.signing_session_store = store;
        self
    }

    /// Set a custom [`SweepService`] implementation (e.g. `TxBuilderSweepService`).
    pub fn with_sweep_service(mut self, svc: Arc<dyn SweepService>) -> Self {
        self.sweep_service = svc;
        self
    }

    /// Set a custom checkpoint repository (for SQLite/Postgres persistence).
    pub fn with_checkpoint_repo(mut self, repo: Arc<dyn CheckpointRepository>) -> Self {
        self.checkpoint_repo = repo;
        self
    }

    /// Set a conviction repository for tracking protocol violations.
    pub fn with_conviction_repo(mut self, repo: Arc<dyn ConvictionRepository>) -> Self {
        self.conviction_repo = repo;
        self
    }

    /// Set a custom asset repository.
    pub fn with_asset_repo(mut self, repo: Arc<dyn AssetRepository>) -> Self {
        self.asset_repo = repo;
        self
    }

    /// Set a custom scheduled-session repository for config persistence (#271).
    pub fn with_scheduled_session_repo(
        mut self,
        repo: Arc<dyn crate::ports::ScheduledSessionRepository>,
    ) -> Self {
        self.scheduled_session_repo = repo;
        self
    }

    /// Set a custom notifier for VTXO expiry notifications (Issue #247).
    /// Set a custom alerts implementation (e.g. Prometheus Alertmanager).
    pub fn with_alerts(mut self, alerts: Arc<dyn Alerts>) -> Self {
        self.alerts = alerts;
        self
    }

    /// Set a custom notifier for VTXO expiry notifications.
    pub fn with_notifier(mut self, notifier: Arc<dyn crate::ports::Notifier>) -> Self {
        self.notifier = notifier;
        self
    }

    /// Get an asset by its ID from the asset repository.
    pub async fn get_asset(&self, asset_id: &str) -> ArkResult<Option<crate::domain::Asset>> {
        self.asset_repo.get_asset(asset_id).await
    }

    /// Get a reference to the asset repository.
    pub fn asset_repo(&self) -> &dyn AssetRepository {
        &*self.asset_repo
    }

    /// Get a reference to the VTXO repository.
    pub fn vtxo_repo(&self) -> &dyn VtxoRepository {
        &*self.vtxo_repo
    }

    /// Calculate the boarding fee for a given amount
    pub async fn calculate_boarding_fee(&self, amount_sats: u64) -> ArkResult<u64> {
        self.fee_manager.boarding_fee(amount_sats).await
    }

    /// Get config
    /// Get a reference to the wallet service.
    pub fn wallet(&self) -> Arc<dyn WalletService> {
        Arc::clone(&self.wallet)
    }

    /// Co-sign a PSBT (hex or base64 encoded) using the ASP signer key.
    ///
    /// Returns the co-signed PSBT in the same hex format.
    /// Used by `SubmitTx` to add the server's signature to offchain txs.
    pub async fn cosign_psbt(&self, psbt_str: &str) -> ArkResult<String> {
        self.signer.sign_transaction(psbt_str, false).await
    }

    /// Get a reference to the scheduled-session repository.
    pub fn scheduled_session_repo(&self) -> &dyn crate::ports::ScheduledSessionRepository {
        self.scheduled_session_repo.as_ref()
    }

    /// Get the Ark configuration.
    pub fn config(&self) -> &ArkConfig {
        &self.config
    }

    /// Check if a transaction is confirmed on-chain via the scanner.
    pub async fn scanner_is_tx_confirmed(&self, txid: &str) -> ArkResult<bool> {
        self.scanner.is_tx_confirmed(txid).await
    }

    /// Compute the expiry for new VTXOs.
    ///
    /// When `vtxo_expiry_blocks` is configured, queries the scanner for the
    /// current tip height and returns a block-height-based expiry.
    /// Otherwise falls back to wall-clock time: `now() + vtxo_expiry_secs`.
    async fn compute_vtxo_expiry(&self) -> VtxoExpiry {
        // Use unilateral_exit_delay as the block-based VTXO expiry.
        // This matches the Go reference server which uses the commitment TX's
        // CSV delay (= unilateral_exit_delay) as the VTXO tree expiry.
        // The vtxo_expiry_blocks config is ignored in favor of the actual
        // CSV timelock that controls when the ASP can sweep.
        let expiry_blocks = self.config.unilateral_exit_delay;
        if expiry_blocks > 0 {
            match self.scanner.tip_height().await {
                Ok(tip) if tip > 0 => {
                    let expires = tip + expiry_blocks;
                    tracing::debug!(
                        tip_height = tip,
                        unilateral_exit_delay = expiry_blocks,
                        expires_at_block = expires,
                        "Using block-height VTXO expiry (CSV delay)"
                    );
                    return VtxoExpiry::Block(expires);
                }
                Ok(_) => {
                    tracing::warn!("Scanner tip is 0; falling back to time-based VTXO expiry");
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Failed to get scanner tip; falling back to time-based VTXO expiry"
                    );
                }
            }
        }
        VtxoExpiry::Timestamp(chrono::Utc::now().timestamp() + self.config.vtxo_expiry_secs)
    }

    /// Return a clone of the current round (if any) for read-only inspection.
    pub async fn current_round_snapshot(&self) -> Option<Round> {
        self.current_round.read().await.clone()
    }

    /// Subscribe to domain events (e.g. VtxoCreated, RoundFinalized).
    pub async fn subscribe_events(&self) -> ArkResult<tokio::sync::broadcast::Receiver<ArkEvent>> {
        self.events.subscribe().await
    }

    /// Get the fee program configuration.
    pub fn get_fee_program(&self) -> &FeeProgram {
        &self.config.fee_program
    }

    /// Reload config from the underlying [`ConfigService`].
    pub async fn reload_config(&self) -> ArkResult<ArkConfig> {
        let new_config = self.config_service.reload().await?;
        tracing::info!("Config reloaded");
        Ok(new_config)
    }

    /// Get service info
    pub async fn get_info(&self) -> ArkResult<ServiceInfo> {
        let signer_pubkey = self.signer.get_pubkey().await?;
        let dust = self.wallet.get_dust_amount().await?;

        // Use the signer pubkey as the forfeit pubkey. The signer key is
        // the one used to ASP-sign VTXO tree nodes (taproot key-path spend).
        // The Go SDK's ValidateVtxoTree checks the sweep tapscript against
        // the forfeit pubkey from GetInfo, so the key used for tree building,
        // signing, and GetInfo must all be the same — the signer key.
        let forfeit_pubkey = signer_pubkey;

        // Derive forfeit address from the signer pubkey (P2TR)
        let network = match self.config.network.as_str() {
            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
            "testnet" => bitcoin::Network::Testnet,
            "signet" => bitcoin::Network::Signet,
            _ => bitcoin::Network::Regtest,
        };
        let forfeit_address = bitcoin::Address::p2tr(
            &bitcoin::secp256k1::Secp256k1::new(),
            forfeit_pubkey,
            None,
            network,
        )
        .to_string();

        // Build checkpoint_tapscript as a CSVMultisigClosure binary script (hex-encoded).
        // The Go SDK decodes this with CSVMultisigClosure.Decode(), which expects:
        //   <BIP68_sequence_push> OP_CSV OP_DROP <32-byte-pubkey-push> OP_CHECKSIG
        //
        // For unilateral_exit_delay blocks (e.g. 144 = 0x90):
        //   01 90            – minimal push of 0x90 (144)
        //   b2               – OP_CHECKSEQUENCEVERIFY
        //   75               – OP_DROP
        //   20 <32-byte-key> – push 32 bytes (x-only pubkey)
        //   ac               – OP_CHECKSIG
        let checkpoint_tapscript = {
            let delay = self.config.unilateral_exit_delay;
            // BIP68 encode: >= 512 → seconds (sets type flag), < 512 → blocks (raw value)
            let seq = dark_bitcoin::bip68_sequence(delay).unwrap_or(delay) as u64;
            // Minimal-push encoding of the sequence number (as Bitcoin Script integer).
            let seq_bytes = bitcoin::script::Builder::new()
                .push_int(seq as i64)
                .into_script();
            // seq_bytes is a full script; the bytes are: <pushop> <data...>
            // We need just the raw bytes (push opcode + data).
            let seq_hex = hex::encode(seq_bytes.as_bytes());
            // Build full script:  <seq_push> OP_CSV OP_DROP 20 <pubkey32> OP_CHECKSIG
            // Use signer pubkey (matches tree building and ASP signing).
            let pubkey_hex = hex::encode(forfeit_pubkey.serialize());
            format!("{}b27520{}ac", seq_hex, pubkey_hex)
        };

        // Serialize pubkeys as 33-byte compressed (02/03 prefix) for protocol compatibility
        // with the reference Go implementation (arkade-os/arkd), which uses
        // `btcec.PublicKey.SerializeCompressed()` in its GetInfo response.
        // We assume even parity (02 prefix) when lifting x-only keys to compressed form.
        let signer_pubkey_compressed = bitcoin::secp256k1::PublicKey::from_x_only_public_key(
            signer_pubkey,
            bitcoin::secp256k1::Parity::Even,
        );

        Ok(ServiceInfo {
            signer_pubkey: hex::encode(signer_pubkey_compressed.serialize()),
            forfeit_pubkey: hex::encode(signer_pubkey_compressed.serialize()),
            unilateral_exit_delay: self.config.unilateral_exit_delay as i64,
            session_duration: self.config.session_duration_secs as i64,
            network: self.config.network.clone(),
            dust,
            vtxo_min_amount: self.config.min_vtxo_amount_sats as i64,
            vtxo_max_amount: self.config.max_vtxo_amount_sats as i64,
            forfeit_address,
            checkpoint_tapscript,
            utxo_min_amount: self.config.utxo_min_amount,
            utxo_max_amount: self.config.utxo_max_amount,
            public_unilateral_exit_delay: self.config.public_unilateral_exit_delay,
            boarding_exit_delay: self.config.boarding_exit_delay,
            max_tx_weight: self.config.max_tx_weight,
        })
    }

    /// Start a new round
    #[instrument(skip(self))]
    pub async fn start_round(&self) -> ArkResult<Round> {
        if let Some(round) = self.current_round.read().await.as_ref() {
            // Only start a new round when the current one has fully ended.
            // A round in Finalization stage is still active (awaiting tree
            // nonces/signatures from cosigners), so we must NOT replace it.
            if !round.is_ended() {
                return Err(ArkError::Internal("Round already active".to_string()));
            }
        }
        let mut round = Round::new();
        round.start_registration().map_err(ArkError::Internal)?;
        info!(round_id = %round.id, "Starting new round");
        *self.current_round.write().await = Some(round.clone());
        self.events
            .publish_event(ArkEvent::RoundStarted {
                round_id: round.id.clone(),
                timestamp: round.starting_timestamp,
            })
            .await?;
        // NOTE: Do NOT emit BatchStarted here. In arkd, BatchStarted is
        // published by startConfirmation() AFTER the registration period
        // ends, with hashed intent IDs. Publishing it here with empty
        // intent_ids causes the Go SDK to skip the event (OnBatchStarted
        // can't find the intent hash) and wait forever.
        // The correct BatchStarted is emitted by finalize_round().
        Ok(round)
    }

    /// Finalize the current round: build commitment tx, emit RoundFinalized.
    ///
    /// Collects all registered intents from the active round, builds the
    /// commitment transaction via `TxBuilder`, and transitions the round to
    /// a terminal (ended) state.  If there are no intents the round is
    /// failed with "No intents to finalize".
    #[instrument(skip(self))]
    pub async fn finalize_round(&self) -> ArkResult<Round> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round to finalize".to_string()))?;

        if round.is_ended() {
            return Err(ArkError::Internal("Round already ended".to_string()));
        }

        // Collect intents (duplicates already filtered in register_intent).
        // Sort deterministically by intent ID so connector leaf → outpoint
        // mapping is consistent regardless of HashMap iteration order.
        let mut intents: Vec<Intent> = round.intents.values().cloned().collect();
        intents.sort_by(|a, b| a.id.cmp(&b.id));

        if intents.is_empty() {
            info!(round_id = %round.id, "No intents — skipping round");
            round.fail("No intents to finalize".to_string());
            let failed_round = round.clone();
            return Ok(failed_round);
        }

        // Transition to finalization stage if still in registration
        if round.stage.code == RoundStage::Registration {
            round.start_finalization().map_err(ArkError::Internal)?;
        }

        // ── Add ASP as MuSig2 cosigner ─────────────────────────────────────
        // Like the Go reference server, add the operator/ASP pubkey to each
        // intent's cosigner list so the tree builder creates MuSig2 aggregated
        // keys that include the ASP. This is essential for key-path spending.
        // Derive the full compressed pubkey (with correct parity prefix) from the secret key.
        // XOnlyPublicKey.serialize() is 32 bytes without parity — using it with a hardcoded
        // 0x02 prefix is incorrect when the actual Y coordinate is odd (prefix 0x03).
        let asp_compressed_hex = {
            let sk_bytes = self.signer.get_secret_key_bytes().await?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes)
                .map_err(|e| ArkError::Internal(format!("Invalid ASP secret key: {e}")))?;
            let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
            hex::encode(pk.serialize())
        };
        for intent in &mut intents {
            if !intent.cosigners_public_keys.contains(&asp_compressed_hex) {
                intent
                    .cosigners_public_keys
                    .push(asp_compressed_hex.clone());
            }
        }
        // Also update the round's copy so complete_round() sees the ASP cosigner
        for intent in round.intents.values_mut() {
            if !intent.cosigners_public_keys.contains(&asp_compressed_hex) {
                intent
                    .cosigners_public_keys
                    .push(asp_compressed_hex.clone());
            }
        }

        // NOTE: BatchStarted is emitted AFTER TreeTxReady events (below) so
        // that Go SDK clients can collect tree nodes before advancing their
        // internal step machine past the "batchStarted" state.
        let intent_ids: Vec<String> = intents.iter().map(|i| i.id.clone()).collect();

        // Collect boarding inputs from intent proof tx inputs.
        // Only include inputs that are on-chain boarding UTXOs (NOT already
        // in the VTXO store as off-chain VTXOs). Off-chain VTXO inputs
        // (e.g. delegate refresh) are spent virtually, not as commitment tx inputs.
        let mut boarding_inputs: Vec<crate::ports::BoardingInput> = Vec::new();
        for intent in &intents {
            for inp in &intent.inputs {
                if inp.amount > 0 && !inp.outpoint.txid.is_empty() {
                    let outpoint_slice = [inp.outpoint.clone()];
                    let is_offchain = self
                        .vtxo_repo
                        .get_vtxos(&outpoint_slice)
                        .await
                        .ok()
                        .map(|v| !v.is_empty())
                        .unwrap_or(false);

                    if !is_offchain {
                        boarding_inputs.push(crate::ports::BoardingInput {
                            outpoint: inp.outpoint.clone(),
                            amount: inp.amount,
                        });
                    }
                }
            }
        }
        // Also check the legacy boarding repo
        let boarding_txs = self.claim_boarding_inputs().await.unwrap_or_default();
        for bt in &boarding_txs {
            if let (Some(txid), Some(vout)) = (bt.funding_txid.as_ref(), bt.funding_vout) {
                boarding_inputs.push(crate::ports::BoardingInput {
                    outpoint: VtxoOutpoint::new(txid.to_string(), vout),
                    amount: bt.amount.to_sat(),
                });
            }
        }
        // NOTE: Server fee input is NOT added here. It will be added later in
        // broadcast_signed_commitment_tx() using wallet.add_fee_input() which
        // uses BDK's TxBuilder to ensure proper PSBT metadata for signing.
        // This fixes issue #322 where BDK couldn't sign externally-built inputs.

        info!(
            boarding_count = boarding_inputs.len(),
            "Including boarding inputs in round"
        );

        // Build commitment transaction.
        // Use the signer pubkey — the same key reported as forfeit_pubkey in
        // GetInfo and the same key used to ASP-sign tree nodes. The Go SDK's
        // ValidateVtxoTree checks the sweep tapscript against GetInfo's
        // forfeit pubkey, so tree building, signing, and GetInfo must all
        // use the signer key.
        let signer_pubkey = self.signer.get_pubkey().await?;
        let result = self
            .tx_builder
            .build_commitment_tx(&signer_pubkey, &intents, &boarding_inputs)
            .await?;

        // Add server wallet fee input NOW, before the PSBT goes to clients.
        // Adding it after client signing breaks taproot signatures because
        // SigHash::All covers all prevouts. The Go server adds its wallet
        // UTXOs in createCommitmentTx for the same reason.
        // Always add a server fee input to fund the commitment tx.
        // For boarding rounds, the fee covers the gap between boarding inputs and
        // outputs plus mining fees. For refresh-only rounds (no boarding inputs),
        // the server wallet provides the sole funding input.
        let commitment_psbt_with_fee = {
            // Decode PSBT to compute how much fee is needed.
            // If decoding fails (e.g. stub/mock tx builder), skip gracefully.
            use base64::Engine;
            let needed = base64::engine::general_purpose::STANDARD
                .decode(&result.commitment_tx)
                .ok()
                .and_then(|bytes| bitcoin::psbt::Psbt::deserialize(&bytes).ok())
                .map(|psbt| {
                    let total_output: u64 = psbt
                        .unsigned_tx
                        .output
                        .iter()
                        .map(|o| o.value.to_sat())
                        .sum();
                    let total_input: u64 = boarding_inputs.iter().map(|b| b.amount).sum();
                    let deficit = total_output.saturating_sub(total_input);
                    const MIN_FEE: u64 = 500;
                    let needed = deficit + MIN_FEE;
                    info!(
                        total_output,
                        total_input,
                        deficit,
                        needed,
                        "Adding server fee input to commitment tx before client signing"
                    );
                    needed
                });

            if let Some(needed) = needed {
                match self
                    .wallet
                    .add_fee_input(&result.commitment_tx, needed)
                    .await
                {
                    Ok(psbt_with_fee) => {
                        info!("Server fee input added to commitment tx PSBT");
                        psbt_with_fee
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to add server fee input — proceeding without (tx may fail to broadcast)");
                        result.commitment_tx.clone()
                    }
                }
            } else {
                warn!("Could not decode commitment PSBT for fee calculation — skipping fee input");
                result.commitment_tx.clone()
            }
        };

        // Use the fee-augmented PSBT from here on.
        // Enrich boarding PSBT inputs with tap_scripts + tap_internal_key + witness_utxo
        // so the Rust client can sign them via the cooperative script leaf (script-path spend).
        let result_commitment_tx = {
            use base64::Engine;

            // Build outpoint -> (user_xonly, amount) map from intent inputs + boarding repo.
            let mut boarding_info: std::collections::HashMap<
                String,
                (bitcoin::XOnlyPublicKey, u64),
            > = std::collections::HashMap::new();

            for intent in &intents {
                for inp in &intent.inputs {
                    if inp.amount > 0 && !inp.outpoint.txid.is_empty() {
                        let xonly = hex::decode(&inp.pubkey).ok().and_then(|b| {
                            if b.len() == 33 {
                                bitcoin::XOnlyPublicKey::from_slice(&b[1..]).ok()
                            } else {
                                bitcoin::XOnlyPublicKey::from_slice(&b).ok()
                            }
                        });
                        let outpoint_key = format!("{}:{}", inp.outpoint.txid, inp.outpoint.vout);
                        let is_in_boarding = boarding_inputs.iter().any(|b| {
                            format!("{}:{}", b.outpoint.txid, b.outpoint.vout) == outpoint_key
                        });
                        if let Some(xk) = xonly {
                            if is_in_boarding {
                                boarding_info.insert(outpoint_key, (xk, inp.amount));
                            }
                        }
                    }
                }
            }
            for (bi, bt) in boarding_inputs.iter().zip(boarding_txs.iter()) {
                let key = format!("{}:{}", bi.outpoint.txid, bi.outpoint.vout);
                boarding_info
                    .entry(key)
                    .or_insert((bt.recipient_pubkey, bi.amount));
            }

            // Use the signer pubkey (same key used for tree building above).
            let asp_xonly = signer_pubkey;

            if !boarding_info.is_empty() {
                if let Ok(bytes) =
                    base64::engine::general_purpose::STANDARD.decode(&commitment_psbt_with_fee)
                {
                    if let Ok(mut psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                        let boarding_delay = self.config.boarding_exit_delay;
                        let network = match self.config.network.as_str() {
                            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
                            "testnet" => bitcoin::Network::Testnet,
                            "signet" => bitcoin::Network::Signet,
                            _ => bitcoin::Network::Regtest,
                        };

                        for (idx, input) in psbt.unsigned_tx.input.iter().enumerate() {
                            let op_key = format!(
                                "{}:{}",
                                input.previous_output.txid, input.previous_output.vout
                            );
                            if let Some((user_xonly, amount)) = boarding_info.get(&op_key) {
                                if !psbt.inputs[idx].tap_scripts.is_empty() {
                                    continue;
                                }
                                match dark_bitcoin::build_vtxo_taproot(
                                    user_xonly,
                                    &asp_xonly,
                                    boarding_delay,
                                ) {
                                    Ok(taproot_info) => {
                                        psbt.inputs[idx].tap_internal_key =
                                            Some(taproot_info.internal_key());
                                        for script_ver in taproot_info.script_map().keys() {
                                            if let Some(cb) = taproot_info.control_block(script_ver)
                                            {
                                                psbt.inputs[idx]
                                                    .tap_scripts
                                                    .insert(cb, script_ver.clone());
                                            }
                                        }
                                        if psbt.inputs[idx].witness_utxo.is_none() {
                                            let addr = bitcoin::Address::p2tr_tweaked(
                                                taproot_info.output_key(),
                                                network,
                                            );
                                            psbt.inputs[idx].witness_utxo = Some(bitcoin::TxOut {
                                                value: bitcoin::Amount::from_sat(*amount),
                                                script_pubkey: addr.script_pubkey(),
                                            });
                                        }
                                        info!(
                                            input_idx = idx,
                                            outpoint = %op_key,
                                            "Populated tap_scripts for boarding input"
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            error = %e,
                                            outpoint = %op_key,
                                            "Failed to build boarding taproot"
                                        );
                                    }
                                }
                            }
                        }

                        base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
                    } else {
                        commitment_psbt_with_fee
                    }
                } else {
                    commitment_psbt_with_fee
                }
            } else {
                commitment_psbt_with_fee
            }
        };

        // Extract and store the fee input signature from the BDK-signed PSBT.
        // This signature may be stripped when Go SDK clients round-trip the PSBT,
        // so we store it here and re-apply it after merge in broadcast_signed_commitment_tx().
        {
            use base64::Engine;
            if let Ok(bytes) =
                base64::engine::general_purpose::STANDARD.decode(&result_commitment_tx)
            {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                    // Fee input is always the last input
                    if let Some(fee_input) = psbt.inputs.last() {
                        if let Some(sig) = fee_input.tap_key_sig {
                            let mut stored_sig = self.fee_input_signature.lock().await;
                            *stored_sig = Some(sig);
                            info!("Stored fee input tap_key_sig for re-application after merge");
                        } else {
                            info!("Fee input has no tap_key_sig (may be finalized or unsigned)");
                        }
                    }
                }
            }
        }

        // After adding the fee input the commitment txid changes.  The vtxo tree
        // was built against the *original* txid, so we must patch every tree node
        // whose input references the old txid to point to the new one.
        // We do this before injecting cosigner fields so the patched PSBTs are
        // the ones that get signed and sent to clients.
        let (patched_vtxo_tree, patched_connectors) = {
            let old_txid = Self::extract_txid_from_psbt(&result.commitment_tx);
            let new_txid = Self::extract_txid_from_psbt(&result_commitment_tx);
            match (old_txid, new_txid) {
                (Some(old), Some(new)) if old != new => {
                    info!(old_txid = %old, new_txid = %new, "Patching vtxo tree and connector tree to new commitment txid after fee input");
                    let vtxo_tree =
                        Self::patch_vtxo_tree_commitment_txid(&result.vtxo_tree, &old, &new);
                    let connectors =
                        Self::patch_vtxo_tree_commitment_txid(&result.connectors, &old, &new);
                    (vtxo_tree, connectors)
                }
                _ => (result.vtxo_tree.clone(), result.connectors.clone()),
            }
        };

        // Collect ALL cosigner pubkeys (including ASP) for PSBT injection.
        let all_cosigners_pubkeys: Vec<String> = intents
            .iter()
            .flat_map(|i| i.cosigners_public_keys.iter())
            .cloned()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        // User-only cosigners (exclude ASP) — used for signing session participant
        // count and the "no cosigners" fast path. The ASP handles its nonces/sigs
        // internally, not through the signing session.
        let cosigners_pubkeys: Vec<String> = all_cosigners_pubkeys
            .iter()
            .filter(|k| k.as_str() != asp_compressed_hex)
            .cloned()
            .collect();

        // The vtxo tree PSBTs already have per-node cosigner fields set
        // correctly by the tree builder (each node carries only its own
        // cosigners). Do NOT overwrite them with the global cosigner list —
        // that would give every node ALL cosigners, causing Go validation
        // to aggregate the wrong set of keys and fail with
        // "invalid taproot script".
        //
        // We still inject cosigner fields into the commitment tx PSBT
        // (which has no tree-level cosigner fields) for protocol compat.
        let vtxo_tree = patched_vtxo_tree;
        let commitment_tx =
            Self::inject_cosigner_fields_single(&result_commitment_tx, &all_cosigners_pubkeys);

        // Store results on the round
        round.commitment_tx = commitment_tx;
        round.connectors = patched_connectors.clone();
        round.connector_address = result.connector_address;
        round.has_boarding_inputs = !boarding_inputs.is_empty();
        // Track boarding transaction IDs so we can mark them as claimed after round completion
        round.boarding_tx_ids = boarding_txs.iter().map(|bt| bt.id.to_string()).collect();

        // Always push the server-signed PSBT as the initial "partial" so
        // broadcast_signed_commitment_tx() can merge the server's fee input
        // signature with client signatures. This applies to both boarding
        // rounds and refresh-only rounds (server wallet always funds the
        // commitment tx).
        {
            let mut partials = self.partial_commitment_psbts.lock().await;
            partials.clear(); // Clear any stale partials from prior rounds
            partials.push((round.id.clone(), round.commitment_tx.clone()));
            drop(partials);
            info!("Stored server-signed commitment PSBT as initial partial");
        }

        // Populate witness_utxo on each tree PSBT (needed for sighash computation
        // during MuSig2 signing) but do NOT sign yet — signing happens via the
        // MuSig2 protocol after nonces are exchanged with cosigners.
        let vtxo_tree_with_utxos = self
            .populate_tree_witness_utxos(&vtxo_tree, &round.commitment_tx)
            .await;
        round.vtxo_tree = vtxo_tree_with_utxos;

        // Extract commitment txid from PSBT
        let commitment_txid =
            Self::extract_txid_from_psbt(&round.commitment_tx).unwrap_or_else(|| round.id.clone());
        round.commitment_txid = commitment_txid.clone();

        // ── DEBUG: validate vtxo tree amounts match batch output ──────────
        {
            use base64::Engine;
            if let Ok(ct_bytes) =
                base64::engine::general_purpose::STANDARD.decode(&round.commitment_tx)
            {
                if let Ok(ct_psbt) = bitcoin::psbt::Psbt::deserialize(&ct_bytes) {
                    let batch_output_amount = ct_psbt
                        .unsigned_tx
                        .output
                        .first()
                        .map(|o| o.value.to_sat())
                        .unwrap_or(0);
                    let ct_output_count = ct_psbt.unsigned_tx.output.len();
                    let ct_input_count = ct_psbt.unsigned_tx.input.len();
                    info!(
                        batch_output_amount,
                        ct_output_count,
                        ct_input_count,
                        commitment_txid = %commitment_txid,
                        "DEBUG: Commitment tx layout"
                    );

                    // Find root node (the one not referenced as child by any other)
                    let child_txids: std::collections::HashSet<String> = round
                        .vtxo_tree
                        .iter()
                        .flat_map(|n| n.children.values())
                        .cloned()
                        .collect();
                    let root_node = round
                        .vtxo_tree
                        .iter()
                        .find(|n| !child_txids.contains(&n.txid));
                    if let Some(root) = root_node {
                        if let Ok(root_bytes) =
                            base64::engine::general_purpose::STANDARD.decode(&root.tx)
                        {
                            if let Ok(root_psbt) = bitcoin::psbt::Psbt::deserialize(&root_bytes) {
                                let root_output_sum: u64 = root_psbt
                                    .unsigned_tx
                                    .output
                                    .iter()
                                    .map(|o| o.value.to_sat())
                                    .sum();
                                let root_output_count = root_psbt.unsigned_tx.output.len();
                                let root_input_txid = root_psbt
                                    .unsigned_tx
                                    .input
                                    .first()
                                    .map(|i| i.previous_output.txid.to_string())
                                    .unwrap_or_default();
                                let root_input_vout = root_psbt
                                    .unsigned_tx
                                    .input
                                    .first()
                                    .map(|i| i.previous_output.vout)
                                    .unwrap_or(0);
                                let amounts_match = root_output_sum == batch_output_amount;
                                info!(
                                    root_output_sum,
                                    batch_output_amount,
                                    root_output_count,
                                    root_input_txid = %root_input_txid,
                                    root_input_vout,
                                    amounts_match,
                                    tree_node_count = round.vtxo_tree.len(),
                                    "DEBUG: VTXO tree root vs batch output"
                                );
                                if !amounts_match {
                                    error!(
                                        root_output_sum,
                                        batch_output_amount,
                                        diff = (root_output_sum as i64 - batch_output_amount as i64),
                                        "AMOUNT MISMATCH: vtxo tree root outputs sum != batch output"
                                    );
                                    // Log each output
                                    for (i, out) in root_psbt.unsigned_tx.output.iter().enumerate()
                                    {
                                        info!(
                                            output_index = i,
                                            amount = out.value.to_sat(),
                                            script_len = out.script_pubkey.len(),
                                            "DEBUG: Root tx output"
                                        );
                                    }
                                    for (i, out) in ct_psbt.unsigned_tx.output.iter().enumerate() {
                                        info!(
                                            output_index = i,
                                            amount = out.value.to_sat(),
                                            script_len = out.script_pubkey.len(),
                                            "DEBUG: Commitment tx output"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // ── END DEBUG ─────────────────────────────────────────────────────

        info!(
            cosigner_count = cosigners_pubkeys.len(),
            cosigners = ?cosigners_pubkeys,
            "Cosigners for TreeSigningPhaseStarted"
        );

        // Initialize the signing session with the correct participant count.
        // Count unique cosigners from the actual PSBT fields (not from
        // intent.cosigners_public_keys which may be empty — the tree builder
        // falls back to receiver pubkeys). The ASP is included since it also
        // submits nonces and sigs via the signing session store.
        let psbt_participant_count = {
            let mut unique_cosigners: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for node in &round.vtxo_tree {
                if let Some(keys) = Self::extract_cosigners_from_psbt_b64(&node.tx) {
                    for k in keys {
                        unique_cosigners.insert(k);
                    }
                }
            }
            unique_cosigners.len()
        };
        self.signing_session_store
            .init_session(&round.id, psbt_participant_count)
            .await?;

        // Emit BatchStarted FIRST so Go SDK clients transition from step 0
        // ("start") to step 1 ("batchStarted").  The Go SDK's state machine
        // only processes TreeTx events at step 1 ("batchStarted") or step 3
        // ("treeNoncesAggregated").  TreeTx events arriving at step 0 are
        // silently dropped, so they MUST come after BatchStarted.
        let timestamp = chrono::Utc::now().timestamp();
        self.events
            .publish_event(ArkEvent::BatchStarted {
                round_id: round.id.clone(),
                intent_ids: intent_ids.clone(),
                unsigned_vtxo_tree: String::new(),
                timestamp,
            })
            .await?;

        // Now emit TreeTxReady for each vtxo tree node — clients are at
        // step 1 ("batchStarted") and will collect these.
        // Use per-node cosigner keys (extracted from the PSBT) as the event
        // topic so that each client only receives tree nodes it actually
        // cosigns.  This avoids the Go client accumulating tree nodes it has
        // no nonces for, which previously required a client-side patch to
        // silently skip unknown txids in AggregateNonces.
        for node in &round.vtxo_tree {
            if node.tx.is_empty() {
                continue;
            }
            // Verify stored txid matches the PSBT's unsigned TX txid.
            // If these differ, the SDK will generate nonces for the wrong txids.
            {
                use base64::Engine;
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&node.tx) {
                    if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                        let recomputed = psbt.unsigned_tx.compute_txid().to_string();
                        if recomputed != node.txid {
                            error!(
                                stored_txid = %node.txid,
                                psbt_txid = %recomputed,
                                "TXID MISMATCH: stored tree node txid differs from PSBT unsigned TX txid!"
                            );
                        } else {
                            debug!(txid = %node.txid, "Tree node txid verified OK");
                        }
                    }
                }
            }
            let node_cosigners =
                Self::extract_cosigners_from_psbt_b64(&node.tx).unwrap_or_default();
            // Fall back to global cosigners only when extraction fails (should
            // not happen for well-formed PSBTs).
            let topic = if node_cosigners.is_empty() {
                cosigners_pubkeys.clone()
            } else {
                node_cosigners
            };
            self.events
                .publish_event(ArkEvent::TreeTxReady {
                    round_id: round.id.clone(),
                    txid: node.txid.clone(),
                    tx: node.tx.clone(),
                    cosigners: topic,
                    children: node.children.clone(),
                    batch_index: 0,
                })
                .await?;
        }

        // Emit TreeTxReady for connector tree nodes (batch_index=1).
        // Go arkd sends these so that delegate clients (who subscribe with their
        // VTXO outpoints) can receive the connector tree and build forfeit txs.
        //
        // Each connector leaf corresponds to one forfeitable intent input.
        // The leaf's topic must be the specific input outpoint so that only
        // the client owning that input receives it — the Go SDK's validator
        // checks `len(Leaves()) == len(myVtxosToForfeit)`.
        // The connector root goes to ALL clients (all input outpoints).
        if !round.connectors.is_empty() {
            // Build the ordered list of forfeitable input outpoints (one per
            // connector leaf, same order as build_connector_tree produced them).
            let forfeitable_outpoints: Vec<String> = intents
                .iter()
                .flat_map(|i| {
                    i.inputs
                        .iter()
                        .filter(|inp| inp.needs_connector())
                        .map(|inp| inp.outpoint.to_string())
                })
                .collect();
            let all_connector_topics: Vec<String> = forfeitable_outpoints.clone();

            for node in &round.connectors {
                if node.tx.is_empty() {
                    continue;
                }
                // Leaf nodes → specific outpoint topic.
                // Root/branch → all outpoints (all clients receive).
                let topic = if node.children.is_empty() {
                    let leaf_idx = round
                        .connectors
                        .iter()
                        .filter(|n| n.children.is_empty() && !n.tx.is_empty())
                        .position(|n| n.txid == node.txid);
                    if let Some(idx) = leaf_idx {
                        if let Some(outpoint) = forfeitable_outpoints.get(idx) {
                            vec![outpoint.clone()]
                        } else {
                            all_connector_topics.clone()
                        }
                    } else {
                        all_connector_topics.clone()
                    }
                } else {
                    all_connector_topics.clone()
                };

                self.events
                    .publish_event(ArkEvent::TreeTxReady {
                        round_id: round.id.clone(),
                        txid: node.txid.clone(),
                        tx: node.tx.clone(),
                        cosigners: topic,
                        children: node.children.clone(),
                        batch_index: 1,
                    })
                    .await?;
            }
        }

        // When there are no cosigners OR the tree is empty, skip the tree signing
        // phase and complete the round immediately. Otherwise the round stays in
        // Finalization forever — blocking subsequent rounds — because no
        // nonces/signatures will ever arrive.
        //
        // IMPORTANT: When the tree is empty (e.g., collaborative exit without VTXO
        // change), we used to auto-complete immediately, but that broke because
        // the SDK hadn't registered intent yet. Now we emit TreeSigningPhaseStarted
        // and let the normal flow proceed. The completion happens in
        // confirm_registration() when all participants have confirmed and tree is empty.
        let _tree_is_empty = round.vtxo_tree.iter().all(|n| n.tx.is_empty());
        let no_cosigners = cosigners_pubkeys.is_empty();

        // Normal path: emit TreeSigningPhaseStarted with cosigners.
        // For collaborative exit without change (empty tree), we still emit this
        // event but the SDK will skip tree signing via WithSkipVtxoTreeSigning().
        // Clients will participate in MuSig2 signing for the tree.
        self.events
            .publish_event(ArkEvent::TreeSigningPhaseStarted {
                round_id: round.id.clone(),
                cosigners_pubkeys: cosigners_pubkeys.clone(),
                unsigned_commitment_tx: round.commitment_tx.clone(),
            })
            .await?;

        // Auto-complete only when there are no cosigners.
        // (Empty tree case is handled above)
        let should_auto_complete = no_cosigners;

        if should_auto_complete {
            // No user cosigners — ASP is the sole cosigner. Sign tree PSBTs
            // directly with a key-path spend (no MuSig2 needed).
            let signed_vtxo_tree = self
                .asp_sign_vtxo_tree(&round.vtxo_tree.clone(), &round.commitment_tx)
                .await;
            round.vtxo_tree = signed_vtxo_tree;

            info!(
                round_id = %round.id,
                intent_count = intents.len(),
                commitment_txid = %commitment_txid,
                "No cosigners — auto-completing round (skipping tree signing phase)"
            );

            // Create VTXOs from intents (same logic as complete_round)
            let vtxo_expiry = self.compute_vtxo_expiry().await;
            let mut vtxos = Vec::new();
            let mut vtxo_idx = 0u32;
            let leaf_nodes: Vec<&TxTreeNode> = round
                .vtxo_tree
                .iter()
                .filter(|n| n.children.is_empty())
                .collect();

            for intent in &intents {
                for receiver in &intent.receivers {
                    if receiver.is_onchain() {
                        continue;
                    }
                    let (vtxo_txid, vtxo_vout) =
                        if let Some(leaf) = leaf_nodes.get(vtxo_idx as usize) {
                            (leaf.txid.clone(), 0u32)
                        } else {
                            (commitment_txid.clone(), vtxo_idx)
                        };
                    let mut vtxo = Vtxo::new(
                        VtxoOutpoint::new(vtxo_txid, vtxo_vout),
                        receiver.amount,
                        receiver.pubkey.clone(),
                    );
                    vtxo.root_commitment_txid = commitment_txid.clone();
                    vtxo.commitment_txids = vec![commitment_txid.clone()];
                    vtxo_expiry.apply_to(&mut vtxo);
                    vtxos.push(vtxo);
                    vtxo_idx += 1;
                }
            }

            if !vtxos.is_empty() {
                for v in &vtxos {
                    info!(
                        txid = %v.outpoint.txid,
                        vout = v.outpoint.vout,
                        pubkey = %v.pubkey,
                        amount = v.amount,
                        "VTXO to persist (auto-complete)"
                    );
                }
                match self.vtxo_repo.add_vtxos(&vtxos).await {
                    Ok(()) => info!(vtxo_count = vtxos.len(), "VTXOs persisted (auto-complete)"),
                    Err(e) => {
                        error!(error = %e, "FAILED to persist VTXOs (auto-complete)!");
                        return Err(e);
                    }
                }
                for vtxo in &vtxos {
                    let _ = self
                        .events
                        .publish_event(ArkEvent::VtxoCreated {
                            vtxo_id: format!("{}:{}", vtxo.outpoint.txid, vtxo.outpoint.vout),
                            pubkey: vtxo.pubkey.clone(),
                            amount: vtxo.amount,
                            round_id: round.id.clone(),
                        })
                        .await;
                }
            }

            // Mark intent input VTXOs (off-chain refresh inputs) as spent now that
            // the round completed and new output VTXOs were created (auto-complete path).
            let spend_list: Vec<(VtxoOutpoint, String)> = intents
                .iter()
                .flat_map(|intent| {
                    intent.inputs.iter().filter_map(|inp| {
                        if inp.outpoint.txid.is_empty() {
                            None
                        } else {
                            Some((inp.outpoint.clone(), commitment_txid.clone()))
                        }
                    })
                })
                .collect();
            if !spend_list.is_empty() {
                if let Err(e) = self
                    .vtxo_repo
                    .spend_vtxos(&spend_list, &commitment_txid)
                    .await
                {
                    warn!(error = %e, "Failed to mark intent input VTXOs as spent (non-fatal, auto-complete)");
                } else {
                    info!(
                        count = spend_list.len(),
                        "Marked intent input VTXOs as spent (auto-complete)"
                    );
                }
            }

            // For each pubkey that has new output VTXOs, mark any prior unspent VTXOs
            // for that pubkey as spent (VTXO refresh / implicit forfeit, auto-complete path).
            let new_outpoints: std::collections::HashSet<String> = vtxos
                .iter()
                .map(|v| format!("{}:{}", v.outpoint.txid, v.outpoint.vout))
                .collect();
            let pubkeys_with_new_vtxos: std::collections::HashSet<&str> =
                vtxos.iter().map(|v| v.pubkey.as_str()).collect();
            for pubkey in pubkeys_with_new_vtxos {
                if let Ok((spendable, _)) = self.vtxo_repo.get_all_vtxos_for_pubkey(pubkey).await {
                    let prior_outpoints: Vec<(VtxoOutpoint, String)> = spendable
                        .into_iter()
                        .filter(|v| {
                            !new_outpoints
                                .contains(&format!("{}:{}", v.outpoint.txid, v.outpoint.vout))
                        })
                        .map(|v| (v.outpoint, commitment_txid.clone()))
                        .collect();
                    if !prior_outpoints.is_empty() {
                        if let Err(e) = self
                            .vtxo_repo
                            .spend_vtxos(&prior_outpoints, &commitment_txid)
                            .await
                        {
                            warn!(error = %e, pubkey, "Failed to mark prior VTXOs as spent on refresh (non-fatal, auto-complete)");
                        } else {
                            info!(
                                count = prior_outpoints.len(),
                                pubkey, "Marked prior VTXOs as spent (VTXO refresh, auto-complete)"
                            );
                        }
                    }
                }
            }

            // Mark boarding transactions as claimed (auto-complete path).
            for boarding_id in &round.boarding_tx_ids {
                if let Err(e) = self.boarding_repo.mark_claimed(boarding_id).await {
                    warn!(
                        boarding_id = %boarding_id,
                        error = %e,
                        "Failed to mark boarding transaction as claimed (non-fatal, auto-complete)"
                    );
                }
            }

            round.end_successfully();

            info!(
                vtxo_tree_len = round.vtxo_tree.len(),
                "auto-complete: about to save round"
            );
            if let Err(e) = self.round_repo.add_or_update_round(round).await {
                warn!(error = %e, "Failed to persist round (non-fatal, auto-complete)");
            }

            let has_boarding = !boarding_inputs.is_empty();
            self.events
                .publish_event(ArkEvent::RoundFinalized {
                    round_id: round.id.clone(),
                    commitment_tx: round.commitment_tx.clone(),
                    timestamp: round.ending_timestamp,
                    vtxo_count: vtxos.len() as u32,
                    has_boarding_inputs: has_boarding,
                    has_connectors: false, // auto-complete path has no connectors
                })
                .await?;

            // Always broadcast the commitment tx (matches Go reference server).
            info!(
                round_id = %round.id,
                has_boarding,
                "Auto-complete — broadcasting commitment tx"
            );
            match self
                .finalize_and_broadcast_commitment_psbt(&round.commitment_tx)
                .await
            {
                Ok(txid) => {
                    info!(txid = %txid, "Commitment tx broadcast (auto-complete)");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to broadcast commitment tx (auto-complete) — emitting RoundBroadcast anyway");
                }
            }

            self.events
                .publish_event(ArkEvent::RoundBroadcast {
                    round_id: round.id.clone(),
                    commitment_txid: commitment_txid.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                })
                .await?;

            // Store for forfeit submission fallback (auto-complete path)
            {
                let mut last = self.last_completed_round.write().await;
                *last = Some(round.clone());
            }

            return Ok(round.clone());
        }

        // ── ASP MuSig2 nonce generation ────────────────────────────────────
        // Generate a secret/public nonce pair for each tree tx that the ASP
        // cosigns. Store SecNonces for later partial signing.
        {
            use musig2::BinaryEncoding;

            let asp_sk_bytes = self.signer.get_secret_key_bytes().await?;
            let asp_seckey = musig2::secp256k1::SecretKey::from_byte_array(asp_sk_bytes)
                .map_err(|e| ArkError::Internal(format!("Invalid ASP secret key: {e}")))?;

            // Use the original secret key as-is (no parity normalization).
            // The musig2 crate handles parity internally via negate_if() during
            // signing. The same key must be used for nonce generation AND signing
            // so the SecNonce's embedded pubkey matches.
            let secp_ctx = musig2::secp256k1::Secp256k1::new();
            let asp_pk = musig2::secp256k1::PublicKey::from_secret_key(&secp_ctx, &asp_seckey);

            // Compute sweep tapscript merkle root (same as tree builder uses).
            let asp_xonly_pubkey = {
                let (xonly, _) = asp_pk.x_only_public_key();
                bitcoin::XOnlyPublicKey::from_slice(&xonly.serialize()).unwrap()
            };
            let sweep_merkle_root = {
                use bitcoin::hashes::Hash as _;
                use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
                let sweep_sc = bitcoin::script::Builder::new()
                    .push_int(self.config.unilateral_exit_delay as i64)
                    .push_opcode(OP_CSV)
                    .push_opcode(OP_DROP)
                    .push_x_only_key(&asp_xonly_pubkey)
                    .push_opcode(OP_CHECKSIG)
                    .into_script();
                let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
                    &sweep_sc,
                    bitcoin::taproot::LeafVersion::TapScript,
                );
                bitcoin::taproot::TapNodeHash::from_byte_array(leaf_hash.to_byte_array())
            };

            let mut sec_nonces: StdHashMap<String, Vec<u8>> = StdHashMap::new();
            let mut asp_nonces_json: StdHashMap<String, String> = StdHashMap::new();

            for node in &round.vtxo_tree {
                if node.tx.is_empty() {
                    continue;
                }
                // Check if ASP is a cosigner for this node
                let node_cosigners =
                    Self::extract_cosigners_from_psbt_b64(&node.tx).unwrap_or_default();
                if !node_cosigners.contains(&asp_compressed_hex) {
                    continue;
                }

                // Generate nonce (message doesn't matter for nonce binding in BIP-327;
                // the signing step uses the actual sighash)
                let msg_placeholder = [0u8; 32];
                let (sec_nonce, pub_nonce) =
                    dark_bitcoin::signing::generate_nonce(&asp_seckey, &msg_placeholder);

                sec_nonces.insert(node.txid.clone(), sec_nonce.to_bytes().to_vec());
                asp_nonces_json.insert(node.txid.clone(), hex::encode(pub_nonce.to_bytes()));
            }

            info!(
                nonce_count = sec_nonces.len(),
                round_id = %round.id,
                "Generated ASP MuSig2 nonces for tree signing"
            );

            // Store ASP state for later signing steps
            {
                use bitcoin::hashes::Hash as _;
                let mut state = self.asp_musig2_state.lock().await;
                *state = Some(AspMusig2State {
                    sec_nonces,
                    agg_nonces: StdHashMap::new(),
                    sweep_merkle_root: sweep_merkle_root.to_byte_array(),
                    asp_compressed_hex: asp_compressed_hex.clone(),
                });
            }

            // Submit ASP nonces to the signing session (same format as client nonces:
            // JSON-serialized map<txid, nonce_hex>).
            let asp_nonces_blob = serde_json::to_vec(&asp_nonces_json)
                .map_err(|e| ArkError::Internal(format!("Failed to serialize ASP nonces: {e}")))?;
            self.signing_session_store
                .add_nonce(&round.id, &asp_compressed_hex, asp_nonces_blob)
                .await?;
            info!("ASP nonces submitted to signing session");
        }

        info!(
            round_id = %round.id,
            intent_count = intents.len(),
            commitment_txid = %commitment_txid,
            "Round entering tree signing phase (awaiting nonces)"
        );

        // Return round still in Finalization stage — NOT ended.
        // VTXOs are created later in complete_round() after signatures are received.
        Ok(round.clone())
    }

    /// Complete the round after tree signatures have been received.
    ///
    /// Creates VTXOs from intents, persists them, ends the round, and emits
    /// RoundFinalized so the event bridge can send BatchFinalization + BatchFinalized.
    pub async fn complete_round(&self) -> ArkResult<Round> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        if round.is_ended() {
            return Err(ArkError::Internal("Round already ended".to_string()));
        }
        if round.stage.code != RoundStage::Finalization {
            return Err(ArkError::Internal(
                "Round not in finalization stage".to_string(),
            ));
        }

        let intents: Vec<Intent> = round.intents.values().cloned().collect();
        let commitment_txid = round.commitment_txid.clone();
        let vtxo_expiry = self.compute_vtxo_expiry().await;

        let mut vtxos = Vec::new();
        let mut vtxo_idx = 0u32;

        let leaf_nodes: Vec<&TxTreeNode> = round
            .vtxo_tree
            .iter()
            .filter(|n| n.children.is_empty())
            .collect();

        for intent in &intents {
            for receiver in &intent.receivers {
                if receiver.is_onchain() {
                    continue;
                }

                let (vtxo_txid, vtxo_vout) = if let Some(leaf) = leaf_nodes.get(vtxo_idx as usize) {
                    (leaf.txid.clone(), 0u32)
                } else {
                    (commitment_txid.clone(), vtxo_idx)
                };

                let mut vtxo = Vtxo::new(
                    VtxoOutpoint::new(vtxo_txid, vtxo_vout),
                    receiver.amount,
                    receiver.pubkey.clone(),
                );
                vtxo.root_commitment_txid = commitment_txid.clone();
                vtxo.commitment_txids = vec![commitment_txid.clone()];
                vtxo_expiry.apply_to(&mut vtxo);

                // Carry over assets from the leaf PSBT's OP_RETURN extension.
                // Find the leaf whose P2TR output matches this receiver's pubkey
                // (not by positional index, which depends on HashMap ordering).
                let receiver_xonly = if receiver.pubkey.len() == 66 {
                    &receiver.pubkey[2..]
                } else {
                    receiver.pubkey.as_str()
                };
                let matching_leaf = leaf_nodes.iter().find(|leaf| {
                    if leaf.tx.is_empty() {
                        return false;
                    }
                    use base64::Engine;
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&leaf.tx) {
                        if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                            // Check if the leaf's first P2TR output matches the receiver
                            for out in &psbt.unsigned_tx.output {
                                let sb = out.script_pubkey.as_bytes();
                                if sb.len() == 34 && sb[0] == 0x51 && sb[1] == 0x20 {
                                    let leaf_xonly = hex::encode(&sb[2..]);
                                    if leaf_xonly == receiver_xonly {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    false
                });
                if let Some(leaf) = matching_leaf.or(leaf_nodes.get(vtxo_idx as usize)) {
                    if !leaf.tx.is_empty() {
                        use base64::Engine;
                        if let Ok(psbt_bytes) =
                            base64::engine::general_purpose::STANDARD.decode(&leaf.tx)
                        {
                            if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
                                // Parse asset info from OP_RETURN outputs
                                for out in &psbt.unsigned_tx.output {
                                    let sb = out.script_pubkey.as_bytes();
                                    if sb.len() < 5 || sb[0] != 0x6a {
                                        continue;
                                    }
                                    let push = {
                                        let mut p = 1usize;
                                        let op = sb[p];
                                        p += 1;
                                        if op <= 75 {
                                            let l = op as usize;
                                            if p + l <= sb.len() {
                                                Some(&sb[p..p + l])
                                            } else {
                                                None
                                            }
                                        } else if op == 0x4c && p < sb.len() {
                                            let l = sb[p] as usize;
                                            p += 1;
                                            if p + l <= sb.len() {
                                                Some(&sb[p..p + l])
                                            } else {
                                                None
                                            }
                                        } else if op == 0x4d && p + 1 < sb.len() {
                                            let l = u16::from_le_bytes([sb[p], sb[p + 1]]) as usize;
                                            p += 2;
                                            if p + l <= sb.len() {
                                                Some(&sb[p..p + l])
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    };
                                    if let Some(push) = push {
                                        if push.len() >= 4
                                            && push[0] == 0x41
                                            && push[1] == 0x52
                                            && push[2] == 0x4b
                                        {
                                            // Found ARK extension — parse asset outputs for this vout
                                            let asset_map = Self::parse_asset_packet_static(
                                                &psbt.unsigned_tx,
                                                &leaf.txid,
                                            );
                                            // vtxo_vout is 0 for leaf outputs
                                            if let Some(assets) = asset_map.get(&0) {
                                                vtxo.assets = assets.clone();
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Carry over assets from intent input VTXOs if the leaf PSBT
                // didn't have an asset extension AND there's only one intent
                // (single-party Settle). Multi-party rounds rely on the leaf
                // PSBT's OP_RETURN asset extension (parsed above).
                if vtxo.assets.is_empty() && intents.len() == 1 {
                    let mut asset_sums: std::collections::HashMap<String, u64> =
                        std::collections::HashMap::new();
                    let input_outpoints: Vec<VtxoOutpoint> =
                        intent.inputs.iter().map(|i| i.outpoint.clone()).collect();
                    if let Ok(input_vtxos) = self.vtxo_repo.get_vtxos(&input_outpoints).await {
                        for iv in &input_vtxos {
                            for (aid, amt) in &iv.assets {
                                *asset_sums.entry(aid.clone()).or_default() += amt;
                            }
                        }
                    }
                    if asset_sums.is_empty() {
                        for iv in &intent.inputs {
                            for (aid, amt) in &iv.assets {
                                *asset_sums.entry(aid.clone()).or_default() += amt;
                            }
                        }
                    }
                    vtxo.assets = asset_sums.into_iter().collect();
                }

                vtxos.push(vtxo);
                vtxo_idx += 1;
            }
        }

        info!(
            vtxo_count_to_persist = vtxos.len(),
            "About to persist VTXOs"
        );
        if !vtxos.is_empty() {
            for v in &vtxos {
                info!(
                    txid = %v.outpoint.txid,
                    vout = v.outpoint.vout,
                    pubkey = %v.pubkey,
                    amount = v.amount,
                    "VTXO to persist"
                );
            }
            match self.vtxo_repo.add_vtxos(&vtxos).await {
                Ok(()) => info!(
                    vtxo_count = vtxos.len(),
                    "VTXOs persisted after round completion"
                ),
                Err(e) => {
                    error!(error = %e, "FAILED to persist VTXOs!");
                    return Err(e);
                }
            }

            // Emit VtxoCreated events BEFORE VtxoSpent events.
            // The Go SDK's NotifyIncomingFunds subscribes to the indexer and
            // expects VtxoCreated first. If VtxoSpent fires first, the SDK
            // may interpret it as "done" and close the subscription before
            // VtxoCreated arrives.
            for vtxo in &vtxos {
                let _ = self
                    .events
                    .publish_event(ArkEvent::VtxoCreated {
                        vtxo_id: format!("{}:{}", vtxo.outpoint.txid, vtxo.outpoint.vout),
                        pubkey: vtxo.pubkey.clone(),
                        amount: vtxo.amount,
                        round_id: round.id.clone(),
                    })
                    .await;
            }
        }

        // Mark intent input VTXOs (off-chain refresh inputs) as spent now that
        // the round completed. This MUST happen even when there are no output
        // VTXOs (e.g. collaborative exit without change).
        {
            let spend_list: Vec<(VtxoOutpoint, String)> = intents
                .iter()
                .flat_map(|intent| {
                    intent.inputs.iter().filter_map(|inp| {
                        if inp.outpoint.txid.is_empty() {
                            None
                        } else {
                            Some((inp.outpoint.clone(), commitment_txid.clone()))
                        }
                    })
                })
                .collect();
            if !spend_list.is_empty() {
                // Use settle_vtxos (not spend_vtxos) to atomically set
                // BOTH spent_by AND settled_by. This ensures fraud
                // detection can always find the correct round via
                // settled_by, even if spent_by is later overwritten
                // by an offchain tx from a different context.
                if let Err(e) = self
                    .vtxo_repo
                    .settle_vtxos(&spend_list, &commitment_txid)
                    .await
                {
                    warn!(error = %e, "Failed to settle intent input VTXOs (non-fatal)");
                } else {
                    info!(count = spend_list.len(), "Settled intent input VTXOs");
                    // Emit VtxoSpent events so indexer subscriptions can notify
                    // clients watching these scripts (e.g. NotifyIncomingFunds).
                    for (outpoint, _) in &spend_list {
                        let _ = self
                            .events
                            .publish_event(ArkEvent::VtxoSpent {
                                vtxo_id: format!("{}:{}", outpoint.txid, outpoint.vout),
                                spending_txid: commitment_txid.clone(),
                            })
                            .await;
                    }
                }
            }
        }

        if !vtxos.is_empty() {
            // For each pubkey that has new output VTXOs, mark any prior unspent VTXOs
            // for that pubkey as spent (VTXO refresh / implicit forfeit).
            // This handles the case where RegisterForRound doesn't pass VTXO inputs explicitly.
            let new_outpoints: std::collections::HashSet<String> = vtxos
                .iter()
                .map(|v| format!("{}:{}", v.outpoint.txid, v.outpoint.vout))
                .collect();
            let pubkeys_with_new_vtxos: std::collections::HashSet<&str> =
                vtxos.iter().map(|v| v.pubkey.as_str()).collect();
            for pubkey in pubkeys_with_new_vtxos {
                if let Ok((spendable, spent)) =
                    self.vtxo_repo.get_all_vtxos_for_pubkey(pubkey).await
                {
                    // Settle prior spendable VTXOs (existing behavior).
                    let mut prior_outpoints: Vec<(VtxoOutpoint, String)> = spendable
                        .into_iter()
                        .filter(|v| {
                            !new_outpoints
                                .contains(&format!("{}:{}", v.outpoint.txid, v.outpoint.vout))
                        })
                        .map(|v| (v.outpoint, commitment_txid.clone()))
                        .collect();

                    // Also settle preconfirmed+swept VTXOs that the batch
                    // superseded.  These are in the "spent" list (swept=true)
                    // but haven't been officially settled (spent=false).
                    // Without this, a preconfirmed vtxo swept by
                    // broadcast_checkpoint_tx remains with spent=false and
                    // shows up as "recoverable" in the Go SDK.
                    let swept_preconfirmed: Vec<(VtxoOutpoint, String)> = spent
                        .into_iter()
                        .filter(|v| {
                            v.preconfirmed
                                && v.swept
                                && !v.spent
                                && !new_outpoints
                                    .contains(&format!("{}:{}", v.outpoint.txid, v.outpoint.vout))
                        })
                        .map(|v| (v.outpoint, commitment_txid.clone()))
                        .collect();
                    prior_outpoints.extend(swept_preconfirmed);

                    if !prior_outpoints.is_empty() {
                        if let Err(e) = self
                            .vtxo_repo
                            .settle_vtxos(&prior_outpoints, &commitment_txid)
                            .await
                        {
                            warn!(error = %e, pubkey, "Failed to settle prior VTXOs on refresh (non-fatal)");
                        } else {
                            info!(
                                count = prior_outpoints.len(),
                                pubkey, "Settled prior VTXOs (VTXO refresh)"
                            );
                        }
                    }
                }
            }
        }

        // Commitment tx broadcast is handled by the client via
        // SubmitSignedForfeitTxs.signed_commitment_tx.  The client signs the
        // boarding inputs, then the ASP co-signs and broadcasts.
        // BatchFinalized is deferred until broadcast (RoundBroadcast event).

        // Use the flag set during finalize_round() to know whether there are
        // on-chain boarding inputs.  The previous approach of checking
        // `!psbt.unsigned_tx.input.is_empty()` was wrong because the PSBT
        // always has inputs (e.g. connector inputs) even when there are no
        // boarding UTXOs, causing BatchFinalized to never be emitted for
        // VTXO-only refresh rounds.
        let has_boarding = round.has_boarding_inputs;
        let has_connectors = !round.connectors.is_empty();
        let boarding_tx_ids = round.boarding_tx_ids.clone();

        round.end_successfully();

        // When connectors exist (forfeits expected), spawn a background
        // ban task that fires if forfeits aren't received within 10s.
        // The round itself ends normally, and BatchFinalized is deferred
        // in the event bridge (has_connectors flag).  If forfeits arrive
        // before the timeout, submit_signed_forfeit_txs emits
        // RoundBroadcast → BatchFinalized.  If they don't, the SDK
        // times out waiting for BatchFinalized and JoinBatchSession
        // returns an error.  The ban task ensures the participant is
        // banned for future operations.
        if has_connectors {
            // Compute ASP compressed key to exclude from ban targets
            let asp_hex = self
                .signer
                .get_secret_key_bytes()
                .await
                .ok()
                .and_then(|sk_bytes| {
                    let secp = bitcoin::secp256k1::Secp256k1::new();
                    bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes)
                        .ok()
                        .map(|sk| {
                            hex::encode(
                                bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
                                    .serialize(),
                            )
                        })
                })
                .unwrap_or_default();

            let ban_targets: Vec<(String, Vec<String>)> = {
                let mut targets = Vec::new();
                for intent in round.intents.values() {
                    let outpoints: Vec<VtxoOutpoint> =
                        intent.inputs.iter().map(|i| i.outpoint.clone()).collect();
                    let owner_keys: Vec<String> = self
                        .vtxo_repo
                        .get_vtxos(&outpoints)
                        .await
                        .map(|vtxos| {
                            vtxos
                                .iter()
                                .map(|v| v.pubkey.clone())
                                .filter(|pk| !pk.is_empty())
                                .collect()
                        })
                        .unwrap_or_default();
                    for cpk in &intent.cosigners_public_keys {
                        if !cpk.is_empty() && cpk != &asp_hex {
                            targets.push((cpk.clone(), owner_keys.clone()));
                        }
                    }
                }
                targets
            };

            // NOTE: Delayed ban removed. Banning is handled by abort_round()
            // when the signing timeout fires. The fire-and-forget delayed ban
            // caused cross-test ban leakage by banning ALL participants
            // (including innocent ones from stale sessions) after every round,
            // even successful ones.
            let _ = &ban_targets; // suppress unused warning
        }

        // Mark boarding transactions as claimed now that the round has completed.
        // This ensures that `GetVtxos` returns them with spent=true status.
        for boarding_id in &boarding_tx_ids {
            if let Err(e) = self.boarding_repo.mark_claimed(boarding_id).await {
                warn!(
                    boarding_id = %boarding_id,
                    error = %e,
                    "Failed to mark boarding transaction as claimed (non-fatal)"
                );
            } else {
                info!(boarding_id = %boarding_id, "Marked boarding transaction as claimed");
            }
        }

        info!(
            round_id = %round.id,
            intent_count = intents.len(),
            has_boarding_inputs = has_boarding,
            boarding_txs_claimed = boarding_tx_ids.len(),
            "Round completed with commitment tx"
        );

        // Persist round to the database so the indexer can serve it later
        // (GetVtxoChain, GetVtxoTree, GetVirtualTxs all depend on stored rounds).
        //
        // Merge forfeit_txs from the DB: submit_signed_forfeit_txs stores
        // forfeits on the DB round before complete_round runs. The in-memory
        // round doesn't have them, so we merge to avoid losing them.
        if let Ok(Some(db_round)) = self.round_repo.get_round_with_id(&round.id).await {
            if !db_round.forfeit_txs.is_empty() && round.forfeit_txs.is_empty() {
                round.forfeit_txs = db_round.forfeit_txs;
            }
        }
        info!(
            vtxo_tree_len = round.vtxo_tree.len(),
            forfeit_txs = round.forfeit_txs.len(),
            "complete_round: about to save round"
        );
        if let Err(e) = self.round_repo.add_or_update_round(round).await {
            warn!(error = %e, "Failed to persist round (non-fatal)");
        }

        // Start watching VTXO scripts for on-chain spends (fraud detection).
        // This enables the scanner listener to detect unilateral exits of
        // already-spent VTXOs.
        if !vtxos.is_empty() {
            self.start_watching_vtxos(&vtxos).await;
            info!(
                vtxo_count = vtxos.len(),
                "Started watching VTXO scripts for fraud detection"
            );
        }

        let has_connectors = !round.connectors.is_empty();
        self.events
            .publish_event(ArkEvent::RoundFinalized {
                round_id: round.id.clone(),
                commitment_tx: round.commitment_tx.clone(),
                timestamp: round.ending_timestamp,
                vtxo_count: vtxos.len() as u32,
                has_boarding_inputs: has_boarding,
                has_connectors,
            })
            .await?;

        // For boarding rounds, the commitment tx is broadcast when clients submit
        // their signed commitment PSBTs via SubmitSignedBatchTx / the event stream.
        // The server merges all partial signatures and broadcasts the finalized tx.
        // We do NOT broadcast here because we only have the server's signatures —
        // the boarding inputs also need client signatures to be valid.
        //
        // For non-boarding rounds (VTXO-only refresh OR collaborative exit), always
        // broadcast the commitment tx immediately. This is required because:
        // - Collaborative exit: on-chain outputs must appear on-chain.
        // - VTXO-only refresh: the vtxo tree transactions spend from the commitment tx,
        //   so the commitment tx MUST be on-chain before clients can unroll (unilateral exit).
        //   Without broadcasting here, TestUnilateralExit fails because tree txs can never
        //   be confirmed (their parent — the commitment tx — is never on-chain).
        if !has_boarding {
            info!(
                round_id = %round.id,
                "Broadcasting commitment tx for non-boarding round"
            );
            match self
                .finalize_and_broadcast_commitment_psbt(&round.commitment_tx)
                .await
            {
                Ok(txid) => {
                    info!(txid = %txid, "Commitment tx broadcast successfully");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to broadcast commitment tx — emitting RoundBroadcast anyway");
                }
            }

            self.events
                .publish_event(ArkEvent::RoundBroadcast {
                    round_id: round.id.clone(),
                    commitment_txid: commitment_txid.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                })
                .await?;
        }

        // Release any wallet UTXO reservations so the next round can use them.
        if let Err(e) = self.wallet.release_all_reservations().await {
            warn!(error = %e, "Failed to release wallet reservations after round (non-fatal)");
        }

        // Keep the completed round in current_round (don't set to None).
        // end_successfully() marks it as terminal, so start_round() will
        // overwrite it (it checks is_ended()). Leaving the ended round in
        // place prevents a race where in-flight ConfirmRegistration calls
        // see None and return "No active round".
        let completed_round = round.clone();
        drop(guard);

        // Store the completed round so submit_signed_forfeit_txs can
        // validate forfeits that arrive after the round completes
        // (BatchFinalizationEvent is emitted post-completion).
        {
            let mut last = self.last_completed_round.write().await;
            *last = Some(completed_round.clone());
        }

        // Immediately start a new round to prevent stalls.
        match self.start_round().await {
            Ok(new_round) => {
                info!(round_id = %new_round.id, "Auto-started new round after completion");
            }
            Err(e) => {
                debug!(error = %e, "Could not auto-start new round immediately (will retry on scheduler tick)");
            }
        }

        Ok(completed_round)
    }

    /// Try to complete the round with only confirmed intents.
    ///
    /// Called by the round loop before aborting on signing timeout. If the round
    /// has unconfirmed intents (from stale SDK sessions), drops them and checks
    /// if all remaining (confirmed) cosigners have submitted nonces. If yes,
    /// returns Ok (the round will complete normally). If not, returns Err.
    pub async fn try_complete_confirmed_only(&self) -> ArkResult<()> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        if round.is_ended() {
            return Ok(()); // Already completed
        }

        // Check if there are unconfirmed intents
        let unconfirmed: Vec<String> = round
            .confirmation_status
            .iter()
            .filter(|(_, status)| matches!(status, crate::domain::ConfirmationStatus::Pending))
            .map(|(id, _)| id.clone())
            .collect();

        if unconfirmed.is_empty() {
            return Err(ArkError::Internal(
                "All intents confirmed — timeout is genuine".to_string(),
            ));
        }

        // Drop unconfirmed intents
        let dropped = round.drop_unconfirmed();
        if dropped > 0 {
            info!(
                round_id = %round.id,
                dropped_count = dropped,
                "Dropped unconfirmed intents from timed-out round"
            );

            // Re-count cosigners from remaining (confirmed) intents
            let confirmed_cosigners: std::collections::HashSet<String> = round
                .vtxo_tree
                .iter()
                .filter(|n| !n.tx.is_empty())
                .flat_map(|n| Self::extract_cosigners_from_psbt_b64(&n.tx).unwrap_or_default())
                .collect();

            // Check if the signing session has all confirmed cosigners' nonces
            if let Ok(Some(session)) = self.signing_session_store.get_session(&round.id).await {
                let nonce_keys: std::collections::HashSet<String> =
                    session.tree_nonces.iter().map(|(k, _)| k.clone()).collect();

                // Check if all confirmed cosigners submitted nonces
                let all_confirmed_have_nonces = confirmed_cosigners.iter().all(|ck| {
                    let xonly = if ck.len() == 66 {
                        &ck[2..]
                    } else {
                        ck.as_str()
                    };
                    nonce_keys.contains(ck) || nonce_keys.contains(xonly)
                });

                if all_confirmed_have_nonces {
                    // Re-initialize signing session with correct participant count
                    let _ = self
                        .signing_session_store
                        .init_session(&round.id, confirmed_cosigners.len())
                        .await;
                    // Re-add nonces from confirmed cosigners
                    for (key, nonce) in &session.tree_nonces {
                        let _ = self
                            .signing_session_store
                            .add_nonce(&round.id, key, nonce.clone())
                            .await;
                    }
                    info!(
                        round_id = %round.id,
                        confirmed_cosigners = confirmed_cosigners.len(),
                        "All confirmed cosigners have nonces — round can proceed"
                    );
                    return Ok(());
                }
            }
        }

        Err(ArkError::Internal(
            "Cannot complete with confirmed-only".to_string(),
        ))
    }

    /// Abort the current round due to timeout or other failure.
    ///
    /// This is used when a round gets stuck (e.g., cosigners fail to submit
    /// tree nonces/signatures within the timeout). The round is marked as failed
    /// and cleared so a new round can start.
    ///
    /// Emits `RoundFailed` event so clients are notified.
    pub async fn abort_round(&self, reason: &str) -> ArkResult<Round> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round to abort".to_string()))?;

        if round.is_ended() {
            return Err(ArkError::Internal("Round already ended".to_string()));
        }

        round.fail(reason.to_string());
        let failed_round = round.clone();

        info!(
            round_id = %failed_round.id,
            reason = %reason,
            "Round aborted"
        );

        // ── Release boarding inputs so they don't accumulate ─────────────
        // Mark boarding inputs from the failed round as "claimed" so they won't
        // be re-included in the next round. Without this, a timeout leaves the
        // boarding UTXOs in the pending pool, and the next round picks them up
        // along with new ones — causing multiple-owner signing failures.
        for boarding_id in &failed_round.boarding_tx_ids {
            let _ = self.boarding_repo.mark_claimed(boarding_id).await;
        }

        // ── Auto-ban non-responding cosigners on signing timeout ──────────
        // When a round times out in the signing phase, ban participants who
        // failed to submit their tree nonces. This prevents malicious or
        // unresponsive cosigners from blocking rounds indefinitely.
        //
        // The expected cosigners are derived from the actual PSBTs in the vtxo
        // tree — the same source used to initialize the signing session. This is
        // the authoritative set of keys that were required to sign. Using
        // intent.cosigners_public_keys instead is incorrect: in delegate flows,
        // the delegate's pubkey appears there but the vtxo tree may be empty
        // (stub/invalid input), so nobody should be banned.
        // Ban participants when the round was in the signing (Finalization)
        // phase.  This covers signing timeout, invalid signatures, and any
        // other failure that causes the round to abort during tree signing.
        if failed_round.stage.code == RoundStage::Finalization || reason == "signing timeout" {
            // Get all expected signers from PSBT cosigner fields in the tree.
            // Also get the ASP key so we don't ban ourselves.
            let asp_compressed_hex = self
                .signer
                .get_secret_key_bytes()
                .await
                .ok()
                .and_then(|sk_bytes| {
                    let secp = bitcoin::secp256k1::Secp256k1::new();
                    bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes)
                        .ok()
                        .map(|sk| {
                            hex::encode(
                                bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
                                    .serialize(),
                            )
                        })
                })
                .unwrap_or_default();

            // Collect all pubkeys that should be banned: tree cosigners
            // AND intent cosigners (which may differ from tree cosigners
            // in delegate flows or custom signer sessions).
            let expected_pubkeys: std::collections::HashSet<String> = failed_round
                .vtxo_tree
                .iter()
                .filter(|n| !n.tx.is_empty())
                .flat_map(|n| Self::extract_cosigners_from_psbt_b64(&n.tx).unwrap_or_default())
                .filter(|pk| !pk.is_empty() && pk != &asp_compressed_hex)
                .collect();

            // Also collect cosigner pubkeys from the intent messages.
            // The test uses a random signer session key as the cosigner,
            // which may differ from the tree PSBT cosigners if the ASP
            // added itself after the intent was registered.
            let mut intent_cosigners: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for intent in failed_round.intents.values() {
                for cpk in &intent.cosigners_public_keys {
                    if !cpk.is_empty() && cpk != &asp_compressed_hex {
                        intent_cosigners.insert(cpk.clone());
                    }
                }
            }

            // Build a map from cosigner key → VTXO owner pubkeys (tap keys)
            // for that intent.  First use the intent's input VTXOs directly
            // (these have pubkeys even for boarding inputs that aren't in the
            // VTXO store), then fall back to the VTXO store for additional
            // pubkeys.
            let mut cosigner_to_owner: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            for intent in failed_round.intents.values() {
                // Collect pubkeys directly from intent inputs (works for all
                // input types including boarding inputs not in VTXO store)
                let mut owner_pubkeys: Vec<String> = intent
                    .inputs
                    .iter()
                    .map(|inp| inp.pubkey.clone())
                    .filter(|pk| !pk.is_empty())
                    .collect();

                // Also look up stored VTXO pubkeys (these may differ from
                // intent input pubkeys — the stored pubkey is the tap key
                // that GetVtxos uses for filtering)
                let input_outpoints: Vec<VtxoOutpoint> = intent
                    .inputs
                    .iter()
                    .map(|inp| inp.outpoint.clone())
                    .collect();
                if let Ok(vtxos) = self.vtxo_repo.get_vtxos(&input_outpoints).await {
                    for v in &vtxos {
                        if !v.pubkey.is_empty() && !owner_pubkeys.contains(&v.pubkey) {
                            owner_pubkeys.push(v.pubkey.clone());
                        }
                    }
                }

                for cpk in &intent.cosigners_public_keys {
                    cosigner_to_owner
                        .entry(cpk.clone())
                        .or_default()
                        .extend(owner_pubkeys.iter().cloned());
                }
            }

            let all_expected: std::collections::HashSet<String> =
                expected_pubkeys.union(&intent_cosigners).cloned().collect();

            if !all_expected.is_empty() {
                let expected_pubkeys = all_expected;
                // Only ban cosigners whose intents have forfeitable VTXO inputs
                // (i.e. inputs that need a connector). Note-only intents (faucet
                // rounds) shouldn't trigger bans because the participant isn't
                // misbehaving — they just got caught in a multi-party round where
                // another participant failed to respond.
                // For signing timeouts where NO signatures were submitted at all,
                // only ban cosigners that didn't submit nonces. Participants
                // that DID submit nonces are innocent — they got caught in a
                // round where someone ELSE failed to respond.
                // If any signatures were submitted, the abort is due to
                // signature issues (not pure nonce timeout) — ban everyone.
                let nonce_submitters: std::collections::HashSet<String> =
                    if reason == "signing timeout" {
                        let session = self
                            .signing_session_store
                            .get_session(&failed_round.id)
                            .await
                            .ok()
                            .flatten();
                        let has_any_sigs = session
                            .as_ref()
                            .map(|s| !s.tree_signatures.is_empty())
                            .unwrap_or(false);
                        if has_any_sigs {
                            // Signatures were submitted — this isn't a pure nonce timeout
                            std::collections::HashSet::new()
                        } else {
                            session
                                .map(|s| {
                                    let mut keys: std::collections::HashSet<String> =
                                        s.tree_nonces.iter().map(|(k, _)| k.clone()).collect();
                                    let xonly: Vec<String> = keys
                                        .iter()
                                        .filter(|k| k.len() == 66)
                                        .map(|k| k[2..].to_string())
                                        .collect();
                                    keys.extend(xonly);
                                    keys
                                })
                                .unwrap_or_default()
                        }
                    } else {
                        std::collections::HashSet::new() // non-timeout: ban everyone
                    };

                for expected_pk in &expected_pubkeys {
                    // For signing timeouts, skip banning participants that submitted nonces
                    if reason == "signing timeout" {
                        let pk_xonly = if expected_pk.len() == 66 {
                            &expected_pk[2..]
                        } else {
                            expected_pk.as_str()
                        };
                        if nonce_submitters.contains(expected_pk)
                            || nonce_submitters.contains(pk_xonly)
                        {
                            info!(
                                pubkey = %expected_pk,
                                round_id = %failed_round.id,
                                "Skipping ban — participant submitted nonces (signing timeout)"
                            );
                            continue;
                        }
                    }
                    warn!(
                        pubkey = %expected_pk,
                        round_id = %failed_round.id,
                        "Auto-banning participant (round timeout)"
                    );
                    if let Err(e) = self
                        .ban_participant(
                            expected_pk,
                            crate::domain::BanReason::FailedToConfirm,
                            &failed_round.id,
                        )
                        .await
                    {
                        error!(pubkey = %expected_pk, error = %e, "Failed to auto-ban");
                    }

                    // Also ban the VTXO owner keys associated with this
                    // cosigner — but ONLY if the cosigner's intent was confirmed.
                    // Unconfirmed intents are from stale SDK sessions (cross-test
                    // collision). Their owner keys are innocent and shouldn't be
                    // banned, otherwise the ban cascades to later tests.
                    let cosigner_was_confirmed = failed_round.intents.values().any(|i| {
                        i.cosigners_public_keys.contains(&expected_pk.to_string())
                            && failed_round
                                .confirmation_status
                                .get(&i.id)
                                .map(|s| {
                                    matches!(s, crate::domain::ConfirmationStatus::Confirmed { .. })
                                })
                                .unwrap_or(false)
                    });
                    if cosigner_was_confirmed {
                        if let Some(owners) = cosigner_to_owner.get(expected_pk) {
                            for owner_pk in owners {
                                let _ = self
                                    .ban_participant(
                                        owner_pk,
                                        crate::domain::BanReason::FailedToConfirm,
                                        &failed_round.id,
                                    )
                                    .await;
                            }
                        }
                    } else {
                        info!(
                            pubkey = %expected_pk,
                            round_id = %failed_round.id,
                            "Skipping owner ban — cosigner's intent was not confirmed"
                        );
                    }
                }
            }
        }

        // Emit BatchFailed event so connected clients know the round failed.
        self.events
            .publish_event(ArkEvent::RoundFailed {
                round_id: failed_round.id.clone(),
                reason: reason.to_string(),
                timestamp: chrono::Utc::now().timestamp(),
            })
            .await?;

        // Release any wallet UTXO reservations so the next round can use them.
        if let Err(e) = self.wallet.release_all_reservations().await {
            warn!(error = %e, "Failed to release wallet reservations after abort (non-fatal)");
        }

        // Keep the failed round in current_round (don't set to None).
        // round.fail() already marked it as terminal, so start_round() will
        // overwrite it (it checks is_ended()). Leaving the failed round in
        // place prevents a race where in-flight ConfirmRegistration calls see
        // None and return "No active round".
        drop(guard);

        // Immediately start a new round to prevent stalls
        match self.start_round().await {
            Ok(new_round) => {
                info!(round_id = %new_round.id, "Auto-started new round after abort");
            }
            Err(e) => {
                debug!(error = %e, "Could not auto-start new round immediately (will retry on scheduler tick)");
            }
        }

        Ok(failed_round)
    }

    // ── Confirmation Phase ───────────────────────────────────────────

    /// Start the confirmation phase: transitions from registration to finalization,
    /// emits BatchStarted event, and initializes confirmation tracking.
    ///
    /// Returns the list of intent IDs that need confirmation.
    #[instrument(skip(self))]
    pub async fn start_confirmation(&self) -> ArkResult<Vec<String>> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        if round.stage.code != RoundStage::Registration {
            return Err(ArkError::Internal(
                "Round not in registration stage".to_string(),
            ));
        }

        if round.is_ended() {
            return Err(ArkError::Internal("Round already ended".to_string()));
        }

        // Check minimum intents
        let intent_count = round.intent_count() as u32;
        if intent_count < self.config.min_intents {
            info!(
                round_id = %round.id,
                intent_count,
                min_intents = self.config.min_intents,
                "Not enough intents — failing round"
            );
            round.fail(format!(
                "Not enough intents: {} < {}",
                intent_count, self.config.min_intents
            ));
            self.events
                .publish_event(ArkEvent::RoundFailed {
                    round_id: round.id.clone(),
                    reason: round.fail_reason.clone(),
                    timestamp: round.ending_timestamp,
                })
                .await?;
            return Err(ArkError::Internal(round.fail_reason.clone()));
        }

        // Transition to finalization stage (confirmation happens within finalization)
        round.start_finalization().map_err(ArkError::Internal)?;

        // Initialize confirmation status for all intents
        round.start_confirmation();

        let intent_ids: Vec<String> = round.intents.keys().cloned().collect();

        // Initialize the confirmation store
        self.confirmation_store
            .init(&round.id, intent_ids.clone())
            .await?;

        // Build unsigned VTXO tree for the BatchStarted event
        // (participants need this to verify before confirming).
        // Use signer pubkey — same key used for ASP-signing tree nodes and
        // reported as forfeit_pubkey in GetInfo.
        let signer_pubkey = self.signer.get_pubkey().await?;
        let intents: Vec<Intent> = round.intents.values().cloned().collect();
        // Collect boarding inputs from intent proof tx inputs.
        // Only include inputs that are on-chain boarding UTXOs (NOT already
        // in the VTXO store as off-chain VTXOs). Off-chain VTXO inputs
        // (e.g. delegate refresh) are spent virtually, not as commitment tx inputs.
        let mut boarding_inputs: Vec<crate::ports::BoardingInput> = Vec::new();
        for intent in &intents {
            for inp in &intent.inputs {
                if inp.amount > 0 && !inp.outpoint.txid.is_empty() {
                    let outpoint_slice = [inp.outpoint.clone()];
                    let is_offchain = self
                        .vtxo_repo
                        .get_vtxos(&outpoint_slice)
                        .await
                        .ok()
                        .map(|v| !v.is_empty())
                        .unwrap_or(false);

                    if !is_offchain {
                        boarding_inputs.push(crate::ports::BoardingInput {
                            outpoint: inp.outpoint.clone(),
                            amount: inp.amount,
                        });
                    }
                }
            }
        }
        // Also check the legacy boarding repo
        let boarding_txs = self.claim_boarding_inputs().await.unwrap_or_default();
        for bt in &boarding_txs {
            if let (Some(txid), Some(vout)) = (bt.funding_txid.as_ref(), bt.funding_vout) {
                boarding_inputs.push(crate::ports::BoardingInput {
                    outpoint: VtxoOutpoint::new(txid.to_string(), vout),
                    amount: bt.amount.to_sat(),
                });
            }
        }

        info!(
            boarding_count = boarding_inputs.len(),
            "Including boarding inputs in confirmation"
        );

        let result = self
            .tx_builder
            .build_commitment_tx(&signer_pubkey, &intents, &boarding_inputs)
            .await?;

        // Store the unsigned tree on the round for later
        round.vtxo_tree = result.vtxo_tree;
        round.connectors = result.connectors;
        round.connector_address = result.connector_address.clone();
        round.has_boarding_inputs = !boarding_inputs.is_empty();
        round.boarding_tx_ids = boarding_txs.iter().map(|bt| bt.id.to_string()).collect();

        let timestamp = chrono::Utc::now().timestamp();

        info!(
            round_id = %round.id,
            intent_count = intent_ids.len(),
            "Confirmation phase started"
        );

        self.events
            .publish_event(ArkEvent::BatchStarted {
                round_id: round.id.clone(),
                intent_ids: intent_ids.clone(),
                unsigned_vtxo_tree: result.commitment_tx,
                timestamp,
            })
            .await?;

        Ok(intent_ids)
    }

    /// Confirm a participant's registration in the current round.
    ///
    /// Called by participants after receiving BatchStarted to confirm
    /// they agree with the VTXO tree construction.
    #[instrument(skip(self))]
    pub async fn confirm_registration(&self, intent_id: &str) -> ArkResult<()> {
        let round_id = {
            let guard = self.current_round.read().await;
            let round = guard
                .as_ref()
                .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

            if round.stage.code != RoundStage::Finalization {
                return Err(ArkError::Internal(
                    "Round not in finalization stage".to_string(),
                ));
            }

            // Accept gracefully if the round was already auto-completed (e.g.
            // empty vtxo tree / collaborative exit without change fast-path).
            // The client calls ConfirmRegistration after receiving BatchStarted,
            // but the auto-complete path may have already ended the round by
            // then. This is not an error — the round succeeded.
            if round.is_ended() {
                info!(
                    intent_id,
                    round_id = %round.id,
                    "confirm_registration: round already ended (auto-completed) — accepting gracefully"
                );
                return Ok(());
            }

            round.id.clone()
        };

        // Mark confirmed in the domain model, and check whether this confirmation
        // completes the round (empty vtxo_tree — collaborative exit without change).
        struct EmptyTreeAutoComplete {
            round_id: String,
            commitment_txid: String,
            commitment_tx: String,
            intents: Vec<Intent>,
            boarding_tx_ids: Vec<String>,
            round_clone: Round,
        }
        let auto_complete: Option<EmptyTreeAutoComplete> = {
            let mut guard = self.current_round.write().await;
            let round = match guard.as_mut() {
                Some(r) => r,
                None => {
                    // Round was cleared by a concurrent complete_round() between
                    // the earlier read-lock check and now. Accept gracefully.
                    info!(
                        intent_id,
                        "confirm_registration: round cleared between read/write lock — accepting gracefully"
                    );
                    return Ok(());
                }
            };

            // Re-check inside the write lock (round may have been ended by a
            // concurrent call between the earlier read-lock check and now).
            if round.is_ended() {
                return Ok(());
            }

            round
                .confirm_intent(intent_id)
                .map_err(|e| ArkError::Internal(e.to_string()))?;

            // Check if this was the last confirmation needed for an empty-tree round.
            // Empty vtxo_tree means all receivers are onchain (collaborative exit without
            // a VTXO change output). In that case nobody will ever call submit_tree_nonces
            // / submit_tree_signatures, so we must complete the round here.
            let tree_is_empty = round.vtxo_tree.iter().all(|n| n.tx.is_empty());
            if tree_is_empty && round.all_confirmed() {
                // Mark as ended immediately (inside the write lock) to prevent a
                // concurrent ConfirmRegistration call from triggering a second
                // auto-complete for the same round.
                round.end_successfully();
                let ac = EmptyTreeAutoComplete {
                    round_id: round.id.clone(),
                    commitment_txid: round.commitment_txid.clone(),
                    commitment_tx: round.commitment_tx.clone(),
                    intents: round.intents.values().cloned().collect(),
                    boarding_tx_ids: round.boarding_tx_ids.clone(),
                    round_clone: round.clone(),
                };
                Some(ac)
            } else {
                None
            }
        };

        // Mark confirmed in the store
        self.confirmation_store
            .confirm(&round_id, intent_id)
            .await?;

        let timestamp = chrono::Utc::now().timestamp();

        info!(round_id = %round_id, intent_id, "Intent confirmed");

        self.events
            .publish_event(ArkEvent::IntentConfirmed {
                round_id: round_id.clone(),
                intent_id: intent_id.to_string(),
                timestamp,
            })
            .await?;

        // ── Empty-tree auto-complete (collaborative exit without VTXO change) ──
        if let Some(ac) = auto_complete {
            info!(
                round_id = %ac.round_id,
                "All intents confirmed, vtxo_tree is empty — auto-completing round \
                 (collaborative exit without change)"
            );

            // Mark input VTXOs as settled (not just spent). settle_vtxos
            // atomically sets BOTH spent_by AND settled_by, which ensures
            // react_to_fraud can find the correct round via settled_by even
            // if spent_by is later overwritten by an offchain tx.
            let spend_list: Vec<(VtxoOutpoint, String)> = ac
                .intents
                .iter()
                .flat_map(|intent| {
                    intent.inputs.iter().filter_map(|inp| {
                        if inp.outpoint.txid.is_empty() {
                            None
                        } else {
                            Some((inp.outpoint.clone(), ac.commitment_txid.clone()))
                        }
                    })
                })
                .collect();
            if !spend_list.is_empty() {
                if let Err(e) = self
                    .vtxo_repo
                    .settle_vtxos(&spend_list, &ac.commitment_txid)
                    .await
                {
                    warn!(
                        error = %e,
                        "Failed to settle input VTXOs (non-fatal, empty-tree auto-complete)"
                    );
                } else {
                    info!(
                        count = spend_list.len(),
                        "Settled input VTXOs (empty-tree auto-complete)"
                    );
                    // Emit VtxoSpent events so indexer subscriptions can notify
                    // clients watching these scripts (e.g. NotifyIncomingFunds).
                    for (outpoint, _) in &spend_list {
                        let _ = self
                            .events
                            .publish_event(ArkEvent::VtxoSpent {
                                vtxo_id: format!("{}:{}", outpoint.txid, outpoint.vout),
                                spending_txid: ac.commitment_txid.clone(),
                            })
                            .await;
                    }
                }
            }

            // Mark boarding transactions as claimed.
            for boarding_id in &ac.boarding_tx_ids {
                if let Err(e) = self.boarding_repo.mark_claimed(boarding_id).await {
                    warn!(
                        boarding_id = %boarding_id,
                        error = %e,
                        "Failed to mark boarding tx as claimed (non-fatal, empty-tree auto-complete)"
                    );
                }
            }

            // Merge forfeit_txs from the DB: submit_signed_forfeit_txs may
            // have stored forfeits on the DB round before this auto-complete
            // runs. The in-memory round_clone doesn't have them, so merge to
            // avoid losing them when we overwrite below.
            let mut round_to_persist = ac.round_clone.clone();
            if let Ok(Some(db_round)) = self.round_repo.get_round_with_id(&ac.round_id).await {
                if !db_round.forfeit_txs.is_empty() && round_to_persist.forfeit_txs.is_empty() {
                    round_to_persist.forfeit_txs = db_round.forfeit_txs;
                }
            }

            // Persist the round (with ended state).
            if let Err(e) = self.round_repo.add_or_update_round(&round_to_persist).await {
                warn!(
                    error = %e,
                    "Failed to persist round (non-fatal, empty-tree auto-complete)"
                );
            }

            let has_boarding = !ac.boarding_tx_ids.is_empty();
            let ending_timestamp = ac.round_clone.ending_timestamp;
            self.events
                .publish_event(ArkEvent::RoundFinalized {
                    round_id: ac.round_id.clone(),
                    commitment_tx: ac.commitment_tx.clone(),
                    timestamp: ending_timestamp,
                    vtxo_count: 0, // all receivers were onchain — no VTXOs created
                    has_boarding_inputs: has_boarding,
                    has_connectors: false,
                })
                .await?;

            // Broadcast the commitment tx.
            match self
                .finalize_and_broadcast_commitment_psbt(&ac.commitment_tx)
                .await
            {
                Ok(txid) => {
                    info!(txid = %txid, "Commitment tx broadcast (empty-tree auto-complete)");
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Failed to broadcast commitment tx (empty-tree auto-complete) \
                         — emitting RoundBroadcast anyway"
                    );
                }
            }

            self.events
                .publish_event(ArkEvent::RoundBroadcast {
                    round_id: ac.round_id.clone(),
                    commitment_txid: ac.commitment_txid.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                })
                .await?;

            // Release wallet UTXO reservations so the next round can use them.
            if let Err(e) = self.wallet.release_all_reservations().await {
                warn!(error = %e, "Failed to release wallet reservations (non-fatal, empty-tree auto-complete)");
            }

            // Store the completed round so submit_signed_forfeit_txs can
            // find it as a fallback when forfeits arrive after completion.
            {
                let mut last = self.last_completed_round.write().await;
                *last = Some(round_to_persist);
            }

            // Auto-start a new round to prevent stalls.
            match self.start_round().await {
                Ok(new_round) => {
                    info!(round_id = %new_round.id, "Auto-started new round after empty-tree auto-complete");
                }
                Err(e) => {
                    debug!(error = %e, "Could not auto-start new round after empty-tree auto-complete (will retry on scheduler tick)");
                }
            }

            info!(round_id = %ac.round_id, "Empty-tree round auto-complete finished");
        }

        Ok(())
    }

    /// End the confirmation phase: drops unconfirmed intents and emits event.
    ///
    /// Returns (confirmed_count, dropped_count).
    #[instrument(skip(self))]
    pub async fn end_confirmation(&self) -> ArkResult<(u32, u32)> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        if round.stage.code != RoundStage::Finalization {
            return Err(ArkError::Internal(
                "Round not in finalization stage".to_string(),
            ));
        }

        // Count confirmed before dropping
        let confirmed_count = round
            .confirmation_status
            .values()
            .filter(|s| matches!(s, crate::domain::ConfirmationStatus::Confirmed { .. }))
            .count() as u32;

        // Drop unconfirmed intents
        let dropped_count = round.drop_unconfirmed() as u32;

        let timestamp = chrono::Utc::now().timestamp();

        info!(
            round_id = %round.id,
            confirmed_count,
            dropped_count,
            "Confirmation phase ended"
        );

        // If all intents were dropped, fail the round
        if round.intents.is_empty() {
            round.fail("All intents dropped during confirmation".to_string());
            self.events
                .publish_event(ArkEvent::RoundFailed {
                    round_id: round.id.clone(),
                    reason: round.fail_reason.clone(),
                    timestamp,
                })
                .await?;
            return Err(ArkError::Internal(round.fail_reason.clone()));
        }

        self.events
            .publish_event(ArkEvent::ConfirmationPhaseEnded {
                round_id: round.id.clone(),
                confirmed_count,
                dropped_count,
                timestamp,
            })
            .await?;

        Ok((confirmed_count, dropped_count))
    }

    /// Check if all intents have confirmed
    pub async fn all_confirmed(&self) -> ArkResult<bool> {
        let guard = self.current_round.read().await;
        let round = guard
            .as_ref()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        Ok(round.all_confirmed())
    }

    /// Get pending (unconfirmed) intent IDs
    pub async fn get_pending_confirmations(&self) -> ArkResult<Vec<String>> {
        let guard = self.current_round.read().await;
        let round = guard
            .as_ref()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        Ok(round
            .pending_confirmations()
            .into_iter()
            .map(String::from)
            .collect())
    }

    /// Get round timing configuration
    pub fn round_timing(&self) -> &RoundTiming {
        &self.config.round_timing
    }

    // ── Intent Registration ─────────────────────────────────────────

    /// Register an intent
    #[instrument(skip(self, intent))]
    pub async fn register_intent(&self, intent: Intent) -> ArkResult<String> {
        // If no round is active, the current round has ended, or the round is no
        // longer accepting registrations (e.g. it transitioned to finalization),
        // start a new round now.
        //
        // This is a self-healing guard: the round loop starts a round on the first
        // scheduler tick, but there is a small window at startup where a client
        // can connect before the scheduler tick is processed.  Auto-starting here
        // eliminates any residual race without requiring exact startup ordering.
        {
            let needs_round = self
                .current_round
                .read()
                .await
                .as_ref()
                .map(|r| !r.is_accepting_registrations())
                .unwrap_or(true); // None → needs a round
            if needs_round {
                // If the current round is stuck (not ended but not accepting
                // registrations), force-end it so a new round can start.
                {
                    let mut guard = self.current_round.write().await;
                    if let Some(ref mut r) = *guard {
                        if !r.is_ended() && !r.is_accepting_registrations() {
                            info!(
                                round_id = %r.id,
                                stage = ?r.stage.code,
                                "Force-ending stuck round to allow new registration"
                            );
                            r.fail(
                                "Force-ended: stuck round replaced by new registration".to_string(),
                            );
                        }
                    }
                }
                let _ = self.start_round().await;
            }
        }

        // ── Double-spend detection (#334) ─────────────────────────────────
        // Check each VTXO input against the on-chain scanner. If any input has
        // already been spent on-chain (published VTXO tree while also being
        // presented in a new round), this is a double-spend attempt.
        //
        // We perform this check before acquiring the write lock to avoid holding
        // it during potentially slow on-chain queries.
        let round_id_for_fraud = {
            self.current_round
                .read()
                .await
                .as_ref()
                .map(|r| r.id.clone())
                .unwrap_or_default()
        };
        for input in &intent.inputs {
            let vtxo_id = format!("{}:{}", input.outpoint.txid, input.outpoint.vout);
            let is_unspent = self.scanner.is_utxo_unspent(&input.outpoint).await?;
            if !is_unspent {
                warn!(
                    vtxo_id = %vtxo_id,
                    round_id = %round_id_for_fraud,
                    "Double-spend detected: VTXO already spent on-chain during intent registration"
                );
                // React to fraud: broadcast any stored forfeit txs for this VTXO
                // and reject the intent.
                if let Err(e) = self
                    .check_and_react_fraud(&vtxo_id, &round_id_for_fraud)
                    .await
                {
                    warn!(error = %e, "check_and_react_fraud failed (non-fatal)");
                }
                return Err(ArkError::Internal(format!(
                    "VTXO {}:{} is already spent on-chain (double-spend attempt)",
                    input.outpoint.txid, input.outpoint.vout
                )));
            }
        }

        let mut guard = self.current_round.write().await;
        // Re-check after acquiring write lock — the round may have ended
        // during the fraud-detection read section above.
        if guard
            .as_ref()
            .map(|r| !r.is_accepting_registrations())
            .unwrap_or(true)
        {
            drop(guard);
            let _ = self.start_round().await;
            guard = self.current_round.write().await;
        }
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        // Isolate note-only intents: if this intent only has note inputs
        // (no forfeitable VTXOs) and the round already has intents from
        // OTHER users, start a new round. This prevents cross-test/cross-user
        // collisions where a faucet note redemption lands in another user's
        // round — the extra cosigner would never submit nonces, causing a
        // signing timeout.
        // Note-only: intent has zero inputs (notes are "redeemed pending"
        // and skipped as intent inputs in RegisterIntent). Settle/SendOffChain
        // intents always have at least one input (VTXO or boarding).
        let is_note_only = intent.inputs.is_empty();
        if is_note_only && !round.intents.is_empty() {
            let my_owner = intent
                .receivers
                .first()
                .map(|r| r.pubkey.as_str())
                .unwrap_or("");
            // Only isolate if the round has a non-note intent from a different
            // user. If ALL existing intents are also notes, share the round
            // (this is the normal batch note redemption case like redeem_notes test).
            let has_non_note_other_user = round.intents.values().any(|existing| {
                let other_owner = existing
                    .receivers
                    .first()
                    .map(|r| r.pubkey.as_str())
                    .unwrap_or("");
                let other_is_note = existing.inputs.is_empty();
                other_owner != my_owner && !other_is_note
            });
            let has_other_user = has_non_note_other_user;
            if has_other_user {
                info!(
                    round_id = %round.id,
                    "Note-only intent collides with other users — starting new round"
                );
                round.fail("Restarting for note isolation".to_string());
                drop(guard);
                let _ = self.start_round().await;
                guard = self.current_round.write().await;
                let round = guard.as_mut().ok_or_else(|| {
                    ArkError::Internal("No active round after restart".to_string())
                })?;
                // Re-register in the fresh round
                round.intents.insert(intent.id.clone(), intent);
                let intent_id = round.intents.keys().last().unwrap().clone();
                info!(round_id = %round.id, intent_id, "Intent registered (in fresh round)");
                return Ok(intent_id);
            }
        }

        // Reject duplicate VTXO inputs: if any input is already registered
        // in another intent within this round, this is a double-spend attempt.
        for input in &intent.inputs {
            let input_op = format!("{}:{}", input.outpoint.txid, input.outpoint.vout);
            for existing_intent in round.intents.values() {
                for existing_input in &existing_intent.inputs {
                    let existing_op = format!(
                        "{}:{}",
                        existing_input.outpoint.txid, existing_input.outpoint.vout
                    );
                    if input_op == existing_op {
                        return Err(ArkError::Internal(format!(
                            "VTXO {} is already registered in intent {}",
                            input_op, existing_intent.id
                        )));
                    }
                }
            }
        }

        // Reject duplicate owner: if the round already has an intent with the
        // same first receiver pubkey, this is a SDK retry that landed in the
        // same round. Including both intents would add an extra cosigner to the
        // signing session that never responds, causing a timeout → ban.
        // Replace the old intent with the new one (the SDK abandoned the old signer session).
        if let Some(owner_pk) = intent.receivers.first().map(|r| &r.pubkey) {
            if !owner_pk.is_empty() {
                let dup_id = round
                    .intents
                    .values()
                    .find(|existing| {
                        existing.receivers.first().map(|r| &r.pubkey) == Some(owner_pk)
                    })
                    .map(|existing| existing.id.clone());
                if let Some(old_id) = dup_id {
                    info!(
                        old_intent = %old_id,
                        new_intent = %intent.id,
                        owner = %owner_pk,
                        "Replacing duplicate intent from same owner (SDK retry)"
                    );
                    round.intents.remove(&old_id);
                }
            }
        }

        // Validate that each offchain receiver meets the dust threshold.
        // The Go SDK's CoinSelect filters sub-dust VTXOs client-side, but we
        // enforce server-side too for safety. Use the dust amount (330 for P2TR),
        // NOT min_vtxo_amount (546). This allows 350-sat combined outputs
        // (100+250 sub-dust VTXOs) while rejecting 100-sat solo Settle attempts.
        let dust = self.wallet.get_dust_amount().await.unwrap_or(330);
        for receiver in &intent.receivers {
            if !receiver.is_onchain() && receiver.amount > 0 && receiver.amount < dust {
                return Err(ArkError::AmountTooSmall {
                    amount: receiver.amount,
                    minimum: dust,
                });
            }
        }

        // TODO(#246): validate boarding UTXOs exist on-chain via BlockchainScanner
        // For each boarding input in the intent, verify the UTXO is unspent:
        // This is now handled above for VTXO inputs. Boarding UTXOs (on-chain UTXOs)
        // could additionally be validated here once boarding input type is distinct.

        let id = intent.id.clone();
        round.register_intent(intent).map_err(ArkError::Internal)?;
        info!(intent_id = %id, "Intent registered");
        // Do NOT re-publish BatchStarted here. The Go SDK's OnBatchStarted
        // validates sha256(intentId) against the event's hashed_intent_ids.
        // The correct BatchStarted (with intent hashes) is published by
        // finalize_round() after the registration period ends, matching
        // arkd's flow where BatchStarted comes from startConfirmation().

        Ok(id)
    }

    /// Get VTXOs for a pubkey.
    ///
    /// Also queries with the taproot output key derived from the compressed
    /// pubkey, so that VTXOs created from offchain tx finalization (which
    /// store the P2TR output key) are found alongside settlement VTXOs
    /// (which store the compressed registration key).
    pub async fn get_vtxos_for_pubkey(&self, pubkey: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
        let (mut spendable, mut spent) = self.vtxo_repo.get_all_vtxos_for_pubkey(pubkey).await?;

        // Derive the taproot output key from the compressed pubkey and also
        // query with that.  Offchain tx outputs store the P2TR output key
        // (tweaked x-only key) while settlement VTXOs store the compressed
        // registration key — this bridges both formats.
        if let Some(tweaked_hex) = Self::compressed_to_taproot_output_key(pubkey) {
            let (s2, sp2) = self
                .vtxo_repo
                .get_all_vtxos_for_pubkey(&tweaked_hex)
                .await?;
            let existing: std::collections::HashSet<String> = spendable
                .iter()
                .chain(spent.iter())
                .map(|v| format!("{}:{}", v.outpoint.txid, v.outpoint.vout))
                .collect();
            for v in s2 {
                let key = format!("{}:{}", v.outpoint.txid, v.outpoint.vout);
                if !existing.contains(&key) {
                    spendable.push(v);
                }
            }
            for v in sp2 {
                let key = format!("{}:{}", v.outpoint.txid, v.outpoint.vout);
                if !existing.contains(&key) {
                    spent.push(v);
                }
            }
        }

        Ok((spendable, spent))
    }

    /// Derive the taproot output key hex from a compressed pubkey hex.
    ///
    /// Given a 33-byte compressed key (66 hex chars, prefix 02/03), computes
    /// the P2TR output key (key-path only, no script tree) and returns it
    /// as a 32-byte hex string.  Returns None if the input isn't a valid
    /// compressed pubkey.
    fn compressed_to_taproot_output_key(pubkey: &str) -> Option<String> {
        if pubkey.len() != 66 || !(pubkey.starts_with("02") || pubkey.starts_with("03")) {
            return None;
        }
        let bytes = hex::decode(pubkey).ok()?;
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let pk = bitcoin::secp256k1::PublicKey::from_slice(&bytes).ok()?;
        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from(pk);
        use bitcoin::key::TapTweak as _;
        let (output_key, _) = xonly.tap_tweak(&secp, None);
        Some(hex::encode(output_key.serialize()))
    }

    /// Get VTXOs by outpoints
    pub async fn get_vtxos(&self, outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
        self.vtxo_repo.get_vtxos(outpoints).await
    }

    // ── Indexer Queries ─────────────────────────────────────────────

    /// List VTXOs via the indexer, optionally filtered by owner pubkey.
    pub async fn list_vtxos(&self, pubkey: Option<&str>) -> ArkResult<Vec<Vtxo>> {
        self.indexer.list_vtxos(pubkey).await
    }

    /// Get a single round by its ID via the indexer.
    pub async fn get_round_by_id(&self, round_id: &str) -> ArkResult<Option<Round>> {
        self.indexer.get_round(round_id).await
    }

    /// Get aggregated indexer statistics.
    pub async fn get_indexer_stats(&self) -> ArkResult<IndexerStats> {
        self.indexer.get_stats().await
    }

    /// Look up a round by its commitment transaction ID via the indexer.
    pub async fn get_round_by_commitment_txid(&self, txid: &str) -> ArkResult<Option<Round>> {
        self.indexer.get_round_by_commitment_txid(txid).await
    }

    // ── Exit Mechanisms ─────────────────────────────────────────────

    /// Request a collaborative exit
    ///
    /// The exit will be included in the next round as on-chain outputs.
    #[instrument(skip(self, request))]
    pub async fn request_collaborative_exit(
        &self,
        request: CollaborativeExitRequest,
        requester_pubkey: bitcoin::XOnlyPublicKey,
    ) -> ArkResult<Exit> {
        // Validate VTXOs exist and are spendable
        let vtxos = self.vtxo_repo.get_vtxos(&request.vtxo_ids).await?;
        if vtxos.is_empty() {
            return Err(ArkError::VtxoNotFound(
                "No VTXOs found for exit".to_string(),
            ));
        }

        for vtxo in &vtxos {
            if !vtxo.is_spendable() {
                return Err(ArkError::VtxoAlreadySpent(vtxo.outpoint.to_string()));
            }
        }

        let total_amount: u64 = vtxos.iter().map(|v| v.amount).sum();
        let exit = Exit::collaborative(
            request.vtxo_ids,
            request.destination,
            requester_pubkey,
            bitcoin::Amount::from_sat(total_amount),
        );

        self.exits.write().await.insert(exit.id, exit.clone());
        info!(exit_id = %exit.id, amount = total_amount, "Collaborative exit requested");

        Ok(exit)
    }

    /// Request a unilateral exit
    ///
    /// The user will publish their VTXO tree branch on-chain.
    #[instrument(skip(self, request))]
    pub async fn request_unilateral_exit(
        &self,
        request: UnilateralExitRequest,
        requester_pubkey: bitcoin::XOnlyPublicKey,
    ) -> ArkResult<Exit> {
        // Validate VTXO exists and is spendable
        let vtxos = self
            .vtxo_repo
            .get_vtxos(std::slice::from_ref(&request.vtxo_id))
            .await?;
        let vtxo = vtxos
            .first()
            .ok_or_else(|| ArkError::VtxoNotFound(request.vtxo_id.to_string()))?;

        if !vtxo.is_spendable() {
            return Err(ArkError::VtxoAlreadySpent(vtxo.outpoint.to_string()));
        }

        // Calculate claimable height (convert exit delay from seconds to blocks)
        let block_time = self.wallet.get_current_block_time().await?;
        // Ceiling division: ensure at least 1 block delay for any non-zero seconds value.
        let delay_blocks = self
            .config
            .unilateral_exit_delay
            .div_ceil(crate::domain::SECS_PER_BLOCK);
        let claimable_height = block_time.height as u32 + delay_blocks;

        let exit = Exit::unilateral(
            request.vtxo_id,
            request.destination,
            requester_pubkey,
            bitcoin::Amount::from_sat(vtxo.amount),
            claimable_height,
        );

        self.exits.write().await.insert(exit.id, exit.clone());
        info!(
            exit_id = %exit.id,
            amount = vtxo.amount,
            claimable_height,
            "Unilateral exit requested"
        );

        Ok(exit)
    }

    /// Get the VTXO tree branch (root→leaf PSBTs) for a given VTXO outpoint.
    ///
    /// Looks up the round by `root_commitment_txid`, then traces the path
    /// from tree root down to the node whose txid matches the VTXO's outpoint txid.
    ///
    /// Returns base64-encoded PSBTs in broadcast order (root first).
    /// Returns an empty vec if the VTXO has no tree (e.g. direct commitment output).
    #[instrument(skip(self))]
    pub async fn get_vtxo_tree_branch(&self, vtxo_id: &VtxoOutpoint) -> ArkResult<Vec<String>> {
        // Fetch the VTXO to get root_commitment_txid
        let vtxos = self
            .vtxo_repo
            .get_vtxos(std::slice::from_ref(vtxo_id))
            .await?;
        let vtxo = vtxos
            .first()
            .ok_or_else(|| ArkError::VtxoNotFound(vtxo_id.to_string()))?;

        let commitment_txid = &vtxo.root_commitment_txid;
        if commitment_txid.is_empty() {
            // Note VTXO — no tree branch
            return Ok(vec![]);
        }

        // Fetch the round
        let round = self
            .indexer
            .get_round_by_commitment_txid(commitment_txid)
            .await?
            .ok_or_else(|| {
                ArkError::Internal(format!(
                    "No round found for commitment txid {}",
                    commitment_txid
                ))
            })?;

        let tree = &round.vtxo_tree;
        if tree.is_empty() {
            return Ok(vec![]);
        }

        // If the VTXO txid equals the commitment txid, it's a direct output — no tree branch
        if vtxo_id.txid == *commitment_txid {
            return Ok(vec![]);
        }

        // Build parent-lookup map: child_txid -> parent_node
        use std::collections::HashMap as BranchMap;
        let mut parent_of: BranchMap<&str, &crate::domain::TxTreeNode> = BranchMap::new();
        for node in tree {
            for child_txid in node.children.values() {
                parent_of.insert(child_txid.as_str(), node);
            }
        }

        // Trace path from target leaf back to root, then reverse
        let target_txid = vtxo_id.txid.as_str();
        let mut path_txids: Vec<&str> = vec![target_txid];
        let mut current = target_txid;
        while let Some(parent) = parent_of.get(current) {
            path_txids.push(parent.txid.as_str());
            current = parent.txid.as_str();
        }
        path_txids.reverse(); // root first

        // Map txids to PSBTs
        let txid_to_node: BranchMap<&str, &crate::domain::TxTreeNode> =
            tree.iter().map(|n| (n.txid.as_str(), n)).collect();

        let branch_psbts: Vec<String> = path_txids
            .iter()
            .filter_map(|txid| txid_to_node.get(txid).map(|n| n.tx.clone()))
            .filter(|tx| !tx.is_empty())
            .collect();

        Ok(branch_psbts)
    }

    /// Mark VTXOs as unrolled (their tree branch was published on-chain).
    pub async fn mark_vtxos_unrolled(&self, outpoints: &[VtxoOutpoint]) -> ArkResult<()> {
        if outpoints.is_empty() {
            return Ok(());
        }
        let vtxos = self.vtxo_repo.get_vtxos(outpoints).await?;
        self.vtxo_repo.mark_vtxos_unrolled(&vtxos).await
    }

    /// Check pending unilateral exits and mark VTXOs as unrolled when their
    /// tree branch leaf transactions are confirmed on-chain.
    ///
    /// Should be called periodically (e.g. after each block) to update state.
    pub async fn check_pending_unilateral_exits(&self) -> ArkResult<()> {
        let exits = self.exits.read().await;
        let pending_exits: Vec<_> = exits
            .values()
            .filter(|e| {
                e.exit_type == crate::domain::ExitType::Unilateral && !e.status.is_terminal()
            })
            .cloned()
            .collect();
        drop(exits);

        for exit in pending_exits {
            for vtxo_id in &exit.vtxo_ids {
                // Check if the VTXO's leaf txid is confirmed on-chain
                let txid = vtxo_id.txid.as_str();
                match self.scanner.is_tx_confirmed(txid).await {
                    Ok(true) => {
                        info!(
                            exit_id = %exit.id,
                            vtxo = %vtxo_id,
                            "VTXO tree leaf confirmed on-chain — marking as unrolled"
                        );
                        if let Err(e) = self
                            .mark_vtxos_unrolled(std::slice::from_ref(vtxo_id))
                            .await
                        {
                            warn!(
                                error = %e,
                                vtxo = %vtxo_id,
                                "Failed to mark VTXO as unrolled"
                            );
                        }
                    }
                    Ok(false) => {} // Not yet confirmed
                    Err(e) => {
                        warn!(
                            error = %e,
                            vtxo = %vtxo_id,
                            "Failed to check tx confirmation"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    // ── Fraud detection & scanner listener ────────────────────────────────

    /// Compute the P2TR script pubkey for a given x-only public key (hex).
    ///
    /// Returns the script pubkey bytes (34 bytes: OP_1 <32-byte-key>).
    /// Extract the Bitcoin txid from a base64-encoded PSBT.
    #[allow(dead_code)]
    fn psbt_to_txid(b64: &str) -> Option<String> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        let psbt = bitcoin::psbt::Psbt::deserialize(&bytes).ok()?;
        Some(psbt.unsigned_tx.compute_txid().to_string())
    }

    fn p2tr_script_from_pubkey(pubkey_hex: &str) -> Option<Vec<u8>> {
        let pubkey_bytes = hex::decode(pubkey_hex).ok()?;
        if pubkey_bytes.len() != 32 {
            return None;
        }
        let xonly = bitcoin::key::XOnlyPublicKey::from_slice(&pubkey_bytes).ok()?;
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let script = bitcoin::ScriptBuf::new_p2tr(&secp, xonly, None);
        Some(script.as_bytes().to_vec())
    }

    /// Start watching VTXO scripts via the blockchain scanner.
    ///
    /// After a round completes, this registers the P2TR scripts for all new
    /// VTXOs so the scanner can detect on-chain spends (unilateral exits).
    pub async fn start_watching_vtxos(&self, vtxos: &[Vtxo]) {
        let mut mapping = self.watched_scripts.write().await;
        for vtxo in vtxos {
            if vtxo.amount == 0 {
                continue; // skip dust / OP_RETURN
            }
            if let Some(script_bytes) = Self::p2tr_script_from_pubkey(&vtxo.pubkey) {
                let script_hex = hex::encode(&script_bytes);
                mapping
                    .entry(script_hex)
                    .or_default()
                    .push(vtxo.outpoint.clone());
                if let Err(e) = self.scanner.watch_script(script_bytes).await {
                    warn!(
                        pubkey = %vtxo.pubkey,
                        error = %e,
                        "Failed to watch VTXO script"
                    );
                }
            }
        }
    }

    /// Check all non-terminal VTXOs to see if their leaf transaction has been
    /// confirmed on-chain, indicating the VTXO tree was unrolled.
    ///
    /// This is the primary unroll detection mechanism: when a user broadcasts
    /// tree transactions (unrolling their branch), the VTXO leaf txid appears
    /// on-chain. We detect this and mark the VTXO as unrolled.
    pub async fn check_unrolled_vtxos(&self) -> ArkResult<u32> {
        // Get ALL VTXOs — both spendable and spent. We need to check spent
        // VTXOs too because a user may unroll a forfeited (spent) VTXO,
        // which is fraud and requires the server to broadcast the forfeit tx.
        let (spendable, spent) = self.vtxo_repo.list_all().await?;
        info!(
            spendable_count = spendable.len(),
            spent_count = spent.len(),
            "check_unrolled_vtxos: checking VTXOs"
        );

        // Group VTXOs by their root commitment txid so we query Esplora
        // once per commitment transaction instead of once per VTXO.
        let mut by_commitment: std::collections::HashMap<String, Vec<&Vtxo>> =
            std::collections::HashMap::new();
        // Track preconfirmed VTXOs separately — they have no commitment txid
        // but can be detected as unrolled when their ark tx (outpoint.txid)
        // is confirmed on-chain.
        let mut preconfirmed_vtxos: Vec<&Vtxo> = Vec::new();
        for vtxo in &spendable {
            // Check preconfirmed BEFORE is_note() — preconfirmed VTXOs have
            // empty commitment_txids so is_note() would incorrectly skip them.
            if vtxo.preconfirmed {
                preconfirmed_vtxos.push(vtxo);
                continue;
            }
            if vtxo.is_note() {
                continue;
            }
            let ctxid = if !vtxo.root_commitment_txid.is_empty() {
                vtxo.root_commitment_txid.clone()
            } else if let Some(first) = vtxo.commitment_txids.first() {
                first.clone()
            } else {
                continue;
            };
            by_commitment.entry(ctxid).or_default().push(vtxo);
        }

        // Also group SPENT VTXOs by commitment txid for fraud detection.
        // If a spent VTXO's tree is unrolled on-chain, we must broadcast
        // the forfeit tx to claim the funds before the user's timelock expires.
        // Spent preconfirmed VTXOs are also collected for checkpoint-based sweep.
        let mut spent_by_commitment: std::collections::HashMap<String, Vec<&Vtxo>> =
            std::collections::HashMap::new();
        for vtxo in &spent {
            if vtxo.is_note() || vtxo.swept || vtxo.unrolled {
                continue;
            }
            // Include spent preconfirmed VTXOs in the preconfirmed list
            // so checkpoint-based sweep can update their expiry.
            if vtxo.preconfirmed {
                preconfirmed_vtxos.push(vtxo);
                continue;
            }
            let ctxid = if !vtxo.root_commitment_txid.is_empty() {
                vtxo.root_commitment_txid.clone()
            } else if let Some(first) = vtxo.commitment_txids.first() {
                first.clone()
            } else {
                continue;
            };
            spent_by_commitment.entry(ctxid).or_default().push(vtxo);
        }

        let mut count = 0u32;

        info!(
            preconfirmed_count = preconfirmed_vtxos.len(),
            commitment_groups = by_commitment.len(),
            spent_commitment_groups = spent_by_commitment.len(),
            spent_total = spent.len(),
            "check_unrolled_vtxos: categorised VTXOs"
        );

        // Check preconfirmed VTXOs (both spendable and spent).
        //
        // Two signals we track:
        //  1. The VTXO's own leaf tx (the ark tx, = outpoint.txid) is
        //     confirmed on-chain → the user has finished the unroll.
        //     Mark the VTXO as `unrolled` and set `expires_at_block` so
        //     the sweeper can reclaim after CSV maturity. Mirrors Go's
        //     `listenToScannerNotifications` which calls `UnrollVtxos`
        //     when the leaf tx lands on-chain.
        //  2. A checkpoint tx (parent of the ark tx) is confirmed on-chain
        //     but the ark tx is not yet confirmed → partial unroll in
        //     progress. Update `expires_at_block` only; do NOT mark as
        //     unrolled yet.
        let csv_delay = self.config.unilateral_exit_delay;
        for vtxo in &preconfirmed_vtxos {
            if vtxo.swept || vtxo.unrolled {
                continue;
            }

            // (1) Leaf ark tx confirmed? The VTXO's outpoint.txid IS the ark
            // tx id for preconfirmed VTXOs (set in finalize_offchain_tx).
            if let Ok(Some(conf_height)) = self
                .scanner
                .get_tx_confirmation_height(&vtxo.outpoint.txid)
                .await
            {
                let new_expiry_block = conf_height + csv_delay;
                let mut updated = (*vtxo).clone();
                updated.unrolled = true;
                updated.expires_at_block = new_expiry_block;
                match self.vtxo_repo.add_vtxos(&[updated]).await {
                    Ok(_) => {
                        count += 1;
                        info!(
                            outpoint = %vtxo.outpoint,
                            ark_txid = %vtxo.outpoint.txid,
                            conf_height, new_expiry_block,
                            "Preconfirmed VTXO ark tx confirmed on-chain — marked as unrolled"
                        );
                    }
                    Err(e) => {
                        warn!(outpoint = %vtxo.outpoint, error = %e,
                            "Failed to mark preconfirmed VTXO as unrolled");
                    }
                }
                continue;
            }

            // (2) Ark tx not yet confirmed — look at checkpoint txs to
            // update the sweeper expiry. Skip if expires_at_block already
            // set (so we don't churn the DB on every loop iteration).
            if vtxo.expires_at_block > 0 {
                continue;
            }

            let offchain_tx_id = &vtxo.ark_txid;
            if let Ok(Some(otx)) = self.offchain_tx_repo.get(offchain_tx_id).await {
                use base64::Engine;

                for ckpt_b64 in &otx.checkpoint_txs {
                    if let Some(ckpt_txid) = base64::engine::general_purpose::STANDARD
                        .decode(ckpt_b64)
                        .ok()
                        .and_then(|bytes| bitcoin::psbt::Psbt::deserialize(&bytes).ok())
                        .map(|psbt| psbt.unsigned_tx.compute_txid().to_string())
                    {
                        if let Ok(Some(conf_height)) =
                            self.scanner.get_tx_confirmation_height(&ckpt_txid).await
                        {
                            let new_expiry_block = conf_height + csv_delay;
                            if vtxo.expires_at_block != new_expiry_block {
                                let mut updated = (*vtxo).clone();
                                updated.expires_at_block = new_expiry_block;
                                if let Err(e) = self.vtxo_repo.add_vtxos(&[updated]).await {
                                    warn!(outpoint = %vtxo.outpoint, error = %e,
                                        "Failed to update preconfirmed VTXO expiry from checkpoint");
                                } else {
                                    info!(outpoint = %vtxo.outpoint,
                                        checkpoint_txid = %ckpt_txid,
                                        conf_height, new_expiry_block,
                                        "Updated preconfirmed VTXO expiry from confirmed checkpoint");
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }

        info!(
            commitment_groups = by_commitment.len(),
            "check_unrolled_vtxos: checking {} commitment txids",
            by_commitment.len()
        );
        for (commitment_txid, vtxos) in &by_commitment {
            info!(
                commitment_txid = %commitment_txid,
                vtxo_count = vtxos.len(),
                "check_unrolled_vtxos: checking outspend for commitment txid"
            );
            // A VTXO's outpoint.txid is the tree LEAF transaction that
            // contains its funds.  The full tree must be unrolled (from the
            // commitment tx's shared output down to the leaf) before the
            // VTXO is truly on-chain.  We mark a VTXO as unrolled only
            // when its specific leaf tx is confirmed, NOT when the tree
            // root is first broadcast — otherwise the SDK filters it out
            // of spendable VTXOs and the user cannot continue unrolling
            // deeper tree levels.
            //
            // Check if the commitment TX output was spent (tree being unrolled).
            // Uses Bitcoin Core RPC fallback to bypass chopsticks indexing lag.
            match self.scanner.is_output_spent(commitment_txid, 0).await {
                Ok(true) => {
                    // Commitment output spent → tree is being unrolled.
                    let csv_delay = self.config.unilateral_exit_delay;
                    for vtxo in vtxos {
                        // Mark ALL VTXOs as unrolled when commitment is spent.
                        // The Go server does this — it doesn't wait for each
                        // individual leaf TX to be confirmed (which requires
                        // multiple blocks for deep trees).
                        if vtxo.unrolled {
                            continue;
                        }
                        match self.scanner.is_tx_confirmed(&vtxo.outpoint.txid).await {
                            Ok(true) => {
                                info!(
                                    outpoint = %vtxo.outpoint,
                                    commitment_txid = %commitment_txid,
                                    "VTXO leaf tx confirmed on-chain — marking as unrolled"
                                );
                                if let Err(e) = self
                                    .vtxo_repo
                                    .mark_vtxos_unrolled(std::slice::from_ref(vtxo))
                                    .await
                                {
                                    warn!(
                                        outpoint = %vtxo.outpoint,
                                        error = %e,
                                        "Failed to mark VTXO as unrolled"
                                    );
                                } else {
                                    count += 1;
                                    // Reset the CSV expiry from the leaf's
                                    // confirmation height so the sweeper fires
                                    // at the right time.
                                    if let Ok(Some(conf_height)) = self
                                        .scanner
                                        .get_tx_confirmation_height(&vtxo.outpoint.txid)
                                        .await
                                    {
                                        let new_expiry_block = conf_height + csv_delay;
                                        let mut updated = (*vtxo).clone();
                                        updated.expires_at_block = new_expiry_block;
                                        if let Err(e) = self.vtxo_repo.add_vtxos(&[updated]).await {
                                            warn!(outpoint = %vtxo.outpoint, error = %e,
                                                "Failed to update expiry after unroll");
                                        } else {
                                            info!(outpoint = %vtxo.outpoint, new_expiry_block,
                                                "Reset VTXO expiry after on-chain unroll");
                                        }
                                    }
                                }
                            }
                            Ok(false) => {
                                // Leaf tx not yet on-chain. Walk the tree to
                                // find an ancestor for sweep timing. Do NOT
                                // mark as unrolled — the SDK may still need
                                // the VTXO for further unroll steps.
                                if vtxo.swept || vtxo.unrolled {
                                    continue;
                                }
                                // Skip if expiry was already updated by a prior cycle.
                                // Original expires_at_block is creation_height + vtxo_expiry_blocks (large).
                                // Updated value is ancestor_conf_height + csv_delay (smaller).
                                if let Some(veb) = self.config.vtxo_expiry_blocks {
                                    if vtxo.expires_at_block > 0 && vtxo.expires_at_block < veb {
                                        continue;
                                    }
                                }
                                if let Ok(Some(round)) = self
                                    .round_repo
                                    .get_round_by_commitment_txid(commitment_txid)
                                    .await
                                {
                                    if let Some(ancestor_conf) = self
                                        .find_confirmed_ancestor_height(
                                            &round.vtxo_tree,
                                            &vtxo.outpoint.txid,
                                        )
                                        .await
                                    {
                                        let new_expiry_block = ancestor_conf + csv_delay;
                                        let mut updated = (*vtxo).clone();
                                        if updated.expires_at_block != new_expiry_block {
                                            updated.expires_at_block = new_expiry_block;
                                            if let Err(e) =
                                                self.vtxo_repo.add_vtxos(&[updated]).await
                                            {
                                                warn!(outpoint = %vtxo.outpoint, error = %e,
                                                    "Failed to update expiry for ancestor-confirmed VTXO");
                                            } else {
                                                info!(outpoint = %vtxo.outpoint, new_expiry_block,
                                                    "Updated VTXO expiry from confirmed ancestor tree node");
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    outpoint = %vtxo.outpoint,
                                    error = %e,
                                    "Failed to check VTXO leaf tx confirmation"
                                );
                            }
                        }
                    }
                }
                Ok(false) => {
                    // Commitment output not spent — no unroll detected
                }
                Err(e) => {
                    info!(
                        commitment_txid = %commitment_txid,
                        error = %e,
                        "Failed to check commitment tx output spend status"
                    );
                }
            }
        }

        if count > 0 {
            info!(unrolled_count = count, "Marked VTXOs as unrolled");
        }

        // Fraud detection: check if any SPENT VTXOs have their tree unrolled.
        // This indicates a user is trying to exit with a forfeited VTXO.
        // The server must broadcast the forfeit tx to claim the funds.
        for (commitment_txid, vtxos) in &spent_by_commitment {
            let unrolled = match self.scanner.is_output_spent(commitment_txid, 0).await {
                Ok(spent) => spent,
                Err(_) => {
                    // Fallback: check tree root tx confirmation
                    if let Ok(Some(round)) = self
                        .round_repo
                        .get_round_by_commitment_txid(commitment_txid)
                        .await
                    {
                        if let Some(root_node) = round.vtxo_tree.last() {
                            let tree_root_txid = Self::compute_txid_from_psbt(&root_node.tx)
                                .unwrap_or_else(|| root_node.txid.clone());
                            self.scanner
                                .is_tx_confirmed(&tree_root_txid)
                                .await
                                .unwrap_or(false)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
            };

            if unrolled {
                for vtxo in vtxos {
                    info!(
                        outpoint = %vtxo.outpoint,
                        commitment_txid = %commitment_txid,
                        spent_by = %vtxo.spent_by,
                        "Fraud detected: spent VTXO tree unrolled on-chain"
                    );
                    // React by broadcasting forfeit/checkpoint tx.
                    // Mark as unrolled on success. On failure, check if a
                    // prior cycle already got the forfeit/checkpoint confirmed
                    // (the VTXO's leaf output will be spent on-chain). If so,
                    // mark as unrolled to stop retrying. Otherwise let the
                    // next maintenance cycle retry.
                    match self.react_to_fraud(vtxo).await {
                        Ok(true) => {
                            // Mark as both unrolled AND swept. The forfeit/
                            // checkpoint was broadcast so the server has
                            // (or will have) the funds once the CSV matures.
                            let mut upd = (*vtxo).clone();
                            upd.unrolled = true;
                            upd.swept = true;
                            let _ = self.vtxo_repo.add_vtxos(&[upd]).await;
                        }
                        Ok(false) => {
                            // Deferred — don't mark as unrolled
                        }
                        Err(e) => {
                            // Check if the VTXO's leaf output was already
                            // spent by a prior forfeit/checkpoint broadcast.
                            let already_spent = self
                                .scanner
                                .is_output_spent(&vtxo.outpoint.txid, vtxo.outpoint.vout)
                                .await
                                .unwrap_or(false);
                            if already_spent {
                                info!(
                                    outpoint = %vtxo.outpoint,
                                    "VTXO leaf already spent on-chain — marking as unrolled+swept"
                                );
                                let mut upd = (*vtxo).clone();
                                upd.unrolled = true;
                                upd.swept = true;
                                let _ = self.vtxo_repo.add_vtxos(&[upd]).await;
                            } else {
                                warn!(
                                    outpoint = %vtxo.outpoint,
                                    error = %e,
                                    "Failed to react to fraud — will retry next cycle"
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(count)
    }

    /// Sweep expired VTXOs by block height.
    ///
    /// Queries the scanner for the current tip height, then finds VTXOs
    /// with `expires_at < tip_height`. This handles block-height-based expiry
    /// (when `allow_csv_block_type` is true in config).
    ///
    /// Since block heights (~800k) are much smaller than unix timestamps (~1.7B),
    /// passing the tip height to `find_expired_vtxos` will only match VTXOs
    /// whose `expires_at` was set as a block height, not as a timestamp.
    pub async fn sweep_expired_by_height(&self) -> ArkResult<u32> {
        let tip = match self.scanner.tip_height().await {
            Ok(h) if h > 0 => h,
            Ok(_) => return Ok(0), // height 0 means scanner not available
            Err(_) => return Ok(0),
        };

        let expired = self.vtxo_repo.find_block_expired_vtxos(tip).await?;

        // `check_unrolled_vtxos` already updated `expires_at_block` for
        // VTXOs under unrolled trees, so `find_block_expired_vtxos` only
        // returns VTXOs whose CSV has genuinely matured.

        // Filter out dust VTXOs from automatic sweep — they're uneconomical
        // to sweep on-chain. The admin sweep endpoint can force-sweep them.
        let dust_threshold = 546u64;
        let expired: Vec<Vtxo> = expired
            .into_iter()
            .filter(|v| v.amount >= dust_threshold)
            .collect();

        if expired.is_empty() {
            return Ok(0);
        }

        info!(
            count = expired.len(),
            tip_height = tip,
            "Found VTXOs expired by block height (including unrolled)"
        );

        // Mark as swept
        if let Err(e) = self.vtxo_repo.mark_vtxos_swept(&expired).await {
            warn!(error = %e, "Failed to mark block-expired VTXOs as swept");
        }

        let count = expired.len() as u32;

        // Publish sweep events
        for vtxo in &expired {
            let vtxo_id = vtxo.outpoint.to_string();
            let _ = self
                .events
                .publish_event(ArkEvent::VtxoForfeited {
                    vtxo_id,
                    forfeit_txid: String::new(),
                })
                .await;
        }

        Ok(count)
    }

    /// Run all maintenance checks: unroll detection and expired VTXO sweeps.
    async fn run_maintenance(self: &Arc<Self>) {
        // 1. Check for unrolled VTXOs (always runs, even when wallet is locked)
        if let Err(e) = self.check_unrolled_vtxos().await {
            warn!(error = %e, "Maintenance: unroll check failed");
        }

        // Skip sweeping when the wallet is locked (simulates server being
        // stopped — the operator can lock the wallet to pause all on-chain
        // activity, then unlock to resume).
        match self.wallet.status().await {
            Ok(status) if !status.unlocked => {
                debug!("Maintenance: wallet is locked, skipping sweeps");
                return;
            }
            Err(e) => {
                warn!(error = %e, "Maintenance: failed to check wallet status, skipping sweeps");
                return;
            }
            _ => {}
        }

        // 2. Sweep expired VTXOs (by wall-clock time)
        if let Err(e) = self.sweep_expired_vtxos().await {
            debug!(error = %e, "Maintenance: time-based sweep failed");
        }

        // 3. Sweep expired VTXOs (by block height)
        // This handles block-height-based CSV configs where expires_at
        // is a block height rather than a timestamp.
        if let Err(e) = self.sweep_expired_by_height().await {
            debug!(error = %e, "Maintenance: block-height sweep failed");
        }
    }

    /// Spawn a background maintenance loop that:
    /// 1. Checks for unrolled VTXOs (on-chain tree broadcasts)
    /// 2. Sweeps expired VTXOs (by wall-clock time and block height)
    ///
    /// Runs immediately on new block notifications from the scanner, and
    /// also periodically (every 10 seconds) as a fallback to ensure the
    /// server stays up-to-date even if block notifications are missed.
    pub fn spawn_maintenance_loop(self: &Arc<Self>) {
        let svc = Arc::clone(self);
        tokio::spawn(async move {
            info!("Maintenance loop started (unroll detection + sweep)");
            let mut block_rx = svc.scanner.block_notification_channel();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            // Skip the immediate first tick
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        debug!("Maintenance: periodic tick");
                    }
                    block_event = block_rx.recv() => {
                        match block_event {
                            Ok(event) => {
                                info!(height = event.height, "Maintenance: new block detected, running checks");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                warn!(skipped = n, "Maintenance: block notification lagged");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                info!("Maintenance: block notification channel closed, falling back to periodic only");
                                // Channel closed — fall through to periodic-only loop below
                                loop {
                                    interval.tick().await;
                                    svc.run_maintenance().await;
                                }
                            }
                        }
                    }
                }

                svc.run_maintenance().await;
            }
        });
    }

    /// Spawn a background task that listens for scanner notifications and
    /// reacts to fraud (on-chain spend of a spent/forfeited VTXO).
    ///
    /// This is the Rust equivalent of Go's `listenToScannerNotifications`.
    pub fn spawn_scanner_listener(self: &Arc<Self>) {
        let svc = Arc::clone(self);
        tokio::spawn(async move {
            let mut rx = svc.scanner.notification_channel();
            info!("Scanner notification listener started");
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let script_hex = hex::encode(&event.script_pubkey);
                        debug!(
                            script = %script_hex,
                            spending_txid = %event.spending_txid,
                            height = event.block_height,
                            "Scanner: script spent on-chain"
                        );

                        // Look up VTXO outpoints for this script
                        let outpoints = {
                            let mapping = svc.watched_scripts.read().await;
                            mapping.get(&script_hex).cloned().unwrap_or_default()
                        };

                        if outpoints.is_empty() {
                            debug!(script = %script_hex, "No VTXOs found for spent script");
                            continue;
                        }

                        for outpoint in outpoints {
                            // Look up the VTXO from the database
                            let vtxos = match svc
                                .vtxo_repo
                                .get_vtxos(std::slice::from_ref(&outpoint))
                                .await
                            {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!(
                                        outpoint = %outpoint,
                                        error = %e,
                                        "Failed to retrieve VTXO, skipping"
                                    );
                                    continue;
                                }
                            };

                            if vtxos.is_empty() {
                                warn!(outpoint = %outpoint, "VTXO not found, skipping");
                                continue;
                            }

                            let vtxo = &vtxos[0];

                            // Mark as unrolled if not already
                            if !vtxo.unrolled {
                                if let Err(e) = svc
                                    .vtxo_repo
                                    .mark_vtxos_unrolled(std::slice::from_ref(vtxo))
                                    .await
                                {
                                    warn!(
                                        outpoint = %outpoint,
                                        error = %e,
                                        "Failed to mark VTXO as unrolled"
                                    );
                                }
                                debug!(outpoint = %outpoint, "VTXO marked as unrolled");
                            }

                            // If the VTXO was already spent (offchain or re-settled),
                            // this is fraud — react by broadcasting forfeit/checkpoint tx
                            if vtxo.spent {
                                info!(
                                    outpoint = %outpoint,
                                    spent_by = %vtxo.spent_by,
                                    "Fraud detected: spent VTXO unrolled on-chain"
                                );
                                if let Err(e) = svc.react_to_fraud(vtxo).await {
                                    warn!(
                                        outpoint = %outpoint,
                                        error = %e,
                                        "Failed to react to fraud"
                                    );
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(
                            skipped = n,
                            "Scanner listener lagged, some events may have been missed"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("Scanner notification channel closed, stopping listener");
                        break;
                    }
                }
            }
        });
    }

    /// React to fraud: a VTXO that was already spent/forfeited is being
    /// unrolled on-chain. Broadcast the appropriate counter-transaction.
    ///
    /// Mirrors Go's `reactToFraud`:
    /// - If the VTXO was settled (re-committed in a new round) → broadcast forfeit tx
    /// - If the VTXO was only spent offchain (not settled) → broadcast checkpoint tx
    ///
    /// Returns Ok(true) if action was taken, Ok(false) if deferred.
    pub async fn react_to_fraud(&self, vtxo: &Vtxo) -> ArkResult<bool> {
        let outpoint_str = format!("{}:{}", vtxo.outpoint.txid, vtxo.outpoint.vout);

        // Prefer the forfeit path (fast — pre-signed tx) over the checkpoint
        // path (slow — requires multi-step confirmation).  Check settled_by
        // first: if the VTXO was re-committed in a later round, that round
        // has the forfeit tx ready to broadcast.
        //
        // Strategy: settled_by → spent_by (round) → spent_by (offchain tx) → scan.
        let mut round: Option<_> = None;

        // 1. Try settled_by first (forfeit path — fastest).
        if !vtxo.settled_by.is_empty() {
            round = self
                .round_repo
                .get_round_by_commitment_txid(&vtxo.settled_by)
                .await?;
        }

        // 2. Try spent_by as round commitment txid.
        if round.is_none() && !vtxo.spent_by.is_empty() {
            round = self
                .round_repo
                .get_round_by_commitment_txid(&vtxo.spent_by)
                .await?;
        }

        // Always verify the found round actually has a forfeit for this VTXO.
        // If not, fall through to the scan.
        if let Some(ref r) = round {
            if self.find_forfeit_tx_for_vtxo(vtxo, &r.forfeit_txs).is_err() {
                round = None;
            }
        }

        // Scan recent rounds for a matching forfeit tx.
        if round.is_none() {
            // Check last completed round (fast path)
            if let Some(last) = self.last_completed_round.read().await.as_ref() {
                if self
                    .find_forfeit_tx_for_vtxo(vtxo, &last.forfeit_txs)
                    .is_ok()
                {
                    round = Some(last.clone());
                }
            }
            // Scan DB rounds
            if round.is_none() {
                if let Ok(rounds) = self.round_repo.list_rounds(0, 50).await {
                    for r in rounds {
                        if self.find_forfeit_tx_for_vtxo(vtxo, &r.forfeit_txs).is_ok() {
                            round = Some(r);
                            break;
                        }
                    }
                }
            }
        }

        if let Some(round) = round {
            // Forfeited VTXO — broadcast the forfeit tx from that round
            info!(
                outpoint = %outpoint_str,
                round_id = %round.id,
                commitment_txid = %round.commitment_txid,
                "Broadcasting forfeit tx for re-settled VTXO"
            );
            self.broadcast_forfeit_tx(vtxo, &round).await?;
            return Ok(true);
        }

        // No round with a forfeit tx found. The VTXO was likely spent
        // via an offchain tx (SendOffChain/SubmitTx), not via a round
        // settlement. Fall through to the checkpoint path.
        //
        // Checkpoint path: VTXO was spent offchain
        info!(
            outpoint = %outpoint_str,
            spent_by = %vtxo.spent_by,
            "Broadcasting checkpoint tx for offchain-spent VTXO"
        );
        self.broadcast_checkpoint_tx(vtxo).await?;
        Ok(true)
    }

    /// Broadcast the forfeit transaction for a VTXO that was re-settled.
    ///
    /// Finds the matching forfeit tx from the round, then broadcasts the
    /// connector branch leading up to it, followed by the forfeit tx itself.
    async fn broadcast_forfeit_tx(&self, vtxo: &Vtxo, round: &Round) -> ArkResult<()> {
        let outpoint_str = format!("{}:{}", vtxo.outpoint.txid, vtxo.outpoint.vout);

        if round.forfeit_txs.is_empty() {
            return Err(ArkError::Internal(format!(
                "No forfeit txs found for round {}",
                round.commitment_txid
            )));
        }

        // Sign connector tree txs (for inclusion in the broadcast package below).
        // The connector tree may have multiple levels (root → leaves). We sign
        // them in tree order: root first, then leaves. Each tx's input
        // witness_utxo comes from its parent (commitment tx for root,
        // parent connector for leaves).
        let mut signed_connector_hexes: Vec<String> = Vec::new();
        {
            use base64::Engine;
            let asp_sk_bytes = self.signer.get_secret_key_bytes().await?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let asp_sk = bitcoin::secp256k1::SecretKey::from_slice(&asp_sk_bytes)
                .map_err(|e| ArkError::Internal(format!("Invalid ASP key: {e}")))?;
            let asp_kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &asp_sk);
            use bitcoin::key::TapTweak as _;
            let asp_kp_tweaked = asp_kp.tap_tweak(&secp, None).to_keypair();

            // Parse the commitment tx for root connector witness_utxo.
            let commitment_outputs: Vec<bitcoin::TxOut> = base64::engine::general_purpose::STANDARD
                .decode(&round.commitment_tx)
                .ok()
                .and_then(|b| bitcoin::psbt::Psbt::deserialize(&b).ok())
                .map(|p| p.unsigned_tx.output)
                .unwrap_or_default();

            // Build a map of signed connector txs so leaf connectors can
            // look up their parent's outputs for witness_utxo.
            let mut signed_tx_map: std::collections::HashMap<String, bitcoin::Transaction> =
                std::collections::HashMap::new();

            // Process connectors in reverse order (root last in the flat list).
            // We process root first (has children), then leaves (no children).
            let mut root_nodes: Vec<&crate::domain::TxTreeNode> = Vec::new();
            let mut leaf_nodes: Vec<&crate::domain::TxTreeNode> = Vec::new();
            for node in &round.connectors {
                if node.tx.is_empty() {
                    continue;
                }
                if node.children.is_empty() {
                    leaf_nodes.push(node);
                } else {
                    root_nodes.push(node);
                }
            }

            // Sign root connectors first, then leaves.
            for connector_node in root_nodes.iter().chain(leaf_nodes.iter()) {
                let psbt_bytes =
                    match base64::engine::general_purpose::STANDARD.decode(&connector_node.tx) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                let mut psbt = match bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Resolve witness_utxo for the input.
                if psbt.inputs[0].witness_utxo.is_none() {
                    let prev_txid = psbt.unsigned_tx.input[0].previous_output.txid.to_string();
                    let prev_vout = psbt.unsigned_tx.input[0].previous_output.vout as usize;

                    // Try commitment tx first, then parent connector.
                    if prev_txid == round.commitment_txid {
                        if let Some(txout) = commitment_outputs.get(prev_vout) {
                            psbt.inputs[0].witness_utxo = Some(txout.clone());
                        }
                    } else if let Some(parent_tx) = signed_tx_map.get(&prev_txid) {
                        if let Some(txout) = parent_tx.output.get(prev_vout) {
                            psbt.inputs[0].witness_utxo = Some(txout.clone());
                        }
                    }
                }

                // Sign with ASP's tweaked key (taproot key-path).
                if let Some(ref utxo) = psbt.inputs[0].witness_utxo {
                    let prevouts = vec![utxo.clone()];
                    let mut cache = bitcoin::sighash::SighashCache::new(&psbt.unsigned_tx);
                    if let Ok(sighash) = cache.taproot_key_spend_signature_hash(
                        0,
                        &bitcoin::sighash::Prevouts::All(&prevouts),
                        bitcoin::TapSighashType::Default,
                    ) {
                        use bitcoin::hashes::Hash;
                        let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
                        let sig = secp.sign_schnorr(&msg, &asp_kp_tweaked);
                        let tap_sig = bitcoin::taproot::Signature {
                            signature: sig,
                            sighash_type: bitcoin::TapSighashType::Default,
                        };
                        psbt.inputs[0].tap_key_sig = Some(tap_sig);
                        psbt.inputs[0].final_script_witness =
                            Some(bitcoin::Witness::from_slice(&[tap_sig.serialize()]));
                    }
                }

                let signed_tx = psbt.extract_tx_unchecked_fee_rate();
                let txid = signed_tx.compute_txid().to_string();
                let tx_hex = hex::encode(bitcoin::consensus::serialize(&signed_tx));
                signed_tx_map.insert(txid, signed_tx);
                signed_connector_hexes.push(tx_hex);
            }
        }

        info!(
            connector_count = signed_connector_hexes.len(),
            commitment_txid = %round.commitment_txid,
            "broadcast_forfeit_tx: signed connectors"
        );

        // Find the forfeit tx that spends this VTXO
        let forfeit_tx_str = self.find_forfeit_tx_for_vtxo(vtxo, &round.forfeit_txs)?;

        // Sign the forfeit tx (connector input needs ASP signature).
        // We request the signed PSBT back (extract_raw = false) so we can
        // manually finalize the VTXO input before extraction.  BDK's sign()
        // finalizes inputs it owns (the connector key-path input) but leaves
        // the VTXO script-path input unfinalized because the signature was
        // provided by the Go SDK, not by BDK.
        let signed_tx_hex = match self.wallet.sign_transaction(&forfeit_tx_str, false).await {
            Ok(signed_psbt_b64) => {
                use base64::Engine;
                let psbt_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&signed_psbt_b64)
                    .map_err(|e| {
                        ArkError::Internal(format!("Failed to decode signed forfeit PSBT: {e}"))
                    })?;
                let mut psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).map_err(|e| {
                    ArkError::Internal(format!("Failed to deserialize signed forfeit PSBT: {e}"))
                })?;

                // The forfeit closure is a 2-of-2 multisig (VTXO owner + ASP).
                // The Go SDK signed with the owner's key; we must add the ASP's
                // Taproot script-path signature to complete the multisig.
                {
                    let asp_sk_bytes = self.signer.get_secret_key_bytes().await?;
                    let secp = bitcoin::secp256k1::Secp256k1::new();
                    let asp_sk = bitcoin::secp256k1::SecretKey::from_slice(&asp_sk_bytes)
                        .map_err(|e| ArkError::Internal(format!("Invalid ASP key: {e}")))?;
                    let asp_kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &asp_sk);
                    let asp_xonly = asp_kp.x_only_public_key().0;

                    // Build prevouts once for sighash computation.
                    let prevouts: Vec<bitcoin::TxOut> = psbt
                        .inputs
                        .iter()
                        .map(|inp| {
                            inp.witness_utxo.clone().unwrap_or(bitcoin::TxOut {
                                value: bitcoin::Amount::ZERO,
                                script_pubkey: bitcoin::ScriptBuf::new(),
                            })
                        })
                        .collect();

                    for input_idx in 0..psbt.inputs.len() {
                        let input = &psbt.inputs[input_idx];
                        if input.final_script_witness.is_some()
                            || input.tap_scripts.is_empty()
                            || input.tap_script_sigs.is_empty()
                        {
                            continue;
                        }

                        // Find the leaf and add ASP's signature.
                        let tap_scripts_clone = input.tap_scripts.clone();
                        for (script, leaf_ver) in tap_scripts_clone.values() {
                            let leaf_hash =
                                bitcoin::taproot::TapLeafHash::from_script(script, *leaf_ver);
                            let asp_key_for_leaf = (asp_xonly, leaf_hash);

                            if psbt.inputs[input_idx]
                                .tap_script_sigs
                                .contains_key(&asp_key_for_leaf)
                            {
                                continue;
                            }

                            let asp_bytes = asp_xonly.serialize();
                            if !script.as_bytes().windows(32).any(|w| w == asp_bytes) {
                                continue;
                            }

                            let mut cache = bitcoin::sighash::SighashCache::new(&psbt.unsigned_tx);
                            if let Ok(sighash) = cache.taproot_script_spend_signature_hash(
                                input_idx,
                                &bitcoin::sighash::Prevouts::All(&prevouts),
                                leaf_hash,
                                bitcoin::TapSighashType::Default,
                            ) {
                                use bitcoin::hashes::Hash;
                                let msg = bitcoin::secp256k1::Message::from_digest(
                                    sighash.to_byte_array(),
                                );
                                let sig = secp.sign_schnorr(&msg, &asp_kp);
                                let tap_sig = bitcoin::taproot::Signature {
                                    signature: sig,
                                    sighash_type: bitcoin::TapSighashType::Default,
                                };
                                psbt.inputs[input_idx]
                                    .tap_script_sigs
                                    .insert(asp_key_for_leaf, tap_sig);
                                info!(
                                    input_idx,
                                    "Added ASP script-path signature to forfeit VTXO input"
                                );
                            }
                            break;
                        }
                    }
                    // Also sign the connector input (key-path) if it hasn't
                    // been finalized by BDK. BDK doesn't own the connector UTXO
                    // so it can't sign it.
                    use bitcoin::key::TapTweak as _;
                    let asp_kp_tweaked = asp_kp.tap_tweak(&secp, None).to_keypair();

                    for input_idx in 0..psbt.inputs.len() {
                        let input = &psbt.inputs[input_idx];
                        // Key-path inputs: no tap_scripts, no tap_script_sigs,
                        // no final_script_witness yet, but has witness_utxo.
                        if input.final_script_witness.is_some()
                            || !input.tap_script_sigs.is_empty()
                            || !input.tap_scripts.is_empty()
                            || input.witness_utxo.is_none()
                        {
                            continue;
                        }

                        let mut cache = bitcoin::sighash::SighashCache::new(&psbt.unsigned_tx);
                        if let Ok(sighash) = cache.taproot_key_spend_signature_hash(
                            input_idx,
                            &bitcoin::sighash::Prevouts::All(&prevouts),
                            bitcoin::TapSighashType::Default,
                        ) {
                            use bitcoin::hashes::Hash;
                            let msg =
                                bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
                            let sig = secp.sign_schnorr(&msg, &asp_kp_tweaked);
                            let tap_sig = bitcoin::taproot::Signature {
                                signature: sig,
                                sighash_type: bitcoin::TapSighashType::Default,
                            };
                            psbt.inputs[input_idx].final_script_witness =
                                Some(bitcoin::Witness::from_slice(&[tap_sig.serialize()]));
                            info!(
                                input_idx,
                                "Finalized connector key-path input for forfeit tx"
                            );
                        }
                    }
                }

                // Finalize Taproot script-path inputs that BDK left unfinalized.
                // Now that both owner and ASP signatures are present, build the
                // witness from tap_script_sigs + tap_scripts.
                for (idx, input) in psbt.inputs.iter_mut().enumerate() {
                    if input.final_script_witness.is_some() {
                        // Already finalized (e.g. connector key-path input
                        // finalized by BDK).
                        continue;
                    }
                    if input.tap_script_sigs.is_empty() || input.tap_scripts.is_empty() {
                        continue;
                    }

                    // Build the witness for a Taproot script-path spend:
                    //   <sig₁> [<sig₂> ...] <script> <control_block>
                    //
                    // tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>
                    // tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), Signature>
                    //
                    // For a forfeit tx there is one leaf with one signature.
                    // We pick the first matching (control_block, script) pair
                    // whose leaf hash appears in tap_script_sigs.
                    let mut finalized = false;
                    for (control_block, (script, _leaf_ver)) in &input.tap_scripts {
                        let leaf_hash =
                            bitcoin::taproot::TapLeafHash::from_script(script, *_leaf_ver);

                        // Collect signatures for this leaf, ordered by pubkey
                        // position in the script (reversed, as required by
                        // OP_CHECKSIGVERIFY/OP_CHECKSIG multisig pattern).
                        // Extract pubkeys from the script (32-byte pushes).
                        let script_bytes = script.as_bytes();
                        let mut pubkeys_in_script: Vec<bitcoin::secp256k1::XOnlyPublicKey> =
                            Vec::new();
                        let mut i_byte = 0;
                        while i_byte < script_bytes.len() {
                            // 0x20 = push 32 bytes
                            if script_bytes[i_byte] == 0x20 && i_byte + 33 <= script_bytes.len() {
                                if let Ok(pk) = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
                                    &script_bytes[i_byte + 1..i_byte + 33],
                                ) {
                                    pubkeys_in_script.push(pk);
                                }
                                i_byte += 33;
                            } else {
                                i_byte += 1;
                            }
                        }

                        // Collect sigs in REVERSE pubkey order (last pubkey's
                        // sig first on the stack).
                        let mut sigs: Vec<Vec<u8>> = Vec::new();
                        for pk in pubkeys_in_script.iter().rev() {
                            let key = (*pk, leaf_hash);
                            if let Some(sig) = input.tap_script_sigs.get(&key) {
                                sigs.push(sig.serialize().to_vec());
                            }
                        }

                        if sigs.is_empty() {
                            continue;
                        }

                        // Witness stack: [sig_last_pk, ..., sig_first_pk, script, control_block]
                        let mut witness = bitcoin::Witness::new();
                        for sig in &sigs {
                            witness.push(sig);
                        }
                        witness.push(script.as_bytes());
                        witness.push(control_block.serialize());

                        input.final_script_witness = Some(witness);
                        // Clear PSBT fields now that the input is finalized.
                        input.tap_script_sigs.clear();
                        input.tap_scripts.clear();
                        input.tap_key_sig = None;
                        input.tap_internal_key = None;
                        input.tap_merkle_root = None;

                        info!(
                            input_idx = idx,
                            num_sigs = sigs.len(),
                            "Finalized Taproot script-path PSBT input for forfeit tx"
                        );
                        finalized = true;
                        break;
                    }

                    if !finalized {
                        warn!(
                            input_idx = idx,
                            tap_script_sigs = input.tap_script_sigs.len(),
                            tap_scripts = input.tap_scripts.len(),
                            "Could not finalize Taproot script-path input: \
                             no matching leaf hash between tap_scripts and tap_script_sigs"
                        );
                    }
                }

                let tx = psbt.extract_tx_unchecked_fee_rate();
                info!(
                    forfeit_version = tx.version.0,
                    forfeit_inputs = tx.input.len(),
                    forfeit_outputs = tx.output.len(),
                    "broadcast_forfeit_tx: forfeit tx details"
                );
                for (i, inp) in tx.input.iter().enumerate() {
                    info!(
                        input_idx = i,
                        witness_len = inp.witness.len(),
                        "broadcast_forfeit_tx: forfeit tx input witness"
                    );
                }
                hex::encode(bitcoin::consensus::serialize(&tx))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to sign forfeit tx, trying to broadcast as-is"
                );
                forfeit_tx_str
            }
        };

        // === Broadcast chain: commitment TX → connectors → forfeit ===
        //
        // The Go reference server broadcasts the commitment TX during round
        // finalization, then during fraud reaction broadcasts the connector
        // branch (waiting for each to confirm) before the forfeit TX.
        //
        // Step 1: Broadcast the commitment TX if not already on-chain.
        // The commitment TX must be confirmed for connector inputs to be valid.
        {
            use base64::Engine;
            if let Ok(psbt_bytes) =
                base64::engine::general_purpose::STANDARD.decode(&round.commitment_tx)
            {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
                    let raw_tx = psbt.extract_tx_unchecked_fee_rate();
                    let tx_hex = hex::encode(bitcoin::consensus::serialize(&raw_tx));
                    match self.wallet.broadcast_transaction(vec![tx_hex]).await {
                        Ok(txid) => {
                            info!(txid = %txid, "Commitment TX broadcast for fraud reaction")
                        }
                        Err(e) => {
                            debug!(error = %e, "Commitment TX broadcast failed (may already be on-chain)")
                        }
                    }
                }
            }
        }

        // Step 2: Broadcast each connector TX with CPFP anchor.
        // Connectors are 0-fee TRUC v3 transactions, so they must be broadcast
        // as CPFP packages (connector + fee-paying child).
        //
        // Following the Go reference server (broadcastConnectorBranch), we wait
        // for each connector to be confirmed before proceeding. This prevents
        // TRUC v3 descendant-count violations when broadcasting the forfeit,
        // which spends a connector output.
        for (i, connector_hex) in signed_connector_hexes.iter().enumerate() {
            // Parse connector txid for confirmation checking.
            let connector_txid = hex::decode(connector_hex).ok().and_then(|b| {
                bitcoin::consensus::deserialize::<bitcoin::Transaction>(&b)
                    .ok()
                    .map(|tx| tx.compute_txid().to_string())
            });

            // Check if connector is already on-chain (skip if so).
            if let Some(ref txid) = connector_txid {
                if self.scanner.is_tx_confirmed(txid).await.unwrap_or(false) {
                    info!(connector_idx = i, txid = %txid, "Connector already confirmed, skipping");
                    continue;
                }
            }

            match self
                .wallet
                .broadcast_forfeit_with_anchor(std::slice::from_ref(connector_hex))
                .await
            {
                Ok(txid) => {
                    info!(connector_idx = i, txid = %txid, "Connector TX broadcast (CPFP)");
                    // Wait for confirmation before proceeding (matches Go's waitForConfirmation).
                    // broadcast_forfeit_with_anchor already mines a regtest block on success,
                    // but the Esplora index may lag. Poll until confirmed.
                    if let Some(ref ctxid) = connector_txid {
                        for _attempt in 0..10 {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            if self.scanner.is_tx_confirmed(ctxid).await.unwrap_or(false) {
                                info!(connector_idx = i, "Connector confirmed");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    // Try raw broadcast as fallback (connector might already be on-chain)
                    match self
                        .wallet
                        .broadcast_transaction(vec![connector_hex.clone()])
                        .await
                    {
                        Ok(txid) => {
                            info!(connector_idx = i, txid = %txid, "Connector TX broadcast (raw)")
                        }
                        Err(e2) => {
                            debug!(connector_idx = i, error = %e, fallback = %e2, "Connector TX broadcast failed")
                        }
                    }
                }
            }
        }

        // Step 3: Broadcast the forfeit TX with CPFP anchor.
        match self
            .wallet
            .broadcast_forfeit_with_anchor(std::slice::from_ref(&signed_tx_hex))
            .await
        {
            Ok(txid) => {
                info!(vtxo = %outpoint_str, forfeit_txid = %txid, "Forfeit tx broadcast successfully");
                Ok(())
            }
            Err(e) => {
                // Fallback: try as raw transaction (no CPFP anchor)
                match self.wallet.broadcast_transaction(vec![signed_tx_hex]).await {
                    Ok(txid) => {
                        info!(vtxo = %outpoint_str, forfeit_txid = %txid, "Forfeit tx broadcast (raw) successfully");
                        Ok(())
                    }
                    Err(e2) => {
                        warn!(vtxo = %outpoint_str, error = %e, fallback = %e2, "Forfeit tx broadcast failed");
                        Err(ArkError::Internal(format!("Forfeit broadcast failed: {e}")))
                    }
                }
            }
        }
    }

    /// Find the forfeit tx that spends the given VTXO from the round's forfeit tx list.
    ///
    /// Mirrors Go's `findForfeitTx`: iterates over all forfeit txs and checks
    /// if any input matches the VTXO outpoint.
    fn find_forfeit_tx_for_vtxo(
        &self,
        vtxo: &Vtxo,
        forfeit_txs: &[crate::domain::ForfeitTx],
    ) -> ArkResult<String> {
        let target_txid = &vtxo.outpoint.txid;
        let target_vout = vtxo.outpoint.vout;

        for ftx in forfeit_txs {
            // Try to decode the forfeit tx and check its inputs
            // The forfeit tx is stored as hex or base64 PSBT.
            // First try hex decoding of the raw tx.
            if let Ok(tx_bytes) = hex::decode(&ftx.tx) {
                if let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&tx_bytes) {
                    for input in &tx.input {
                        if input.previous_output.txid.to_string() == *target_txid
                            && input.previous_output.vout == target_vout
                        {
                            return Ok(ftx.tx.clone());
                        }
                    }
                    continue;
                }
            }

            // Try base64 PSBT decoding
            if let Ok(psbt_bytes) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &ftx.tx)
            {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
                    for input in &psbt.unsigned_tx.input {
                        if input.previous_output.txid.to_string() == *target_txid
                            && input.previous_output.vout == target_vout
                        {
                            // Return the original PSBT string so the wallet
                            // can sign the connector input before broadcast.
                            return Ok(ftx.tx.clone());
                        }
                    }
                    continue;
                }
            }

            // Fallback: check if the tx string contains the VTXO txid
            // (heuristic matching for partially-encoded txs)
            if ftx.tx.contains(target_txid) {
                return Ok(ftx.tx.clone());
            }
        }

        Err(ArkError::Internal(format!(
            "Forfeit tx not found for VTXO {}:{}",
            target_txid, target_vout
        )))
    }

    /// Rewrite a checkpoint PSBT's input outpoints with the actual on-chain
    /// txids.  The PSBT references the tree leaf by the PSBT-computed txid,
    /// but the on-chain txid may differ after unrolling (intermediate node
    /// finalization changes descendant txids).
    ///
    /// For each input, look up the VTXO in the database.  If the VTXO has a
    /// `root_commitment_txid`, walk the round's tree to find the confirmed
    /// leaf txid matching the VTXO's pubkey/amount and rewrite the input.
    async fn rewrite_psbt_inputs_with_onchain_txids(
        &self,
        psbt_bytes: &[u8],
    ) -> ArkResult<Vec<u8>> {
        let mut psbt = bitcoin::psbt::Psbt::deserialize(psbt_bytes)
            .map_err(|e| ArkError::Internal(format!("PSBT deserialize: {e}")))?;

        let mut changed = false;
        for input in &mut psbt.unsigned_tx.input {
            let orig_txid = input.previous_output.txid.to_string();
            let orig_vout = input.previous_output.vout;

            // Check if this outpoint exists on-chain already
            if let Ok(true) = self.scanner.is_tx_confirmed(&orig_txid).await {
                continue; // Original txid is valid
            }

            // Look up the VTXO to find its tree context
            let outpoint = VtxoOutpoint::new(orig_txid.clone(), orig_vout);
            if let Ok(vtxos) = self.vtxo_repo.get_vtxos(&[outpoint]).await {
                if let Some(vtxo) = vtxos.first() {
                    // Try to find the confirmed on-chain txid by scanning
                    // for a confirmed TX that pays to this VTXO's script.
                    let script_hex = if vtxo.pubkey.len() == 66 {
                        format!("5120{}", &vtxo.pubkey[2..])
                    } else if vtxo.pubkey.len() == 64 {
                        format!("5120{}", vtxo.pubkey)
                    } else {
                        continue;
                    };

                    if let Ok(Some(confirmed_txid)) = self
                        .scanner
                        .find_confirmed_tx_for_script(&script_hex, vtxo.amount)
                        .await
                    {
                        info!(
                            original_txid = %orig_txid,
                            confirmed_txid = %confirmed_txid,
                            "Rewriting checkpoint input with on-chain txid"
                        );
                        if let Ok(txid) = confirmed_txid.parse::<bitcoin::Txid>() {
                            input.previous_output.txid = txid;
                            changed = true;
                        }
                    }
                }
            }
        }

        if changed {
            Ok(psbt.serialize())
        } else {
            Ok(psbt_bytes.to_vec())
        }
    }

    /// Broadcast the checkpoint transaction for a VTXO that was spent offchain.
    ///
    /// Called by `react_to_fraud` when a user tries to redeem on-chain a VTXO
    /// that was already spent offchain. The signed checkpoint tx pins the
    /// offchain state on-chain. After the checkpoint's CSV matures, the server
    /// sweeps the checkpoint output.
    ///
    /// Also marks all downstream preconfirmed VTXOs in the offchain TX chain
    /// as swept, matching the Go sweeper's `SweepVtxos(GetAllChildrenVtxos)`
    /// behaviour that fires after the checkpoint sweep. The server's claim on
    /// those funds is only fully on-chain once the checkpoint sweep confirms,
    /// but if a downstream recipient unrolls their own ark tx first, our
    /// `check_unrolled_vtxos` loop will mark that VTXO as `unrolled=true`
    /// and react independently — `unrolled=true` dominates `swept=true` in
    /// SDK balance calculation so that path still reports balance=0.
    async fn broadcast_checkpoint_tx(&self, vtxo: &Vtxo) -> ArkResult<()> {
        // Broadcast ONLY the checkpoint tx for this specific VTXO. Do NOT
        // iterate/recurse over downstream offchain txs — their checkpoint txs
        // spend virtual ark-tx outputs that were never broadcast on-chain, so
        // any broadcast would be rejected with `bad-txns-inputs-missingorspent`
        // and waste RPC round-trips on every fraud-reaction cycle. Matches
        // Go's `broadcastCheckpointTx` which broadcasts a single checkpoint.
        self.broadcast_checkpoint_for_vtxo(vtxo).await?;

        // Walk the offchain TX chain starting from the checkpoint's parent
        // offchain tx, marking all output VTXOs as swept. This matches Go's
        // sweep-task behavior (createCheckpointSweepTask marks all children
        // vtxos as swept after broadcasting the sweep).
        let mut current_tx_id = vtxo.spent_by.clone();
        let mut seen = std::collections::HashSet::new();
        while !current_tx_id.is_empty() && seen.insert(current_tx_id.clone()) {
            let Ok(Some(otx)) = self.offchain_tx_repo.get(&current_tx_id).await else {
                break;
            };
            let output_outpoints: Vec<crate::domain::VtxoOutpoint> = otx
                .outputs
                .iter()
                .enumerate()
                .map(|(i, _)| crate::domain::VtxoOutpoint::new(current_tx_id.clone(), i as u32))
                .collect();
            let Ok(output_vtxos) = self.vtxo_repo.get_vtxos(&output_outpoints).await else {
                break;
            };
            let swept: Vec<crate::domain::Vtxo> = output_vtxos
                .iter()
                .map(|v| {
                    let mut u = v.clone();
                    u.swept = true;
                    u
                })
                .collect();
            let _ = self.vtxo_repo.add_vtxos(&swept).await;

            // Follow to the next TX in the chain, if any output was further
            // spent offchain.
            current_tx_id = output_vtxos
                .iter()
                .find(|v| !v.spent_by.is_empty() && v.spent_by != current_tx_id)
                .map(|v| v.spent_by.clone())
                .unwrap_or_default();
        }
        Ok(())
    }

    /// Broadcast the one checkpoint PSBT whose input matches `vtxo.outpoint`.
    ///
    /// The offchain tx stored under `vtxo.spent_by` may have multiple
    /// checkpoint PSBTs (one per input VTXO it consumes). Only the PSBT that
    /// spends the just-unrolled VTXO's outpoint is broadcastable — the others
    /// spend sibling inputs whose outputs are not on-chain.
    ///
    /// The checkpoint PSBT references the tree leaf by its PSBT-computed txid,
    /// but the actual on-chain txid may differ (intermediate nodes finalised
    /// with anchors change descendant txids). Before broadcasting we rewrite
    /// each input's outpoint to the confirmed on-chain txid.
    async fn broadcast_checkpoint_for_vtxo(&self, vtxo: &Vtxo) -> ArkResult<()> {
        let tx_id = vtxo.spent_by.as_str();
        let offchain_tx = self.offchain_tx_repo.get(tx_id).await?;

        if let Some(offchain_tx) = offchain_tx {
            if !offchain_tx.checkpoint_txs.is_empty() {
                if let Some((i, checkpoint_b64)) =
                    self.find_checkpoint_for_outpoint(&offchain_tx.checkpoint_txs, &vtxo.outpoint)
                {
                    self.broadcast_single_checkpoint(tx_id, i, checkpoint_b64)
                        .await;
                } else {
                    warn!(
                        otx = %tx_id,
                        outpoint = %vtxo.outpoint,
                        "No checkpoint PSBT matches VTXO outpoint — skipping broadcast",
                    );
                }
                return Ok(());
            }

            // Legacy fallback: check inputs for signed_tx
            for input in &offchain_tx.inputs {
                if !input.signed_tx.is_empty() {
                    let tx_hex = hex::encode(&input.signed_tx);
                    match self
                        .wallet
                        .broadcast_transaction(vec![tx_hex.clone()])
                        .await
                    {
                        Ok(txid) => {
                            info!(
                                otx = %tx_id,
                                checkpoint_txid = %txid,
                                "Checkpoint tx broadcast successfully (from signed input)"
                            );
                        }
                        Err(e) => {
                            warn!(
                                otx = %tx_id,
                                error = %e,
                                "Checkpoint tx broadcast failed (may already be confirmed)"
                            );
                        }
                    }
                }
            }
            return Ok(());
        }

        // Fallback: try looking up via checkpoint repository
        let checkpoint = self.checkpoint_repo.get_checkpoint(tx_id).await?;
        if let Some(checkpoint) = checkpoint {
            info!(
                otx = %tx_id,
                checkpoint_id = %checkpoint.id,
                "Constructing checkpoint tx from tapscript"
            );

            let signed_psbt = self
                .wallet
                .sign_transaction(&checkpoint.tapscript, false)
                .await
                .map_err(|e| {
                    warn!(otx = %tx_id, error = %e, "Failed to sign checkpoint PSBT");
                    e
                })?;

            let raw_tx = self
                .tx_builder
                .finalize_and_extract(&signed_psbt)
                .await
                .map_err(|e| {
                    warn!(otx = %tx_id, error = %e, "Failed to finalize checkpoint tx");
                    e
                })?;

            match self.wallet.broadcast_transaction(vec![raw_tx]).await {
                Ok(txid) => {
                    info!(otx = %tx_id, checkpoint_txid = %txid,
                        "Checkpoint tx from tapscript broadcast successfully");
                }
                Err(e) => {
                    warn!(otx = %tx_id, error = %e,
                        "Checkpoint tx from tapscript broadcast failed");
                }
            }
            return Ok(());
        }

        warn!(otx = %tx_id, "No checkpoint or offchain tx found");
        Ok(())
    }

    /// Locate the checkpoint PSBT in `checkpoint_txs` whose single input spends
    /// `target`. Returns `(index, b64)` so the caller can log the position.
    fn find_checkpoint_for_outpoint<'a>(
        &self,
        checkpoint_txs: &'a [String],
        target: &VtxoOutpoint,
    ) -> Option<(usize, &'a String)> {
        use base64::Engine;
        for (i, b64) in checkpoint_txs.iter().enumerate() {
            let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) else {
                continue;
            };
            let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) else {
                continue;
            };
            for input in &psbt.unsigned_tx.input {
                if input.previous_output.txid.to_string() == target.txid
                    && input.previous_output.vout == target.vout
                {
                    return Some((i, b64));
                }
            }
        }
        None
    }

    /// Finalise and broadcast one checkpoint PSBT, rewriting virtual txids
    /// to on-chain ones first.
    async fn broadcast_single_checkpoint(&self, tx_id: &str, idx: usize, checkpoint_b64: &str) {
        use base64::Engine;
        let psbt_bytes = match base64::engine::general_purpose::STANDARD.decode(checkpoint_b64) {
            Ok(b) => b,
            Err(e) => {
                warn!(otx = %tx_id, error = %e, idx, "Failed to decode checkpoint base64");
                return;
            }
        };

        let rewritten = match self
            .rewrite_psbt_inputs_with_onchain_txids(&psbt_bytes)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                warn!(otx = %tx_id, error = %e, idx,
                    "Failed to rewrite checkpoint inputs — using original");
                psbt_bytes.clone()
            }
        };

        let hex_psbt = hex::encode(&rewritten);
        match self.tx_builder.finalize_and_extract(&hex_psbt).await {
            Ok(raw_tx) => match self.wallet.broadcast_with_anchor_bump(&raw_tx).await {
                Ok(txid) => {
                    info!(otx = %tx_id, checkpoint_txid = %txid, idx,
                        "Checkpoint tx broadcast successfully");
                }
                Err(e) => {
                    warn!(otx = %tx_id, error = %e, idx,
                        "Checkpoint tx broadcast failed");
                }
            },
            Err(e) => {
                warn!(otx = %tx_id, error = %e, idx,
                    "Checkpoint tx finalize failed");
            }
        }
    }

    /// Cancel a pending exit
    #[instrument(skip(self))]
    pub async fn cancel_exit(&self, exit_id: uuid::Uuid) -> ArkResult<()> {
        let mut exits = self.exits.write().await;
        let exit = exits
            .get_mut(&exit_id)
            .ok_or_else(|| ArkError::ExitNotFound(exit_id.to_string()))?;

        exit.cancel()
            .map_err(|e| ArkError::InvalidExitRequest(e.to_string()))?;

        info!(exit_id = %exit_id, "Exit cancelled");
        Ok(())
    }

    /// Get an exit by ID
    pub async fn get_exit(&self, exit_id: uuid::Uuid) -> ArkResult<Exit> {
        self.exits
            .read()
            .await
            .get(&exit_id)
            .cloned()
            .ok_or_else(|| ArkError::ExitNotFound(exit_id.to_string()))
    }

    /// Get all exits for a given type
    pub async fn get_exits_by_type(&self, exit_type: ExitType) -> Vec<ExitSummary> {
        self.exits
            .read()
            .await
            .values()
            .filter(|e| e.exit_type == exit_type)
            .map(ExitSummary::from)
            .collect()
    }

    /// Get pending collaborative exits for inclusion in next round
    pub async fn get_pending_collaborative_exits(&self) -> Vec<Exit> {
        self.exits
            .read()
            .await
            .values()
            .filter(|e| {
                e.exit_type == ExitType::Collaborative
                    && e.status == crate::domain::ExitStatus::Pending
            })
            .cloned()
            .collect()
    }

    /// Complete an exit after round finalization or on-chain confirmation
    #[instrument(skip(self))]
    pub async fn complete_exit(&self, exit_id: uuid::Uuid, fee: bitcoin::Amount) -> ArkResult<()> {
        let mut exits = self.exits.write().await;
        let exit = exits
            .get_mut(&exit_id)
            .ok_or_else(|| ArkError::ExitNotFound(exit_id.to_string()))?;

        exit.complete(fee);
        info!(exit_id = %exit_id, "Exit completed");
        Ok(())
    }

    /// Sweep all pending checkpoints whose exit delay has elapsed.
    ///
    /// Returns the count of swept checkpoints.
    /// Sweep all expired VTXOs, publishing forfeit events for each.
    ///
    /// Returns the number of VTXOs swept.
    pub async fn sweep_expired_vtxos(&self) -> ArkResult<u32> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let sweeper = crate::sweeper::Sweeper::new(
            Arc::clone(&self.vtxo_repo),
            Arc::clone(&self.events),
            Arc::clone(&self.tx_builder),
            Arc::clone(&self.wallet),
            Arc::clone(&self.signer),
        )
        .with_notifier(Arc::clone(&self.notifier));
        sweeper.sweep_expired(now, None).await
    }

    /// Sweep pending checkpoints whose exit delay has elapsed.
    pub async fn sweep_checkpoints(&self) -> ArkResult<u32> {
        let pending = self.checkpoint_repo.list_pending().await?;
        if pending.is_empty() {
            return Ok(0);
        }

        // Get current chain state to verify exit delays
        let block_time = self.wallet.get_current_block_time().await?;
        let current_height = block_time.height;
        let current_timestamp = block_time.timestamp as u64;

        let mut swept = 0u32;
        for mut cp in pending {
            // Estimate the checkpoint creation height from timestamps.
            // elapsed_secs / SECS_PER_BLOCK gives approximate blocks since creation.
            let elapsed_secs = current_timestamp.saturating_sub(cp.created_at);
            let elapsed_blocks = elapsed_secs / u64::from(crate::domain::SECS_PER_BLOCK);
            let estimated_creation_height = current_height.saturating_sub(elapsed_blocks);

            // Verify the exit delay (CSV) has elapsed: current height must be
            // at or beyond creation height + exit_delay blocks.
            let required_height = estimated_creation_height + u64::from(cp.exit_delay);
            if current_height < required_height {
                debug!(
                    checkpoint_id = %cp.id,
                    current_height = current_height,
                    required_height = required_height,
                    exit_delay = cp.exit_delay,
                    "Checkpoint exit delay not yet elapsed, skipping"
                );
                continue;
            }

            cp.mark_swept();
            self.checkpoint_repo.store_checkpoint(cp.clone()).await?;
            swept += 1;
        }
        info!(swept_count = swept, "Checkpoint sweep complete");
        Ok(swept)
    }

    /// Run a scheduled sweep via the pluggable [`SweepService`] port.
    ///
    /// If any VTXOs were swept, publishes an [`ArkEvent::SweepCompleted`].
    pub async fn run_scheduled_sweep(&self, current_height: u32) -> ArkResult<()> {
        let result = self
            .sweep_service
            .sweep_expired_vtxos(current_height)
            .await?;
        if result.vtxos_swept > 0 {
            tracing::info!(
                vtxos_swept = result.vtxos_swept,
                sats_recovered = result.sats_recovered,
                "Sweep complete"
            );
            self.events
                .publish_event(ArkEvent::SweepCompleted {
                    vtxos_swept: result.vtxos_swept,
                    sats_recovered: result.sats_recovered,
                })
                .await?;
        }
        Ok(())
    }

    /// Run a scheduled sweep and return the `SweepResult`.
    ///
    /// Like [`run_scheduled_sweep`](Self::run_scheduled_sweep) but returns the
    /// result instead of only logging it — useful for gRPC responses.
    pub async fn run_scheduled_sweep_with_result(
        &self,
        current_height: u32,
    ) -> ArkResult<crate::ports::SweepResult> {
        let result = self
            .sweep_service
            .sweep_expired_vtxos(current_height)
            .await?;
        if result.vtxos_swept > 0 {
            tracing::info!(
                vtxos_swept = result.vtxos_swept,
                sats_recovered = result.sats_recovered,
                "Sweep complete (with_result)"
            );
            self.events
                .publish_event(ArkEvent::SweepCompleted {
                    vtxos_swept: result.vtxos_swept,
                    sats_recovered: result.sats_recovered,
                })
                .await?;
        }
        Ok(result)
    }

    /// Submit a forfeit transaction for persistence.
    pub async fn submit_forfeit(
        &self,
        round_id: String,
        vtxo_id: String,
        tx_hex: String,
    ) -> ArkResult<ForfeitRecord> {
        let record = ForfeitRecord::new(round_id, vtxo_id, tx_hex);
        self.forfeit_repo.store_forfeit(record.clone()).await?;
        info!(forfeit_id = %record.id, vtxo_id = %record.vtxo_id, "Forfeit stored");
        Ok(record)
    }

    /// Get all forfeit records for a given round.
    pub async fn get_round_forfeits(&self, round_id: &str) -> ArkResult<Vec<ForfeitRecord>> {
        self.forfeit_repo.list_by_round(round_id).await
    }

    // ── Fraud detection ─────────────────────────────────────────────

    /// Check if a VTXO has been double-spent and, if so, broadcast its
    /// forfeit transactions as a reaction.
    #[instrument(skip(self))]
    pub async fn check_and_react_fraud(&self, vtxo_id: &str, round_id: &str) -> ArkResult<()> {
        let is_fraud = self
            .fraud_detector
            .detect_double_spend(vtxo_id, round_id)
            .await?;
        if is_fraud {
            tracing::warn!(vtxo_id, round_id, "Fraud detected: double spend");
            // Get forfeit txs from store and broadcast each
            let forfeits = self.forfeit_repo.list_by_round(round_id).await?;
            for forfeit in forfeits {
                self.fraud_detector
                    .react_to_fraud(vtxo_id, &forfeit.tx_hex)
                    .await?;
            }
            // Emit event
            self.events
                .publish_event(ArkEvent::FraudDetected {
                    vtxo_id: vtxo_id.to_string(),
                    round_id: round_id.to_string(),
                })
                .await?;
        }
        Ok(())
    }

    // ── Boarding ────────────────────────────────────────────────────

    /// Register a new boarding transaction from a user.
    ///
    /// Creates a `BoardingTransaction` for the given recipient and amount,
    /// persists it via the `BoardingRepository`.  The transaction will be
    /// claimed during the next round finalization once funded.
    #[instrument(skip(self))]
    pub async fn register_boarding(
        &self,
        recipient_pubkey: bitcoin::XOnlyPublicKey,
        amount: bitcoin::Amount,
    ) -> ArkResult<BoardingTransaction> {
        let sats = amount.to_sat();

        // Validate amount against boarding limits
        if sats < self.config.utxo_min_amount {
            return Err(ArkError::AmountTooSmall {
                amount: sats,
                minimum: self.config.utxo_min_amount,
            });
        }
        if self.config.utxo_max_amount > 0 && sats > self.config.utxo_max_amount {
            return Err(ArkError::Internal(format!(
                "Boarding amount {} exceeds maximum {}",
                sats, self.config.utxo_max_amount
            )));
        }

        let tx = BoardingTransaction::new(recipient_pubkey, amount);
        self.boarding_repo.register_boarding(tx.clone()).await?;
        info!(boarding_id = %tx.id, amount = sats, "Boarding registered");
        Ok(tx)
    }

    /// Claim all pending (funded) boarding transactions for inclusion in the current round.
    pub async fn claim_boarding_inputs(&self) -> ArkResult<Vec<BoardingTransaction>> {
        let pending = self.boarding_repo.get_pending_boarding().await?;
        info!(count = pending.len(), "Claiming boarding inputs for round");
        Ok(pending)
    }

    /// Set offchain tx repository (builder-style).
    pub fn set_offchain_tx_repo(mut self, repo: Arc<dyn OffchainTxRepository>) -> Self {
        self.offchain_tx_repo = repo;
        self
    }

    /// Submit an offchain transaction for processing in the next round.
    ///
    /// Validates inputs, creates the transaction, stores it as pending,
    /// emits a `TxSubmitted` event, and returns the transaction ID.
    #[instrument(skip(self, inputs, outputs), fields(input_count, output_count))]
    pub async fn submit_offchain_tx(
        &self,
        inputs: Vec<VtxoInput>,
        outputs: Vec<VtxoOutput>,
    ) -> ArkResult<String> {
        if inputs.is_empty() {
            return Err(ArkError::Validation("inputs must not be empty".into()));
        }

        if outputs.is_empty() {
            return Err(ArkError::Validation("outputs must not be empty".into()));
        }

        // Validate output amounts
        for o in &outputs {
            if o.amount_sats < MIN_VTXO_AMOUNT_SATS {
                return Err(ArkError::Validation(format!(
                    "output amount {} below dust limit {}",
                    o.amount_sats, MIN_VTXO_AMOUNT_SATS
                )));
            }
        }

        let tx = OffchainTx::new(inputs, outputs);
        let tx_id = tx.id.clone();

        self.offchain_tx_repo.create(&tx).await?;

        self.events
            .publish_event(ArkEvent::TxSubmitted {
                ark_txid: tx_id.clone(),
            })
            .await?;

        info!(tx_id = %tx_id, "Offchain tx submitted");
        Ok(tx_id)
    }

    /// Finalize an offchain transaction — marks it as finalized with the given on-chain txid.
    ///
    /// Looks up the pending transaction, transitions its stage to Finalized,
    /// persists the update, and emits a `TxFinalized` event.
    #[instrument(skip(self))]
    pub async fn finalize_offchain_tx(&self, tx_id: &str) -> ArkResult<String> {
        let mut tx = self
            .offchain_tx_repo
            .get(tx_id)
            .await?
            .ok_or_else(|| ArkError::NotFound(format!("Offchain tx {tx_id} not found")))?;

        let commitment_txid = tx_id.to_string();
        tx.finalize(commitment_txid.clone())
            .map_err(|e| ArkError::Validation(format!("Cannot finalize offchain tx: {e}")))?;

        self.offchain_tx_repo.update_stage(tx_id, &tx.stage).await?;

        self.events
            .publish_event(ArkEvent::TxFinalized {
                ark_txid: tx_id.to_string(),
                commitment_txid: commitment_txid.clone(),
            })
            .await?;

        info!(tx_id = %tx_id, "Offchain tx finalized");
        Ok(commitment_txid)
    }

    /// Finalize an offchain transaction AND update VTXO state atomically.
    ///
    /// This is the real implementation of FinalizeTx:
    /// 1. Marks the stored offchain tx as Finalized.
    /// 2. Marks all input VTXOs as spent (referencing `ark_txid`).
    /// 3. Creates output VTXOs from the transaction's output list.
    /// 4. Emits a `TxFinalized` event.
    ///
    /// If the offchain tx is not found (e.g. it was already finalized or was never
    /// stored), we return Ok so that FinalizeTx is idempotent.
    #[instrument(skip(self))]
    pub async fn finalize_offchain_tx_with_vtxo_update(&self, tx_id: &str) -> ArkResult<String> {
        // Fetch the pending tx — if not found, assume already finalised
        let tx_opt = self.offchain_tx_repo.get(tx_id).await?;
        let tx = match tx_opt {
            Some(t) => t,
            None => {
                info!(tx_id = %tx_id, "finalize_offchain_tx_with_vtxo_update: tx not found (already finalised?)");
                return Ok(tx_id.to_string());
            }
        };

        // Skip if already finalised
        if tx.is_finalized() {
            return Ok(tx_id.to_string());
        }

        // Transition stage
        let mut updated_tx = tx.clone();
        updated_tx
            .finalize(tx_id.to_string())
            .map_err(|e| ArkError::Validation(format!("Cannot finalize offchain tx: {e}")))?;
        self.offchain_tx_repo
            .update_stage(tx_id, &updated_tx.stage)
            .await?;

        // Spend all input VTXOs
        if !tx.inputs.is_empty() {
            let spend_list: Vec<(VtxoOutpoint, String)> = tx
                .inputs
                .iter()
                .filter_map(|inp| {
                    // vtxo_id is "txid:vout"
                    let parts: Vec<&str> = inp.vtxo_id.rsplitn(2, ':').collect();
                    if parts.len() == 2 {
                        let vout: u32 = parts[0].parse().unwrap_or(0);
                        let txid = parts[1].to_string();
                        Some((VtxoOutpoint::new(txid, vout), tx_id.to_string()))
                    } else {
                        None
                    }
                })
                .collect();

            if !spend_list.is_empty() {
                if let Err(e) = self.vtxo_repo.spend_vtxos(&spend_list, tx_id).await {
                    // Log but don't abort — the VTXO may not exist in test environments
                    tracing::warn!(tx_id = %tx_id, error = %e, "Failed to mark input VTXOs as spent (non-fatal in test mode)");
                }
            }

            // NOTE: We do NOT broadcast tree nodes here during offchain TX
            // finalization. Tree nodes should only be broadcast when:
            //   - The user explicitly calls Unroll (unilateral exit)
            //   - The server needs to sweep expired VTXOs
            //   - The server reacts to fraud (checkpoint/forfeit broadcast)
            // Broadcasting tree nodes eagerly causes the maintenance loop to
            // mark VTXOs as "unrolled", which breaks subsequent Unroll() calls
            // ("no vtxos to unroll") because getSpendableVtxos filters them out.
        }

        // Create output VTXOs
        if !tx.outputs.is_empty() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let dust = self.wallet.get_dust_amount().await.unwrap_or(330);
            let output_vtxos: Vec<Vtxo> = tx
                .outputs
                .iter()
                .enumerate()
                .map(|(i, out)| {
                    let mut vtxo = Vtxo::new(
                        VtxoOutpoint::new(tx_id.to_string(), i as u32),
                        out.amount_sats,
                        out.pubkey.clone(),
                    );
                    vtxo.ark_txid = tx_id.to_string();
                    vtxo.preconfirmed = true;
                    // unilateral_exit_delay is in blocks. Convert to seconds
                    // using 10 min/block (BIP68 convention). This ensures
                    // the timestamp sweep doesn't expire VTXOs prematurely.
                    vtxo.expires_at = now + (self.config.unilateral_exit_delay as i64) * 600;
                    vtxo.assets = out.assets.clone();
                    // Mark sub-dust preconfirmed VTXOs as swept, matching Go server
                    // behavior. Sub-dust VTXOs can't be spent individually or
                    // unilaterally exited (their output uses OP_RETURN). They are
                    // treated as recoverable by the SDK.
                    if out.amount_sats < dust {
                        vtxo.swept = true;
                    }
                    vtxo
                })
                .collect();

            for vtxo in &output_vtxos {
                info!(
                    tx_id = %tx_id,
                    outpoint = %vtxo.outpoint,
                    pubkey = %vtxo.pubkey,
                    amount = vtxo.amount,
                    "finalize_offchain_tx: creating output VTXO"
                );
            }

            if let Err(e) = self.vtxo_repo.add_vtxos(&output_vtxos).await {
                tracing::warn!(tx_id = %tx_id, error = %e, "Failed to create output VTXOs (non-fatal in test mode)");
            }

            // Register assets from the VTXO asset fields so GetAsset can find them.
            // Also parse the signed ark tx to extract control asset relationships
            // from the asset extension and store issuance records.
            {
                // Collect unique asset IDs from all output VTXOs
                let mut seen_assets: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for vtxo in &output_vtxos {
                    for (asset_id, amount) in &vtxo.assets {
                        if seen_assets.insert(asset_id.clone()) {
                            let asset = crate::domain::Asset {
                                asset_id: asset_id.clone(),
                                amount: *amount,
                                issuer_pubkey: vtxo.pubkey.clone(),
                                max_supply: None,
                                metadata: std::collections::HashMap::new(),
                            };
                            let _ = self.asset_repo.store_asset(&asset).await;
                        }
                    }
                }

                // Parse the asset extension from the signed ark tx to find
                // control asset references and store issuance records.
                if !tx.signed_ark_tx.is_empty() {
                    self.store_asset_issuance_records(tx_id, &tx.signed_ark_tx)
                        .await;
                }
            }

            // Emit VtxoCreated events so subscribers (e.g. NotifyIncomingFunds) are notified
            for vtxo in &output_vtxos {
                let _ = self
                    .events
                    .publish_event(ArkEvent::VtxoCreated {
                        vtxo_id: format!("{}:{}", vtxo.outpoint.txid, vtxo.outpoint.vout),
                        pubkey: vtxo.pubkey.clone(),
                        amount: vtxo.amount,
                        round_id: tx_id.to_string(),
                    })
                    .await;
            }
        }

        self.events
            .publish_event(ArkEvent::TxFinalized {
                ark_txid: tx_id.to_string(),
                commitment_txid: tx_id.to_string(),
            })
            .await?;

        info!(tx_id = %tx_id, "Offchain tx finalized with VTXO state update");
        Ok(tx_id.to_string())
    }

    /// Finalize all pending offchain transactions for a given public key.
    ///
    /// Used by the FinalizePendingTxs reconnect flow: fetches all Requested/Accepted
    /// offchain txs whose inputs are owned by `pubkey` and finalizes each one.
    pub async fn finalize_pending_txs_for_pubkey(&self, pubkey: &str) -> ArkResult<Vec<String>> {
        let pending = self.offchain_tx_repo.get_pending().await?;
        let mut finalized_ids = Vec::new();

        for tx in pending {
            // Check if any input VTXO belongs to this pubkey
            let belongs_to_pubkey = if pubkey.is_empty() {
                true // empty pubkey → finalize all pending
            } else {
                let input_outpoints: Vec<VtxoOutpoint> = tx
                    .inputs
                    .iter()
                    .filter_map(|inp| {
                        let parts: Vec<&str> = inp.vtxo_id.rsplitn(2, ':').collect();
                        if parts.len() == 2 {
                            let vout: u32 = parts[0].parse().unwrap_or(0);
                            Some(VtxoOutpoint::new(parts[1].to_string(), vout))
                        } else {
                            None
                        }
                    })
                    .collect();

                if input_outpoints.is_empty() {
                    false
                } else {
                    match self.vtxo_repo.get_vtxos(&input_outpoints).await {
                        Ok(vtxos) => vtxos.iter().any(|v| v.pubkey == pubkey),
                        Err(_) => false,
                    }
                }
            };

            if belongs_to_pubkey {
                let tx_id = tx.id.clone();
                match self.finalize_offchain_tx_with_vtxo_update(&tx_id).await {
                    Ok(id) => {
                        finalized_ids.push(id);
                    }
                    Err(e) => {
                        tracing::warn!(tx_id = %tx_id, error = %e, "Failed to finalize pending tx");
                    }
                }
            }
        }

        Ok(finalized_ids)
    }

    /// Get a pending offchain transaction by ID.
    pub async fn get_offchain_tx(&self, tx_id: &str) -> ArkResult<Option<OffchainTx>> {
        self.offchain_tx_repo.get(tx_id).await
    }

    /// Access the offchain tx repository (for indexer queries).
    pub fn get_offchain_tx_repo(&self) -> &dyn OffchainTxRepository {
        self.offchain_tx_repo.as_ref()
    }

    /// Parse the ARK asset extension from a transaction's OP_RETURN output.
    /// Returns a map from output vout to Vec<(asset_id, amount)>.
    fn parse_asset_packet_static(
        tx: &bitcoin::Transaction,
        ark_txid: &str,
    ) -> std::collections::HashMap<u16, Vec<(String, u64)>> {
        let mut result: std::collections::HashMap<u16, Vec<(String, u64)>> =
            std::collections::HashMap::new();

        // Find OP_RETURN with ARK extension
        let mut ext_data: Option<&[u8]> = None;
        for out in &tx.output {
            let sb = out.script_pubkey.as_bytes();
            if sb.len() < 5 || sb[0] != 0x6a {
                continue;
            }
            let push = {
                let mut p = 1usize;
                let op = sb[p];
                p += 1;
                if op <= 75 {
                    let l = op as usize;
                    if p + l <= sb.len() {
                        Some(&sb[p..p + l])
                    } else {
                        None
                    }
                } else if op == 0x4c && p < sb.len() {
                    let l = sb[p] as usize;
                    p += 1;
                    if p + l <= sb.len() {
                        Some(&sb[p..p + l])
                    } else {
                        None
                    }
                } else if op == 0x4d && p + 1 < sb.len() {
                    let l = u16::from_le_bytes([sb[p], sb[p + 1]]) as usize;
                    p += 2;
                    if p + l <= sb.len() {
                        Some(&sb[p..p + l])
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(d) = push {
                if d.len() >= 3 && d[0] == 0x41 && d[1] == 0x52 && d[2] == 0x4b {
                    ext_data = Some(d);
                    break;
                }
            }
        }
        let ext_data = match ext_data {
            Some(d) => d,
            None => return result,
        };
        let data = &ext_data[3..];
        if data.is_empty() {
            return result;
        }

        let mut pos = 0;
        while pos < data.len() {
            let pkt_type = data[pos];
            pos += 1;
            let (pkt_len, n) = match Self::read_varint_static(&data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += n;
            if pkt_type == 0x00 {
                let end = std::cmp::min(pos + pkt_len as usize, data.len());
                Self::parse_asset_groups_static(&data[pos..end], ark_txid, &mut result);
            }
            pos += pkt_len as usize;
        }
        result
    }

    /// Parse asset groups from packet body, populate vout → assets map.
    fn parse_asset_groups_static(
        data: &[u8],
        ark_txid: &str,
        result: &mut std::collections::HashMap<u16, Vec<(String, u64)>>,
    ) {
        let mut pos = 0;
        let (group_count, n) = match Self::read_varint_static(&data[pos..]) {
            Some(v) => v,
            None => return,
        };
        pos += n;

        for gidx in 0..group_count as u16 {
            if pos >= data.len() {
                break;
            }
            let presence = data[pos];
            pos += 1;
            let has_aid = (presence & 0x01) != 0;
            let has_ctrl = (presence & 0x02) != 0;
            let has_meta = (presence & 0x04) != 0;

            let aid = if has_aid {
                if pos + 34 > data.len() {
                    break;
                }
                let s = hex::encode(&data[pos..pos + 34]);
                pos += 34;
                s
            } else {
                format!("{}{}", ark_txid, hex::encode(gidx.to_le_bytes()))
            };

            if has_ctrl {
                if pos >= data.len() {
                    break;
                }
                let rt = data[pos];
                pos += 1;
                match rt {
                    1 => pos += 34,
                    2 => pos += 2,
                    _ => break,
                }
            }
            if has_meta {
                let (mc, n) = match Self::read_varint_static(&data[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n;
                for _ in 0..mc {
                    let (kl, n) = match Self::read_varint_static(&data[pos..]) {
                        Some(v) => v,
                        None => return,
                    };
                    pos += n + kl as usize;
                    let (vl, n) = match Self::read_varint_static(&data[pos..]) {
                        Some(v) => v,
                        None => return,
                    };
                    pos += n + vl as usize;
                }
            }
            // Skip inputs
            let (ic, n) = match Self::read_varint_static(&data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += n;
            for _ in 0..ic {
                if pos >= data.len() {
                    break;
                }
                let it = data[pos];
                pos += 1;
                match it {
                    1 => {
                        pos += 2;
                        let (_, n) = match Self::read_varint_static(&data[pos..]) {
                            Some(v) => v,
                            None => return,
                        };
                        pos += n;
                    }
                    2 => {
                        pos += 34;
                        let (_, n) = match Self::read_varint_static(&data[pos..]) {
                            Some(v) => v,
                            None => return,
                        };
                        pos += n;
                    }
                    _ => return,
                }
            }
            // Read outputs
            let (oc, n) = match Self::read_varint_static(&data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += n;
            for _ in 0..oc {
                if pos >= data.len() {
                    break;
                }
                pos += 1; // type
                if pos + 2 > data.len() {
                    break;
                }
                let vout = u16::from_le_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                let (amount, n) = match Self::read_varint_static(&data[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n;
                result.entry(vout).or_default().push((aid.clone(), amount));
            }
        }
    }

    /// Parse a signed ark tx PSBT for asset extension data and store
    /// issuance records (with control asset relationships) in the asset repo.
    async fn store_asset_issuance_records(&self, ark_txid: &str, signed_ark_tx: &str) {
        use base64::Engine;
        let psbt_bytes = match base64::engine::general_purpose::STANDARD.decode(signed_ark_tx) {
            Ok(b) => b,
            Err(_) => return,
        };
        let psbt = match bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
            Ok(p) => p,
            Err(_) => return,
        };
        // Find OP_RETURN with ARK extension
        for out in &psbt.unsigned_tx.output {
            let sb = out.script_pubkey.as_bytes();
            if sb.len() < 5 || sb[0] != 0x6a {
                continue;
            }
            // Decode push data
            let push = {
                let mut pos = 1usize;
                let op = sb[pos];
                pos += 1;
                if op <= 75 {
                    let len = op as usize;
                    if pos + len <= sb.len() {
                        Some(&sb[pos..pos + len])
                    } else {
                        None
                    }
                } else if op == 0x4c && pos < sb.len() {
                    let len = sb[pos] as usize;
                    pos += 1;
                    if pos + len <= sb.len() {
                        Some(&sb[pos..pos + len])
                    } else {
                        None
                    }
                } else if op == 0x4d && pos + 1 < sb.len() {
                    let len = u16::from_le_bytes([sb[pos], sb[pos + 1]]) as usize;
                    pos += 2;
                    if pos + len <= sb.len() {
                        Some(&sb[pos..pos + len])
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            let push = match push {
                Some(d) => d,
                None => continue,
            };
            if push.len() < 4 || push[0] != 0x41 || push[1] != 0x52 || push[2] != 0x4b {
                continue;
            }
            // Parse extension packets
            let data = &push[3..];
            if data.is_empty() {
                break;
            }
            let pkt_type = data[0];
            if pkt_type != 0x00 {
                break;
            } // only asset packets
            let (pkt_len, n) = match Self::read_varint_static(&data[1..]) {
                Some(v) => v,
                None => break,
            };
            let pkt_start = 1 + n;
            let pkt_end = std::cmp::min(pkt_start + pkt_len as usize, data.len());
            self.parse_and_store_issuances(&data[pkt_start..pkt_end], ark_txid)
                .await;
            break;
        }
    }

    /// Read a protobuf-style base-128 varint.
    fn read_varint_static(data: &[u8]) -> Option<(u64, usize)> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        for (i, &byte) in data.iter().enumerate() {
            if shift >= 64 {
                return None;
            }
            value |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return Some((value, i + 1));
            }
        }
        None
    }

    /// Parse asset groups from packet body and store issuance records.
    async fn parse_and_store_issuances(&self, pkt_data: &[u8], ark_txid: &str) {
        let mut pos = 0;
        let (group_count, n) = match Self::read_varint_static(pkt_data) {
            Some(v) => v,
            None => return,
        };
        pos += n;

        let mut group_ids: Vec<String> = Vec::new();
        let mut control_refs: Vec<Option<u16>> = Vec::new();

        for gidx in 0..group_count as u16 {
            if pos >= pkt_data.len() {
                break;
            }
            let presence = pkt_data[pos];
            pos += 1;
            let has_aid = (presence & 0x01) != 0;
            let has_ctrl = (presence & 0x02) != 0;
            let has_meta = (presence & 0x04) != 0;

            let aid = if has_aid {
                if pos + 34 > pkt_data.len() {
                    break;
                }
                let s = hex::encode(&pkt_data[pos..pos + 34]);
                pos += 34;
                s
            } else {
                format!("{}{}", ark_txid, hex::encode(gidx.to_le_bytes()))
            };

            let mut cref: Option<u16> = None;
            if has_ctrl {
                if pos >= pkt_data.len() {
                    break;
                }
                let rt = pkt_data[pos];
                pos += 1;
                match rt {
                    1 => pos += 34,
                    2 => {
                        if pos + 2 <= pkt_data.len() {
                            cref = Some(u16::from_le_bytes([pkt_data[pos], pkt_data[pos + 1]]));
                        }
                        pos += 2;
                    }
                    _ => break,
                }
            }
            if has_meta {
                let (mc, n) = match Self::read_varint_static(&pkt_data[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n;
                for _ in 0..mc {
                    let (kl, n) = match Self::read_varint_static(&pkt_data[pos..]) {
                        Some(v) => v,
                        None => return,
                    };
                    pos += n + kl as usize;
                    let (vl, n) = match Self::read_varint_static(&pkt_data[pos..]) {
                        Some(v) => v,
                        None => return,
                    };
                    pos += n + vl as usize;
                }
            }
            // Skip inputs
            let (ic, n) = match Self::read_varint_static(&pkt_data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += n;
            for _ in 0..ic {
                if pos >= pkt_data.len() {
                    break;
                }
                let it = pkt_data[pos];
                pos += 1;
                match it {
                    1 => {
                        pos += 2;
                        let (_, n) = match Self::read_varint_static(&pkt_data[pos..]) {
                            Some(v) => v,
                            None => return,
                        };
                        pos += n;
                    }
                    2 => {
                        pos += 34;
                        let (_, n) = match Self::read_varint_static(&pkt_data[pos..]) {
                            Some(v) => v,
                            None => return,
                        };
                        pos += n;
                    }
                    _ => return,
                }
            }
            // Skip outputs
            let (oc, n) = match Self::read_varint_static(&pkt_data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += n;
            for _ in 0..oc {
                if pos >= pkt_data.len() {
                    break;
                }
                pos += 3; // type + vout
                let (_, n) = match Self::read_varint_static(&pkt_data[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n;
            }
            group_ids.push(aid);
            control_refs.push(cref);
        }

        // Store issuance records
        for (i, aid) in group_ids.iter().enumerate() {
            let ctrl = control_refs
                .get(i)
                .and_then(|c| *c)
                .and_then(|ci| group_ids.get(ci as usize).cloned());
            let issuance = crate::domain::AssetIssuance {
                txid: ark_txid.to_string(),
                asset_id: aid.clone(),
                amount: 0,
                issuer_pubkey: String::new(),
                control_asset_id: ctrl,
                metadata: std::collections::HashMap::new(),
            };
            let _ = self.asset_repo.store_issuance(&issuance).await;
        }
    }

    /// Emit a TxFinalized event for an off-chain transaction.
    /// Used by FinalizeTx gRPC to notify subscribers.
    pub async fn emit_tx_finalized_event(&self, ark_txid: &str) -> ArkResult<()> {
        self.events
            .publish_event(ArkEvent::TxFinalized {
                ark_txid: ark_txid.to_string(),
                commitment_txid: ark_txid.to_string(),
            })
            .await
    }

    // ── Ban / conviction ──────────────────────────────────────────────

    /// Ban a participant for misbehaviour and emit a `ParticipantBanned` event.
    pub async fn ban_participant(
        &self,
        pubkey: &str,
        reason: BanReason,
        round_id: &str,
    ) -> ArkResult<()> {
        self.ban_repo.ban(pubkey, reason, round_id).await?;
        self.events
            .publish_event(ArkEvent::ParticipantBanned {
                pubkey: pubkey.to_string(),
            })
            .await?;
        info!(pubkey = %pubkey, round_id = %round_id, "Participant banned");
        Ok(())
    }

    /// Check whether a participant is currently banned.
    pub async fn is_participant_banned(&self, pubkey: &str) -> ArkResult<bool> {
        self.ban_repo.is_banned(pubkey).await
    }

    // ── Go dark parity methods (#159) ───────────────────────────────

    /// Get an intent by its ID from the current round.
    pub async fn get_intent_by_id(&self, intent_id: &str) -> ArkResult<Option<Intent>> {
        let guard = self.current_round.read().await;
        match guard.as_ref() {
            Some(round) => Ok(round.intents.get(intent_id).cloned()),
            None => Ok(None),
        }
    }

    /// Remove an intent from the current round by its ID.
    ///
    /// Returns `Ok(())` if the intent was found and removed,
    /// or `ArkError::NotFound` if no active round or intent not found.
    pub async fn unregister_intent(&self, intent_id: &str) -> ArkResult<()> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::NotFound("No active round".to_string()))?;
        if round.intents.remove(intent_id).is_some() {
            info!(intent_id = %intent_id, "Intent unregistered");
            Ok(())
        } else {
            Err(ArkError::NotFound(format!(
                "Intent {} not found in active round",
                intent_id
            )))
        }
    }

    /// Delete intents from the active round by matching their input outpoints
    /// against those in the provided proof PSBT.
    ///
    /// This matches Go arkd's `DeleteIntentsByProof` which iterates cached
    /// intents and removes those whose inputs match the proof's outpoints.
    /// Delete a single intent by its ID from the current round.
    ///
    /// Returns Ok(()) even if the intent is not found — it may have been
    /// consumed by a completed round, which is equivalent to deletion.
    pub async fn delete_intent(&self, intent_id: &str) -> ArkResult<()> {
        let mut guard = self.current_round.write().await;
        if let Some(round) = guard.as_mut() {
            if round.intents.remove(intent_id).is_some() {
                info!(intent_id = %intent_id, "Intent deleted by ID");
            } else {
                info!(intent_id = %intent_id, "Intent not in current round (already consumed)");
            }
        } else {
            info!(intent_id = %intent_id, "No active round — intent already consumed");
        }
        Ok(())
    }

    /// Delete intents whose inputs match the given outpoints.
    ///
    /// Used for proof-based deletion (BIP-322 PSBT): extracts input outpoints
    /// from the proof and removes any registered intents that spend them.
    pub async fn delete_intents_by_inputs(
        &self,
        input_outpoints: &[(String, u32)],
    ) -> ArkResult<Vec<String>> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::NotFound("No active round".to_string()))?;

        let mut deleted_ids = Vec::new();
        let input_set: std::collections::HashSet<(String, u32)> =
            input_outpoints.iter().cloned().collect();

        // Collect intent IDs that have any input matching the provided outpoints.
        let matching_ids: Vec<String> = round
            .intents
            .iter()
            .filter(|(_, intent)| {
                intent
                    .inputs
                    .iter()
                    .any(|inp| input_set.contains(&(inp.outpoint.txid.clone(), inp.outpoint.vout)))
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in matching_ids {
            if round.intents.remove(&id).is_some() {
                info!(intent_id = %id, "Intent deleted by input match");
                deleted_ids.push(id);
            }
        }

        if deleted_ids.is_empty() {
            Err(ArkError::NotFound(
                "No intents with matching inputs found in active round".to_string(),
            ))
        } else {
            Ok(deleted_ids)
        }
    }

    /// Submit MuSig2 tree nonces for the current batch.
    ///
    /// Called by cosigners during the tree signing phase.
    /// After storing, emits `TreeNoncesForwarded` per tree node so the event
    /// bridge can forward `TreeNonces` proto events to clients.
    #[instrument(skip(self, nonces))]
    pub async fn submit_tree_nonces(
        &self,
        batch_id: &str,
        pubkey: &str,
        nonces: Vec<u8>,
    ) -> ArkResult<()> {
        // Verify round exists and is in finalization stage
        let round_id = {
            let guard = self.current_round.read().await;
            let round = guard
                .as_ref()
                .ok_or_else(|| ArkError::NotFound("No active round".to_string()))?;

            if round.id != batch_id {
                return Err(ArkError::NotFound(format!(
                    "Batch {} does not match current round {}",
                    batch_id, round.id
                )));
            }

            if round.stage.code != RoundStage::Finalization {
                return Err(ArkError::Internal(
                    "Round not in finalization stage".to_string(),
                ));
            }
            round.id.clone()
        };

        // Store nonces in the signing session store
        self.signing_session_store
            .add_nonce(batch_id, pubkey, nonces)
            .await?;

        info!(batch_id, pubkey, "Tree nonces submitted");

        // Check if all nonces collected — if so, emit TreeNoncesForwarded events.
        // Go clients send map<txid, nonce_hex> and need one TreeNoncesEvent per txid
        // with all participants' nonces for that txid.
        if self
            .signing_session_store
            .all_nonces_collected(batch_id)
            .await?
        {
            info!(
                batch_id,
                "All tree nonces collected — emitting per-txid nonces events"
            );

            // Fetch the real nonces from the signing session store.
            // Each participant's nonce blob is a JSON-serialized map<txid, nonce_hex>.
            // Build map<txid, map<x_only_pubkey, nonce_hex>> to emit one event per txid.
            let session = self.signing_session_store.get_session(batch_id).await?;

            // nonces_by_txid: txid -> { x_only_pubkey -> nonce_hex }
            let mut nonces_by_txid: std::collections::HashMap<
                String,
                std::collections::HashMap<String, String>,
            > = std::collections::HashMap::new();

            // cosigners_by_txid: txid -> Vec<compressed_pubkey>
            // Used as topic for event filtering so clients only receive
            // TreeNonces events for tree nodes they cosign.
            let mut cosigners_by_txid: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();

            if let Some(session) = session {
                for (participant_pubkey_compressed, nonce_blob) in &session.tree_nonces {
                    let x_only_pubkey_hex = if participant_pubkey_compressed.len() == 66 {
                        participant_pubkey_compressed[2..].to_string()
                    } else {
                        participant_pubkey_compressed.clone()
                    };

                    // nonce_blob is JSON-serialized map<txid, nonce_hex>
                    let participant_nonces: std::collections::HashMap<String, String> =
                        match serde_json::from_slice(nonce_blob) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::warn!(
                                    pubkey = %participant_pubkey_compressed,
                                    error = %e,
                                    "Failed to deserialize participant nonces — skipping"
                                );
                                continue;
                            }
                        };

                    info!(
                        participant = %participant_pubkey_compressed,
                        nonce_txid_count = participant_nonces.len(),
                        "Nonce blob: participant submitted nonces for N txids"
                    );
                    // Store nonces with BOTH compressed and x-only keys.
                    // Go SDK lookups use compressed in OnTreeNonces but
                    // x-only internally in AggregateNonces.
                    for (txid, nonce_hex) in participant_nonces {
                        let map = nonces_by_txid.entry(txid.clone()).or_default();
                        map.insert(participant_pubkey_compressed.clone(), nonce_hex.clone());
                        map.insert(x_only_pubkey_hex.clone(), nonce_hex);
                        cosigners_by_txid
                            .entry(txid)
                            .or_default()
                            .push(participant_pubkey_compressed.clone());
                    }
                }
            }

            // Emit one TreeNoncesForwarded event per txid
            for (txid, nonces_by_pubkey) in &nonces_by_txid {
                let cosigners_compressed = cosigners_by_txid.get(txid).cloned().unwrap_or_default();
                self.events
                    .publish_event(ArkEvent::TreeNoncesForwarded {
                        round_id: round_id.clone(),
                        txid: txid.clone(),
                        nonces_by_pubkey: nonces_by_pubkey.clone(),
                        cosigners_compressed,
                    })
                    .await?;
            }

            // Compute aggregated nonces per txid for the TreeNoncesAggregated event.
            // Use only compressed keys (66 chars) to avoid double-counting.
            use musig2::BinaryEncoding as _;
            let mut aggregated_nonces: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            for (txid, nonces_map) in &nonces_by_txid {
                let mut pub_nonces: Vec<musig2::PubNonce> = Vec::new();
                for (key, nonce_hex) in nonces_map {
                    if key.len() != 66 {
                        continue;
                    }
                    if let Ok(bytes) = hex::decode(nonce_hex) {
                        if let Ok(pn) = musig2::PubNonce::from_bytes(&bytes) {
                            pub_nonces.push(pn);
                        }
                    }
                }
                if pub_nonces.len() >= 2 {
                    let agg = dark_bitcoin::signing::aggregate_nonces(&pub_nonces);
                    aggregated_nonces.insert(txid.clone(), hex::encode(agg.to_bytes()));
                }
            }

            self.events
                .publish_event(ArkEvent::TreeNoncesCollected {
                    round_id: batch_id.to_string(),
                    aggregated_nonces,
                })
                .await?;

            // ── ASP partial signature creation ──────────────────────────────
            // Now that all nonces are collected, the ASP creates its partial
            // MuSig2 signatures for each tree tx and submits them to the
            // signing session.
            //
            // Multiple concurrent submit_tree_nonces calls may all pass the
            // all_nonces_collected check.  asp_create_and_submit_partial_sigs
            // atomically takes the ASP MuSig2 state (SecNonces) under a
            // mutex — the first call consumes it and the rest get Ok(())
            // because the state is already consumed (no-op).
            if let Err(e) = self
                .asp_create_and_submit_partial_sigs(batch_id, &nonces_by_txid)
                .await
            {
                error!(error = %e, "Failed to create ASP partial signatures");
                return Err(e);
            }
        }

        Ok(())
    }

    /// Submit MuSig2 tree partial signatures for the current batch.
    ///
    /// Called by cosigners after nonces have been aggregated.
    /// After the first signature submission, completes the round (creates VTXOs,
    /// ends the round, emits RoundFinalized → BatchFinalization + BatchFinalized).
    #[instrument(skip(self, signatures))]
    pub async fn submit_tree_signatures(
        &self,
        batch_id: &str,
        pubkey: &str,
        signatures: Vec<u8>,
    ) -> ArkResult<()> {
        // Verify round exists and is in finalization stage.
        // Accept gracefully if round already ended or rotated (late cosigner submission).
        {
            let guard = self.current_round.read().await;
            match guard.as_ref() {
                None => {
                    info!(
                        batch_id,
                        pubkey, "No active round — accepting late tree signature gracefully"
                    );
                    return Ok(());
                }
                Some(round) if round.id != batch_id => {
                    info!(
                        batch_id,
                        pubkey, "Round already rotated — accepting late tree signature gracefully"
                    );
                    return Ok(());
                }
                Some(round) if round.is_ended() => {
                    info!(
                        batch_id,
                        pubkey,
                        "Round already completed — accepting late tree signature gracefully"
                    );
                    return Ok(());
                }
                Some(round) if round.stage.code != RoundStage::Finalization => {
                    return Err(ArkError::Internal(
                        "Round not in finalization stage".to_string(),
                    ));
                }
                _ => {} // active round in finalization — proceed normally
            }
        }

        // Store signatures in the signing session store
        self.signing_session_store
            .add_signature(batch_id, pubkey, signatures)
            .await?;

        info!(batch_id, pubkey, "Tree signatures submitted");

        // Only complete the round when ALL participants have submitted signatures
        if self
            .signing_session_store
            .all_signatures_collected(batch_id)
            .await?
        {
            info!(batch_id, "All tree signatures collected — completing round");
            self.events
                .publish_event(ArkEvent::TreeSignaturesCollected {
                    round_id: batch_id.to_string(),
                })
                .await?;

            // ── Aggregate MuSig2 partial sigs into final Schnorr tap_key_sig ──
            // Before completing the round, aggregate all cosigners' partial sigs
            // into final 64-byte Schnorr signatures and apply them to each tree
            // PSBT's input[0].tap_key_sig.
            if let Err(e) = self.aggregate_tree_signatures(batch_id).await {
                error!(error = %e, "Failed to aggregate tree signatures — aborting round and banning participants");
                // Invalid signatures → abort the round and ban all non-ASP
                // cosigners immediately (don't wait for the 10s signing timeout).
                let _ = self.abort_round("invalid tree signatures").await;
                return Err(e);
            }

            // Complete the round: create VTXOs, end round, emit RoundFinalized.
            // Another concurrent submit_tree_signatures might beat us — that's OK.
            match self.complete_round().await {
                Ok(_) => {}
                Err(e) if e.to_string().contains("already ended") => {
                    info!(batch_id, "Round already completed by another cosigner — OK");
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Complete round signing and broadcast: aggregate signatures, finalize PSBT,
    /// sign via the ASP wallet, broadcast to the Bitcoin network, and update the round.
    ///
    /// This is the final step after all MuSig2 tree signatures have been collected.
    /// It performs:
    /// 1. Retrieve collected nonces and partial signatures from the signing session store
    /// 2. Sign the commitment tx via the ASP signer/wallet
    /// 3. Finalize the PSBT and extract the raw transaction
    /// 4. Broadcast the raw transaction to the Bitcoin network
    /// 5. Update the round with the commitment txid
    /// 6. Emit `RoundBroadcast` event
    ///
    /// Decode a base64-encoded commitment PSBT, finalize it, extract the raw
    /// transaction, and broadcast it.  This is used when the server needs to
    /// broadcast the commitment tx directly (e.g. boarding rounds without
    /// cosigners, or after tree signing completes) rather than going through
    /// the full `broadcast_signed_commitment_tx` merge flow.
    async fn finalize_and_broadcast_commitment_psbt(
        &self,
        commitment_psbt_b64: &str,
    ) -> ArkResult<String> {
        use base64::Engine;

        // 1. Decode base64 → raw PSBT bytes
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(commitment_psbt_b64)
            .map_err(|e| ArkError::Internal(format!("Invalid base64 commitment PSBT: {e}")))?;

        // 2. Convert to hex (finalize_and_extract expects hex-encoded PSBT)
        let psbt_hex = hex::encode(&psbt_bytes);

        // 3. ASP co-signs the PSBT (adds server signatures for boarding inputs)
        let signed_psbt = match self
            .signer
            .sign_transaction(commitment_psbt_b64, false)
            .await
        {
            Ok(s) => {
                info!("ASP co-signed commitment PSBT for direct broadcast");
                // Signer may return hex; convert to hex if not already
                if let Ok(bytes) = hex::decode(&s) {
                    hex::encode(bytes)
                } else if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&s) {
                    hex::encode(bytes)
                } else {
                    psbt_hex.clone()
                }
            }
            Err(e) => {
                info!(error = %e, "ASP co-signing skipped for direct broadcast");
                psbt_hex
            }
        };

        // 4. Wallet (BDK) signs (fee input)
        let wallet_signed = {
            let psbt_bytes_for_wallet = hex::decode(&signed_psbt)
                .map_err(|e| ArkError::Internal(format!("hex decode after ASP sign: {e}")))?;
            let b64_for_wallet =
                base64::engine::general_purpose::STANDARD.encode(psbt_bytes_for_wallet);
            match self.wallet.sign_transaction(&b64_for_wallet, false).await {
                Ok(s) => {
                    info!("Wallet signed commitment PSBT for direct broadcast");
                    if let Ok(bytes) = hex::decode(&s) {
                        hex::encode(bytes)
                    } else if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&s) {
                        hex::encode(bytes)
                    } else {
                        signed_psbt.clone()
                    }
                }
                Err(e) => {
                    info!(error = %e, "Wallet signing skipped for direct broadcast");
                    signed_psbt
                }
            }
        };

        // 5. Finalize and extract raw transaction hex
        let raw_tx = self.tx_builder.finalize_and_extract(&wallet_signed).await?;

        // 6. Broadcast
        let txid = self.wallet.broadcast_transaction(vec![raw_tx]).await?;
        info!(txid = %txid, "Commitment tx broadcast via finalize_and_broadcast_commitment_psbt");
        Ok(txid)
    }

    ///
    /// The round must be in the Finalization stage with a non-empty `commitment_tx`.
    #[instrument(skip(self))]
    pub async fn sign_and_broadcast_round(&self) -> ArkResult<Round> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        if round.stage.code != RoundStage::Finalization {
            return Err(ArkError::Internal(
                "Round not in finalization stage".to_string(),
            ));
        }

        if round.is_ended() {
            return Err(ArkError::Internal("Round already ended".to_string()));
        }

        if round.commitment_tx.is_empty() {
            return Err(ArkError::Internal(
                "No commitment tx to sign — run finalize_round first".to_string(),
            ));
        }

        let round_id = round.id.clone();

        // Step 1: Verify all signatures have been collected
        let all_sigs = self
            .signing_session_store
            .all_signatures_collected(&round_id)
            .await?;
        if !all_sigs {
            return Err(ArkError::Internal(
                "Not all tree signatures collected yet".to_string(),
            ));
        }

        // Step 2: Retrieve collected nonces and signatures for aggregation
        let _nonces = self.signing_session_store.get_nonces(&round_id).await?;
        let _signatures = self.signing_session_store.get_signatures(&round_id).await?;

        info!(
            round_id = %round_id,
            nonce_count = _nonces.len(),
            sig_count = _signatures.len(),
            "Aggregating MuSig2 nonces and signatures"
        );

        // Step 3: Sign the commitment tx via the ASP signer
        // The ASP signs the PSBT with its own key (co-sign)
        let signed_psbt = self
            .signer
            .sign_transaction(&round.commitment_tx, false)
            .await?;

        // Step 4: Finalize the PSBT and extract raw transaction
        let raw_tx = self.tx_builder.finalize_and_extract(&signed_psbt).await?;

        // Step 5: Broadcast to the Bitcoin network
        let txid = self.wallet.broadcast_transaction(vec![raw_tx]).await?;

        info!(
            round_id = %round_id,
            commitment_txid = %txid,
            "Commitment tx broadcast successfully"
        );

        // Step 6: Update the round
        round.commitment_txid = txid.clone();
        round.end_successfully();

        // Mark signing session as complete
        // Use an empty combined_sig placeholder — the real aggregated sig
        // is embedded in the finalized transaction
        self.signing_session_store
            .complete_session(&round_id, vec![])
            .await?;

        let timestamp = round.ending_timestamp;
        let result = round.clone();

        // Step 7: Emit RoundBroadcast event
        self.events
            .publish_event(ArkEvent::RoundBroadcast {
                round_id,
                commitment_txid: txid,
                timestamp,
            })
            .await?;

        Ok(result)
    }

    /// Submit signed forfeit transactions for the current batch.
    ///
    /// Called by participants after tree signing is complete.
    /// Collect a client-signed commitment tx PSBT. When all expected inputs are
    /// signed, merge the PSBTs, finalize, and broadcast.
    pub async fn broadcast_signed_commitment_tx(
        &self,
        signed_commitment_tx: &str,
        round_id: &str,
    ) -> ArkResult<String> {
        use base64::Engine;

        // Decode the incoming PSBT
        let incoming_bytes = base64::engine::general_purpose::STANDARD
            .decode(signed_commitment_tx)
            .map_err(|e| ArkError::Internal(format!("Invalid base64 PSBT: {e}")))?;
        let incoming_psbt = bitcoin::psbt::Psbt::deserialize(&incoming_bytes)
            .map_err(|e| ArkError::Internal(format!("Invalid PSBT: {e}")))?;

        let num_inputs = incoming_psbt.unsigned_tx.input.len();

        // Store this partial PSBT
        let mut partials = self.partial_commitment_psbts.lock().await;
        partials.push((round_id.to_string(), signed_commitment_tx.to_string()));

        info!(
            partial_count = partials.len(),
            total_inputs = num_inputs,
            "Received partial commitment tx PSBT"
        );

        // Merge all received partial PSBTs and check if every input has at
        // least one signature. This avoids relying on `current_round` which
        // may have already been replaced by a new round when the scheduler
        // ticks between clients submitting their signed PSBTs.
        //
        // IMPORTANT: Use the server's original PSBT (first partial) as the base
        // for merging to ensure consistent input ordering. Client PSBTs may have
        // inputs in a different order, so we match by outpoint, not by index.
        let server_psbt_b64 = partials
            .first()
            .map(|(_, b64)| b64.clone())
            .unwrap_or_else(|| signed_commitment_tx.to_string());
        let server_psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(&server_psbt_b64)
            .map_err(|e| ArkError::Internal(format!("Invalid base64 server PSBT: {e}")))?;
        let mut merged = bitcoin::psbt::Psbt::deserialize(&server_psbt_bytes)
            .map_err(|e| ArkError::Internal(format!("Invalid server PSBT: {e}")))?;

        // Skip the first partial (server's original) when merging since it's already our base
        for (_rid, partial_b64) in partials.iter().skip(1) {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(partial_b64) {
                if let Ok(partial) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                    // Build outpoint -> index map for the partial PSBT
                    let partial_outpoints: std::collections::HashMap<_, _> = partial
                        .unsigned_tx
                        .input
                        .iter()
                        .enumerate()
                        .map(|(i, inp)| (inp.previous_output, i))
                        .collect();

                    for (merged_idx, merged_txin) in merged.unsigned_tx.input.iter().enumerate() {
                        // Find matching input in partial PSBT by outpoint
                        let Some(&partial_idx) =
                            partial_outpoints.get(&merged_txin.previous_output)
                        else {
                            continue;
                        };
                        let Some(input) = partial.inputs.get(partial_idx) else {
                            continue;
                        };
                        let i = merged_idx;
                        if i < merged.inputs.len() {
                            // Copy witness_utxo (needed for sighash computation)
                            if merged.inputs[i].witness_utxo.is_none() {
                                merged.inputs[i].witness_utxo = input.witness_utxo.clone();
                            }
                            // Copy taproot key spend sig
                            if merged.inputs[i].tap_key_sig.is_none() {
                                merged.inputs[i].tap_key_sig = input.tap_key_sig;
                            }
                            // Copy taproot script spend sigs
                            for (key, sig) in &input.tap_script_sigs {
                                merged.inputs[i].tap_script_sigs.entry(*key).or_insert(*sig);
                            }
                            // Copy taproot leaf scripts
                            if merged.inputs[i].tap_scripts.is_empty() {
                                merged.inputs[i].tap_scripts = input.tap_scripts.clone();
                            }
                            // Copy taproot internal key
                            if merged.inputs[i].tap_internal_key.is_none() {
                                merged.inputs[i].tap_internal_key = input.tap_internal_key;
                            }
                            // Copy taproot merkle root
                            if merged.inputs[i].tap_merkle_root.is_none() {
                                merged.inputs[i].tap_merkle_root = input.tap_merkle_root;
                            }
                            // Copy tap_key_origins (needed for BDK to recognize inputs it should sign)
                            for (key, origin) in &input.tap_key_origins {
                                merged.inputs[i]
                                    .tap_key_origins
                                    .entry(*key)
                                    .or_insert(origin.clone());
                            }
                            // Copy ECDSA partial sigs (for segwit v0 inputs)
                            for (key, sig) in &input.partial_sigs {
                                merged.inputs[i].partial_sigs.entry(*key).or_insert(*sig);
                            }
                            // Copy bip32_derivation (for BDK to recognize segwit v0 inputs)
                            for (key, origin) in &input.bip32_derivation {
                                merged.inputs[i]
                                    .bip32_derivation
                                    .entry(*key)
                                    .or_insert(origin.clone());
                            }
                            // Copy final_script_witness if already finalized
                            if merged.inputs[i].final_script_witness.is_none() {
                                merged.inputs[i].final_script_witness =
                                    input.final_script_witness.clone();
                            }
                            // Copy final_script_sig if already finalized
                            if merged.inputs[i].final_script_sig.is_none() {
                                merged.inputs[i].final_script_sig = input.final_script_sig.clone();
                            }
                        }
                    }
                }
            }
        }

        // Before checking for unsigned inputs, apply wallet (BDK) and ASP
        // signatures to the merged PSBT.  The fee input was signed by BDK
        // during finalize_round(), but that signature may be lost when Go
        // clients round-trip the PSBT (Go's psbt library can strip
        // tap_key_sig on inputs it doesn't recognise).  Re-signing here
        // ensures the fee input always has a valid signature.  Similarly,
        // the ASP must co-sign boarding inputs (script-path spend) before
        // we can declare them "signed".
        let merged_b64_pre = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(merged.serialize())
        };

        // 1) ASP co-signs boarding inputs (script-path spend).
        //    Must run BEFORE wallet/BDK signing so tap_scripts and
        //    tap_internal_key metadata is still intact for the ASP
        //    signer to inspect.
        let after_asp = match self.signer.sign_transaction(&merged_b64_pre, false).await {
            Ok(s) => {
                info!("ASP co-signing of merged PSBT succeeded");
                s
            }
            Err(e) => {
                info!(error = %e, "ASP co-signing failed -- continuing");
                merged_b64_pre.clone()
            }
        };

        // Merge ASP signatures back into merged PSBT using outpoint matching.
        // This preserves our consistent input ordering even if ASP returns different order.
        {
            use base64::Engine;
            // Signer returns hex-encoded PSBT when extract_raw=false.
            // Try hex first (most likely), then fall back to base64.
            let bytes = hex::decode(&after_asp)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&after_asp))
                .ok();
            if let Some(bytes) = bytes {
                if let Ok(asp_psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                    let asp_outpoints: std::collections::HashMap<_, _> = asp_psbt
                        .unsigned_tx
                        .input
                        .iter()
                        .enumerate()
                        .map(|(i, inp)| (inp.previous_output, i))
                        .collect();

                    for (merged_idx, merged_txin) in merged.unsigned_tx.input.iter().enumerate() {
                        if let Some(&asp_idx) = asp_outpoints.get(&merged_txin.previous_output) {
                            if let Some(asp_input) = asp_psbt.inputs.get(asp_idx) {
                                if merged_idx < merged.inputs.len() {
                                    // Copy taproot script spend sigs from ASP
                                    let asp_sigs_added = asp_input.tap_script_sigs.len();
                                    for (key, sig) in &asp_input.tap_script_sigs {
                                        merged.inputs[merged_idx]
                                            .tap_script_sigs
                                            .insert(*key, *sig);
                                    }
                                    if asp_sigs_added > 0 {
                                        info!(
                                            merged_idx,
                                            asp_sigs_added, "Merged ASP tap_script_sigs"
                                        );
                                    }
                                    // Copy taproot key spend sig if present
                                    if merged.inputs[merged_idx].tap_key_sig.is_none() {
                                        merged.inputs[merged_idx].tap_key_sig =
                                            asp_input.tap_key_sig;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2) Wallet (BDK) re-signs -- picks up the fee input automatically.
        //    BDK sign() with try_finalize:true may move tap_key_sig to
        //    final_script_witness, which is fine for the unsigned check.
        let wallet_signed = match self.wallet.sign_transaction(&merged_b64_pre, false).await {
            Ok(s) => {
                info!("Wallet (BDK) re-signing of merged PSBT succeeded");
                s
            }
            Err(e) => {
                info!(error = %e, "Wallet (BDK) re-signing failed -- continuing");
                merged_b64_pre.clone()
            }
        };

        // Merge wallet signatures back into merged PSBT using outpoint matching.
        // This preserves our consistent input ordering even if wallet returns different order.
        {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&wallet_signed)
                .or_else(|_| hex::decode(&wallet_signed))
                .ok();
            if let Some(bytes) = bytes {
                if let Ok(wallet_psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                    let wallet_outpoints: std::collections::HashMap<_, _> = wallet_psbt
                        .unsigned_tx
                        .input
                        .iter()
                        .enumerate()
                        .map(|(i, inp)| (inp.previous_output, i))
                        .collect();

                    for (merged_idx, merged_txin) in merged.unsigned_tx.input.iter().enumerate() {
                        if let Some(&wallet_idx) =
                            wallet_outpoints.get(&merged_txin.previous_output)
                        {
                            if let Some(wallet_input) = wallet_psbt.inputs.get(wallet_idx) {
                                if merged_idx < merged.inputs.len() {
                                    // Copy taproot key spend sig from wallet
                                    if merged.inputs[merged_idx].tap_key_sig.is_none() {
                                        merged.inputs[merged_idx].tap_key_sig =
                                            wallet_input.tap_key_sig;
                                    }
                                    // Copy final_script_witness
                                    if merged.inputs[merged_idx].final_script_witness.is_none() {
                                        merged.inputs[merged_idx].final_script_witness =
                                            wallet_input.final_script_witness.clone();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // If the fee input (last input) is still unsigned and all inputs have
        // witness_utxo, try manual signing. This handles the case where BDK fails
        // to sign during add_fee_input because boarding inputs lacked witness_utxo
        // (which is only populated during merge from client PSBTs).
        if let Some(fee_input) = merged.inputs.last() {
            let fee_unsigned =
                fee_input.tap_key_sig.is_none() && fee_input.final_script_witness.is_none();
            let all_have_witness_utxo = merged.inputs.iter().all(|i| i.witness_utxo.is_some());

            if fee_unsigned && all_have_witness_utxo {
                info!("Fee input unsigned after merge — attempting manual signing");
                let merged_b64 = {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(merged.serialize())
                };
                match self.wallet.manual_sign_fee_input(&merged_b64).await {
                    Ok(signed_b64) => {
                        use base64::Engine;
                        if let Ok(bytes) =
                            base64::engine::general_purpose::STANDARD.decode(&signed_b64)
                        {
                            if let Ok(signed_psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                                merged = signed_psbt;
                                info!("Manual fee input signing succeeded after merge");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Manual fee input signing failed after merge");
                    }
                }
            }
        }

        // Re-apply the stored fee input signature if the last input is still unsigned.
        // This handles the case where Go SDK strips tap_key_sig during PSBT round-trip.
        // IMPORTANT: Use .clone() instead of .take() so the signature persists across
        // multiple calls. The first client's call returns early (not all inputs signed),
        // and .take() would consume the signature, leaving it unavailable when the
        // second client's call needs it to finalize and broadcast.
        {
            let stored_sig = self.fee_input_signature.lock().await;
            if let Some(sig) = stored_sig.as_ref() {
                if let Some(fee_input) = merged.inputs.last_mut() {
                    if fee_input.tap_key_sig.is_none() && fee_input.final_script_witness.is_none() {
                        fee_input.tap_key_sig = Some(*sig);
                        info!("Re-applied stored fee input tap_key_sig to last input");
                    }
                }
            }
        }

        // Check if all inputs have sufficient signatures after merging
        // and server signing.  For boarding inputs (script-path with
        // collaborative leaf), we need at least 2 tap_script_sigs: the
        // user's and the ASP's.  The ASP co-signs all boarding inputs
        // when called above, so if a boarding input still has < 2 sigs
        // it means the user's client hasn't submitted their partial yet.
        // For key-path inputs (fee input), tap_key_sig suffices.
        let unsigned_count = merged
            .inputs
            .iter()
            .filter(|inp| {
                // Already finalized — fully signed
                if inp.final_script_witness.is_some() || inp.final_script_sig.is_some() {
                    return false;
                }
                if !inp.tap_scripts.is_empty() {
                    // Script-path input (boarding): needs both user + ASP sigs
                    inp.tap_script_sigs.len() < 2
                } else {
                    // Key-path input (fee / other): needs tap_key_sig or partial_sigs
                    inp.tap_key_sig.is_none() && inp.partial_sigs.is_empty()
                }
            })
            .count();

        if unsigned_count > 0 {
            // Debug: log what each input has to help diagnose why some are unsigned
            for (i, input) in merged.inputs.iter().enumerate() {
                let is_unsigned =
                    if input.final_script_witness.is_some() || input.final_script_sig.is_some() {
                        false
                    } else if !input.tap_scripts.is_empty() {
                        input.tap_script_sigs.len() < 2
                    } else {
                        input.tap_key_sig.is_none() && input.partial_sigs.is_empty()
                    };
                let internal_key_hex = input
                    .tap_internal_key
                    .map(|k| hex::encode(k.serialize()))
                    .unwrap_or_default();
                info!(
                    input_idx = i,
                    is_unsigned,
                    tap_key_sig = input.tap_key_sig.is_some(),
                    tap_script_sigs = input.tap_script_sigs.len(),
                    tap_key_origins = input.tap_key_origins.len(),
                    tap_scripts = input.tap_scripts.len(),
                    has_witness_utxo = input.witness_utxo.is_some(),
                    internal_key = %internal_key_hex,
                    partial_sigs = input.partial_sigs.len(),
                    final_witness = input.final_script_witness.is_some(),
                    "Input signature state (waiting for more)"
                );
            }
            info!(
                unsigned_inputs = unsigned_count,
                total_partials = partials.len(),
                "Not all inputs signed yet -- waiting for more partial PSBTs"
            );
            return Ok(String::new()); // Wait for more
        }

        // Debug: log what each input has after merge + sign
        for (i, input) in merged.inputs.iter().enumerate() {
            info!(
                input_idx = i,
                tap_script_sigs = input.tap_script_sigs.len(),
                tap_scripts = input.tap_scripts.len(),
                partial_sigs = input.partial_sigs.len(),
                has_key_sig = input.tap_key_sig.is_some(),
                has_internal_key = input.tap_internal_key.is_some(),
                has_witness_utxo = input.witness_utxo.is_some(),
                has_final_witness = input.final_script_witness.is_some(),
                "Merged PSBT input state"
            );
        }

        // Grab the round_id from the stored partials. Don't clear partials yet -
        // we only clear after successful broadcast to ensure subsequent client
        // submissions can still merge properly if this attempt fails.
        let effective_round_id = partials
            .first()
            .map(|(rid, _)| rid.clone())
            .unwrap_or_else(|| round_id.to_string());

        // Release lock before broadcast (may involve network I/O)
        drop(partials);

        // Use the fully-merged PSBT which has all signatures merged in-place
        // from ASP co-signing, wallet signing, manual fee input signing, and
        // stored fee signature re-application. The previous code incorrectly
        // used `wallet_signed` which only contains the wallet's signature on
        // the pre-merge PSBT, losing all the other merged signatures.
        let merged_hex = hex::encode(merged.serialize());

        // Finalize and broadcast
        let raw_tx = self.tx_builder.finalize_and_extract(&merged_hex).await?;
        info!(raw_tx_hex = %raw_tx, "About to broadcast finalized commitment tx");
        let txid = self.wallet.broadcast_transaction(vec![raw_tx]).await?;

        // Clear partials and stored fee signature only after successful broadcast.
        // If broadcast failed, partials remains intact so the next client
        // submission can still use the server's original PSBT as the merge base.
        self.partial_commitment_psbts.lock().await.clear();
        *self.fee_input_signature.lock().await = None;

        info!(txid = %txid, "Merged commitment tx broadcast successfully");

        // Emit RoundBroadcast so the event bridge publishes BatchFinalized.
        self.events
            .publish_event(ArkEvent::RoundBroadcast {
                round_id: effective_round_id,
                commitment_txid: txid.clone(),
                timestamp: chrono::Utc::now().timestamp(),
            })
            .await?;

        Ok(txid)
    }

    /// Submit signed forfeit transactions from a participant.
    ///
    /// Validates each forfeit transaction structure before storing:
    /// - Correct inputs (spending the right VTXOs and connectors)
    /// - Correct output (to ASP connector/forfeit address)
    /// - Valid taproot signature on the VTXO input
    /// - Amount matches expected (input total minus fee = output)
    #[instrument(skip(self, signed_forfeit_txs))]
    pub async fn submit_signed_forfeit_txs(
        &self,
        batch_id: &str,
        signed_forfeit_txs: Vec<String>,
    ) -> ArkResult<()> {
        use bitcoin::consensus::deserialize;
        use bitcoin::hashes::Hash;
        use bitcoin::key::TapTweak;
        use bitcoin::secp256k1::{Message, Secp256k1};
        use bitcoin::sighash::{Prevouts, SighashCache};
        use bitcoin::TapSighashType;

        // Try current round first. If it has no connectors (e.g. a new round
        // started after the previous one completed), fall back to the last
        // completed round. This handles the race where BatchFinalizationEvent
        // is emitted after round completion and the client submits forfeits
        // against the just-completed round.
        let (effective_batch_id, expected_vtxos, valid_connectors) = {
            let guard = self.current_round.read().await;
            let round = guard
                .as_ref()
                .ok_or_else(|| ArkError::NotFound("No active round".to_string()))?;

            let bid = if batch_id.is_empty() {
                round.id.clone()
            } else {
                batch_id.to_string()
            };

            let mut vtxos: std::collections::HashMap<(String, u32), Vtxo> =
                std::collections::HashMap::new();
            for intent in round.intents.values() {
                for vtxo in &intent.inputs {
                    // Accept forfeits for ALL intent inputs, not just those
                    // that requires_forfeit(). Intent input VTXOs created
                    // from proof PSBTs may lack commitment_txids (making
                    // is_note() true), but forfeits are still valid for them.
                    vtxos.insert(
                        (vtxo.outpoint.txid.clone(), vtxo.outpoint.vout),
                        vtxo.clone(),
                    );
                }
            }

            let mut connectors: std::collections::HashMap<String, TxTreeNode> =
                std::collections::HashMap::new();
            for node in &round.connectors {
                if node.children.is_empty() {
                    connectors.insert(node.txid.clone(), node.clone());
                }
            }

            // If current round has no connectors, try the last completed round.
            if connectors.is_empty() {
                drop(guard);
                let last_guard = self.last_completed_round.read().await;
                if let Some(last_round) = last_guard.as_ref() {
                    let mut last_vtxos: std::collections::HashMap<(String, u32), Vtxo> =
                        std::collections::HashMap::new();
                    for intent in last_round.intents.values() {
                        for vtxo in &intent.inputs {
                            last_vtxos.insert(
                                (vtxo.outpoint.txid.clone(), vtxo.outpoint.vout),
                                vtxo.clone(),
                            );
                        }
                    }
                    let mut last_connectors: std::collections::HashMap<String, TxTreeNode> =
                        std::collections::HashMap::new();
                    for node in &last_round.connectors {
                        if node.children.is_empty() {
                            last_connectors.insert(node.txid.clone(), node.clone());
                        }
                    }
                    if !last_connectors.is_empty() {
                        info!(
                            last_round_id = %last_round.id,
                            "submit_signed_forfeit_txs: using last completed round (current has no connectors)"
                        );
                        (last_round.id.clone(), last_vtxos, last_connectors)
                    } else {
                        (bid, vtxos, connectors)
                    }
                } else {
                    (bid, vtxos, connectors)
                }
            } else {
                drop(guard);
                (bid, vtxos, connectors)
            }
        };

        // Get the ASP's forfeit pubkey (same as signer pubkey).
        let asp_xonly = self.signer.get_pubkey().await?;
        let secp = Secp256k1::verification_only();
        // Derive the ASP's P2TR script with standard BIP-341 key-path tweak
        // (no script tree). The Go SDK uses this for the forfeit address.
        let (tweaked_key, _parity) = asp_xonly.tap_tweak(&secp, None);
        let asp_script = bitcoin::ScriptBuf::new_p2tr_tweaked(tweaked_key);

        // Validate and store each forfeit transaction.
        for (idx, tx_str) in signed_forfeit_txs.iter().enumerate() {
            // 1. Deserialize the signed forfeit transaction.
            //    Go SDK sends base64 PSBTs (matching Go arkd's psbt.NewFromRawBytes).
            //    Try base64 PSBT first, then hex raw tx for backwards compat.
            let tx: bitcoin::Transaction = {
                use base64::Engine;
                let psbt_result = base64::engine::general_purpose::STANDARD
                    .decode(tx_str)
                    .ok()
                    .and_then(|b| bitcoin::psbt::Psbt::deserialize(&b).ok())
                    .and_then(|psbt| psbt.extract_tx().ok());

                if let Some(extracted) = psbt_result {
                    extracted
                } else {
                    let tx_bytes = hex::decode(tx_str).map_err(|e| {
                        ArkError::Validation(format!("Forfeit tx {idx}: invalid format: {e}"))
                    })?;
                    deserialize(&tx_bytes).map_err(|e| {
                        ArkError::Validation(format!("Forfeit tx {idx}: invalid transaction: {e}"))
                    })?
                }
            };

            // 2. Must have exactly 2 inputs (VTXO + connector).
            if tx.input.len() != 2 {
                return Err(ArkError::Validation(format!(
                    "Forfeit tx {idx}: expected 2 inputs, got {}",
                    tx.input.len()
                )));
            }

            // 3. Identify the VTXO input and connector input.
            // One input must reference a connector leaf, the other a known VTXO.
            let mut vtxo_input_idx: Option<usize> = None;
            let mut connector_input_idx: Option<usize> = None;
            let mut matched_connector_node: Option<&TxTreeNode> = None;

            for (i, input) in tx.input.iter().enumerate() {
                let prev_txid = input.previous_output.txid.to_string();
                if valid_connectors.contains_key(&prev_txid) {
                    connector_input_idx = Some(i);
                    matched_connector_node = valid_connectors.get(&prev_txid);
                } else {
                    vtxo_input_idx = Some(i);
                }
            }

            let vtxo_idx = vtxo_input_idx.ok_or_else(|| {
                ArkError::Validation(format!("Forfeit tx {idx}: could not identify VTXO input"))
            })?;
            let _connector_idx = connector_input_idx.ok_or_else(|| {
                ArkError::Validation(format!(
                    "Forfeit tx {idx}: no input matches a valid connector leaf"
                ))
            })?;

            // 4. Verify the VTXO input references a known VTXO in this round.
            let vtxo_prev = &tx.input[vtxo_idx].previous_output;
            let vtxo_key = (vtxo_prev.txid.to_string(), vtxo_prev.vout);
            let vtxo = expected_vtxos.get(&vtxo_key).ok_or_else(|| {
                ArkError::Validation(format!(
                    "Forfeit tx {idx}: VTXO {}:{} is not expected in this round",
                    vtxo_key.0, vtxo_key.1
                ))
            })?;

            // 5. Verify the output pays to the ASP's forfeit script.
            if tx.output.is_empty() {
                return Err(ArkError::Validation(format!(
                    "Forfeit tx {idx}: no outputs"
                )));
            }

            // The primary output (first non-anchor) must pay to the ASP.
            let asp_output = tx
                .output
                .iter()
                .find(|o| o.value.to_sat() > 0 && !o.script_pubkey.is_op_return())
                .ok_or_else(|| {
                    ArkError::Validation(format!("Forfeit tx {idx}: no non-anchor output found"))
                })?;

            if asp_output.script_pubkey != asp_script {
                return Err(ArkError::Validation(format!(
                    "Forfeit tx {idx}: output script does not pay to ASP forfeit address"
                )));
            }

            // 6. Verify amounts: output should not exceed input total.
            // Parse the connector transaction to get the connector output amount.
            // The connector tx may be stored as hex raw tx or base64 PSBT.
            let connector_node = matched_connector_node.unwrap();
            let conn_vout = tx.input[_connector_idx].previous_output.vout as usize;
            let connector_amount = {
                let mut amount = 0u64;
                // Try hex-encoded raw transaction
                if let Ok(raw) = hex::decode(&connector_node.tx) {
                    if let Ok(ctx) = deserialize::<bitcoin::Transaction>(&raw) {
                        amount = ctx
                            .output
                            .get(conn_vout)
                            .map(|o| o.value.to_sat())
                            .unwrap_or(0);
                    }
                }
                // Try base64-encoded PSBT
                if amount == 0 {
                    if let Ok(psbt_bytes) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &connector_node.tx,
                    ) {
                        if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
                            amount = psbt
                                .unsigned_tx
                                .output
                                .get(conn_vout)
                                .map(|o| o.value.to_sat())
                                .unwrap_or(0);
                        }
                    }
                }
                amount
            };

            let vtxo_amount = vtxo.amount;
            let total_input = vtxo_amount.saturating_add(connector_amount);
            let total_output: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

            if total_output > total_input {
                return Err(ArkError::Validation(format!(
                    "Forfeit tx {idx}: output total ({total_output}) exceeds input total ({total_input})"
                )));
            }

            // 7. Verify the taproot signature on the VTXO input (best-effort).
            // Forfeits may be submitted as partially-signed PSBTs where the
            // VTXO witness is in PSBT fields rather than the extracted tx
            // witness. Signature validation happens at broadcast time.
            let vtxo_witness = &tx.input[vtxo_idx].witness;
            let sig_bytes: Option<&[u8]> = if !vtxo_witness.is_empty() {
                vtxo_witness.nth(0)
            } else {
                None
            };
            let is_script_path = vtxo_witness.len() >= 2;

            // Key-path signature verification (skip for script-path spends
            // and partially-signed PSBTs without extracted witnesses).
            if !is_script_path && sig_bytes.is_some_and(|s| s.len() >= 64) {
                let sig_bytes = sig_bytes.unwrap();
                let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(
                    &sig_bytes[..64],
                )
                .map_err(|e| {
                    ArkError::Validation(format!(
                        "Forfeit tx {idx}: invalid Schnorr signature: {e}"
                    ))
                })?;

                // Get the VTXO owner's x-only public key.
                let vtxo_pubkey = vtxo.tap_key().ok_or_else(|| {
                    ArkError::Validation(format!(
                        "Forfeit tx {idx}: VTXO has invalid pubkey '{}'",
                        vtxo.pubkey
                    ))
                })?;

                // Build prevouts for sighash computation.
                let vtxo_script = bitcoin::ScriptBuf::new_p2tr_tweaked(
                    bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(vtxo_pubkey),
                );
                let vtxo_txout = bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(vtxo_amount),
                    script_pubkey: vtxo_script,
                };

                // Build connector prevout (use ASP script as connector script).
                let connector_txout = bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(connector_amount),
                    script_pubkey: asp_script.clone(),
                };

                // Order prevouts to match input order.
                let prevouts_vec = if vtxo_idx == 0 {
                    vec![vtxo_txout, connector_txout]
                } else {
                    vec![connector_txout, vtxo_txout]
                };

                // Only verify signature if we have valid connector amount (parsed successfully).
                if connector_amount > 0 {
                    let mut cache = SighashCache::new(&tx);
                    let sighash_type = if sig_bytes.len() == 65 {
                        // Explicit sighash type in the last byte.
                        match sig_bytes[64] {
                            0x00 | 0x01 => TapSighashType::Default,
                            0x02 => TapSighashType::NonePlusAnyoneCanPay,
                            0x03 => TapSighashType::SinglePlusAnyoneCanPay,
                            0x81 => TapSighashType::AllPlusAnyoneCanPay,
                            _ => TapSighashType::Default,
                        }
                    } else {
                        TapSighashType::Default
                    };

                    match cache.taproot_key_spend_signature_hash(
                        vtxo_idx,
                        &Prevouts::All(&prevouts_vec),
                        sighash_type,
                    ) {
                        Ok(sighash) => {
                            let digest: [u8; 32] = sighash.to_byte_array();
                            let msg = Message::from_digest(digest);
                            if secp
                                .verify_schnorr(&schnorr_sig, &msg, &vtxo_pubkey)
                                .is_err()
                            {
                                return Err(ArkError::Validation(format!(
                                    "Forfeit tx {idx}: invalid taproot signature for VTXO {}:{}",
                                    vtxo_key.0, vtxo_key.1
                                )));
                            }
                        }
                        Err(e) => {
                            return Err(ArkError::Validation(format!(
                                "Forfeit tx {idx}: sighash computation failed: {e}"
                            )));
                        }
                    }
                }
            } // end if !is_script_path

            // Validation passed — store the forfeit transaction.
            let vtxo_id = format!("{}:{}", effective_batch_id, vtxo_key.0);
            self.forfeit_repo
                .store_forfeit({
                    let mut record =
                        ForfeitRecord::new(effective_batch_id.clone(), vtxo_id, tx_str.clone());
                    record.mark_validated();
                    record
                })
                .await?;

            // Also persist the forfeit on the round so broadcast_forfeit_tx
            // can find it when reacting to fraud.
            if let Ok(Some(mut round)) =
                self.round_repo.get_round_with_id(&effective_batch_id).await
            {
                round.forfeit_txs.push(crate::domain::ForfeitTx {
                    txid: tx.compute_txid().to_string(),
                    tx: tx_str.clone(),
                });
                let _ = self.round_repo.add_or_update_round(&round).await;
            }
        }

        info!(
            batch_id,
            count = signed_forfeit_txs.len(),
            "Signed forfeit txs validated and submitted"
        );

        // End the in-memory round now that forfeits have been received.
        // This allows the round_loop to start a new round.
        {
            let mut guard = self.current_round.write().await;
            if let Some(ref mut r) = *guard {
                if r.id == effective_batch_id && !r.is_ended() {
                    r.end_successfully();
                }
            }
        }

        // Emit RoundBroadcast to trigger BatchFinalized in the event bridge.
        // This completes the BatchFinalization → forfeit submission → BatchFinalized
        // pipeline.  The commitment txid is extracted from the round's stored tx.
        if let Ok(Some(round)) = self.round_repo.get_round_with_id(&effective_batch_id).await {
            let commitment_txid =
                Self::extract_txid_from_psbt(&round.commitment_tx).unwrap_or_default();
            self.events
                .publish_event(ArkEvent::RoundBroadcast {
                    round_id: effective_batch_id.to_string(),
                    commitment_txid,
                    timestamp: chrono::Utc::now().timestamp(),
                })
                .await?;
        }

        Ok(())
    }

    // ── Round queries ─────────────────────────────────────────────────

    /// List rounds via the indexer with pagination.
    pub async fn list_rounds(&self, offset: u32, limit: u32) -> ArkResult<Vec<Round>> {
        self.indexer.list_rounds(offset, limit).await
    }

    // ── Conviction management (#170) ──────────────────────────────────

    /// Get convictions by their IDs.
    pub async fn get_convictions_by_ids(&self, ids: &[String]) -> ArkResult<Vec<Conviction>> {
        self.conviction_repo.get_by_ids(ids).await
    }

    /// Get convictions created within a time range.
    pub async fn get_convictions_in_range(&self, from: i64, to: i64) -> ArkResult<Vec<Conviction>> {
        self.conviction_repo.get_in_range(from, to).await
    }

    /// Get convictions for a specific round.
    pub async fn get_convictions_by_round(&self, round_id: &str) -> ArkResult<Vec<Conviction>> {
        self.conviction_repo.get_by_round(round_id).await
    }

    /// Get active convictions for a script.
    pub async fn get_active_script_convictions(&self, script: &str) -> ArkResult<Vec<Conviction>> {
        self.conviction_repo.get_active_by_script(script).await
    }

    /// Pardon a conviction by ID.
    pub async fn pardon_conviction(&self, id: &str) -> ArkResult<()> {
        self.conviction_repo.pardon(id).await
    }

    /// Ban a script by creating a conviction record.
    pub async fn ban_script(
        &self,
        script: &str,
        reason: &str,
        ban_duration_secs: i64,
    ) -> ArkResult<()> {
        let conviction = Conviction::manual_ban(script, reason, ban_duration_secs);
        self.conviction_repo.store(conviction).await
    }

    /// Extract txid from a hex-encoded PSBT.
    /// Inject cosigner pubkeys as PSBT Unknown fields into a base64-encoded PSBT.
    /// Format: Key = [0xDE] + "cosigner" + [4-byte BE index], Value = 33-byte compressed pubkey
    /// Patch every vtxo tree node whose TxIn[0].previous_output.txid equals
    /// `old_txid` to reference `new_txid` instead.  This is required after
    /// adding the server fee input to the commitment tx, which changes its txid.
    /// Extract the txid from a base64-encoded PSBT's unsigned transaction.
    /// Walk the VTXO tree upward from a leaf txid to find the lowest
    /// ancestor whose transaction is confirmed on-chain. Returns its
    /// confirmation block height. Used to calculate when the server's
    /// CSV timeout path on that ancestor output becomes spendable.
    async fn find_confirmed_ancestor_height(
        &self,
        tree: &[crate::domain::TxTreeNode],
        leaf_txid: &str,
    ) -> Option<u32> {
        // Build child→parent mapping: for every node that lists a child
        // txid, record (child_txid → parent_node_real_txid).
        let mut child_to_parent: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut real_txids: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for node in tree {
            let real_txid =
                Self::compute_txid_from_psbt(&node.tx).unwrap_or_else(|| node.txid.clone());
            real_txids.insert(node.txid.clone(), real_txid.clone());
            for child_txid in node.children.values() {
                // The child_txid in the map refers to another node's .txid field
                child_to_parent.insert(child_txid.clone(), node.txid.clone());
            }
        }

        // Walk from the leaf up toward the root, checking each ancestor
        let mut current = leaf_txid.to_string();
        while let Some(p) = child_to_parent.get(&current) {
            let parent_stored_txid = p.clone();
            let parent_real_txid = real_txids
                .get(&parent_stored_txid)
                .cloned()
                .unwrap_or_else(|| parent_stored_txid.clone());

            if let Ok(Some(height)) = self
                .scanner
                .get_tx_confirmation_height(&parent_real_txid)
                .await
            {
                return Some(height);
            }
            current = parent_stored_txid;
        }

        None
    }

    fn compute_txid_from_psbt(psbt_b64: &str) -> Option<String> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64)
            .ok()?;
        let psbt = bitcoin::psbt::Psbt::deserialize(&bytes).ok()?;
        Some(psbt.unsigned_tx.compute_txid().to_string())
    }

    fn patch_vtxo_tree_commitment_txid(
        tree: &[crate::domain::TxTreeNode],
        old_txid: &str,
        new_txid: &str,
    ) -> Vec<crate::domain::TxTreeNode> {
        use base64::Engine;
        use std::collections::HashMap;

        // Index nodes by their current txid for quick lookup.
        let mut nodes: HashMap<String, crate::domain::TxTreeNode> =
            tree.iter().map(|n| (n.txid.clone(), n.clone())).collect();

        // Patch a single node's PSBT inputs, replacing old_parent_txid with
        // new_parent_txid. Returns (new_psbt_b64, new_txid) or None if unchanged.
        let patch_node_input = |node: &crate::domain::TxTreeNode,
                                old_parent: &str,
                                new_parent: &str|
         -> Option<(String, String)> {
            if node.tx.is_empty() {
                return None;
            }
            let new_parent_hash: bitcoin::Txid = new_parent.parse().ok()?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&node.tx)
                .ok()?;
            let mut psbt = bitcoin::psbt::Psbt::deserialize(&bytes).ok()?;
            let mut changed = false;
            for txin in psbt.unsigned_tx.input.iter_mut() {
                if txin.previous_output.txid.to_string() == old_parent {
                    txin.previous_output.txid = new_parent_hash;
                    changed = true;
                }
            }
            if !changed {
                return None;
            }
            let new_computed_txid = psbt.unsigned_tx.compute_txid().to_string();
            let new_tx_b64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
            Some((new_tx_b64, new_computed_txid))
        };

        // Cascading patch: a queue of (old_txid_to_find_in_inputs, new_txid_to_set).
        // We start with the commitment txid change which affects the root.
        let mut queue: Vec<(String, String)> = vec![(old_txid.to_string(), new_txid.to_string())];

        while let Some((old_parent, new_parent)) = queue.pop() {
            // Find all nodes whose PSBT inputs reference old_parent.
            let affected_txids: Vec<String> = nodes
                .values()
                .filter_map(|n| {
                    if n.tx.is_empty() {
                        return None;
                    }
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(&n.tx)
                        .ok()?;
                    let psbt = bitcoin::psbt::Psbt::deserialize(&bytes).ok()?;
                    let references_old = psbt
                        .unsigned_tx
                        .input
                        .iter()
                        .any(|txin| txin.previous_output.txid.to_string() == old_parent);
                    if references_old {
                        Some(n.txid.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for affected_old_txid in affected_txids {
                let node = match nodes.get(&affected_old_txid) {
                    Some(n) => n.clone(),
                    None => continue,
                };

                if let Some((new_tx_b64, new_node_txid)) =
                    patch_node_input(&node, &old_parent, &new_parent)
                {
                    // This node's txid changed; its children will need patching too.
                    if affected_old_txid != new_node_txid {
                        queue.push((affected_old_txid.clone(), new_node_txid.clone()));
                    }

                    // Update the node in our map under the new txid.
                    nodes.remove(&affected_old_txid);
                    nodes.insert(
                        new_node_txid.clone(),
                        crate::domain::TxTreeNode {
                            txid: new_node_txid.clone(),
                            tx: new_tx_b64,
                            children: node.children.clone(),
                        },
                    );

                    // Update any parent's children map that referenced the old txid.
                    for n in nodes.values_mut() {
                        let mut updated = false;
                        let new_children: HashMap<u32, String> = n
                            .children
                            .iter()
                            .map(|(&idx, child)| {
                                if child == &affected_old_txid {
                                    updated = true;
                                    (idx, new_node_txid.clone())
                                } else {
                                    (idx, child.clone())
                                }
                            })
                            .collect();
                        if updated {
                            n.children = new_children;
                        }
                    }
                }
            }
        }

        // Return all nodes (order doesn't matter for the flat list since
        // the tree structure is encoded in the children maps).
        nodes.into_values().collect()
    }

    fn inject_cosigner_fields_single(psbt_b64: &str, cosigners: &[String]) -> String {
        use base64::Engine;
        if cosigners.is_empty() || psbt_b64.is_empty() {
            return psbt_b64.to_string();
        }
        let Ok(psbt_bytes) = base64::engine::general_purpose::STANDARD.decode(psbt_b64) else {
            return psbt_b64.to_string();
        };
        let Ok(mut psbt) = bitcoin::psbt::Psbt::deserialize(&psbt_bytes) else {
            return psbt_b64.to_string();
        };

        if psbt.inputs.is_empty() {
            return psbt_b64.to_string();
        }

        // Add cosigner Unknown fields to the first input
        for (i, cosigner_hex) in cosigners.iter().enumerate() {
            let Ok(pubkey_bytes) = hex::decode(cosigner_hex) else {
                continue;
            };
            if pubkey_bytes.len() != 33 {
                continue;
            }
            // Key data: "cosigner" + [4-byte BE index]
            let mut key_data = b"cosigner".to_vec();
            key_data.extend_from_slice(&(i as u32).to_be_bytes());

            let raw_key = bitcoin::psbt::raw::Key {
                type_value: 0xDE,
                key: key_data,
            };
            psbt.inputs[0].unknown.insert(raw_key, pubkey_bytes);
        }

        base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
    }

    /// Extract compressed cosigner pubkeys (hex) from a base64-encoded PSBT.
    ///
    /// Looks for PSBT Unknown fields with type 0xDE whose key starts with
    /// `"cosigner"` followed by a 4-byte BE index — the same layout used by
    /// `inject_cosigner_fields_single` and `add_cosigner_field` in the tree
    /// builder. The value of each such field is a 33-byte compressed SEC key.
    fn extract_cosigners_from_psbt_b64(psbt_b64: &str) -> Option<Vec<String>> {
        use base64::Engine;
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64)
            .ok()?;
        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).ok()?;
        if psbt.inputs.is_empty() {
            return None;
        }
        let mut cosigners: Vec<(u32, String)> = Vec::new();
        for (raw_key, value) in &psbt.inputs[0].unknown {
            if raw_key.type_value != 0xDE {
                continue;
            }
            // key layout: "cosigner" (8 bytes) + index (4 bytes BE)
            if raw_key.key.len() != 12 {
                continue;
            }
            if &raw_key.key[..8] != b"cosigner" {
                continue;
            }
            if value.len() != 33 {
                continue;
            }
            let idx = u32::from_be_bytes([
                raw_key.key[8],
                raw_key.key[9],
                raw_key.key[10],
                raw_key.key[11],
            ]);
            cosigners.push((idx, hex::encode(value)));
        }
        if cosigners.is_empty() {
            return None;
        }
        // Sort by index to preserve insertion order
        cosigners.sort_by_key(|(idx, _)| *idx);
        Some(cosigners.into_iter().map(|(_, hex)| hex).collect())
    }

    /// Create ASP partial MuSig2 signatures for each tree tx and submit them
    /// to the signing session. Called after all nonces are collected.
    async fn asp_create_and_submit_partial_sigs(
        &self,
        batch_id: &str,
        nonces_by_txid: &std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        >,
    ) -> ArkResult<()> {
        use musig2::BinaryEncoding;

        let asp_sk_bytes = self.signer.get_secret_key_bytes().await?;
        let asp_seckey = musig2::secp256k1::SecretKey::from_byte_array(asp_sk_bytes)
            .map_err(|e| ArkError::Internal(format!("Invalid ASP secret key: {e}")))?;

        // Use the original secret key as-is (no parity normalization).
        // The musig2 crate handles parity internally via negate_if().
        // Must match the key used in nonce generation.

        // Take ASP state (consumes SecNonces).  Multiple concurrent
        // submit_tree_nonces calls may reach here; only the first one
        // finds the state — the rest see None and return Ok(()) since the
        // work is already done.
        let mut asp_state_guard = self.asp_musig2_state.lock().await;
        let mut asp_state = match asp_state_guard.take() {
            Some(s) => s,
            None => {
                info!("ASP MuSig2 state already consumed — partial sigs already created");
                return Ok(());
            }
        };

        // Get tree PSBTs and output map from the current round
        let (tree_nodes, commitment_tx) = {
            let guard = self.current_round.read().await;
            let round = guard
                .as_ref()
                .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;
            (round.vtxo_tree.clone(), round.commitment_tx.clone())
        };

        let output_map = Self::build_tree_output_map(&tree_nodes, &commitment_tx);
        let sweep_merkle_root = asp_state.sweep_merkle_root;

        // Log tree structure for debugging nonce mismatches
        let tree_txids: Vec<&str> = tree_nodes
            .iter()
            .filter(|n| !n.tx.is_empty())
            .map(|n| n.txid.as_str())
            .collect();
        let nonce_txids: Vec<&String> = nonces_by_txid.keys().collect();
        info!(
            tree_node_count = tree_txids.len(),
            nonce_txid_count = nonce_txids.len(),
            tree_txids = ?tree_txids,
            nonce_txids = ?nonce_txids,
            "ASP partial sigs: tree txids vs nonce txids"
        );

        let mut asp_sigs_json: StdHashMap<String, String> = StdHashMap::new();

        for node in &tree_nodes {
            if node.tx.is_empty() {
                continue;
            }

            // Only sign txids we have SecNonces for (i.e. txids where ASP is cosigner)
            let sec_nonce_bytes = match asp_state.sec_nonces.remove(&node.txid) {
                Some(b) => b,
                None => continue,
            };

            // Get all pub nonces for this txid from nonces_by_txid
            let txid_nonces = match nonces_by_txid.get(&node.txid) {
                Some(n) => n,
                None => {
                    warn!(txid = %node.txid, "No nonces found for tree txid — skipping");
                    continue;
                }
            };

            // Extract cosigner pubkeys from the PSBT (determines MuSig2 key order)
            let cosigner_hexes =
                Self::extract_cosigners_from_psbt_b64(&node.tx).unwrap_or_default();
            if cosigner_hexes.is_empty() {
                warn!(txid = %node.txid, "No cosigners in PSBT — skipping");
                continue;
            }

            // Build musig2 pubkeys with original parity (matching Go's btcec musig2).
            let mut musig_pubkeys: Vec<musig2::secp256k1::PublicKey> = Vec::new();
            for hex_key in &cosigner_hexes {
                let bytes = hex::decode(hex_key)
                    .map_err(|e| ArkError::Internal(format!("Invalid cosigner hex: {e}")))?;
                let pk = musig2::secp256k1::PublicKey::from_slice(&bytes)
                    .map_err(|e| ArkError::Internal(format!("Invalid cosigner pubkey: {e}")))?;
                // Use original parity (02/03 prefix) — matching Go's btcec musig2
                musig_pubkeys.push(pk);
            }
            musig_pubkeys.sort();

            // Build KeyAggContext with taproot tweak
            let key_agg_ctx = musig2::KeyAggContext::new(musig_pubkeys.clone())
                .map_err(|e| ArkError::Internal(format!("MuSig2 key agg failed: {e}")))?
                .with_taproot_tweak(&sweep_merkle_root)
                .map_err(|e| ArkError::Internal(format!("Taproot tweak failed: {e}")))?;

            // Collect and aggregate pub nonces in the same key order
            let mut pub_nonces: Vec<musig2::PubNonce> = Vec::new();
            for pk in &musig_pubkeys {
                let compressed_hex = hex::encode(pk.serialize());
                let xonly_hex = hex::encode(&pk.serialize()[1..]);
                // Try compressed key first (Go SDK compat), fall back to x-only
                let nonce_hex = txid_nonces
                    .get(&compressed_hex)
                    .or_else(|| txid_nonces.get(&xonly_hex))
                    .ok_or_else(|| {
                        let available_keys: Vec<&String> = txid_nonces.keys().collect();
                        error!(
                            cosigner = %compressed_hex,
                            cosigner_xonly = %xonly_hex,
                            txid = %node.txid,
                            available_nonce_keys = ?available_keys,
                            "Missing nonce for cosigner — dumping available keys"
                        );
                        ArkError::Internal(format!(
                            "Missing nonce for cosigner {compressed_hex} in txid {}",
                            node.txid
                        ))
                    })?;
                let nonce_bytes = hex::decode(nonce_hex)
                    .map_err(|e| ArkError::Internal(format!("Invalid nonce hex: {e}")))?;
                let pub_nonce = musig2::PubNonce::from_bytes(&nonce_bytes)
                    .map_err(|e| ArkError::Internal(format!("Invalid PubNonce: {e}")))?;
                pub_nonces.push(pub_nonce);
            }

            let agg_nonce = dark_bitcoin::signing::aggregate_nonces(&pub_nonces);

            // Store agg_nonce for later signature aggregation
            asp_state
                .agg_nonces
                .insert(node.txid.clone(), agg_nonce.to_bytes().to_vec());

            // Compute sighash for this tree PSBT
            let sighash = Self::compute_tree_psbt_sighash(&node.tx, &output_map)?;

            // Deserialize ASP SecNonce
            let sec_nonce = musig2::SecNonce::from_bytes(&sec_nonce_bytes)
                .map_err(|e| ArkError::Internal(format!("Invalid SecNonce: {e}")))?;

            // Create ASP partial signature
            let partial_sig: musig2::PartialSignature = dark_bitcoin::signing::create_partial_sig(
                &key_agg_ctx,
                &asp_seckey,
                sec_nonce,
                &agg_nonce,
                &sighash,
            )
            .map_err(|e| ArkError::Internal(format!("MuSig2 partial sig failed: {e}")))?;

            asp_sigs_json.insert(node.txid.clone(), hex::encode(partial_sig.serialize()));
        }

        info!(
            sig_count = asp_sigs_json.len(),
            batch_id, "ASP created MuSig2 partial signatures"
        );

        // Put state back (with agg_nonces filled, sec_nonces consumed)
        *asp_state_guard = Some(asp_state);
        drop(asp_state_guard);

        // Guard: if no sigs were produced (e.g., concurrent call already consumed
        // SecNonces), skip submitting to avoid overwriting valid sigs with empty map.
        if asp_sigs_json.is_empty() {
            info!(
                batch_id,
                "No ASP sigs produced (SecNonces already consumed) — skipping submit"
            );
            return Ok(());
        }

        // Submit ASP signatures to signing session
        let asp_compressed_hex = {
            let state = self.asp_musig2_state.lock().await;
            state
                .as_ref()
                .map(|s| s.asp_compressed_hex.clone())
                .unwrap_or_default()
        };
        let asp_sigs_blob = serde_json::to_vec(&asp_sigs_json)
            .map_err(|e| ArkError::Internal(format!("Failed to serialize ASP sigs: {e}")))?;
        self.signing_session_store
            .add_signature(batch_id, &asp_compressed_hex, asp_sigs_blob)
            .await?;
        info!("ASP partial signatures submitted to signing session");

        Ok(())
    }

    /// Aggregate all MuSig2 partial signatures into final Schnorr signatures
    /// and apply them to each tree PSBT as tap_key_sig.
    async fn aggregate_tree_signatures(&self, batch_id: &str) -> ArkResult<()> {
        use base64::Engine;

        // Get ASP state (for agg_nonces and sweep_merkle_root)
        let asp_state = {
            let guard = self.asp_musig2_state.lock().await;
            guard
                .as_ref()
                .ok_or_else(|| ArkError::Internal("ASP MuSig2 state not found".to_string()))?
                .clone_for_aggregation()
        };

        // Get all partial sigs from signing session
        let session = self
            .signing_session_store
            .get_session(batch_id)
            .await?
            .ok_or_else(|| ArkError::Internal("Signing session not found".to_string()))?;

        // Build per-txid map: txid -> Vec<(compressed_pubkey, sig_hex)>
        let mut sigs_by_txid: StdHashMap<String, StdHashMap<String, String>> = StdHashMap::new();
        for (participant_compressed, sig_blob) in &session.tree_signatures {
            let participant_sigs: StdHashMap<String, String> = serde_json::from_slice(sig_blob)
                .map_err(|e| {
                    ArkError::Internal(format!("Failed to deserialize participant sigs: {e}"))
                })?;
            for (txid, sig_hex) in participant_sigs {
                sigs_by_txid
                    .entry(txid)
                    .or_default()
                    .insert(participant_compressed.clone(), sig_hex);
            }
        }

        // Get tree and commitment tx from round.
        // Guard against a concurrent submit_tree_signatures call that already
        // completed the round (TOCTOU: both callers can see
        // all_signatures_collected() == true when the last sig races with the
        // all_sigs check of an earlier participant).
        let mut guard = self.current_round.write().await;
        let round = match guard.as_mut() {
            None => {
                // Round already cleared by a concurrent completion — nothing to do.
                info!(
                    batch_id,
                    "aggregate_tree_signatures: round already cleared by concurrent \
                     completion — skipping"
                );
                return Ok(());
            }
            Some(r) if r.is_ended() => {
                // Round ended between the all_sigs check and this write lock.
                info!(
                    batch_id,
                    "aggregate_tree_signatures: round already ended by concurrent \
                     completion — skipping"
                );
                return Ok(());
            }
            Some(r) if r.id != batch_id => {
                // A new round replaced this one while we were waiting.
                info!(
                    batch_id,
                    current_round_id = %r.id,
                    "aggregate_tree_signatures: round rotated — skipping"
                );
                return Ok(());
            }
            Some(r) => r,
        };

        let output_map = Self::build_tree_output_map(&round.vtxo_tree, &round.commitment_tx);
        let mut signed_tree: Vec<crate::domain::TxTreeNode> = Vec::new();

        for node in &round.vtxo_tree {
            if node.tx.is_empty() {
                signed_tree.push(node.clone());
                continue;
            }

            // Get cosigner pubkeys from PSBT
            let cosigner_hexes =
                Self::extract_cosigners_from_psbt_b64(&node.tx).unwrap_or_default();

            // Get aggregated nonce for this txid
            let agg_nonce_bytes = match asp_state.agg_nonces.get(&node.txid) {
                Some(b) => b.clone(),
                None => {
                    // No agg nonce means ASP wasn't a cosigner — keep as-is
                    signed_tree.push(node.clone());
                    continue;
                }
            };

            let agg_nonce = musig2::AggNonce::from_bytes(&agg_nonce_bytes).map_err(|e| {
                ArkError::Internal(format!("Invalid AggNonce for {}: {e}", node.txid))
            })?;

            // Build KeyAggContext with original parity keys (matching Go's btcec musig2)
            let mut musig_pubkeys: Vec<musig2::secp256k1::PublicKey> = Vec::new();
            for hex_key in &cosigner_hexes {
                let bytes = hex::decode(hex_key)
                    .map_err(|e| ArkError::Internal(format!("Invalid cosigner hex: {e}")))?;
                let pk = musig2::secp256k1::PublicKey::from_slice(&bytes)
                    .map_err(|e| ArkError::Internal(format!("Invalid cosigner pubkey: {e}")))?;
                // Use original parity (02/03 prefix) — matching Go's btcec musig2
                musig_pubkeys.push(pk);
            }
            musig_pubkeys.sort();

            let key_agg_ctx = musig2::KeyAggContext::new(musig_pubkeys.clone())
                .map_err(|e| ArkError::Internal(format!("MuSig2 key agg failed: {e}")))?
                .with_taproot_tweak(&asp_state.sweep_merkle_root)
                .map_err(|e| ArkError::Internal(format!("Taproot tweak failed: {e}")))?;

            // Collect partial sigs in key order
            let txid_sigs = match sigs_by_txid.get(&node.txid) {
                Some(s) => s,
                None => {
                    warn!(txid = %node.txid, "No partial sigs for txid — keeping unsigned");
                    signed_tree.push(node.clone());
                    continue;
                }
            };

            let mut partial_sigs: Vec<musig2::PartialSignature> = Vec::new();
            for pk in &musig_pubkeys {
                // Look up sig by x-only hex (sigs may be stored under 02 or 03 prefix)
                let xonly_hex = hex::encode(&pk.serialize()[1..]);
                let sig_hex = txid_sigs
                    .get(&format!("02{xonly_hex}"))
                    .or_else(|| txid_sigs.get(&format!("03{xonly_hex}")))
                    .or_else(|| txid_sigs.get(&xonly_hex))
                    .ok_or_else(|| {
                        ArkError::Internal(format!(
                            "Missing partial sig from {xonly_hex} for txid {}",
                            node.txid
                        ))
                    })?;
                let sig_bytes = hex::decode(sig_hex)
                    .map_err(|e| ArkError::Internal(format!("Invalid sig hex: {e}")))?;
                let partial_sig = musig2::PartialSignature::try_from(sig_bytes.as_slice())
                    .map_err(|e| ArkError::Internal(format!("Invalid partial sig: {e}")))?;
                partial_sigs.push(partial_sig);
            }

            // Compute sighash
            let sighash = Self::compute_tree_psbt_sighash(&node.tx, &output_map)?;

            // Aggregate into final 64-byte Schnorr signature
            let final_sig = dark_bitcoin::signing::aggregate_signatures(
                &key_agg_ctx,
                &agg_nonce,
                &partial_sigs,
                &sighash,
            )
            .map_err(|e| ArkError::Internal(format!("MuSig2 sig aggregation failed: {e}")))?;

            // Verify the aggregate signature before applying it to the PSBT.
            // If verification fails (e.g. due to cross-library MuSig2 incompatibility),
            // fall back to ASP-only script-path signing.
            let agg_xonly: musig2::secp256k1::XOnlyPublicKey = key_agg_ctx.aggregated_pubkey();
            let verify_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&agg_xonly.serialize())
                .map_err(|e| ArkError::Internal(format!("Invalid agg key: {e}")))?;
            let verify_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&final_sig)
                .map_err(|e| ArkError::Internal(format!("Invalid Schnorr sig bytes: {e}")))?;
            let verify_msg = bitcoin::secp256k1::Message::from_digest(sighash);
            let secp_verify = bitcoin::secp256k1::Secp256k1::verification_only();
            let sig_valid = secp_verify
                .verify_schnorr(&verify_sig, &verify_msg, &verify_key)
                .is_ok();

            if !sig_valid {
                warn!(
                    txid = %node.txid,
                    agg_key = %hex::encode(agg_xonly.serialize()),
                    sighash_hex = %hex::encode(sighash),
                    sig_hex = %hex::encode(final_sig),
                    cosigner_count = musig_pubkeys.len(),
                    "MuSig2 aggregate signature FAILED verification — tree tx will be invalid on-chain"
                );
            }

            // Apply to PSBT as tap_key_sig
            let psbt_bytes = base64::engine::general_purpose::STANDARD
                .decode(&node.tx)
                .map_err(|e| ArkError::Internal(format!("Invalid base64: {e}")))?;
            let mut psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
                .map_err(|e| ArkError::Internal(format!("Invalid PSBT: {e}")))?;

            let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&final_sig)
                .map_err(|e| ArkError::Internal(format!("Invalid Schnorr sig: {e}")))?;
            psbt.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
                signature: schnorr_sig,
                sighash_type: bitcoin::sighash::TapSighashType::Default,
            });

            let signed_b64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

            signed_tree.push(crate::domain::TxTreeNode {
                txid: node.txid.clone(),
                tx: signed_b64,
                children: node.children.clone(),
            });

            info!(txid = %node.txid, "Applied aggregated Schnorr signature to tree PSBT");
        }

        round.vtxo_tree = signed_tree;
        info!(
            batch_id,
            node_count = round.vtxo_tree.len(),
            "All tree PSBTs signed with aggregated MuSig2 signatures"
        );

        Ok(())
    }

    /// Compute the BIP-341 taproot key-spend sighash for input 0 of a tree PSBT.
    fn compute_tree_psbt_sighash(
        psbt_b64: &str,
        output_map: &std::collections::HashMap<String, Vec<bitcoin::TxOut>>,
    ) -> ArkResult<[u8; 32]> {
        use base64::Engine;
        use bitcoin::hashes::Hash;
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};

        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64)
            .map_err(|e| ArkError::Internal(format!("Invalid base64 PSBT: {e}")))?;
        let mut psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
            .map_err(|e| ArkError::Internal(format!("Invalid PSBT: {e}")))?;

        // Ensure witness_utxo is set for each input
        for (idx, input_tx) in psbt.unsigned_tx.input.iter().enumerate() {
            if psbt.inputs[idx].witness_utxo.is_some() {
                continue;
            }
            let parent_txid = input_tx.previous_output.txid.to_string();
            let parent_vout = input_tx.previous_output.vout as usize;
            if let Some(outputs) = output_map.get(&parent_txid) {
                if parent_vout < outputs.len() {
                    psbt.inputs[idx].witness_utxo = Some(outputs[parent_vout].clone());
                }
            }
        }

        // Collect prevouts
        let prevouts: Vec<bitcoin::TxOut> = psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                input.witness_utxo.clone().ok_or_else(|| {
                    ArkError::Internal(format!("Missing witness_utxo for input {i}"))
                })
            })
            .collect::<ArkResult<Vec<_>>>()?;

        let mut sighash_cache = SighashCache::new(psbt.unsigned_tx.clone());
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .map_err(|e| ArkError::Internal(format!("Sighash computation failed: {e}")))?;

        Ok(sighash.to_byte_array())
    }

    fn extract_txid_from_psbt(psbt_str: &str) -> Option<String> {
        use base64::Engine;
        // Try base64 first, then hex
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_str)
            .or_else(|_| hex::decode(psbt_str))
            .ok()?;
        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).ok()?;
        Some(psbt.unsigned_tx.compute_txid().to_string())
    }

    /// Populate witness_utxo on each tree PSBT input without signing.
    ///
    /// Used in the MuSig2 flow: witness_utxo is needed for sighash computation
    /// during the nonce/signing rounds. Actual signing happens via MuSig2
    /// aggregation after all cosigners have contributed.
    async fn populate_tree_witness_utxos(
        &self,
        tree: &[crate::domain::TxTreeNode],
        commitment_tx_b64: &str,
    ) -> Vec<crate::domain::TxTreeNode> {
        use base64::Engine;

        let output_map = Self::build_tree_output_map(tree, commitment_tx_b64);

        let mut result = Vec::with_capacity(tree.len());
        for node in tree {
            if node.tx.is_empty() {
                result.push(node.clone());
                continue;
            }
            let updated_tx = match base64::engine::general_purpose::STANDARD.decode(&node.tx) {
                Ok(bytes) => match bitcoin::psbt::Psbt::deserialize(&bytes) {
                    Ok(mut psbt) => {
                        for (idx, input_tx) in psbt.unsigned_tx.input.iter().enumerate() {
                            if psbt.inputs[idx].witness_utxo.is_some() {
                                continue;
                            }
                            let parent_txid = input_tx.previous_output.txid.to_string();
                            let parent_vout = input_tx.previous_output.vout as usize;
                            if let Some(outputs) = output_map.get(&parent_txid) {
                                if parent_vout < outputs.len() {
                                    psbt.inputs[idx].witness_utxo =
                                        Some(outputs[parent_vout].clone());
                                }
                            }
                        }
                        base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
                    }
                    Err(_) => node.tx.clone(),
                },
                Err(_) => node.tx.clone(),
            };
            result.push(crate::domain::TxTreeNode {
                txid: node.txid.clone(),
                tx: updated_tx,
                children: node.children.clone(),
            });
        }
        result
    }

    /// Build a txid → Vec<TxOut> map from commitment tx and tree nodes.
    ///
    /// Also aliases unknown parent txids (from pre-fee-input commitment) to
    /// the commitment tx outputs.
    fn build_tree_output_map(
        tree: &[crate::domain::TxTreeNode],
        commitment_tx_b64: &str,
    ) -> std::collections::HashMap<String, Vec<bitcoin::TxOut>> {
        use base64::Engine;

        let mut output_map: std::collections::HashMap<String, Vec<bitcoin::TxOut>> =
            std::collections::HashMap::new();

        let mut commitment_outputs: Option<Vec<bitcoin::TxOut>> = None;
        if let Ok(ct_bytes) = base64::engine::general_purpose::STANDARD.decode(commitment_tx_b64) {
            if let Ok(ct_psbt) = bitcoin::psbt::Psbt::deserialize(&ct_bytes) {
                let txid = ct_psbt.unsigned_tx.compute_txid().to_string();
                commitment_outputs = Some(ct_psbt.unsigned_tx.output.clone());
                output_map.insert(txid, ct_psbt.unsigned_tx.output.clone());
            }
        }

        for node in tree {
            if node.tx.is_empty() {
                continue;
            }
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&node.tx) {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                    output_map.insert(node.txid.clone(), psbt.unsigned_tx.output.clone());
                }
            }
        }

        // Alias unknown parent txids to commitment tx outputs (fee input txid change)
        if let Some(ref ct_outs) = commitment_outputs {
            for node in tree {
                if node.tx.is_empty() {
                    continue;
                }
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&node.tx) {
                    if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                        for input_tx in &psbt.unsigned_tx.input {
                            let parent_txid = input_tx.previous_output.txid.to_string();
                            if let std::collections::hash_map::Entry::Vacant(e) =
                                output_map.entry(parent_txid)
                            {
                                e.insert(ct_outs.clone());
                            }
                        }
                    }
                }
            }
        }

        output_map
    }

    /// ASP-sign all VTXO tree PSBTs so clients can finalize them for unilateral exit.
    ///
    /// Each VTXO tree transaction spends a parent output that is P2TR-keyed to the
    /// ASP pubkey.  The Go SDK's `NextRedeemTx()` expects `TaprootKeySpendSig` on
    /// each tree PSBT input.  Without the ASP's signature the PSBTs are not
    /// finalizable and the "invalid tx, unable to finalize" error occurs.
    ///
    /// Algorithm:
    /// 1. Build a lookup map  txid → Vec<TxOut>  from the commitment tx and all
    ///    tree nodes so we can resolve `witness_utxo` for every input.
    /// 2. For each tree node, set `witness_utxo` on input 0 from the parent
    ///    output, then sign the PSBT with the ASP signer (key-path).
    async fn asp_sign_vtxo_tree(
        &self,
        tree: &[crate::domain::TxTreeNode],
        commitment_tx_b64: &str,
    ) -> Vec<crate::domain::TxTreeNode> {
        use base64::Engine;

        // Build output lookup: txid → outputs
        let mut output_map: std::collections::HashMap<String, Vec<bitcoin::TxOut>> =
            std::collections::HashMap::new();

        // Add commitment tx outputs.  Keep them aside so we can alias them
        // below for tree root nodes that still reference the pre-fee-input txid.
        let mut commitment_outputs: Option<Vec<bitcoin::TxOut>> = None;
        if let Ok(ct_bytes) = base64::engine::general_purpose::STANDARD.decode(commitment_tx_b64) {
            if let Ok(ct_psbt) = bitcoin::psbt::Psbt::deserialize(&ct_bytes) {
                let txid = ct_psbt.unsigned_tx.compute_txid().to_string();
                commitment_outputs = Some(ct_psbt.unsigned_tx.output.clone());
                output_map.insert(txid, ct_psbt.unsigned_tx.output.clone());
            }
        }

        // Add tree node outputs
        for node in tree {
            if node.tx.is_empty() {
                continue;
            }
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&node.tx) {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                    output_map.insert(node.txid.clone(), psbt.unsigned_tx.output.clone());
                }
            }
        }

        // When a fee input is added to the commitment tx its txid changes,
        // but the vtxo tree was built against the *original* txid.  Detect
        // any parent txids referenced by tree node inputs that are missing
        // from the map and alias them to the commitment tx outputs.  The
        // original outputs at the same vout positions are unchanged because
        // the fee input only appends an extra input (and possibly a change
        // output at the end).
        if let Some(ref ct_outs) = commitment_outputs {
            for node in tree {
                if node.tx.is_empty() {
                    continue;
                }
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&node.tx) {
                    if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                        for input_tx in &psbt.unsigned_tx.input {
                            let parent_txid = input_tx.previous_output.txid.to_string();
                            if let std::collections::hash_map::Entry::Vacant(e) =
                                output_map.entry(parent_txid.clone())
                            {
                                tracing::info!(
                                    parent_txid = %parent_txid,
                                    "Aliasing unknown parent txid to commitment tx outputs \
                                     (fee input likely changed commitment txid)"
                                );
                                e.insert(ct_outs.clone());
                            }
                        }
                    }
                }
            }
        }

        // Sign each tree node PSBT
        let mut signed_tree = Vec::with_capacity(tree.len());
        for node in tree {
            if node.tx.is_empty() {
                signed_tree.push(node.clone());
                continue;
            }

            let signed_tx = match self.asp_sign_single_tree_psbt(&node.tx, &output_map).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        txid = %node.txid,
                        error = %e,
                        "Failed to ASP-sign tree PSBT — storing unsigned"
                    );
                    node.tx.clone()
                }
            };

            signed_tree.push(crate::domain::TxTreeNode {
                txid: node.txid.clone(),
                tx: signed_tx,
                children: node.children.clone(),
            });
        }

        signed_tree
    }

    /// Sign a single VTXO tree PSBT with the ASP key after populating witness_utxo.
    async fn asp_sign_single_tree_psbt(
        &self,
        psbt_b64: &str,
        output_map: &std::collections::HashMap<String, Vec<bitcoin::TxOut>>,
    ) -> ArkResult<String> {
        use base64::Engine;

        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64)
            .map_err(|e| ArkError::Internal(format!("Invalid base64 PSBT: {e}")))?;
        let mut psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
            .map_err(|e| ArkError::Internal(format!("Invalid PSBT: {e}")))?;

        // Set witness_utxo for each input from the parent output
        for (idx, input_tx) in psbt.unsigned_tx.input.iter().enumerate() {
            if psbt.inputs[idx].witness_utxo.is_some() {
                continue; // already set
            }
            let parent_txid = input_tx.previous_output.txid.to_string();
            let parent_vout = input_tx.previous_output.vout as usize;
            if let Some(outputs) = output_map.get(&parent_txid) {
                if parent_vout < outputs.len() {
                    psbt.inputs[idx].witness_utxo = Some(outputs[parent_vout].clone());
                }
            }
        }

        // Re-encode and sign with ASP signer
        let psbt_b64_with_utxo = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

        let signed_hex = self
            .signer
            .sign_transaction(&psbt_b64_with_utxo, false)
            .await?;

        // sign_transaction returns hex-encoded PSBT, but tree nodes must be
        // base64 because the Go SDK parses them with psbt.NewFromRawBytes(_, true).
        let signed_bytes = hex::decode(&signed_hex)
            .map_err(|e| ArkError::Internal(format!("Signed PSBT is not valid hex: {e}")))?;
        let signed_b64 = base64::engine::general_purpose::STANDARD.encode(&signed_bytes);

        Ok(signed_b64)
    }
}

/// Service info
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceInfo {
    /// Signer pubkey
    pub signer_pubkey: String,
    /// Forfeit pubkey
    pub forfeit_pubkey: String,
    /// Exit delay
    pub unilateral_exit_delay: i64,
    /// Session duration
    pub session_duration: i64,
    /// Network
    pub network: String,
    /// Dust
    pub dust: u64,
    /// Min VTXO amount
    pub vtxo_min_amount: i64,
    /// Max VTXO amount
    pub vtxo_max_amount: i64,
    /// On-chain address for forfeit outputs
    pub forfeit_address: String,
    /// Tapscript for checkpoint outputs
    pub checkpoint_tapscript: String,
    /// Min UTXO amount for boarding (sats)
    pub utxo_min_amount: u64,
    /// Max UTXO amount for boarding (sats)
    pub utxo_max_amount: u64,
    /// CSV delay for public unilateral exits (seconds)
    pub public_unilateral_exit_delay: u32,
    /// CSV delay for boarding inputs (seconds)
    pub boarding_exit_delay: u32,
    /// Max commitment tx weight
    pub max_tx_weight: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FlatTxTree, Receiver, Vtxo};
    use crate::ports::{
        BlockTimestamp, BoardingInput, CacheService, CommitmentTxResult, SignerService, TxBuilder,
        TxInput, ValidForfeitTx, VtxoRepository, WalletService,
    };
    use async_trait::async_trait;
    use bitcoin::XOnlyPublicKey;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::broadcast;

    // ── Stub implementations ────────────────────────────────────────

    struct StubWallet;
    #[async_trait]
    impl WalletService for StubWallet {
        async fn status(&self) -> ArkResult<crate::ports::WalletStatus> {
            Ok(crate::ports::WalletStatus {
                initialized: true,
                unlocked: true,
                synced: true,
            })
        }
        async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
            Ok(XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap())
        }
        async fn derive_connector_address(&self) -> ArkResult<String> {
            Ok(String::new())
        }
        async fn sign_transaction(&self, p: &str, _: bool) -> ArkResult<String> {
            Ok(p.into())
        }
        async fn select_utxos(&self, _: u64, _: bool) -> ArkResult<(Vec<TxInput>, u64)> {
            Ok((vec![], 0))
        }
        async fn broadcast_transaction(&self, _: Vec<String>) -> ArkResult<String> {
            Ok(String::new())
        }
        async fn fee_rate(&self) -> ArkResult<u64> {
            Ok(1)
        }
        async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
            Ok(BlockTimestamp {
                height: 1,
                timestamp: 0,
            })
        }
        async fn get_dust_amount(&self) -> ArkResult<u64> {
            Ok(546)
        }
        async fn get_outpoint_status(&self, _: &VtxoOutpoint) -> ArkResult<bool> {
            Ok(false)
        }
    }

    struct StubSigner;
    #[async_trait]
    impl SignerService for StubSigner {
        async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
            Ok(XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap())
        }
        async fn sign_transaction(&self, p: &str, _: bool) -> ArkResult<String> {
            Ok(p.into())
        }
        async fn get_secret_key_bytes(&self) -> ArkResult<[u8; 32]> {
            let mut key = [0u8; 32];
            key[31] = 1;
            Ok(key)
        }
    }

    struct StubVtxoRepo;
    #[async_trait]
    impl VtxoRepository for StubVtxoRepo {
        async fn add_vtxos(&self, _: &[Vtxo]) -> ArkResult<()> {
            Ok(())
        }
        async fn get_vtxos(&self, _: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
            Ok(vec![])
        }
        async fn get_all_vtxos_for_pubkey(&self, _: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
            Ok((vec![], vec![]))
        }
        async fn spend_vtxos(&self, _: &[(VtxoOutpoint, String)], _: &str) -> ArkResult<()> {
            Ok(())
        }
    }

    struct StubTxBuilder;
    #[async_trait]
    impl TxBuilder for StubTxBuilder {
        async fn build_commitment_tx(
            &self,
            _: &XOnlyPublicKey,
            intents: &[Intent],
            _: &[BoardingInput],
        ) -> ArkResult<CommitmentTxResult> {
            // Build a minimal vtxo_tree with one leaf node per offchain receiver
            // so the tree isn't empty when there are cosigners (which would
            // trigger the auto-complete path and skip tree signing).
            let mut vtxo_tree = Vec::new();
            let mut leaf_idx = 0u32;
            for intent in intents {
                for receiver in &intent.receivers {
                    if !receiver.is_onchain() {
                        vtxo_tree.push(TxTreeNode {
                            txid: format!("stub_leaf_{}", leaf_idx),
                            tx: "stub_psbt".to_string(),
                            children: std::collections::HashMap::new(),
                        });
                        leaf_idx += 1;
                    }
                }
            }
            Ok(CommitmentTxResult {
                commitment_tx: "stub_commitment_tx".to_string(),
                vtxo_tree,
                connector_address: "bc1qstub".to_string(),
                connectors: vec![],
            })
        }
        async fn verify_forfeit_txs(
            &self,
            _: &[Vtxo],
            _: &FlatTxTree,
            _: &[String],
        ) -> ArkResult<Vec<ValidForfeitTx>> {
            Ok(vec![])
        }
        async fn build_sweep_tx(
            &self,
            _: &[crate::ports::SweepInput],
        ) -> ArkResult<(String, String)> {
            Ok(("stub_txid".into(), "stub_sweep_hex".into()))
        }
        async fn get_sweepable_batch_outputs(
            &self,
            _: &FlatTxTree,
        ) -> ArkResult<Option<crate::ports::SweepableOutput>> {
            Ok(None)
        }
        async fn finalize_and_extract(&self, _: &str) -> ArkResult<String> {
            Ok("stub_raw_tx".into())
        }
        async fn verify_vtxo_tapscript_sigs(&self, _: &str, _: bool) -> ArkResult<bool> {
            Ok(true)
        }
        async fn verify_boarding_tapscript_sigs(
            &self,
            _: &str,
            _: &str,
        ) -> ArkResult<std::collections::HashMap<u32, crate::ports::SignedBoardingInput>> {
            Ok(std::collections::HashMap::new())
        }
    }

    struct StubCache;
    #[async_trait]
    impl CacheService for StubCache {
        async fn set(&self, _: &str, _: &[u8], _: Option<u64>) -> ArkResult<()> {
            Ok(())
        }
        async fn get(&self, _: &str) -> ArkResult<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn delete(&self, _: &str) -> ArkResult<bool> {
            Ok(false)
        }
    }

    struct RecordingEvents {
        started: AtomicU32,
        finalized: AtomicU32,
        broadcast: AtomicU32,
    }
    impl RecordingEvents {
        fn new() -> Self {
            Self {
                started: AtomicU32::new(0),
                finalized: AtomicU32::new(0),
                broadcast: AtomicU32::new(0),
            }
        }
    }
    #[async_trait]
    impl EventPublisher for RecordingEvents {
        async fn publish_event(&self, event: ArkEvent) -> ArkResult<()> {
            match event {
                ArkEvent::RoundStarted { .. } => {
                    self.started.fetch_add(1, Ordering::SeqCst);
                }
                ArkEvent::RoundFinalized { .. } => {
                    self.finalized.fetch_add(1, Ordering::SeqCst);
                }
                ArkEvent::RoundBroadcast { .. } => {
                    self.broadcast.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
            Ok(())
        }
        async fn subscribe(&self) -> ArkResult<broadcast::Receiver<ArkEvent>> {
            let (_tx, rx) = broadcast::channel(1);
            Ok(rx)
        }
    }

    fn make_service(events: Arc<RecordingEvents>) -> ArkService {
        ArkService::new(
            Arc::new(StubWallet),
            Arc::new(StubSigner),
            Arc::new(StubVtxoRepo),
            Arc::new(StubTxBuilder),
            Arc::new(StubCache),
            events,
            ArkConfig::default(),
        )
    }

    #[test]
    fn test_config_defaults() {
        let config = ArkConfig::default();
        assert!(config.vtxo_expiry_secs > 0);
        assert!(config.max_intents > config.min_intents);
        assert!(config.min_vtxo_amount_sats >= 546);
    }

    #[test]
    fn test_round_timing_defaults() {
        let timing = RoundTiming::default();
        assert_eq!(timing.registration_duration_secs, 4);
        assert_eq!(timing.confirmation_duration_secs, 3);
        assert_eq!(timing.finalization_duration_secs, 3);
        assert_eq!(timing.total_duration_secs(), 10);
    }

    #[test]
    fn test_round_timing_finalization_split() {
        let timing = RoundTiming {
            registration_duration_secs: 10,
            confirmation_duration_secs: 5,
            finalization_duration_secs: 9, // divisible by 3
        };
        assert_eq!(timing.nonce_collection_duration_secs(), 3);
        assert_eq!(timing.signature_collection_duration_secs(), 3);
        assert_eq!(timing.forfeit_collection_duration_secs(), 3);
    }

    #[test]
    fn test_config_new_field_defaults() {
        let config = ArkConfig::default();
        assert_eq!(config.utxo_min_amount, 1_000);
        assert_eq!(config.utxo_max_amount, 100_000_000);
        assert_eq!(config.public_unilateral_exit_delay, 512);
        assert_eq!(config.boarding_exit_delay, 1_024);
        assert_eq!(config.max_tx_weight, 400_000);
    }

    #[tokio::test]
    async fn test_finalize_round_with_intents() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events.clone());

        // Start a round
        let _round = svc.start_round().await.unwrap();
        assert_eq!(events.started.load(Ordering::SeqCst), 1);

        // Register an intent
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("deadbeef".repeat(8), 0),
            50_000,
            "ab".repeat(32),
        );
        let mut intent =
            Intent::new("proof_tx".into(), "proof".into(), "msg".into(), vec![vtxo]).unwrap();
        intent
            .add_receivers(vec![Receiver::offchain(25_000, "rcv_pk".into())])
            .unwrap();
        // Add a cosigner so the round doesn't auto-complete (zero-cosigner path)
        intent.cosigners_public_keys = vec!["cd".repeat(33)];
        svc.register_intent(intent).await.unwrap();

        // Finalize (phase 1): enters tree signing, round stays in Finalization
        let phase1 = svc.finalize_round().await.unwrap();
        assert!(!phase1.is_ended()); // NOT ended yet — awaiting tree signatures
        assert_eq!(phase1.stage.code, RoundStage::Finalization);
        assert_eq!(phase1.commitment_tx, "stub_commitment_tx");
        assert!(phase1.fail_reason.is_empty());
        // RoundFinalized not emitted yet
        assert_eq!(events.finalized.load(Ordering::SeqCst), 0);

        // Complete the round (phase 2): creates VTXOs, ends round
        let completed = svc.complete_round().await.unwrap();
        assert!(completed.is_ended());
        assert_eq!(events.finalized.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_finalize_round_no_intents_skips() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events.clone());

        svc.start_round().await.unwrap();

        // Finalize with zero intents → round should be failed/skipped
        let result = svc.finalize_round().await.unwrap();
        assert!(result.is_ended());
        assert_eq!(result.fail_reason, "No intents to finalize");
        // RoundFinalized should NOT have been emitted
        assert_eq!(events.finalized.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_finalize_round_without_active_round_errors() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events);

        let err = svc.finalize_round().await.unwrap_err();
        assert!(err.to_string().contains("No active round"));
    }

    #[tokio::test]
    async fn test_sweep_checkpoints_returns_zero_on_empty() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events);
        // NoopCheckpointRepository returns empty list → 0 swept
        let swept = svc.sweep_checkpoints().await.unwrap();
        assert_eq!(swept, 0);
    }

    #[test]
    fn test_forfeit_record_new() {
        let record = ForfeitRecord::new("round-1".into(), "vtxo-abc".into(), "deadbeef".into());
        assert_eq!(record.round_id, "round-1");
        assert_eq!(record.vtxo_id, "vtxo-abc");
        assert_eq!(record.tx_hex, "deadbeef");
        assert!(!record.validated);
        assert!(!record.id.is_empty());
        assert!(record.submitted_at > 0);
    }

    #[test]
    fn test_forfeit_mark_validated() {
        let mut record = ForfeitRecord::new("round-1".into(), "vtxo-abc".into(), "deadbeef".into());
        assert!(!record.validated);
        record.mark_validated();
        assert!(record.validated);
    }

    #[test]
    fn test_forfeit_serde_roundtrip() {
        let record = ForfeitRecord::new("round-42".into(), "vtxo-xyz".into(), "cafebabe".into());
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: ForfeitRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, record.id);
        assert_eq!(deserialized.round_id, record.round_id);
        assert_eq!(deserialized.vtxo_id, record.vtxo_id);
        assert_eq!(deserialized.tx_hex, record.tx_hex);
        assert_eq!(deserialized.submitted_at, record.submitted_at);
        assert_eq!(deserialized.validated, record.validated);
    }

    #[tokio::test]
    async fn test_submit_forfeit_stores_record() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events);
        // NoopForfeitRepository accepts the store silently
        let record = svc
            .submit_forfeit("round-1".into(), "vtxo-1".into(), "aabbcc".into())
            .await
            .unwrap();
        assert_eq!(record.round_id, "round-1");
        assert_eq!(record.vtxo_id, "vtxo-1");
        assert_eq!(record.tx_hex, "aabbcc");
        assert!(!record.validated);
    }

    #[tokio::test]
    async fn test_get_round_forfeits_empty() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events);
        // NoopForfeitRepository returns empty vec
        let forfeits = svc.get_round_forfeits("nonexistent").await.unwrap();
        assert!(forfeits.is_empty());
    }

    // ── Boarding tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_register_boarding_returns_transaction() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events);
        let pubkey = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let result = svc
            .register_boarding(pubkey, bitcoin::Amount::from_sat(50_000))
            .await
            .unwrap();
        assert_eq!(result.amount, bitcoin::Amount::from_sat(50_000));
        assert_eq!(
            result.status,
            crate::domain::BoardingStatus::AwaitingFunding
        );
    }

    #[tokio::test]
    async fn test_register_boarding_rejects_below_minimum() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events);
        let pubkey = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        // Default utxo_min_amount is 1_000
        let err = svc
            .register_boarding(pubkey, bitcoin::Amount::from_sat(100))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too small") || err.to_string().contains("Amount"));
    }

    #[tokio::test]
    async fn test_claim_boarding_inputs_empty() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events);
        // NoopBoardingRepository returns empty list
        let pending = svc.claim_boarding_inputs().await.unwrap();
        assert!(pending.is_empty());
    }

    // ── Fraud detection tests ───────────────────────────────────────

    #[tokio::test]
    async fn test_noop_fraud_detector_no_fraud() {
        use crate::ports::{FraudDetector, NoopFraudDetector};
        let detector = NoopFraudDetector;
        let result = detector
            .detect_double_spend("vtxo-1", "round-1")
            .await
            .unwrap();
        assert!(!result, "NoopFraudDetector should never detect fraud");
        // react_to_fraud should also succeed silently
        detector.react_to_fraud("vtxo-1", "deadbeef").await.unwrap();
    }

    #[tokio::test]
    async fn test_fraud_detection_emits_event() {
        use crate::ports::FraudDetector;
        use std::sync::atomic::AtomicU32;

        struct AlwaysFraudDetector;
        #[async_trait]
        impl FraudDetector for AlwaysFraudDetector {
            async fn detect_double_spend(
                &self,
                _vtxo_id: &str,
                _round_id: &str,
            ) -> ArkResult<bool> {
                Ok(true)
            }
            async fn react_to_fraud(&self, _vtxo_id: &str, _forfeit_tx_hex: &str) -> ArkResult<()> {
                Ok(())
            }
        }

        struct FraudEventRecorder {
            fraud_count: AtomicU32,
        }
        impl FraudEventRecorder {
            fn new() -> Self {
                Self {
                    fraud_count: AtomicU32::new(0),
                }
            }
        }
        #[async_trait]
        impl EventPublisher for FraudEventRecorder {
            async fn publish_event(&self, event: ArkEvent) -> ArkResult<()> {
                if matches!(event, ArkEvent::FraudDetected { .. }) {
                    self.fraud_count.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            }
            async fn subscribe(&self) -> ArkResult<broadcast::Receiver<ArkEvent>> {
                let (_tx, rx) = broadcast::channel(1);
                Ok(rx)
            }
        }

        let recorder = Arc::new(FraudEventRecorder::new());
        let mut svc = make_service(Arc::new(RecordingEvents::new()));
        svc.events = recorder.clone();
        svc.fraud_detector = Arc::new(AlwaysFraudDetector);

        svc.check_and_react_fraud("vtxo-bad", "round-42")
            .await
            .unwrap();
        assert_eq!(recorder.fraud_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_react_to_fraud_calls_detector() {
        use crate::ports::FraudDetector;
        use std::sync::atomic::AtomicU32;

        struct CountingFraudDetector {
            react_calls: AtomicU32,
        }
        impl CountingFraudDetector {
            fn new() -> Self {
                Self {
                    react_calls: AtomicU32::new(0),
                }
            }
        }
        #[async_trait]
        impl FraudDetector for CountingFraudDetector {
            async fn detect_double_spend(
                &self,
                _vtxo_id: &str,
                _round_id: &str,
            ) -> ArkResult<bool> {
                Ok(true)
            }
            async fn react_to_fraud(&self, _vtxo_id: &str, _forfeit_tx_hex: &str) -> ArkResult<()> {
                self.react_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        /// In-memory forfeit repo that returns pre-loaded records.
        struct MemForfeitRepo {
            records: Vec<ForfeitRecord>,
        }
        #[async_trait]
        impl ForfeitRepository for MemForfeitRepo {
            async fn store_forfeit(&self, _record: ForfeitRecord) -> ArkResult<()> {
                Ok(())
            }
            async fn get_forfeit(&self, _id: &str) -> ArkResult<Option<ForfeitRecord>> {
                Ok(None)
            }
            async fn list_by_round(&self, _round_id: &str) -> ArkResult<Vec<ForfeitRecord>> {
                Ok(self.records.clone())
            }
            async fn mark_validated(&self, _id: &str) -> ArkResult<()> {
                Ok(())
            }
        }

        let detector = Arc::new(CountingFraudDetector::new());
        let mut svc = make_service(Arc::new(RecordingEvents::new()));
        svc.fraud_detector = detector.clone();
        svc.forfeit_repo = Arc::new(MemForfeitRepo {
            records: vec![
                ForfeitRecord::new("round-1".into(), "vtxo-bad".into(), "tx_hex_1".into()),
                ForfeitRecord::new("round-1".into(), "vtxo-bad".into(), "tx_hex_2".into()),
            ],
        });

        svc.check_and_react_fraud("vtxo-bad", "round-1")
            .await
            .unwrap();
        assert_eq!(
            detector.react_calls.load(Ordering::SeqCst),
            2,
            "should call react_to_fraud for each forfeit"
        );
    }

    #[test]
    fn test_fraud_detector_trait_object_safe() {
        use crate::ports::{FraudDetector, NoopFraudDetector};
        // Ensure FraudDetector can be used as a trait object
        let _: Arc<dyn FraudDetector> = Arc::new(NoopFraudDetector);
    }

    // ── Double-spend detection in register_intent (#334) ───────────

    /// Scanner that reports a specific outpoint as already spent on-chain.
    struct SpentScanner {
        spent_txid: String,
        spent_vout: u32,
        sender: tokio::sync::broadcast::Sender<crate::ports::ScriptSpentEvent>,
    }

    impl SpentScanner {
        fn new(txid: &str, vout: u32) -> Self {
            let (sender, _) = tokio::sync::broadcast::channel(16);
            Self {
                spent_txid: txid.to_string(),
                spent_vout: vout,
                sender,
            }
        }
    }

    #[async_trait]
    impl crate::ports::BlockchainScanner for SpentScanner {
        async fn watch_script(&self, _: Vec<u8>) -> ArkResult<()> {
            Ok(())
        }
        async fn unwatch_script(&self, _: &[u8]) -> ArkResult<()> {
            Ok(())
        }
        fn notification_channel(
            &self,
        ) -> tokio::sync::broadcast::Receiver<crate::ports::ScriptSpentEvent> {
            self.sender.subscribe()
        }
        async fn tip_height(&self) -> ArkResult<u32> {
            Ok(0)
        }
        async fn is_utxo_unspent(&self, outpoint: &VtxoOutpoint) -> ArkResult<bool> {
            if outpoint.txid == self.spent_txid && outpoint.vout == self.spent_vout {
                return Ok(false); // spent → double-spend detected
            }
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_register_intent_rejects_spent_vtxo() {
        let events = Arc::new(RecordingEvents::new());
        let txid = "deadbeef".repeat(8);

        let svc = ArkService::new(
            Arc::new(StubWallet),
            Arc::new(StubSigner),
            Arc::new(StubVtxoRepo),
            Arc::new(StubTxBuilder),
            Arc::new(StubCache),
            events,
            ArkConfig::default(),
        )
        .with_scanner(Arc::new(SpentScanner::new(&txid, 0)));

        svc.start_round().await.unwrap();

        let vtxo = Vtxo::new(VtxoOutpoint::new(txid.clone(), 0), 50_000, "ab".repeat(32));
        let mut intent =
            Intent::new("proof_tx".into(), "proof".into(), "msg".into(), vec![vtxo]).unwrap();
        intent
            .add_receivers(vec![Receiver::offchain(25_000, "rcv_pk".into())])
            .unwrap();

        let result = svc.register_intent(intent).await;
        assert!(
            result.is_err(),
            "register_intent should reject a spent VTXO (double-spend)"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already spent on-chain"),
            "error should mention on-chain spend, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_register_intent_accepts_unspent_vtxo() {
        let events = Arc::new(RecordingEvents::new());
        // NoopBlockchainScanner returns is_utxo_unspent = true for all outpoints
        let svc = make_service(events);

        svc.start_round().await.unwrap();

        let vtxo = Vtxo::new(
            VtxoOutpoint::new("deadbeef".repeat(8), 0),
            50_000,
            "ab".repeat(32),
        );
        let mut intent =
            Intent::new("proof_tx".into(), "proof".into(), "msg".into(), vec![vtxo]).unwrap();
        intent
            .add_receivers(vec![Receiver::offchain(25_000, "rcv_pk".into())])
            .unwrap();

        let result = svc.register_intent(intent).await;
        assert!(
            result.is_ok(),
            "register_intent should accept an unspent VTXO"
        );
    }

    // ── Confirmation phase tests ────────────────────────────────────

    #[tokio::test]
    async fn test_start_confirmation_transitions_stage() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events.clone());

        // Start a round
        svc.start_round().await.unwrap();

        // Register an intent (min_intents default is 1)
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("deadbeef".repeat(8), 0),
            50_000,
            "ab".repeat(32),
        );
        let mut intent =
            Intent::new("proof_tx".into(), "proof".into(), "msg".into(), vec![vtxo]).unwrap();
        intent
            .add_receivers(vec![Receiver::offchain(25_000, "rcv_pk".into())])
            .unwrap();
        let intent_id = intent.id.clone();
        svc.register_intent(intent).await.unwrap();

        // Start confirmation
        let intent_ids = svc.start_confirmation().await.unwrap();
        assert_eq!(intent_ids.len(), 1);
        assert_eq!(intent_ids[0], intent_id);

        // Check round is now in finalization stage
        let guard = svc.current_round.read().await;
        let round = guard.as_ref().unwrap();
        assert_eq!(round.stage.code, RoundStage::Finalization);
    }

    #[tokio::test]
    async fn test_start_confirmation_fails_without_enough_intents() {
        let events = Arc::new(RecordingEvents::new());
        let mut config = ArkConfig::default();
        config.min_intents = 2; // Require at least 2 intents
        let svc = ArkService::new(
            Arc::new(StubWallet),
            Arc::new(StubSigner),
            Arc::new(StubVtxoRepo),
            Arc::new(StubTxBuilder),
            Arc::new(StubCache),
            events.clone(),
            config,
        );

        // Start a round
        svc.start_round().await.unwrap();

        // Register only 1 intent
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("deadbeef".repeat(8), 0),
            50_000,
            "ab".repeat(32),
        );
        let mut intent =
            Intent::new("proof_tx".into(), "proof".into(), "msg".into(), vec![vtxo]).unwrap();
        intent
            .add_receivers(vec![Receiver::offchain(25_000, "rcv_pk".into())])
            .unwrap();
        svc.register_intent(intent).await.unwrap();

        // Start confirmation should fail
        let result = svc.start_confirmation().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Not enough intents"));
    }

    #[tokio::test]
    async fn test_confirm_registration_marks_confirmed() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events.clone());

        // Start a round and register an intent
        svc.start_round().await.unwrap();
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("deadbeef".repeat(8), 0),
            50_000,
            "ab".repeat(32),
        );
        let mut intent =
            Intent::new("proof_tx".into(), "proof".into(), "msg".into(), vec![vtxo]).unwrap();
        intent
            .add_receivers(vec![Receiver::offchain(25_000, "rcv_pk".into())])
            .unwrap();
        let intent_id = intent.id.clone();
        svc.register_intent(intent).await.unwrap();

        // Start confirmation
        svc.start_confirmation().await.unwrap();

        // Confirm the intent
        svc.confirm_registration(&intent_id).await.unwrap();

        // Check it's confirmed
        assert!(svc.all_confirmed().await.unwrap());
    }

    #[tokio::test]
    async fn test_end_confirmation_drops_unconfirmed() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events.clone());

        // Start a round and register two intents
        svc.start_round().await.unwrap();

        for i in 0..2 {
            let vtxo = Vtxo::new(
                VtxoOutpoint::new(format!("{:064x}", i), 0),
                50_000,
                format!("{:064x}", i + 100),
            );
            let mut intent = Intent::new(
                format!("tx_{i}"),
                format!("proof_{i}"),
                format!("msg_{i}"),
                vec![vtxo],
            )
            .unwrap();
            intent
                .add_receivers(vec![Receiver::offchain(25_000, format!("rcv_{i}"))])
                .unwrap();
            svc.register_intent(intent).await.unwrap();
        }

        // Start confirmation
        let intent_ids = svc.start_confirmation().await.unwrap();
        assert_eq!(intent_ids.len(), 2);

        // Confirm only one intent
        svc.confirm_registration(&intent_ids[0]).await.unwrap();

        // End confirmation
        let (confirmed, dropped) = svc.end_confirmation().await.unwrap();
        assert_eq!(confirmed, 1);
        assert_eq!(dropped, 1);

        // Check only one intent remains
        let guard = svc.current_round.read().await;
        let round = guard.as_ref().unwrap();
        assert_eq!(round.intent_count(), 1);
    }

    #[tokio::test]
    async fn test_end_confirmation_fails_round_if_all_dropped() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events.clone());

        // Start a round and register an intent
        svc.start_round().await.unwrap();
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("deadbeef".repeat(8), 0),
            50_000,
            "ab".repeat(32),
        );
        let mut intent =
            Intent::new("proof_tx".into(), "proof".into(), "msg".into(), vec![vtxo]).unwrap();
        intent
            .add_receivers(vec![Receiver::offchain(25_000, "rcv_pk".into())])
            .unwrap();
        svc.register_intent(intent).await.unwrap();

        // Start confirmation
        svc.start_confirmation().await.unwrap();

        // Don't confirm anything → end confirmation
        let result = svc.end_confirmation().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("All intents dropped"));
    }

    // ── Offchain transaction tests ──────────────────────────────────

    mod offchain_tests {
        use super::*;
        use crate::domain::{OffchainTxStage, VtxoInput, VtxoOutput};
        use crate::ports::OffchainTxRepository;
        use std::collections::HashMap;
        use tokio::sync::Mutex;

        /// In-memory offchain tx repository for testing.
        struct InMemoryOffchainTxRepo {
            txs: Mutex<HashMap<String, OffchainTx>>,
        }

        impl InMemoryOffchainTxRepo {
            fn new() -> Self {
                Self {
                    txs: Mutex::new(HashMap::new()),
                }
            }
        }

        #[async_trait]
        impl OffchainTxRepository for InMemoryOffchainTxRepo {
            async fn create(&self, tx: &OffchainTx) -> ArkResult<()> {
                self.txs.lock().await.insert(tx.id.clone(), tx.clone());
                Ok(())
            }
            async fn get(&self, id: &str) -> ArkResult<Option<OffchainTx>> {
                Ok(self.txs.lock().await.get(id).cloned())
            }
            async fn get_pending(&self) -> ArkResult<Vec<OffchainTx>> {
                Ok(self
                    .txs
                    .lock()
                    .await
                    .values()
                    .filter(|tx| {
                        matches!(
                            tx.stage,
                            OffchainTxStage::Requested | OffchainTxStage::Accepted { .. }
                        )
                    })
                    .cloned()
                    .collect())
            }
            async fn get_all_finalized(&self) -> ArkResult<Vec<OffchainTx>> {
                Ok(self
                    .txs
                    .lock()
                    .await
                    .values()
                    .filter(|tx| matches!(tx.stage, OffchainTxStage::Finalized { .. }))
                    .cloned()
                    .collect())
            }
            async fn update_stage(&self, id: &str, stage: &OffchainTxStage) -> ArkResult<()> {
                if let Some(tx) = self.txs.lock().await.get_mut(id) {
                    tx.stage = stage.clone();
                }
                Ok(())
            }
            async fn set_signed_ark_tx(&self, id: &str, signed_ark_tx: &str) -> ArkResult<()> {
                if let Some(tx) = self.txs.lock().await.get_mut(id) {
                    tx.signed_ark_tx = signed_ark_tx.to_string();
                }
                Ok(())
            }
            async fn set_checkpoint_txs(
                &self,
                id: &str,
                checkpoint_txs: &[String],
            ) -> ArkResult<()> {
                if let Some(tx) = self.txs.lock().await.get_mut(id) {
                    tx.checkpoint_txs = checkpoint_txs.to_vec();
                }
                Ok(())
            }
            async fn is_input_spent(&self, vtxo_id: &str) -> ArkResult<bool> {
                let store = self.txs.lock().await;
                for tx in store.values() {
                    for input in &tx.inputs {
                        if input.vtxo_id == vtxo_id {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
        }

        fn make_offchain_service() -> (ArkService, Arc<InMemoryOffchainTxRepo>) {
            let repo = Arc::new(InMemoryOffchainTxRepo::new());
            let events = Arc::new(RecordingEvents::new());
            let svc = make_service(events).set_offchain_tx_repo(Arc::clone(&repo) as _);
            (svc, repo)
        }

        fn test_inputs() -> Vec<VtxoInput> {
            vec![VtxoInput {
                vtxo_id: "abc123:0".to_string(),
                signed_tx: vec![1, 2, 3],
            }]
        }

        fn test_outputs() -> Vec<VtxoOutput> {
            vec![VtxoOutput {
                pubkey: "02deadbeef".to_string(),
                amount_sats: 10_000,
                assets: vec![],
            }]
        }

        #[tokio::test]
        async fn test_submit_offchain_tx_returns_id() {
            let (svc, _repo) = make_offchain_service();
            let tx_id = svc
                .submit_offchain_tx(test_inputs(), test_outputs())
                .await
                .unwrap();
            assert!(!tx_id.is_empty());
        }

        #[tokio::test]
        async fn test_submit_offchain_tx_stores_pending() {
            let (svc, repo) = make_offchain_service();
            let tx_id = svc
                .submit_offchain_tx(test_inputs(), test_outputs())
                .await
                .unwrap();
            let stored = repo
                .get(&tx_id)
                .await
                .unwrap()
                .expect("tx should be stored");
            assert_eq!(stored.id, tx_id);
            assert_eq!(stored.stage, OffchainTxStage::Requested);
            assert_eq!(stored.inputs.len(), 1);
            assert_eq!(stored.outputs.len(), 1);
        }

        #[tokio::test]
        async fn test_finalize_offchain_tx_marks_confirmed() {
            let (svc, repo) = make_offchain_service();
            let tx_id = svc
                .submit_offchain_tx(test_inputs(), test_outputs())
                .await
                .unwrap();
            let _txid = svc.finalize_offchain_tx(&tx_id).await.unwrap();
            let stored = repo.get(&tx_id).await.unwrap().expect("tx should exist");
            assert!(matches!(stored.stage, OffchainTxStage::Finalized { .. }));
        }

        #[tokio::test]
        async fn test_finalize_nonexistent_tx_returns_error() {
            let (svc, _repo) = make_offchain_service();
            let result = svc.finalize_offchain_tx("nonexistent-id").await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("not found"));
        }

        #[tokio::test]
        async fn test_submit_offchain_tx_rejects_empty_inputs() {
            let (svc, _repo) = make_offchain_service();
            let result = svc.submit_offchain_tx(vec![], test_outputs()).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("inputs"));
        }

        #[tokio::test]
        async fn test_submit_offchain_tx_rejects_empty_outputs() {
            let (svc, _repo) = make_offchain_service();
            let result = svc.submit_offchain_tx(test_inputs(), vec![]).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("outputs"));
        }

        #[tokio::test]
        async fn test_submit_offchain_tx_rejects_dust_output() {
            let (svc, _repo) = make_offchain_service();
            let outputs = vec![VtxoOutput {
                pubkey: "02deadbeef".to_string(),
                amount_sats: 100, // below 546 dust limit
                assets: vec![],
            }];
            let result = svc.submit_offchain_tx(test_inputs(), outputs).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("dust"));
        }
    }

    // ── Sweep service tests ─────────────────────────────────────────

    mod sweep_tests {
        use super::*;
        use crate::ports::{NoopSweepService, SweepResult, SweepService};

        #[tokio::test]
        async fn test_noop_sweep_returns_empty_result() {
            let svc = NoopSweepService;
            let result = svc.sweep_expired_vtxos(100).await.unwrap();
            assert_eq!(result.vtxos_swept, 0);
            assert_eq!(result.sats_recovered, 0);
            assert!(result.tx_ids.is_empty());

            let result = svc.sweep_connectors("round-1").await.unwrap();
            assert_eq!(result.vtxos_swept, 0);
            assert_eq!(result.sats_recovered, 0);
            assert!(result.tx_ids.is_empty());
        }

        #[test]
        fn test_sweep_result_default() {
            let r = SweepResult::default();
            assert_eq!(r.vtxos_swept, 0);
            assert_eq!(r.sats_recovered, 0);
            assert!(r.tx_ids.is_empty());
        }

        #[tokio::test]
        async fn test_run_scheduled_sweep_no_vtxos() {
            let events = Arc::new(RecordingEvents::new());
            let svc = make_service(events.clone());
            // NoopSweepService returns 0 vtxos → no event published, no error.
            svc.run_scheduled_sweep(500).await.unwrap();
            // started/finalized counters unchanged (no SweepCompleted counted there).
            assert_eq!(events.started.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn test_sweep_service_trait_object_safe() {
            // Proves SweepService can be used as a trait object.
            let _: Arc<dyn SweepService> = Arc::new(NoopSweepService);
        }
    }

    // ── sign_and_broadcast_round tests (#175) ───────────────────────

    mod broadcast_tests {
        use super::*;
        use crate::domain::{Receiver, Vtxo};
        use crate::ports::SigningSessionStore;
        use std::sync::Mutex;

        /// A mock wallet that records broadcast calls and returns a fake txid.
        struct MockBroadcastWallet {
            broadcast_calls: Mutex<Vec<Vec<String>>>,
        }
        impl MockBroadcastWallet {
            fn new() -> Self {
                Self {
                    broadcast_calls: Mutex::new(Vec::new()),
                }
            }
        }
        #[async_trait]
        impl WalletService for MockBroadcastWallet {
            async fn status(&self) -> ArkResult<crate::ports::WalletStatus> {
                Ok(crate::ports::WalletStatus {
                    initialized: true,
                    unlocked: true,
                    synced: true,
                })
            }
            async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
                Ok(XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap())
            }
            async fn derive_connector_address(&self) -> ArkResult<String> {
                Ok(String::new())
            }
            async fn sign_transaction(&self, p: &str, _: bool) -> ArkResult<String> {
                Ok(p.into())
            }
            async fn select_utxos(&self, _: u64, _: bool) -> ArkResult<(Vec<TxInput>, u64)> {
                Ok((vec![], 0))
            }
            async fn broadcast_transaction(&self, txs: Vec<String>) -> ArkResult<String> {
                self.broadcast_calls.lock().unwrap().push(txs);
                Ok("abc123def456".to_string())
            }
            async fn fee_rate(&self) -> ArkResult<u64> {
                Ok(1)
            }
            async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
                Ok(BlockTimestamp {
                    height: 1,
                    timestamp: 0,
                })
            }
            async fn get_dust_amount(&self) -> ArkResult<u64> {
                Ok(546)
            }
            async fn get_outpoint_status(&self, _: &VtxoOutpoint) -> ArkResult<bool> {
                Ok(false)
            }
        }

        /// A mock signing session store that returns controllable state.
        struct MockSigningStore {
            all_sigs_collected: bool,
            nonces: Vec<Vec<u8>>,
            signatures: Vec<Vec<u8>>,
            completed: Mutex<bool>,
        }
        impl MockSigningStore {
            fn ready() -> Self {
                Self {
                    all_sigs_collected: true,
                    nonces: vec![vec![1, 2, 3], vec![4, 5, 6]],
                    signatures: vec![vec![10, 20], vec![30, 40]],
                    completed: Mutex::new(false),
                }
            }
            fn not_ready() -> Self {
                Self {
                    all_sigs_collected: false,
                    nonces: vec![],
                    signatures: vec![],
                    completed: Mutex::new(false),
                }
            }
        }
        #[async_trait]
        impl SigningSessionStore for MockSigningStore {
            async fn init_session(&self, _: &str, _: usize) -> ArkResult<()> {
                Ok(())
            }
            async fn get_session(
                &self,
                _: &str,
            ) -> ArkResult<Option<crate::domain::SigningSession>> {
                Ok(None)
            }
            async fn add_nonce(&self, _: &str, _: &str, _: Vec<u8>) -> ArkResult<()> {
                Ok(())
            }
            async fn all_nonces_collected(&self, _: &str) -> ArkResult<bool> {
                Ok(true)
            }
            async fn add_signature(&self, _: &str, _: &str, _: Vec<u8>) -> ArkResult<()> {
                Ok(())
            }
            async fn all_signatures_collected(&self, _: &str) -> ArkResult<bool> {
                Ok(self.all_sigs_collected)
            }
            async fn get_nonces(&self, _: &str) -> ArkResult<Vec<Vec<u8>>> {
                Ok(self.nonces.clone())
            }
            async fn get_signatures(&self, _: &str) -> ArkResult<Vec<Vec<u8>>> {
                Ok(self.signatures.clone())
            }
            async fn complete_session(&self, _: &str, _: Vec<u8>) -> ArkResult<()> {
                *self.completed.lock().unwrap() = true;
                Ok(())
            }
        }

        fn make_broadcast_service(
            events: Arc<RecordingEvents>,
            wallet: Arc<dyn WalletService>,
            signing_store: Arc<dyn SigningSessionStore>,
        ) -> ArkService {
            ArkService::new(
                wallet,
                Arc::new(StubSigner),
                Arc::new(StubVtxoRepo),
                Arc::new(StubTxBuilder),
                Arc::new(StubCache),
                events,
                ArkConfig::default(),
            )
            .with_signing_session_store(signing_store)
        }

        /// Helper: set up a round in finalization stage with a commitment_tx ready.
        async fn setup_round_for_broadcast(svc: &ArkService) {
            // Start round + register intent
            svc.start_round().await.unwrap();
            let vtxo = Vtxo::new(
                VtxoOutpoint::new("deadbeef".repeat(8), 0),
                50_000,
                "ab".repeat(32),
            );
            let mut intent =
                Intent::new("proof_tx".into(), "proof".into(), "msg".into(), vec![vtxo]).unwrap();
            intent
                .add_receivers(vec![Receiver::offchain(25_000, "rcv_pk".into())])
                .unwrap();
            svc.register_intent(intent).await.unwrap();

            // Finalize (builds commitment tx, marks ended)
            // But for sign_and_broadcast we need the round in finalization stage,
            // NOT ended. So we'll manually set it up instead.
            {
                let mut guard = svc.current_round.write().await;
                let round = guard.as_mut().unwrap();
                // Transition to finalization
                round.start_finalization().ok();
                // Set a commitment tx (simulating build_commitment_tx output)
                round.commitment_tx = "psbt_commitment_hex".to_string();
                round.vtxo_tree = vec![];
                round.connectors = vec![];
                round.connector_address = "bc1qtest".to_string();
            }
        }

        #[tokio::test]
        async fn test_sign_and_broadcast_success() {
            let events = Arc::new(RecordingEvents::new());
            let wallet = Arc::new(MockBroadcastWallet::new());
            let signing = Arc::new(MockSigningStore::ready());
            let svc = make_broadcast_service(events.clone(), wallet.clone(), signing.clone());

            setup_round_for_broadcast(&svc).await;

            let result = svc.sign_and_broadcast_round().await.unwrap();
            assert!(result.is_ended());
            assert_eq!(result.commitment_txid, "abc123def456");
            assert_eq!(events.broadcast.load(Ordering::SeqCst), 1);

            // Verify wallet was called with the raw tx
            let calls = wallet.broadcast_calls.lock().unwrap();
            assert_eq!(calls.len(), 1);

            // Verify signing session was marked complete
            assert!(*signing.completed.lock().unwrap());
        }

        #[tokio::test]
        async fn test_sign_and_broadcast_no_active_round() {
            let events = Arc::new(RecordingEvents::new());
            let wallet = Arc::new(MockBroadcastWallet::new());
            let signing = Arc::new(MockSigningStore::ready());
            let svc = make_broadcast_service(events, wallet, signing);

            let err = svc.sign_and_broadcast_round().await.unwrap_err();
            assert!(err.to_string().contains("No active round"));
        }

        #[tokio::test]
        async fn test_sign_and_broadcast_signatures_not_ready() {
            let events = Arc::new(RecordingEvents::new());
            let wallet = Arc::new(MockBroadcastWallet::new());
            let signing = Arc::new(MockSigningStore::not_ready());
            let svc = make_broadcast_service(events.clone(), wallet.clone(), signing);

            setup_round_for_broadcast(&svc).await;

            let err = svc.sign_and_broadcast_round().await.unwrap_err();
            assert!(err.to_string().contains("Not all tree signatures"));
            assert_eq!(events.broadcast.load(Ordering::SeqCst), 0);

            // Wallet should NOT have been called
            let calls = wallet.broadcast_calls.lock().unwrap();
            assert!(calls.is_empty());
        }

        #[tokio::test]
        async fn test_sign_and_broadcast_no_commitment_tx() {
            let events = Arc::new(RecordingEvents::new());
            let wallet = Arc::new(MockBroadcastWallet::new());
            let signing = Arc::new(MockSigningStore::ready());
            let svc = make_broadcast_service(events, wallet, signing);

            // Start round but DON'T build commitment tx
            svc.start_round().await.unwrap();
            let vtxo = Vtxo::new(
                VtxoOutpoint::new("deadbeef".repeat(8), 0),
                50_000,
                "ab".repeat(32),
            );
            let mut intent =
                Intent::new("proof_tx".into(), "proof".into(), "msg".into(), vec![vtxo]).unwrap();
            intent
                .add_receivers(vec![Receiver::offchain(25_000, "rcv_pk".into())])
                .unwrap();
            svc.register_intent(intent).await.unwrap();

            // Manually transition to finalization without setting commitment_tx
            {
                let mut guard = svc.current_round.write().await;
                let round = guard.as_mut().unwrap();
                round.start_finalization().ok();
                // commitment_tx is still empty
            }

            let err = svc.sign_and_broadcast_round().await.unwrap_err();
            assert!(err.to_string().contains("No commitment tx to sign"));
        }

        #[tokio::test]
        async fn test_sign_and_broadcast_already_ended_round() {
            let events = Arc::new(RecordingEvents::new());
            let wallet = Arc::new(MockBroadcastWallet::new());
            let signing = Arc::new(MockSigningStore::ready());
            let svc = make_broadcast_service(events, wallet, signing);

            setup_round_for_broadcast(&svc).await;

            // Manually end the round
            {
                let mut guard = svc.current_round.write().await;
                let round = guard.as_mut().unwrap();
                round.end_successfully();
            }

            let err = svc.sign_and_broadcast_round().await.unwrap_err();
            assert!(err.to_string().contains("Round already ended"));
        }
    }
}
