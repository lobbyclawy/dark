//! Application services — aligned with Go arkd's `application.Service`

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, instrument};

use crate::domain::ban::BanReason;
use crate::domain::config_service::StaticConfigService;
use crate::domain::conviction::Conviction;
use crate::domain::ForfeitRecord;
use crate::domain::InMemoryBanRepository;
use crate::domain::{
    BoardingTransaction, CollaborativeExitRequest, Exit, ExitSummary, ExitType, Intent, Round,
    RoundStage, UnilateralExitRequest, Vtxo, VtxoOutpoint, DEFAULT_BOARDING_EXIT_DELAY,
    DEFAULT_CHECKPOINT_EXIT_DELAY, DEFAULT_MAX_INTENTS, DEFAULT_MAX_TX_WEIGHT, DEFAULT_MIN_INTENTS,
    DEFAULT_PUBLIC_UNILATERAL_EXIT_DELAY, DEFAULT_SESSION_DURATION_SECS,
    DEFAULT_UNILATERAL_EXIT_DELAY, DEFAULT_UTXO_MAX_AMOUNT, DEFAULT_UTXO_MIN_AMOUNT,
    DEFAULT_VTXO_EXPIRY_SECS, MIN_VTXO_AMOUNT_SATS,
};
use crate::domain::{FeeProgram, OffchainTx, VtxoInput, VtxoOutput};
use crate::error::{ArkError, ArkResult};
use crate::ports::{
    ArkEvent, AssetRepository, BanRepository, BlockchainScanner, BoardingRepository, CacheService,
    CheckpointRepository, ConfigService, ConfirmationStore, ConvictionRepository, EventPublisher,
    FeeManagerService, ForfeitRepository, FraudDetector, IndexerService, IndexerStats,
    NoopAssetRepository, NoopBlockchainScanner, NoopBoardingRepository, NoopCheckpointRepository,
    NoopConfirmationStore, NoopConvictionRepository, NoopFeeManager, NoopForfeitRepository,
    NoopFraudDetector, NoopIndexerService, NoopOffchainTxRepository, NoopSweepService,
    OffchainTxRepository, SignerService, SigningSessionStore, SweepService, TxBuilder,
    VtxoRepository, WalletService,
};

/// Round timing configuration (matches Go arkd's `roundTiming`)
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
            // Go arkd defaults: sessionDuration is 10s, split as:
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
    /// Unilateral exit delay (blocks)
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
    /// CSV delay for public unilateral exits (blocks)
    pub public_unilateral_exit_delay: u32,
    /// CSV delay for boarding inputs (blocks)
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
    notifier: Arc<dyn crate::ports::Notifier>,
    config: ArkConfig,
    config_service: Arc<dyn ConfigService>,
    current_round: RwLock<Option<Round>>,
    /// Active exits indexed by ID
    /// TODO(#9): Back with SQLite persistence to survive restarts
    exits: RwLock<std::collections::HashMap<uuid::Uuid, Exit>>,
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
            notifier: Arc::new(crate::ports::NoopNotifier),
            config,
            config_service,
            current_round: RwLock::new(None),
            exits: RwLock::new(std::collections::HashMap::new()),
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

    /// Set a custom notifier for VTXO expiry notifications (Issue #247).
    pub fn with_notifier(mut self, notifier: Arc<dyn crate::ports::Notifier>) -> Self {
        self.notifier = notifier;
        self
    }

    /// Get an asset by its ID from the asset repository.
    pub async fn get_asset(&self, asset_id: &str) -> ArkResult<Option<crate::domain::Asset>> {
        self.asset_repo.get_asset(asset_id).await
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

    /// Get the Ark configuration.
    pub fn config(&self) -> &ArkConfig {
        &self.config
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
        let forfeit_pubkey = self.wallet.get_forfeit_pubkey().await?;
        let dust = self.wallet.get_dust_amount().await?;

        // Derive forfeit address from the forfeit pubkey (P2TR)
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

        // Derive checkpoint tapscript from the signer pubkey (hex-encoded OP_CHECKSIG script)
        let checkpoint_tapscript = format!("20{}ac", signer_pubkey);

        Ok(ServiceInfo {
            signer_pubkey: signer_pubkey.to_string(),
            forfeit_pubkey: forfeit_pubkey.to_string(),
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

        // Collect intents
        let intents: Vec<Intent> = round.intents.values().cloned().collect();

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

        // Collect pending boarding inputs
        let boarding_txs = self.claim_boarding_inputs().await.unwrap_or_default();
        let boarding_inputs: Vec<crate::ports::BoardingInput> = boarding_txs
            .iter()
            .filter_map(|bt| {
                let txid = bt.funding_txid.as_ref()?;
                let vout = bt.funding_vout?;
                Some(crate::ports::BoardingInput {
                    outpoint: VtxoOutpoint::new(txid.to_string(), vout),
                    amount: bt.amount.to_sat(),
                })
            })
            .collect();
        info!(
            boarding_count = boarding_inputs.len(),
            "Including boarding inputs in round"
        );

        // Build commitment transaction
        let signer_pubkey = self.signer.get_pubkey().await?;
        let result = self
            .tx_builder
            .build_commitment_tx(&signer_pubkey, &intents, &boarding_inputs)
            .await?;

        // Store results on the round
        round.commitment_tx = result.commitment_tx.clone();
        round.vtxo_tree = result.vtxo_tree;
        round.connectors = result.connectors;
        round.connector_address = result.connector_address;

        // Mark round as successfully ended
        round.end_successfully();

        info!(
            round_id = %round.id,
            intent_count = intents.len(),
            "Round finalized with commitment tx"
        );

        self.events
            .publish_event(ArkEvent::RoundFinalized {
                round_id: round.id.clone(),
                commitment_tx: round.commitment_tx.clone(),
                timestamp: round.ending_timestamp,
                vtxo_count: round.vtxo_tree.len() as u32,
            })
            .await?;

        Ok(round.clone())
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
        // (participants need this to verify before confirming)
        let signer_pubkey = self.signer.get_pubkey().await?;
        let intents: Vec<Intent> = round.intents.values().cloned().collect();
        let boarding_inputs: Vec<crate::ports::BoardingInput> = vec![]; // TODO: include boarding
        let result = self
            .tx_builder
            .build_commitment_tx(&signer_pubkey, &intents, &boarding_inputs)
            .await?;

        // Store the unsigned tree on the round for later
        round.vtxo_tree = result.vtxo_tree;
        round.connectors = result.connectors;
        round.connector_address = result.connector_address.clone();

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

            if round.is_ended() {
                return Err(ArkError::Internal("Round already ended".to_string()));
            }

            round.id.clone()
        };

        // Mark confirmed in the domain model
        {
            let mut guard = self.current_round.write().await;
            let round = guard.as_mut().unwrap();
            round
                .confirm_intent(intent_id)
                .map_err(|e| ArkError::Internal(e.to_string()))?;
        }

        // Mark confirmed in the store
        self.confirmation_store
            .confirm(&round_id, intent_id)
            .await?;

        let timestamp = chrono::Utc::now().timestamp();

        info!(round_id = %round_id, intent_id, "Intent confirmed");

        self.events
            .publish_event(ArkEvent::IntentConfirmed {
                round_id,
                intent_id: intent_id.to_string(),
                timestamp,
            })
            .await?;

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
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;
        for input in &intent.inputs {
            if input.amount < self.config.min_vtxo_amount_sats {
                return Err(ArkError::AmountTooSmall {
                    amount: input.amount,
                    minimum: self.config.min_vtxo_amount_sats,
                });
            }
        }
        // TODO(#246): validate boarding UTXOs exist on-chain via BlockchainScanner
        // For each boarding input in the intent, verify the UTXO is unspent:
        // for input in &intent.inputs {
        //     if !self.scanner.is_utxo_unspent(&input.outpoint).await? {
        //         return Err(ArkError::Internal(format!(
        //             "Boarding UTXO {}:{} is already spent on-chain",
        //             input.outpoint.txid, input.outpoint.vout
        //         )));
        //     }
        // }

        let id = intent.id.clone();
        round.register_intent(intent).map_err(ArkError::Internal)?;
        info!(intent_id = %id, "Intent registered");
        Ok(id)
    }

    /// Get VTXOs for a pubkey
    pub async fn get_vtxos_for_pubkey(&self, pubkey: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
        self.vtxo_repo.get_all_vtxos_for_pubkey(pubkey).await
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

        // Calculate claimable height
        let block_time = self.wallet.get_current_block_time().await?;
        let claimable_height = block_time.height as u32 + self.config.unilateral_exit_delay;

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
        let sweeper =
            crate::sweeper::Sweeper::new(Arc::clone(&self.vtxo_repo), Arc::clone(&self.events))
                .with_notifier(Arc::clone(&self.notifier));
        sweeper.sweep_expired(now).await
    }

    /// Sweep pending checkpoints whose exit delay has elapsed.
    pub async fn sweep_checkpoints(&self) -> ArkResult<u32> {
        let pending = self.checkpoint_repo.list_pending().await?;
        let mut swept = 0u32;
        for mut cp in pending {
            // TODO: verify exit_delay elapsed via block height check
            cp.mark_swept();
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

    /// Get a pending offchain transaction by ID.
    pub async fn get_offchain_tx(&self, tx_id: &str) -> ArkResult<Option<OffchainTx>> {
        self.offchain_tx_repo.get(tx_id).await
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

    // ── Go arkd parity methods (#159) ───────────────────────────────

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

    /// Submit MuSig2 tree nonces for the current batch.
    ///
    /// Called by cosigners during the tree signing phase.
    #[instrument(skip(self, nonces))]
    pub async fn submit_tree_nonces(
        &self,
        batch_id: &str,
        pubkey: &str,
        nonces: Vec<u8>,
    ) -> ArkResult<()> {
        // Verify round exists and is in finalization stage
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
        drop(guard);

        // Store nonces in the signing session store
        self.signing_session_store
            .add_nonce(batch_id, pubkey, nonces)
            .await?;

        info!(batch_id, pubkey, "Tree nonces submitted");

        // Check if all nonces collected
        if self
            .signing_session_store
            .all_nonces_collected(batch_id)
            .await?
        {
            info!(batch_id, "All tree nonces collected");
            self.events
                .publish_event(ArkEvent::TreeNoncesCollected {
                    round_id: batch_id.to_string(),
                })
                .await?;
        }

        Ok(())
    }

    /// Submit MuSig2 tree partial signatures for the current batch.
    ///
    /// Called by cosigners after nonces have been aggregated.
    #[instrument(skip(self, signatures))]
    pub async fn submit_tree_signatures(
        &self,
        batch_id: &str,
        pubkey: &str,
        signatures: Vec<u8>,
    ) -> ArkResult<()> {
        // Verify round exists and is in finalization stage
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
        drop(guard);

        // Store signatures in the signing session store
        self.signing_session_store
            .add_signature(batch_id, pubkey, signatures)
            .await?;

        info!(batch_id, pubkey, "Tree signatures submitted");

        // Check if all signatures collected
        if self
            .signing_session_store
            .all_signatures_collected(batch_id)
            .await?
        {
            info!(batch_id, "All tree signatures collected");
            self.events
                .publish_event(ArkEvent::TreeSignaturesCollected {
                    round_id: batch_id.to_string(),
                })
                .await?;
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
    #[instrument(skip(self, signed_forfeit_txs))]
    pub async fn submit_signed_forfeit_txs(
        &self,
        batch_id: &str,
        signed_forfeit_txs: Vec<String>,
    ) -> ArkResult<()> {
        // Verify round exists and is in finalization stage
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
        drop(guard);

        // Store forfeit transactions
        for (idx, tx_hex) in signed_forfeit_txs.iter().enumerate() {
            let vtxo_id = format!("{}:{}", batch_id, idx);
            self.forfeit_repo
                .store_forfeit(ForfeitRecord::new(
                    batch_id.to_string(),
                    vtxo_id,
                    tx_hex.clone(),
                ))
                .await?;
        }

        info!(
            batch_id,
            count = signed_forfeit_txs.len(),
            "Signed forfeit txs submitted"
        );

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
    /// CSV delay for public unilateral exits (blocks)
    pub public_unilateral_exit_delay: u32,
    /// CSV delay for boarding inputs (blocks)
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
            _: &[Intent],
            _: &[BoardingInput],
        ) -> ArkResult<CommitmentTxResult> {
            Ok(CommitmentTxResult {
                commitment_tx: "stub_commitment_tx".to_string(),
                vtxo_tree: vec![],
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
        assert_eq!(config.boarding_exit_delay, 512);
        assert_eq!(config.max_tx_weight, 400_000);
    }

    #[tokio::test]
    async fn test_finalize_round_with_intents() {
        let events = Arc::new(RecordingEvents::new());
        let svc = make_service(events.clone());

        // Start a round
        let round = svc.start_round().await.unwrap();
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
        svc.register_intent(intent).await.unwrap();

        // Finalize
        let finalized = svc.finalize_round().await.unwrap();
        assert!(finalized.is_ended());
        assert_eq!(finalized.commitment_tx, "stub_commitment_tx");
        assert_eq!(events.finalized.load(Ordering::SeqCst), 1);
        assert!(finalized.fail_reason.is_empty());
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
        // ── Offchain transaction tests ──────────────────────────────────

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
            async fn update_stage(&self, id: &str, stage: &OffchainTxStage) -> ArkResult<()> {
                if let Some(tx) = self.txs.lock().await.get_mut(id) {
                    tx.stage = stage.clone();
                }
                Ok(())
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
        use crate::domain::{Receiver, SigningSession, SigningSessionStatus, Vtxo};
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
