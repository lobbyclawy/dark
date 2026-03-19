//! Ports - External interfaces for dependency inversion
//!
//! Aligns with Go arkd port interfaces.

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

use crate::application::ArkConfig;
use crate::domain::{
    Asset, AssetIssuance, BanReason, BanRecord, BoardingTransaction, CheckpointTx, Conviction,
    FlatTxTree, ForfeitRecord, Intent, OffchainTx, OffchainTxStage, Round, Vtxo, VtxoOutpoint,
};
use crate::error::{ArkError, ArkResult};

// ---------------------------------------------------------------------------
// Indexer service
// ---------------------------------------------------------------------------

/// Aggregated statistics for the indexer.
#[derive(Debug, Default, Clone)]
pub struct IndexerStats {
    /// Total number of VTXOs tracked.
    pub total_vtxos: u64,
    /// Total number of rounds tracked.
    pub total_rounds: u64,
    /// Total number of forfeit records tracked.
    pub total_forfeits: u64,
    /// Total sats locked in active VTXOs.
    pub total_sats_locked: u64,
}

/// Unified query interface for VTXOs, rounds, and forfeit records.
///
/// Mirrors Go arkd's `IndexerService` — provides read-only, cross-repository
/// querying without exposing the underlying repository details.
#[async_trait]
pub trait IndexerService: Send + Sync {
    /// List VTXOs, optionally filtered by owner pubkey.
    async fn list_vtxos(&self, pubkey: Option<&str>) -> ArkResult<Vec<Vtxo>>;
    /// Get a single VTXO by its outpoint string (`txid:vout`).
    async fn get_vtxo(&self, vtxo_id: &str) -> ArkResult<Option<Vtxo>>;
    /// List rounds with pagination.
    async fn list_rounds(&self, offset: u32, limit: u32) -> ArkResult<Vec<Round>>;
    /// Get a single round by ID.
    async fn get_round(&self, round_id: &str) -> ArkResult<Option<Round>>;
    /// List forfeit records for a given round.
    async fn list_forfeits(&self, round_id: &str) -> ArkResult<Vec<ForfeitRecord>>;
    /// Get aggregated statistics.
    async fn get_stats(&self) -> ArkResult<IndexerStats>;
    /// Look up a round by its commitment transaction ID.
    async fn get_round_by_commitment_txid(&self, _txid: &str) -> ArkResult<Option<Round>> {
        Ok(None)
    }
}

/// No-op indexer that returns empty/default for every query.
pub struct NoopIndexerService;

#[async_trait]
impl IndexerService for NoopIndexerService {
    async fn list_vtxos(&self, _pubkey: Option<&str>) -> ArkResult<Vec<Vtxo>> {
        Ok(vec![])
    }
    async fn get_vtxo(&self, _vtxo_id: &str) -> ArkResult<Option<Vtxo>> {
        Ok(None)
    }
    async fn list_rounds(&self, _offset: u32, _limit: u32) -> ArkResult<Vec<Round>> {
        Ok(vec![])
    }
    async fn get_round(&self, _round_id: &str) -> ArkResult<Option<Round>> {
        Ok(None)
    }
    async fn list_forfeits(&self, _round_id: &str) -> ArkResult<Vec<ForfeitRecord>> {
        Ok(vec![])
    }
    async fn get_stats(&self) -> ArkResult<IndexerStats> {
        Ok(IndexerStats::default())
    }
    async fn get_round_by_commitment_txid(&self, _txid: &str) -> ArkResult<Option<Round>> {
        Ok(None)
    }
}

/// Wallet service interface
#[async_trait]
pub trait WalletService: Send + Sync {
    /// Check wallet status
    async fn status(&self) -> ArkResult<WalletStatus>;
    /// Get the forfeit pubkey
    async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey>;
    /// Derive a connector address
    async fn derive_connector_address(&self) -> ArkResult<String>;
    /// Sign a PSBT transaction
    async fn sign_transaction(&self, partial_tx: &str, extract_raw: bool) -> ArkResult<String>;
    /// Select UTXOs for a given amount
    async fn select_utxos(
        &self,
        amount: u64,
        confirmed_only: bool,
    ) -> ArkResult<(Vec<TxInput>, u64)>;
    /// Broadcast a transaction
    async fn broadcast_transaction(&self, txs: Vec<String>) -> ArkResult<String>;
    /// Get current fee rate (sat/vB)
    async fn fee_rate(&self) -> ArkResult<u64>;
    /// Get the current block timestamp
    async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp>;
    /// Get dust amount
    async fn get_dust_amount(&self) -> ArkResult<u64>;
    /// Get outpoint status
    async fn get_outpoint_status(&self, outpoint: &VtxoOutpoint) -> ArkResult<bool>;

    // ── Operator wallet management (gRPC WalletService) ──────────────

    /// Generate a new BIP-39 mnemonic seed phrase.
    async fn gen_seed(&self) -> ArkResult<String> {
        Err(ArkError::WalletError("gen_seed not implemented".into()))
    }

    /// Create / initialise a wallet from a mnemonic and password.
    async fn create_wallet(&self, _mnemonic: &str, _password: &str) -> ArkResult<()> {
        Err(ArkError::WalletError(
            "create_wallet not implemented".into(),
        ))
    }

    /// Restore a wallet from a mnemonic and password.
    async fn restore_wallet(&self, _mnemonic: &str, _password: &str) -> ArkResult<()> {
        Err(ArkError::WalletError(
            "restore_wallet not implemented".into(),
        ))
    }

    /// Unlock the wallet with a password.
    async fn unlock(&self, _password: &str) -> ArkResult<()> {
        Err(ArkError::WalletError("unlock not implemented".into()))
    }

    /// Lock the wallet.
    async fn lock(&self) -> ArkResult<()> {
        Err(ArkError::WalletError("lock not implemented".into()))
    }

    /// Derive a new receive address.
    async fn derive_address(&self) -> ArkResult<DerivedAddress> {
        Err(ArkError::WalletError(
            "derive_address not implemented".into(),
        ))
    }

    /// Get the wallet balance.
    async fn get_balance(&self) -> ArkResult<WalletBalance> {
        Err(ArkError::WalletError("get_balance not implemented".into()))
    }

    /// Send funds on-chain to the given address and amount (sats).
    /// Returns the broadcast txid.
    async fn withdraw(&self, _address: &str, _amount_sats: u64) -> ArkResult<String> {
        Err(ArkError::WalletError("withdraw not implemented".into()))
    }
}

/// A derived wallet address with its derivation path.
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    /// The address string
    pub address: String,
    /// The BIP derivation path
    pub derivation_path: String,
}

/// Wallet balance breakdown.
#[derive(Debug, Clone)]
pub struct WalletBalance {
    /// Confirmed on-chain balance in satoshis
    pub confirmed: u64,
    /// Unconfirmed (pending) balance in satoshis
    pub unconfirmed: u64,
    /// Balance locked in pending transactions
    pub locked: u64,
}

/// Wallet status
#[derive(Debug, Clone)]
pub struct WalletStatus {
    /// Initialized
    pub initialized: bool,
    /// Unlocked
    pub unlocked: bool,
    /// Synced
    pub synced: bool,
}

/// Transaction input
#[derive(Debug, Clone)]
pub struct TxInput {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount
    pub amount: u64,
    /// Script
    pub script: String,
}

/// Block timestamp
#[derive(Debug, Clone)]
pub struct BlockTimestamp {
    /// Height
    pub height: u64,
    /// Timestamp
    pub timestamp: i64,
}

/// Signer service
#[async_trait]
pub trait SignerService: Send + Sync {
    /// Get pubkey
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey>;
    /// Sign PSBT
    async fn sign_transaction(&self, partial_tx: &str, extract_raw: bool) -> ArkResult<String>;
}

/// Input for sweep transactions.
#[derive(Debug, Clone)]
pub struct SweepInput {
    /// Transaction ID of the output to sweep
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Tapscript paths for spending
    pub tapscripts: Vec<String>,
}

/// A sweepable batch output from a VTXO tree.
#[derive(Debug, Clone)]
pub struct SweepableOutput {
    /// The outpoint (txid:vout)
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Relative locktime (CSV delay in blocks) for expiry
    pub csv_delay: u32,
    /// Tapscript paths for spending
    pub tapscripts: Vec<String>,
}

/// Signed boarding input with taproot script-spend signatures.
#[derive(Debug, Clone)]
pub struct SignedBoardingInput {
    /// Serialized taproot script-spend signatures (hex-encoded)
    pub signatures: Vec<String>,
    /// Leaf script used for signing (hex-encoded)
    pub leaf_script: String,
}

/// Transaction builder
#[async_trait]
pub trait TxBuilder: Send + Sync {
    /// Build commitment tx
    async fn build_commitment_tx(
        &self,
        signer_pubkey: &XOnlyPublicKey,
        intents: &[Intent],
        boarding_inputs: &[BoardingInput],
    ) -> ArkResult<CommitmentTxResult>;

    /// Verify forfeit txs
    async fn verify_forfeit_txs(
        &self,
        vtxos: &[Vtxo],
        connectors: &FlatTxTree,
        txs: &[String],
    ) -> ArkResult<Vec<ValidForfeitTx>>;

    /// Build a sweep transaction from the given inputs.
    /// Returns (txid, signed_sweep_tx_hex).
    async fn build_sweep_tx(&self, inputs: &[SweepInput]) -> ArkResult<(String, String)>;

    /// Get sweepable batch outputs from a VTXO tree.
    /// Returns `None` if no outputs are sweepable.
    async fn get_sweepable_batch_outputs(
        &self,
        vtxo_tree: &FlatTxTree,
    ) -> ArkResult<Option<SweepableOutput>>;

    /// Finalize a PSBT and extract the raw transaction hex.
    async fn finalize_and_extract(&self, tx: &str) -> ArkResult<String>;

    /// Verify VTXO tapscript signatures in a PSBT.
    /// If `must_include_signer` is true, the ASP's signature must be present.
    async fn verify_vtxo_tapscript_sigs(
        &self,
        tx: &str,
        must_include_signer: bool,
    ) -> ArkResult<bool>;

    /// Verify boarding tapscript signatures.
    /// Returns a map of input index → signed boarding input info.
    async fn verify_boarding_tapscript_sigs(
        &self,
        signed_tx: &str,
        commitment_tx: &str,
    ) -> ArkResult<std::collections::HashMap<u32, SignedBoardingInput>>;
}

/// Commitment tx result
#[derive(Debug, Clone)]
pub struct CommitmentTxResult {
    /// Commitment tx (PSBT)
    pub commitment_tx: String,
    /// VTXO tree
    pub vtxo_tree: FlatTxTree,
    /// Connector address
    pub connector_address: String,
    /// Connectors
    pub connectors: FlatTxTree,
}

/// Boarding input
#[derive(Debug, Clone)]
pub struct BoardingInput {
    /// Outpoint
    pub outpoint: VtxoOutpoint,
    /// Amount
    pub amount: u64,
}

/// Repository for persisting and querying boarding transactions.
#[async_trait]
pub trait BoardingRepository: Send + Sync {
    /// Store a new boarding transaction.
    async fn register_boarding(&self, tx: BoardingTransaction) -> ArkResult<()>;
    /// Get all funded (pending) boarding transactions not yet included in a round.
    async fn get_pending_boarding(&self) -> ArkResult<Vec<BoardingTransaction>>;
    /// Mark a boarding transaction as claimed (included in a round).
    async fn mark_claimed(&self, id: &str) -> ArkResult<()>;
}

/// No-op boarding repository for dev/test environments.
pub struct NoopBoardingRepository;

#[async_trait]
impl BoardingRepository for NoopBoardingRepository {
    async fn register_boarding(&self, _tx: BoardingTransaction) -> ArkResult<()> {
        Ok(())
    }
    async fn get_pending_boarding(&self) -> ArkResult<Vec<BoardingTransaction>> {
        Ok(vec![])
    }
    async fn mark_claimed(&self, _id: &str) -> ArkResult<()> {
        Ok(())
    }
}

/// Validated forfeit tx
#[derive(Debug, Clone)]
pub struct ValidForfeitTx {
    /// Tx
    pub tx: String,
    /// Connector
    pub connector: VtxoOutpoint,
}

/// VTXO repository
#[async_trait]
pub trait VtxoRepository: Send + Sync {
    /// Add VTXOs
    async fn add_vtxos(&self, vtxos: &[Vtxo]) -> ArkResult<()>;
    /// Get VTXOs
    async fn get_vtxos(&self, outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>>;
    /// Get all for pubkey
    async fn get_all_vtxos_for_pubkey(&self, pubkey: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)>;
    /// Spend VTXOs
    async fn spend_vtxos(&self, spent: &[(VtxoOutpoint, String)], ark_txid: &str) -> ArkResult<()>;
    /// Find expired VTXOs eligible for sweep
    ///
    /// Returns VTXOs where expires_at < before_timestamp and not spent/swept/unrolled.
    async fn find_expired_vtxos(&self, before_timestamp: i64) -> ArkResult<Vec<Vtxo>> {
        // Default implementation returns empty — override in concrete repos
        let _ = before_timestamp;
        Ok(Vec::new())
    }
}

/// Round repository
#[async_trait]
pub trait RoundRepository: Send + Sync {
    /// Save/update round
    async fn add_or_update_round(&self, round: &Round) -> ArkResult<()>;
    /// Get by ID
    async fn get_round_with_id(&self, id: &str) -> ArkResult<Option<Round>>;
    /// Get stats
    async fn get_round_stats(
        &self,
        commitment_txid: &str,
    ) -> ArkResult<Option<crate::domain::RoundStats>>;
    /// Confirm a specific intent within a round
    async fn confirm_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<()>;
    /// Get intent IDs that have not yet confirmed in a round
    async fn get_pending_confirmations(&self, round_id: &str) -> ArkResult<Vec<String>>;
    /// Look up a round by its commitment transaction ID.
    /// Default returns None; SQLite/Postgres repos override with a real query.
    async fn get_round_by_commitment_txid(&self, _txid: &str) -> ArkResult<Option<Round>> {
        Ok(None)
    }
}

/// Offchain transaction repository
#[async_trait]
pub trait OffchainTxRepository: Send + Sync {
    /// Create a new offchain transaction
    async fn create(&self, tx: &OffchainTx) -> ArkResult<()>;
    /// Get an offchain transaction by ID
    async fn get(&self, id: &str) -> ArkResult<Option<OffchainTx>>;
    /// Get all pending (Requested or Accepted) offchain transactions
    async fn get_pending(&self) -> ArkResult<Vec<OffchainTx>>;
    /// Update the stage of an offchain transaction
    async fn update_stage(&self, id: &str, stage: &OffchainTxStage) -> ArkResult<()>;
}

/// Fee estimation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FeeStrategy {
    /// Conservative: higher confirmation target (6 blocks), cheaper fee
    Conservative,
    /// Economical: lower confirmation target (1 block), faster confirmation
    Economical,
    /// Custom: explicit fee rate in sats/vbyte
    Custom(u64),
}

/// Fee manager — estimates fee rates for transactions
#[async_trait]
pub trait FeeManager: Send + Sync {
    /// Estimate fee rate in sat/vbyte for the given strategy.
    async fn estimate_fee_rate(&self, strategy: FeeStrategy) -> ArkResult<u64>;
    /// Invalidate cached estimate.
    async fn invalidate_cache(&self) -> ArkResult<()>;
}

/// Fee manager service — calculates fees for specific transaction types.
///
/// Unlike [`FeeManager`] which estimates raw fee rates, this trait provides
/// higher-level fee calculations for boarding, transfer, and round transactions.
#[async_trait]
pub trait FeeManagerService: Send + Sync {
    /// Calculate the fee for a boarding (onboarding) transaction
    async fn boarding_fee(&self, amount_sats: u64) -> ArkResult<u64>;
    /// Calculate the fee for a VTXO transfer
    async fn transfer_fee(&self, amount_sats: u64) -> ArkResult<u64>;
    /// Calculate the fee for a round participation
    async fn round_fee(&self, vtxo_count: u32) -> ArkResult<u64>;
    /// Get the current fee rate in sat/vbyte
    async fn current_fee_rate(&self) -> ArkResult<u64>;

    /// Compute intent fees based on transaction weight.
    ///
    /// Estimates the fee for an intent by computing the virtual size (vbytes)
    /// from the number of boarding inputs, VTXO inputs, on-chain outputs,
    /// and off-chain outputs, then multiplying by the fee rate.
    ///
    /// Mirrors Go arkd's `FeeManager.ComputeIntentFees`.
    async fn compute_intent_fees(
        &self,
        boarding_inputs: &[BoardingInput],
        vtxo_inputs: &[Vtxo],
        onchain_outputs: usize,
        offchain_outputs: usize,
    ) -> ArkResult<u64> {
        // Default: fall back to round_fee with total output count
        let total = onchain_outputs as u32
            + offchain_outputs as u32
            + boarding_inputs.len() as u32
            + vtxo_inputs.len() as u32;
        self.round_fee(total).await
    }
}

/// No-op fee manager service that returns zero fees (fee_rate=1).
///
/// Useful for testing or when fee management is not needed.
pub struct NoopFeeManager;

#[async_trait]
impl FeeManagerService for NoopFeeManager {
    async fn boarding_fee(&self, _amount_sats: u64) -> ArkResult<u64> {
        Ok(0)
    }
    async fn transfer_fee(&self, _amount_sats: u64) -> ArkResult<u64> {
        Ok(0)
    }
    async fn round_fee(&self, _vtxo_count: u32) -> ArkResult<u64> {
        Ok(0)
    }
    async fn current_fee_rate(&self) -> ArkResult<u64> {
        Ok(1)
    }
}

/// Cache service
#[async_trait]
pub trait CacheService: Send + Sync {
    /// Set value
    async fn set(&self, key: &str, value: &[u8], ttl_seconds: Option<u64>) -> ArkResult<()>;
    /// Get value
    async fn get(&self, key: &str) -> ArkResult<Option<Vec<u8>>>;
    /// Delete value
    async fn delete(&self, key: &str) -> ArkResult<bool>;
}

// Re-export ArkEvent from domain for backward compatibility
pub use crate::domain::ArkEvent;

/// Event publisher
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish event
    async fn publish_event(&self, event: ArkEvent) -> ArkResult<()>;
    /// Subscribe
    async fn subscribe(&self) -> ArkResult<tokio::sync::broadcast::Receiver<ArkEvent>>;
}

/// Simple [`EventPublisher`] that logs events via `tracing` and broadcasts
/// them through a [`tokio::sync::broadcast`] channel.
pub struct LoggingEventPublisher {
    sender: tokio::sync::broadcast::Sender<ArkEvent>,
}

impl LoggingEventPublisher {
    /// Create a new publisher with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(capacity);
        Self { sender }
    }
}

#[async_trait]
impl EventPublisher for LoggingEventPublisher {
    async fn publish_event(&self, event: ArkEvent) -> ArkResult<()> {
        tracing::info!(kind = event.kind(), "ArkEvent published");
        let _ = self.sender.send(event); // ignore if no subscribers
        Ok(())
    }

    async fn subscribe(&self) -> ArkResult<tokio::sync::broadcast::Receiver<ArkEvent>> {
        Ok(self.sender.subscribe())
    }
}

/// Ephemeral storage for active round state (survives process restart via Redis,
/// but does NOT need to be durable — round will fail/retry on crash).
#[async_trait]
pub trait LiveStore: Send + Sync {
    /// Store an intent for a round. Expires after `ttl_secs`.
    async fn set_intent(
        &self,
        round_id: &str,
        intent_id: &str,
        data: &[u8],
        ttl_secs: u64,
    ) -> ArkResult<()>;
    /// Get an intent by round and intent ID.
    async fn get_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<Option<Vec<u8>>>;
    /// List all intent IDs for a round.
    async fn list_intents(&self, round_id: &str) -> ArkResult<Vec<String>>;
    /// Delete an intent.
    async fn delete_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<()>;

    /// Store a nonce for a signing session.
    async fn set_nonce(
        &self,
        session_id: &str,
        pubkey: &str,
        nonce: &[u8],
        ttl_secs: u64,
    ) -> ArkResult<()>;
    /// Get a nonce by session and pubkey.
    async fn get_nonce(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>>;
    /// List all pubkeys that have submitted nonces for a session.
    async fn list_nonces(&self, session_id: &str) -> ArkResult<Vec<String>>;

    /// Store a partial signature.
    async fn set_partial_sig(
        &self,
        session_id: &str,
        pubkey: &str,
        sig: &[u8],
        ttl_secs: u64,
    ) -> ArkResult<()>;
    /// Get a partial signature by session and pubkey.
    async fn get_partial_sig(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>>;
    /// List all pubkeys that have submitted partial sigs for a session.
    async fn list_partial_sigs(&self, session_id: &str) -> ArkResult<Vec<String>>;
}

/// Notification when a watched script is spent on-chain.
#[derive(Debug, Clone)]
pub struct ScriptSpentEvent {
    /// The watched script pubkey bytes.
    pub script_pubkey: Vec<u8>,
    /// Transaction ID that spent the script.
    pub spending_txid: String,
    /// Block height where the spend was confirmed.
    pub block_height: u32,
}

/// Blockchain scanner for watching on-chain VTXO spends.
///
/// Implementations monitor the blockchain for transactions that spend
/// watched script pubkeys, enabling detection of unilateral exits and
/// forfeit transactions.
#[async_trait]
pub trait BlockchainScanner: Send + Sync {
    /// Start watching a script pubkey for on-chain spends.
    async fn watch_script(&self, script_pubkey: Vec<u8>) -> ArkResult<()>;
    /// Stop watching a script pubkey.
    async fn unwatch_script(&self, script_pubkey: &[u8]) -> ArkResult<()>;
    /// Get a receiver for script-spent notifications.
    fn notification_channel(&self) -> tokio::sync::broadcast::Receiver<ScriptSpentEvent>;
    /// Get current chain tip height.
    async fn tip_height(&self) -> ArkResult<u32>;

    /// Check if a UTXO is unspent on-chain.
    ///
    /// Used for boarding input validation — verifies the UTXO exists and
    /// has not been spent before accepting it in a round.
    ///
    /// Default implementation returns `Ok(true)` (optimistic, no on-chain check).
    async fn is_utxo_unspent(&self, _outpoint: &crate::domain::VtxoOutpoint) -> ArkResult<bool> {
        Ok(true)
    }
}

/// No-op blockchain scanner for dev/test environments within arkd-core.
///
/// Returns `Ok(())` for watch/unwatch, height 0, and an idle notification channel.
pub struct NoopBlockchainScanner {
    sender: tokio::sync::broadcast::Sender<ScriptSpentEvent>,
}

impl NoopBlockchainScanner {
    /// Create a new no-op blockchain scanner.
    pub fn new() -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(16);
        Self { sender }
    }
}

impl Default for NoopBlockchainScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockchainScanner for NoopBlockchainScanner {
    async fn watch_script(&self, _script_pubkey: Vec<u8>) -> ArkResult<()> {
        Ok(())
    }

    async fn unwatch_script(&self, _script_pubkey: &[u8]) -> ArkResult<()> {
        Ok(())
    }

    fn notification_channel(&self) -> tokio::sync::broadcast::Receiver<ScriptSpentEvent> {
        self.sender.subscribe()
    }

    async fn tip_height(&self) -> ArkResult<u32> {
        Ok(0)
    }
}

/// Asset repository — manages registered tokens, NFTs, and issuances on this ASP.
#[async_trait]
pub trait AssetRepository: Send + Sync {
    /// Store or update an asset.
    async fn store_asset(&self, asset: &Asset) -> ArkResult<()>;
    /// Get an asset by ID.
    async fn get_asset(&self, asset_id: &str) -> ArkResult<Option<Asset>>;
    /// List all registered assets.
    async fn list_assets(&self) -> ArkResult<Vec<Asset>>;
    /// Store an asset issuance record.
    async fn store_issuance(&self, issuance: &AssetIssuance) -> ArkResult<()>;
}

/// No-op asset repository (for testing / stubs).
pub struct NoopAssetRepository;

#[async_trait]
impl AssetRepository for NoopAssetRepository {
    async fn store_asset(&self, _asset: &Asset) -> ArkResult<()> {
        Ok(())
    }
    async fn get_asset(&self, _asset_id: &str) -> ArkResult<Option<Asset>> {
        Ok(None)
    }
    async fn list_assets(&self) -> ArkResult<Vec<Asset>> {
        Ok(vec![])
    }
    async fn store_issuance(&self, _issuance: &AssetIssuance) -> ArkResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Forfeit repository
// ---------------------------------------------------------------------------

/// Repository for persisting forfeit transactions.
#[async_trait]
pub trait ForfeitRepository: Send + Sync {
    /// Store a forfeit record.
    async fn store_forfeit(&self, record: ForfeitRecord) -> ArkResult<()>;
    /// Get a forfeit record by ID.
    async fn get_forfeit(&self, id: &str) -> ArkResult<Option<ForfeitRecord>>;
    /// List all forfeit records for a given round.
    async fn list_by_round(&self, round_id: &str) -> ArkResult<Vec<ForfeitRecord>>;
    /// Mark a forfeit record as validated.
    async fn mark_validated(&self, id: &str) -> ArkResult<()>;
}

/// No-op forfeit repository for dev/test environments.
pub struct NoopForfeitRepository;

#[async_trait]
impl ForfeitRepository for NoopForfeitRepository {
    async fn store_forfeit(&self, _record: ForfeitRecord) -> ArkResult<()> {
        Ok(())
    }
    async fn get_forfeit(&self, _id: &str) -> ArkResult<Option<ForfeitRecord>> {
        Ok(None)
    }
    async fn list_by_round(&self, _round_id: &str) -> ArkResult<Vec<ForfeitRecord>> {
        Ok(vec![])
    }
    async fn mark_validated(&self, _id: &str) -> ArkResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fraud detection
// ---------------------------------------------------------------------------

/// Detects and reacts to fraud (e.g. VTXO double-spend across rounds).
#[async_trait]
pub trait FraudDetector: Send + Sync {
    /// Check if a VTXO has been double-spent (used in two rounds).
    async fn detect_double_spend(&self, vtxo_id: &str, round_id: &str) -> ArkResult<bool>;
    /// React to detected fraud: broadcast forfeit tx.
    async fn react_to_fraud(&self, vtxo_id: &str, forfeit_tx_hex: &str) -> ArkResult<()>;
}

/// No-op fraud detector for dev/test environments.
pub struct NoopFraudDetector;

#[async_trait]
impl FraudDetector for NoopFraudDetector {
    async fn detect_double_spend(&self, vtxo_id: &str, _round_id: &str) -> ArkResult<bool> {
        tracing::debug!(vtxo_id, "NoopFraudDetector: skipping double-spend check");
        Ok(false)
    }
    async fn react_to_fraud(&self, vtxo_id: &str, _forfeit_tx_hex: &str) -> ArkResult<()> {
        tracing::warn!(
            vtxo_id,
            "NoopFraudDetector: would broadcast forfeit tx (stub)"
        );
        Ok(())
    }
}

/// No-op offchain tx repository (returns empty/Ok for all operations)
pub struct NoopOffchainTxRepository;

#[async_trait]
impl OffchainTxRepository for NoopOffchainTxRepository {
    async fn create(&self, _tx: &OffchainTx) -> ArkResult<()> {
        Ok(())
    }
    async fn get(&self, _id: &str) -> ArkResult<Option<OffchainTx>> {
        Ok(None)
    }
    async fn get_pending(&self) -> ArkResult<Vec<OffchainTx>> {
        Ok(vec![])
    }
    async fn update_stage(&self, _id: &str, _stage: &OffchainTxStage) -> ArkResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    fn _assert_object_safe<T: ?Sized>() {}

    #[test]
    fn test_traits_are_object_safe() {
        _assert_object_safe::<dyn WalletService>();
        _assert_object_safe::<dyn SignerService>();
        _assert_object_safe::<dyn VtxoRepository>();
        _assert_object_safe::<dyn RoundRepository>();
        _assert_object_safe::<dyn CacheService>();
        _assert_object_safe::<dyn OffchainTxRepository>();
        _assert_object_safe::<dyn LiveStore>();
        _assert_object_safe::<dyn BlockchainScanner>();
        _assert_object_safe::<dyn FeeManager>();
        _assert_object_safe::<dyn FeeManagerService>();
        _assert_object_safe::<dyn AssetRepository>();
        _assert_object_safe::<dyn BoardingRepository>();
        _assert_object_safe::<dyn AdminPort>();
        _assert_object_safe::<dyn ForfeitRepository>();
        _assert_object_safe::<dyn IntentsQueue>();
        _assert_object_safe::<dyn ForfeitTxsStore>();
        _assert_object_safe::<dyn ConfirmationStore>();
        _assert_object_safe::<dyn SigningSessionStore>();
        _assert_object_safe::<dyn CurrentRoundStore>();
        _assert_object_safe::<dyn FraudDetector>();
        _assert_object_safe::<dyn IndexerService>();
        _assert_object_safe::<dyn ConvictionRepository>();
        _assert_object_safe::<dyn BanRepository>();
        _assert_object_safe::<dyn TxDecoder>();
        _assert_object_safe::<dyn Unlocker>();
        _assert_object_safe::<dyn Alerts>();
    }

    #[tokio::test]
    async fn test_create_note_noop_returns_error() {
        let svc = NoopAdminService;
        let result = svc.create_note(50_000, "deadbeef").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("not implemented"),
            "expected 'not implemented' in: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_noop_indexer_returns_empty() {
        let svc = NoopIndexerService;
        assert!(svc.list_vtxos(None).await.unwrap().is_empty());
        assert!(svc.list_vtxos(Some("abc")).await.unwrap().is_empty());
        assert!(svc.get_vtxo("abc:0").await.unwrap().is_none());
        assert!(svc.list_rounds(0, 10).await.unwrap().is_empty());
        assert!(svc.get_round("r1").await.unwrap().is_none());
        assert!(svc.list_forfeits("r1").await.unwrap().is_empty());
    }

    #[test]
    fn test_indexer_stats_default() {
        let stats = IndexerStats::default();
        assert_eq!(stats.total_vtxos, 0);
        assert_eq!(stats.total_rounds, 0);
        assert_eq!(stats.total_forfeits, 0);
        assert_eq!(stats.total_sats_locked, 0);
    }

    #[tokio::test]
    async fn test_noop_asset_repo_list_empty() {
        let repo = NoopAssetRepository;
        let assets = repo.list_assets().await.unwrap();
        assert!(assets.is_empty());
        assert!(repo.get_asset("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_noop_blockchain_scanner_watch_unwatch() {
        let scanner = NoopBlockchainScanner::new();
        assert!(scanner.watch_script(vec![0xab, 0xcd]).await.is_ok());
        assert!(scanner.unwatch_script(&[0xab, 0xcd]).await.is_ok());
    }

    #[tokio::test]
    async fn test_noop_blockchain_scanner_tip_height() {
        let scanner = NoopBlockchainScanner::new();
        assert_eq!(scanner.tip_height().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_noop_blockchain_scanner_notification_channel() {
        let scanner = NoopBlockchainScanner::new();
        let _rx = scanner.notification_channel();
        // Channel created — no messages expected from noop
    }

    #[tokio::test]
    async fn test_noop_blockchain_scanner_as_trait_object() {
        let scanner: Arc<dyn BlockchainScanner> = Arc::new(NoopBlockchainScanner::new());
        let watch_result: ArkResult<()> = scanner.watch_script(vec![0x01, 0x02]).await;
        assert!(watch_result.is_ok());
        let unwatch_result: ArkResult<()> = scanner.unwatch_script(&[0x01, 0x02]).await;
        assert!(unwatch_result.is_ok());
        let height: u32 = scanner.tip_height().await.unwrap();
        assert_eq!(height, 0);
    }

    #[test]
    fn test_noop_blockchain_scanner_default() {
        let scanner = NoopBlockchainScanner::default();
        let _rx = scanner.notification_channel();
        // Default impl works
    }

    #[tokio::test]
    async fn test_noop_fee_manager_returns_zero() {
        let fm = NoopFeeManager;
        assert_eq!(fm.boarding_fee(100_000).await.unwrap(), 0);
        assert_eq!(fm.transfer_fee(50_000).await.unwrap(), 0);
        assert_eq!(fm.round_fee(10).await.unwrap(), 0);
        assert_eq!(fm.current_fee_rate().await.unwrap(), 1);
    }

    #[test]
    fn test_fee_manager_service_object_safe() {
        // Compile-time check that FeeManagerService is object-safe
        fn _assert<T: ?Sized>() {}
        _assert::<dyn FeeManagerService>();
    }

    #[tokio::test]
    async fn test_noop_tx_decoder_returns_error() {
        let decoder = NoopTxDecoder;
        let result = decoder.decode_tx("deadbeef").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("not implemented"),
            "expected 'not implemented' in: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_noop_tx_decoder_as_trait_object() {
        let decoder: Arc<dyn TxDecoder> = Arc::new(NoopTxDecoder);
        assert!(decoder.decode_tx("cafebabe").await.is_err());
    }

    #[tokio::test]
    async fn test_env_unlocker_missing_var() {
        // Ensure the env var is NOT set for this test
        std::env::remove_var("ARKD_WALLET_PASS");
        let unlocker = EnvUnlocker;
        let result = unlocker.get_password().await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("ARKD_WALLET_PASS"),
            "expected env var name in error: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_env_unlocker_with_var() {
        std::env::set_var("ARKD_WALLET_PASS", "test-password-123");
        let unlocker = EnvUnlocker;
        let password = unlocker.get_password().await.unwrap();
        assert_eq!(password, "test-password-123");
        std::env::remove_var("ARKD_WALLET_PASS");
    }

    #[tokio::test]
    async fn test_noop_alerts_publish_ok() {
        let alerts = NoopAlerts;
        let payload = serde_json::json!({"round_id": "r1"});
        assert!(alerts
            .publish(AlertTopic::BatchFinalized, payload)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_noop_alerts_as_trait_object() {
        let alerts: Arc<dyn Alerts> = Arc::new(NoopAlerts);
        let payload = serde_json::json!({"tx": "abc"});
        assert!(alerts.publish(AlertTopic::ArkTx, payload).await.is_ok());
    }

    #[test]
    fn test_alert_topic_display() {
        assert_eq!(AlertTopic::BatchFinalized.to_string(), "Batch Finalized");
        assert_eq!(AlertTopic::ArkTx.to_string(), "Ark Tx");
    }

    #[test]
    fn test_decoded_tx_structs() {
        let tx = DecodedTx {
            txid: "abc123".to_string(),
            inputs: vec![DecodedTxIn {
                txid: "prev_tx".to_string(),
                vout: 0,
            }],
            outputs: vec![DecodedTxOut {
                amount: 50_000,
                pk_script: vec![0x76, 0xa9],
            }],
        };
        assert_eq!(tx.txid, "abc123");
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs[0].amount, 50_000);
    }

    #[test]
    fn test_batch_finalized_alert_serde() {
        let alert = BatchFinalizedAlert {
            id: "batch-1".to_string(),
            commitment_txid: "txid123".to_string(),
            duration: "2m30s".to_string(),
            liquidity_provider_input_amount: 1_000_000,
            liquidity_provider_confirmed_balance: 500_000,
            liquidity_provider_unconfirmed_balance: 200_000,
            liquidity_cost: "0.5%".to_string(),
            liquidity_provided: 800_000,
            boarding_input_count: 3,
            boarding_input_amount: 100_000,
            intents_count: 10,
            leaf_count: 8,
            leaf_amount: 400_000,
            connectors_count: 4,
            connectors_amount: 50_000,
            exit_count: 2,
            exit_amount: 30_000,
            forfeit_count: 1,
            forfeit_amount: 10_000,
            onchain_fees: 5_000,
            collected_fees: 3_000,
        };
        let json = serde_json::to_value(&alert).unwrap();
        assert_eq!(json["id"], "batch-1");
        assert_eq!(json["commitment_txid"], "txid123");
        assert_eq!(json["onchain_fees"], 5_000);
    }
}

/// Time-based scheduler: triggers at fixed intervals.
#[async_trait]
pub trait TimeScheduler: Send + Sync {
    /// Start a periodic timer that sends a tick every `interval`.
    async fn schedule(
        &self,
        interval: std::time::Duration,
    ) -> ArkResult<tokio::sync::mpsc::Receiver<()>>;
}

/// Block-height-based scheduler: triggers every N blocks.
#[async_trait]
pub trait BlockScheduler: Send + Sync {
    /// Start monitoring the chain and send the new height every `n` blocks.
    async fn schedule_every_n_blocks(&self, n: u32) -> ArkResult<tokio::sync::mpsc::Receiver<u32>>;
    /// Return the current chain tip height.
    async fn current_height(&self) -> ArkResult<u32>;
}

// ---------------------------------------------------------------------------
// Admin service — operator-level actions (notes, config, etc.)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Notifier — send notifications to users about VTXO lifecycle events
// ---------------------------------------------------------------------------

/// Notifier port — send notifications to users about VTXO lifecycle events.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Notify a user (identified by pubkey) about an event.
    async fn notify(&self, recipient_pubkey: &str, subject: &str, body: &str) -> ArkResult<()>;
    /// Notify that a VTXO is approaching expiry.
    async fn notify_vtxo_expiry(
        &self,
        recipient_pubkey: &str,
        vtxo_id: &str,
        blocks_remaining: u32,
    ) -> ArkResult<()>;
    /// Notify that a round has completed.
    async fn notify_round_complete(&self, round_id: &str, vtxo_count: u32) -> ArkResult<()>;
}

/// No-op notifier — silently discards all notifications.
pub struct NoopNotifier;

#[async_trait]
impl Notifier for NoopNotifier {
    async fn notify(&self, _: &str, _: &str, _: &str) -> ArkResult<()> {
        Ok(())
    }
    async fn notify_vtxo_expiry(&self, _: &str, _: &str, _: u32) -> ArkResult<()> {
        Ok(())
    }
    async fn notify_round_complete(&self, _: &str, _: u32) -> ArkResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NotificationService — richer notification port for production push notifications
// ---------------------------------------------------------------------------

/// Production notification service port — richer than `Notifier`, supports
/// VTXO expiry, round completion, boarding completion, and generic messages.
///
/// This is a separate trait from [`Notifier`] and does NOT replace it.
#[async_trait]
pub trait NotificationService: Send + Sync {
    /// Notify a user that their VTXO is about to expire.
    async fn notify_vtxo_expiry(
        &self,
        pubkey: &str,
        vtxo_id: &str,
        blocks_remaining: u32,
    ) -> ArkResult<()>;

    /// Notify that a round completed successfully.
    async fn notify_round_complete(
        &self,
        round_id: &str,
        vtxo_count: u32,
        total_sats: u64,
    ) -> ArkResult<()>;

    /// Notify of a boarding completion.
    async fn notify_boarding_complete(&self, pubkey: &str, amount_sats: u64) -> ArkResult<()>;

    /// Generic notification.
    async fn notify(&self, pubkey: &str, subject: &str, message: &str) -> ArkResult<()>;
}

/// No-op notification service — silently discards all notifications.
pub struct NoopNotificationService;

#[async_trait]
impl NotificationService for NoopNotificationService {
    async fn notify_vtxo_expiry(&self, _: &str, _: &str, _: u32) -> ArkResult<()> {
        Ok(())
    }
    async fn notify_round_complete(&self, _: &str, _: u32, _: u64) -> ArkResult<()> {
        Ok(())
    }
    async fn notify_boarding_complete(&self, _: &str, _: u64) -> ArkResult<()> {
        Ok(())
    }
    async fn notify(&self, _: &str, _: &str, _: &str) -> ArkResult<()> {
        Ok(())
    }
}

/// Admin service port for operator-level actions.
#[async_trait]
pub trait AdminPort: Send + Sync {
    /// Create a note VTXO (instant onboarding, no commitment chain required).
    async fn create_note(&self, amount: u64, receiver_pubkey: &str) -> ArkResult<Vtxo>;
}

/// No-op admin service — returns errors for all operations.
pub struct NoopAdminService;

#[async_trait]
impl AdminPort for NoopAdminService {
    async fn create_note(&self, _amount: u64, _receiver_pubkey: &str) -> ArkResult<Vtxo> {
        Err(crate::error::ArkError::Internal(
            "create_note not implemented (NoopAdminService)".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Checkpoint repository
// ---------------------------------------------------------------------------

/// Repository for persisting and querying checkpoint transactions.
#[async_trait]
pub trait CheckpointRepository: Send + Sync {
    /// Store a new checkpoint transaction.
    async fn store_checkpoint(&self, checkpoint: CheckpointTx) -> ArkResult<()>;
    /// Retrieve a checkpoint by ID.
    async fn get_checkpoint(&self, id: &str) -> ArkResult<Option<CheckpointTx>>;
    /// List all pending (un-swept) checkpoints.
    async fn list_pending(&self) -> ArkResult<Vec<CheckpointTx>>;
}

/// No-op checkpoint repository for use as a default / in tests.
pub struct NoopCheckpointRepository;

#[async_trait]
impl CheckpointRepository for NoopCheckpointRepository {
    async fn store_checkpoint(&self, _checkpoint: CheckpointTx) -> ArkResult<()> {
        Ok(())
    }
    async fn get_checkpoint(&self, _id: &str) -> ArkResult<Option<CheckpointTx>> {
        Ok(None)
    }
    async fn list_pending(&self) -> ArkResult<Vec<CheckpointTx>> {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// LiveStore: higher-level ephemeral round-state components
// ---------------------------------------------------------------------------

/// FIFO queue of registered intents for the current round.
#[async_trait]
pub trait IntentsQueue: Send + Sync {
    /// Push an intent onto the queue.
    async fn push(&self, intent: Intent) -> ArkResult<()>;
    /// Drain and return all queued intents.
    async fn pop_all(&self) -> ArkResult<Vec<Intent>>;
    /// Number of intents currently queued.
    async fn len(&self) -> ArkResult<usize>;
    /// Whether the queue is empty.
    async fn is_empty(&self) -> ArkResult<bool>;
    /// Clear the queue.
    async fn clear(&self) -> ArkResult<()>;
}

/// Tracks expected vs received forfeit transactions per round.
#[async_trait]
pub trait ForfeitTxsStore: Send + Sync {
    /// Initialize tracking for a round with the expected count.
    async fn init(&self, round_id: &str, expected: usize) -> ArkResult<()>;
    /// Add a received forfeit transaction.
    async fn add(&self, round_id: &str, tx_hex: String) -> ArkResult<()>;
    /// Check whether all expected forfeit txs have been received.
    async fn all_received(&self, round_id: &str) -> ArkResult<bool>;
    /// Drain and return all stored forfeit txs for a round.
    async fn pop_all(&self, round_id: &str) -> ArkResult<Vec<String>>;
}

/// Tracks which intents have been confirmed for a round.
#[async_trait]
pub trait ConfirmationStore: Send + Sync {
    /// Initialize with the set of intent IDs that need confirmation.
    async fn init(&self, round_id: &str, intent_ids: Vec<String>) -> ArkResult<()>;
    /// Mark an intent as confirmed.
    async fn confirm(&self, round_id: &str, intent_id: &str) -> ArkResult<()>;
    /// Check whether all intents are confirmed.
    async fn all_confirmed(&self, round_id: &str) -> ArkResult<bool>;
    /// Return the list of confirmed intent IDs.
    async fn get_confirmed(&self, round_id: &str) -> ArkResult<Vec<String>>;
    /// Return the list of intent IDs that have NOT confirmed yet.
    async fn get_pending(&self, round_id: &str) -> ArkResult<Vec<String>>;
}

/// No-op confirmation store that immediately confirms all intents.
pub struct NoopConfirmationStore;

#[async_trait]
impl ConfirmationStore for NoopConfirmationStore {
    async fn init(&self, _round_id: &str, _intent_ids: Vec<String>) -> ArkResult<()> {
        Ok(())
    }
    async fn confirm(&self, _round_id: &str, _intent_id: &str) -> ArkResult<()> {
        Ok(())
    }
    async fn all_confirmed(&self, _round_id: &str) -> ArkResult<bool> {
        Ok(true) // Always consider confirmed in noop mode
    }
    async fn get_confirmed(&self, _round_id: &str) -> ArkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_pending(&self, _round_id: &str) -> ArkResult<Vec<String>> {
        Ok(vec![])
    }
}

/// MuSig2 nonce and partial-signature collection for signing sessions.
///
/// The store manages [`SigningSession`](crate::domain::SigningSession) lifecycle:
/// init → collect nonces → collect signatures → complete.
#[async_trait]
pub trait SigningSessionStore: Send + Sync {
    /// Initialize a signing session with the expected participant count.
    async fn init_session(&self, session_id: &str, participant_count: usize) -> ArkResult<()>;
    /// Retrieve the current session state, if it exists.
    async fn get_session(
        &self,
        session_id: &str,
    ) -> ArkResult<Option<crate::domain::SigningSession>>;
    /// Add a nonce from a participant.
    async fn add_nonce(
        &self,
        session_id: &str,
        participant_id: &str,
        nonce: Vec<u8>,
    ) -> ArkResult<()>;
    /// Check whether all nonces have been collected.
    async fn all_nonces_collected(&self, session_id: &str) -> ArkResult<bool>;
    /// Add a partial signature from a participant.
    async fn add_signature(
        &self,
        session_id: &str,
        participant_id: &str,
        sig: Vec<u8>,
    ) -> ArkResult<()>;
    /// Check whether all signatures have been collected.
    async fn all_signatures_collected(&self, session_id: &str) -> ArkResult<bool>;
    /// Return all collected nonces.
    async fn get_nonces(&self, session_id: &str) -> ArkResult<Vec<Vec<u8>>>;
    /// Return all collected signatures.
    async fn get_signatures(&self, session_id: &str) -> ArkResult<Vec<Vec<u8>>>;
    /// Mark the session complete with an aggregated signature.
    async fn complete_session(&self, session_id: &str, combined_sig: Vec<u8>) -> ArkResult<()>;
}

/// Atomic get/set of the active round ID.
#[async_trait]
pub trait CurrentRoundStore: Send + Sync {
    /// Get the current round ID, if any.
    async fn get_current_round_id(&self) -> ArkResult<Option<String>>;
    /// Set the current round ID.
    async fn set_current_round_id(&self, round_id: &str) -> ArkResult<()>;
    /// Clear the current round ID.
    async fn clear(&self) -> ArkResult<()>;
}

// ── Sweep service ─────────────────────────────────────────────────

/// Result of a sweep operation.
#[derive(Debug, Default, Clone)]
pub struct SweepResult {
    /// Number of VTXOs swept
    pub vtxos_swept: usize,
    /// Total satoshis recovered
    pub sats_recovered: u64,
    /// Transaction IDs produced
    pub tx_ids: Vec<String>,
}

/// Port for sweeping expired VTXOs and round connectors back to the ASP.
#[async_trait]
pub trait SweepService: Send + Sync {
    /// Sweep VTXOs that have expired by `current_height`.
    async fn sweep_expired_vtxos(&self, current_height: u32) -> ArkResult<SweepResult>;
    /// Sweep connector outputs for a given round.
    async fn sweep_connectors(&self, round_id: &str) -> ArkResult<SweepResult>;
}

/// No-op implementation of [`SigningSessionStore`] for tests and early bootstrapping.
pub struct NoopSigningSessionStore;

#[async_trait]
impl SigningSessionStore for NoopSigningSessionStore {
    async fn init_session(&self, _session_id: &str, _participant_count: usize) -> ArkResult<()> {
        Ok(())
    }
    async fn get_session(
        &self,
        _session_id: &str,
    ) -> ArkResult<Option<crate::domain::SigningSession>> {
        Ok(None)
    }
    async fn add_nonce(
        &self,
        _session_id: &str,
        _participant_id: &str,
        _nonce: Vec<u8>,
    ) -> ArkResult<()> {
        Ok(())
    }
    async fn all_nonces_collected(&self, _session_id: &str) -> ArkResult<bool> {
        Ok(true)
    }
    async fn add_signature(
        &self,
        _session_id: &str,
        _participant_id: &str,
        _sig: Vec<u8>,
    ) -> ArkResult<()> {
        Ok(())
    }
    async fn all_signatures_collected(&self, _session_id: &str) -> ArkResult<bool> {
        Ok(true)
    }
    async fn get_nonces(&self, _session_id: &str) -> ArkResult<Vec<Vec<u8>>> {
        Ok(vec![])
    }
    async fn get_signatures(&self, _session_id: &str) -> ArkResult<Vec<Vec<u8>>> {
        Ok(vec![])
    }
    async fn complete_session(&self, _session_id: &str, _combined_sig: Vec<u8>) -> ArkResult<()> {
        Ok(())
    }
}

/// No-op implementation of [`SweepService`] for tests and early bootstrapping.
pub struct NoopSweepService;

#[async_trait]
impl SweepService for NoopSweepService {
    async fn sweep_expired_vtxos(&self, current_height: u32) -> ArkResult<SweepResult> {
        tracing::debug!(
            current_height,
            "NoopSweepService: skipping expired VTXO sweep"
        );
        Ok(SweepResult::default())
    }

    async fn sweep_connectors(&self, round_id: &str) -> ArkResult<SweepResult> {
        tracing::debug!(round_id, "NoopSweepService: skipping connector sweep");
        Ok(SweepResult::default())
    }
}

// ---------------------------------------------------------------------------
// Conviction repository — Go admin.proto aligned (#162)
// ---------------------------------------------------------------------------

/// Repository for persisting and querying conviction records.
///
/// Convictions track protocol violations and script bans. This matches
/// the Go arkd conviction system with rich querying capabilities.
#[async_trait]
pub trait ConvictionRepository: Send + Sync {
    /// Store a new conviction.
    async fn store(&self, conviction: Conviction) -> ArkResult<()>;
    /// Get convictions by their IDs.
    async fn get_by_ids(&self, ids: &[String]) -> ArkResult<Vec<Conviction>>;
    /// Get convictions created within a time range (unix timestamps).
    async fn get_in_range(&self, from: i64, to: i64) -> ArkResult<Vec<Conviction>>;
    /// Get convictions for a specific round.
    async fn get_by_round(&self, round_id: &str) -> ArkResult<Vec<Conviction>>;
    /// Get active (non-expired, non-pardoned) convictions for a script.
    async fn get_active_by_script(&self, script: &str) -> ArkResult<Vec<Conviction>>;
    /// Pardon a conviction by ID.
    async fn pardon(&self, id: &str) -> ArkResult<()>;
}

/// No-op conviction repository for dev/test environments.
pub struct NoopConvictionRepository;

#[async_trait]
impl ConvictionRepository for NoopConvictionRepository {
    async fn store(&self, _conviction: Conviction) -> ArkResult<()> {
        Ok(())
    }
    async fn get_by_ids(&self, _ids: &[String]) -> ArkResult<Vec<Conviction>> {
        Ok(vec![])
    }
    async fn get_in_range(&self, _from: i64, _to: i64) -> ArkResult<Vec<Conviction>> {
        Ok(vec![])
    }
    async fn get_by_round(&self, _round_id: &str) -> ArkResult<Vec<Conviction>> {
        Ok(vec![])
    }
    async fn get_active_by_script(&self, _script: &str) -> ArkResult<Vec<Conviction>> {
        Ok(vec![])
    }
    async fn pardon(&self, _id: &str) -> ArkResult<()> {
        Ok(())
    }
}

/// Ban repository for tracking misbehaving participants.
#[async_trait]
pub trait BanRepository: Send + Sync {
    /// Ban a participant for a given reason during a specific round.
    async fn ban(&self, pubkey: &str, reason: BanReason, round_id: &str) -> ArkResult<()>;
    /// Check if a participant is currently banned.
    async fn is_banned(&self, pubkey: &str) -> ArkResult<bool>;
    /// Get the ban record for a participant, if any.
    async fn get_ban(&self, pubkey: &str) -> ArkResult<Option<BanRecord>>;
    /// Remove a ban for a participant.
    async fn unban(&self, pubkey: &str) -> ArkResult<()>;
    /// List all currently banned participants.
    async fn list_banned(&self) -> ArkResult<Vec<BanRecord>>;
}

// ---------------------------------------------------------------------------
// ConfigService — hot-reload support (#139)
// ---------------------------------------------------------------------------

/// Configuration service for hot-reload support.
///
/// Implementations can watch config files on disk, receive config from a
/// remote source, or simply return a fixed config (see `StaticConfigService`).
#[async_trait]
pub trait ConfigService: Send + Sync {
    /// Get the current active config.
    async fn get_config(&self) -> ArkResult<ArkConfig>;
    /// Reload config from its source (hot-reload).
    async fn reload(&self) -> ArkResult<ArkConfig>;
    /// Subscribe to config changes — returns a watch channel receiver.
    fn subscribe(&self) -> tokio::sync::watch::Receiver<ArkConfig>;
}

// ---------------------------------------------------------------------------
// TxDecoder — decode raw transactions
// ---------------------------------------------------------------------------

/// A decoded transaction input (mirrors Go's `TxIn = domain.Outpoint`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecodedTxIn {
    /// Previous transaction ID.
    pub txid: String,
    /// Previous output index.
    pub vout: u32,
}

/// A decoded transaction output.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecodedTxOut {
    /// Output value in satoshis.
    pub amount: u64,
    /// The scriptPubKey bytes.
    pub pk_script: Vec<u8>,
}

/// Result of decoding a raw transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecodedTx {
    /// Transaction ID.
    pub txid: String,
    /// Decoded inputs.
    pub inputs: Vec<DecodedTxIn>,
    /// Decoded outputs.
    pub outputs: Vec<DecodedTxOut>,
}

/// Decode a raw or hex-encoded transaction into its components.
///
/// Mirrors Go arkd's `TxDecoder` interface.
#[async_trait]
pub trait TxDecoder: Send + Sync {
    /// Decode a hex-encoded transaction, returning its txid, inputs, and outputs.
    async fn decode_tx(&self, tx: &str) -> ArkResult<DecodedTx>;
}

/// No-op transaction decoder — always returns an error.
pub struct NoopTxDecoder;

#[async_trait]
impl TxDecoder for NoopTxDecoder {
    async fn decode_tx(&self, _tx: &str) -> ArkResult<DecodedTx> {
        Err(crate::error::ArkError::Internal(
            "decode_tx not implemented (NoopTxDecoder)".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Unlocker — retrieve wallet passwords
// ---------------------------------------------------------------------------

/// Retrieve a wallet unlock password from the environment or user.
///
/// Mirrors Go arkd's `Unlocker` interface.
#[async_trait]
pub trait Unlocker: Send + Sync {
    /// Get the wallet password.
    async fn get_password(&self) -> ArkResult<String>;
}

/// Environment-variable-based unlocker — reads `ARKD_WALLET_PASS`.
pub struct EnvUnlocker;

#[async_trait]
impl Unlocker for EnvUnlocker {
    async fn get_password(&self) -> ArkResult<String> {
        std::env::var("ARKD_WALLET_PASS").map_err(|_| {
            crate::error::ArkError::Internal("ARKD_WALLET_PASS environment variable not set".into())
        })
    }
}

/// File-based unlocker — reads the password from a file on disk.
///
/// The file should contain the password as its sole content (trailing
/// whitespace is stripped).
pub struct FileUnlocker {
    /// Path to the file containing the wallet password.
    pub path: std::path::PathBuf,
}

impl FileUnlocker {
    /// Create a new file-based unlocker for the given path.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl Unlocker for FileUnlocker {
    async fn get_password(&self) -> ArkResult<String> {
        let content = tokio::fs::read_to_string(&self.path).await.map_err(|e| {
            crate::error::ArkError::Internal(format!(
                "Failed to read password file {}: {e}",
                self.path.display()
            ))
        })?;
        Ok(content.trim().to_string())
    }
}

// ---------------------------------------------------------------------------
// Alerts — publish operational alerts
// ---------------------------------------------------------------------------

/// Topic for alert messages.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AlertTopic {
    /// A batch/round has been finalized.
    BatchFinalized,
    /// An Ark transaction event.
    ArkTx,
}

impl std::fmt::Display for AlertTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertTopic::BatchFinalized => write!(f, "Batch Finalized"),
            AlertTopic::ArkTx => write!(f, "Ark Tx"),
        }
    }
}

/// Alert payload for a finalized batch (round).
///
/// Mirrors Go arkd's `BatchFinalizedAlert` struct.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchFinalizedAlert {
    /// Round/batch identifier.
    pub id: String,
    /// Commitment transaction ID.
    pub commitment_txid: String,
    /// Round duration as a human-readable string.
    pub duration: String,
    /// Liquidity provider input amount in satoshis.
    pub liquidity_provider_input_amount: u64,
    /// Liquidity provider confirmed balance.
    pub liquidity_provider_confirmed_balance: u64,
    /// Liquidity provider unconfirmed balance.
    pub liquidity_provider_unconfirmed_balance: u64,
    /// Liquidity cost as a human-readable string.
    pub liquidity_cost: String,
    /// Liquidity provided in satoshis.
    pub liquidity_provided: u64,
    /// Number of boarding inputs.
    pub boarding_input_count: i32,
    /// Boarding input amount in satoshis.
    pub boarding_input_amount: u64,
    /// Number of intents in the batch.
    pub intents_count: i32,
    /// Number of VTXO leaves.
    pub leaf_count: i32,
    /// Leaf VTXO amount in satoshis.
    pub leaf_amount: u64,
    /// Number of connectors.
    pub connectors_count: i32,
    /// Connectors amount in satoshis.
    pub connectors_amount: u64,
    /// Number of exits.
    pub exit_count: i32,
    /// Exit amount in satoshis.
    pub exit_amount: u64,
    /// Number of forfeit transactions.
    pub forfeit_count: i32,
    /// Forfeit amount in satoshis.
    pub forfeit_amount: u64,
    /// On-chain fees paid in satoshis.
    pub onchain_fees: u64,
    /// Fees collected in satoshis.
    pub collected_fees: u64,
}

/// Publish operational alerts to external systems (Slack, PagerDuty, etc.).
///
/// Mirrors Go arkd's `Alerts` interface.
#[async_trait]
pub trait Alerts: Send + Sync {
    /// Publish an alert for the given topic with an arbitrary JSON payload.
    async fn publish(&self, topic: AlertTopic, payload: serde_json::Value) -> ArkResult<()>;
}

/// No-op alerts — silently discards all alert messages.
pub struct NoopAlerts;

#[async_trait]
impl Alerts for NoopAlerts {
    async fn publish(&self, _topic: AlertTopic, _payload: serde_json::Value) -> ArkResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Event Store (issue #243)
// ---------------------------------------------------------------------------

/// Event sourcing store for aggregate event persistence.
///
/// Mirrors Go arkd's event-store pattern (Badger/Postgres backed).
/// Used for audit trails, replays, and CQRS projections.
#[async_trait]
pub trait EventStore: Send + Sync {
    /// Append a serialized event to the given aggregate's event stream.
    async fn append_event(&self, aggregate_id: &str, event: &[u8]) -> ArkResult<()>;

    /// Load all events for the given aggregate, ordered by append time.
    async fn load_events(&self, aggregate_id: &str) -> ArkResult<Vec<Vec<u8>>>;
}

/// No-op event store — discards writes and returns empty streams.
pub struct NoopEventStore;

#[async_trait]
impl EventStore for NoopEventStore {
    async fn append_event(&self, _aggregate_id: &str, _event: &[u8]) -> ArkResult<()> {
        Ok(())
    }

    async fn load_events(&self, _aggregate_id: &str) -> ArkResult<Vec<Vec<u8>>> {
        Ok(vec![])
    }
}
