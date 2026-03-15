//! Ports - External interfaces for dependency inversion
//!
//! Aligns with Go arkd port interfaces.

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

use crate::domain::{
    AssetRecord, BoardingTransaction, CheckpointTx, FlatTxTree, ForfeitRecord, Intent, OffchainTx,
    OffchainTxStage, Round, Vtxo, VtxoOutpoint,
};
use crate::error::ArkResult;

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
}

/// Asset repository — manages registered tokens and NFTs on this ASP.
#[async_trait]
pub trait AssetRepository: Send + Sync {
    /// Register a new asset.
    async fn register_asset(&self, record: AssetRecord) -> ArkResult<()>;
    /// Look up an asset by its ID.
    async fn get_asset(&self, asset_id: &str) -> ArkResult<Option<AssetRecord>>;
    /// List all registered assets.
    async fn list_assets(&self) -> ArkResult<Vec<AssetRecord>>;
}

/// No-op asset repository for dev/test environments.
pub struct NoopAssetRepository;

#[async_trait]
impl AssetRepository for NoopAssetRepository {
    async fn register_asset(&self, _record: AssetRecord) -> ArkResult<()> {
        Ok(())
    }
    async fn get_asset(&self, _asset_id: &str) -> ArkResult<Option<AssetRecord>> {
        Ok(None)
    }
    async fn list_assets(&self) -> ArkResult<Vec<AssetRecord>> {
        Ok(vec![])
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
    async fn test_noop_asset_repo_list_empty() {
        let repo = NoopAssetRepository;
        let assets = repo.list_assets().await.unwrap();
        assert!(assets.is_empty());
        assert!(repo.get_asset("nonexistent").await.unwrap().is_none());
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
#[async_trait]
pub trait SigningSessionStore: Send + Sync {
    /// Initialize a signing session with the expected participant count.
    async fn init_session(&self, session_id: &str, participant_count: usize) -> ArkResult<()>;
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
