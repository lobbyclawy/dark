//! Ports - External interfaces for dependency inversion
//!
//! Aligns with Go arkd port interfaces.

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

use crate::domain::{FlatTxTree, Intent, OffchainTx, OffchainTxStage, Round, Vtxo, VtxoOutpoint};
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
