//! Client types for dark responses.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Server information returned by GetInfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub pubkey: String,
    pub forfeit_pubkey: String,
    pub network: String,
    pub session_duration: u32,
    pub unilateral_exit_delay: u32,
    pub boarding_exit_delay: u32,
    pub version: String,
    pub dust: u64,
    pub vtxo_min_amount: u64,
    pub vtxo_max_amount: u64,
}

/// A VTXO owned by a pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vtxo {
    pub id: String,
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    /// Script (pubkey or tapscript)
    pub script: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub is_spent: bool,
    pub is_swept: bool,
    pub is_unrolled: bool,
    pub spent_by: String,
    pub ark_txid: String,
    /// Assets embedded in this VTXO (empty for BTC-only VTXOs).
    pub assets: Vec<Asset>,
}

/// Summary of a round (from ListRounds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundSummary {
    pub id: String,
    pub starting_timestamp: i64,
    pub ending_timestamp: i64,
    pub stage: String,
    pub commitment_txid: String,
    pub failed: bool,
}

/// Detailed round information (from GetRound).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundInfo {
    pub id: String,
    pub starting_timestamp: i64,
    pub ending_timestamp: i64,
    pub stage: String,
    pub commitment_txid: String,
    pub failed: bool,
    pub intent_count: u32,
}

/// A round registration intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub amount: u64,
    pub receiver_pubkey: String,
}

/// Result of submitting an offchain transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResult {
    pub tx_id: String,
    pub status: String,
}

// ── Address types ──────────────────────────────────────────────────────────

/// An offchain (VTXO) receive address with its associated tapscripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffchainAddress {
    /// Bech32m-encoded offchain address (pubkey script).
    pub address: String,
    /// Taproot leaf scripts associated with this address.
    pub tapscripts: Vec<String>,
}

/// A boarding (on-chain → Ark) deposit address with its associated tapscripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardingAddress {
    /// Bech32m-encoded on-chain boarding address.
    pub address: String,
    /// Taproot leaf scripts associated with this boarding address.
    pub tapscripts: Vec<String>,
}

// ── Balance types ──────────────────────────────────────────────────────────

/// An amount that is time-locked until `expires_at` (Unix timestamp).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedAmount {
    /// Locked amount in satoshis.
    pub amount: u64,
    /// Unix timestamp at which the lock expires.
    pub expires_at: i64,
}

/// On-chain balance breakdown for a pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnchainBalance {
    /// Immediately spendable on-chain satoshis.
    pub spendable_amount: u64,
    /// Time-locked on-chain amounts (e.g. boarding outputs in exit delay).
    pub locked_amount: Vec<LockedAmount>,
}

/// Offchain (VTXO) balance for a pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffchainBalance {
    /// Total spendable offchain satoshis across all VTXOs.
    pub total: u64,
}

/// Combined on-chain and offchain balance for a pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    /// On-chain component (spendable + locked UTXOs).
    pub onchain: OnchainBalance,
    /// Offchain component (VTXO total).
    pub offchain: OffchainBalance,
    /// Per-asset offchain balances: asset_id → total amount across all VTXOs.
    pub asset_balances: HashMap<String, u64>,
}

// ── Settlement types ───────────────────────────────────────────────────────

/// Result of a completed batch/settlement transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTxRes {
    /// Txid of the commitment (batch) transaction broadcast to Bitcoin.
    pub commitment_txid: String,
}

// ── Asset types ────────────────────────────────────────────────────────────

/// An asset embedded in a VTXO (RGB-style token).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Asset {
    /// Unique asset identifier.
    pub asset_id: String,
    /// Amount of this asset in the VTXO.
    pub amount: u64,
}

/// Controls who can reissue an asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlAssetOption {
    /// Create a new control asset with the given supply.
    New(NewControlAsset),
    /// Use an existing control asset by its ID.
    Existing(ExistingControlAsset),
}

/// Parameters for creating a new control asset alongside issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewControlAsset {
    /// Supply of the control asset (typically 1 for a singleton).
    pub amount: u64,
}

/// Reference to an existing control asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExistingControlAsset {
    /// ID of the existing control asset.
    pub id: String,
}

/// Optional key-value metadata attached to an asset issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetMetadata {
    /// Metadata key.
    pub key: String,
    /// Metadata value.
    pub value: String,
}

/// Result returned by `issue_asset`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueAssetResult {
    /// Transaction ID of the issuance.
    pub txid: String,
    /// List of issued asset IDs.
    pub issued_assets: Vec<String>,
}

// ── Event stream types ─────────────────────────────────────────────────────

/// Events emitted on the batch lifecycle stream (`GetEventStream`).
///
/// Maps to the proto `RoundEvent` oneof.
#[derive(Debug, Clone)]
pub enum BatchEvent {
    /// A new batch round has started; participants should register intents.
    BatchStarted { round_id: String, timestamp: i64 },
    /// The batch is being finalised; MuSig2 signing is complete.
    BatchFinalization {
        round_id: String,
        timestamp: i64,
        min_relay_fee_rate: i64,
    },
    /// The batch commitment transaction has been broadcast.
    BatchFinalized {
        round_id: String,
        /// Commitment transaction ID.
        txid: String,
    },
    /// The batch round failed (e.g. not enough participants).
    BatchFailed { round_id: String, reason: String },
    /// MuSig2 tree signing has started; cosigners should submit nonces.
    TreeSigningStarted {
        round_id: String,
        cosigner_pubkeys: Vec<String>,
        timestamp: i64,
    },
    /// A tree transaction node — carries the txid of a tree node to cosign.
    TreeTx { round_id: String, txid: String },
    /// All MuSig2 nonces have been aggregated; signers should submit signatures.
    TreeNoncesAggregated { round_id: String, timestamp: i64 },
    /// Server heartbeat — stream is alive.
    Heartbeat { timestamp: i64 },
}

/// Events emitted on the transactions stream (`GetTransactionsStream`).
///
/// Maps to the proto `TransactionEvent` oneof.
#[derive(Debug, Clone)]
pub enum TxEvent {
    /// A commitment (batch) transaction was broadcast.
    CommitmentTx {
        txid: String,
        round_id: String,
        timestamp: i64,
    },
    /// An Ark (offchain) transaction was settled.
    ArkTx {
        txid: String,
        from_script: String,
        to_script: String,
        amount: u64,
        timestamp: i64,
    },
    /// Server heartbeat — stream is alive.
    Heartbeat { timestamp: i64 },
}
