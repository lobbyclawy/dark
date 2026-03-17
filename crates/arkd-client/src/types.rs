//! Client types for arkd-rs responses.

use serde::{Deserialize, Serialize};

/// Server information returned by GetInfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub pubkey: String,
    pub forfeit_pubkey: String,
    pub network: String,
    pub session_duration: u32,
    pub unilateral_exit_delay: u32,
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
}
