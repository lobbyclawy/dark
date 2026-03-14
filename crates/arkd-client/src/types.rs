use serde::{Deserialize, Serialize};

/// Server information returned by GetInfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub pubkey: String,
    pub network: String,
    pub round_lifetime: u32,
    pub unilateral_exit_delay: u32,
    pub version: String,
}

/// A VTXO owned by a pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vtxo {
    pub id: String,
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub pubkey: String,
    pub expiry_at: u64,
    pub is_note: bool,
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
