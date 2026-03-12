//! Virtual Transaction Output (VTXO) domain model
//!
//! Aligned with Go arkd: `github.com/ark-network/ark/internal/core/domain/vtxo.go`

use bitcoin::{OutPoint, XOnlyPublicKey};
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Outpoint identifying a VTXO (matches Go's `domain.Outpoint`)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VtxoOutpoint {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
}

impl VtxoOutpoint {
    /// Create from components
    pub fn new(txid: String, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Parse from "txid:vout" string format
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            let vout = parts[1].parse::<u32>().ok()?;
            Some(Self {
                txid: parts[0].to_string(),
                vout,
            })
        } else {
            None
        }
    }

    /// Convert from bitcoin OutPoint
    pub fn from_outpoint(outpoint: OutPoint) -> Self {
        Self {
            txid: outpoint.txid.to_string(),
            vout: outpoint.vout,
        }
    }
}

impl std::fmt::Display for VtxoOutpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// A Virtual Transaction Output (VTXO) — matches Go's `domain.Vtxo`
///
/// Key differences from the old Rust model:
/// - Uses `VtxoOutpoint` as identity (not UUID)
/// - `expires_at` is a unix timestamp (not block height)
/// - Tracks `commitment_txids` chain (not a single round_id)
/// - Status is represented by boolean flags (Spent/Unrolled/Swept)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vtxo {
    /// The outpoint identifying this VTXO in the transaction tree
    pub outpoint: VtxoOutpoint,
    /// The amount in satoshis
    pub amount: u64,
    /// Owner's public key (hex-encoded, Schnorr/x-only)
    pub pubkey: String,
    /// Chain of commitment transaction IDs
    pub commitment_txids: Vec<String>,
    /// The root (original) commitment txid
    pub root_commitment_txid: String,
    /// Commitment txid that settled this VTXO
    pub settled_by: String,
    /// Forfeit or checkpoint txid that spent this VTXO
    pub spent_by: String,
    /// The Ark transaction ID that spent this VTXO
    pub ark_txid: String,
    /// Whether this VTXO has been spent
    pub spent: bool,
    /// Whether this VTXO's tree branch has been unrolled (published on-chain)
    pub unrolled: bool,
    /// Whether this VTXO has been swept by the ASP
    pub swept: bool,
    /// Whether this VTXO is preconfirmed (not yet in a finalized round)
    pub preconfirmed: bool,
    /// Unix timestamp when this VTXO expires
    pub expires_at: i64,
    /// Unix timestamp when this VTXO was created
    pub created_at: i64,
}

impl Vtxo {
    /// Create a new VTXO
    pub fn new(outpoint: VtxoOutpoint, amount: u64, pubkey: String) -> Self {
        let now = Utc::now().timestamp();
        Self {
            outpoint,
            amount,
            pubkey,
            commitment_txids: Vec::new(),
            root_commitment_txid: String::new(),
            settled_by: String::new(),
            spent_by: String::new(),
            ark_txid: String::new(),
            spent: false,
            unrolled: false,
            swept: false,
            preconfirmed: false,
            expires_at: 0,
            created_at: now,
        }
    }

    /// Check if this VTXO is a "note" (no commitment chain)
    pub fn is_note(&self) -> bool {
        self.commitment_txids.is_empty() && self.root_commitment_txid.is_empty()
    }

    /// Check if this VTXO requires a forfeit transaction to be spent
    pub fn requires_forfeit(&self) -> bool {
        !self.swept && !self.is_note()
    }

    /// Check if this VTXO is spendable
    pub fn is_spendable(&self) -> bool {
        !self.spent && !self.swept && !self.unrolled
    }

    /// Check if this VTXO is expired at the given unix timestamp
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        self.expires_at > 0 && now_unix >= self.expires_at
    }

    /// Get the owner's public key as XOnlyPublicKey
    pub fn tap_key(&self) -> Option<XOnlyPublicKey> {
        let bytes = hex::decode(&self.pubkey).ok()?;
        XOnlyPublicKey::from_slice(&bytes).ok()
    }
}

/// A receiver for VTXO outputs (matches Go's `domain.Receiver`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receiver {
    /// Amount in satoshis
    pub amount: u64,
    /// On-chain destination address
    pub onchain_address: String,
    /// Off-chain public key
    pub pubkey: String,
}

impl Receiver {
    /// Check if this is an on-chain receiver
    pub fn is_onchain(&self) -> bool {
        !self.onchain_address.is_empty()
    }

    /// Create an on-chain receiver
    pub fn onchain(amount: u64, address: String) -> Self {
        Self {
            amount,
            onchain_address: address,
            pubkey: String::new(),
        }
    }

    /// Create an off-chain receiver
    pub fn offchain(amount: u64, pubkey: String) -> Self {
        Self {
            amount,
            onchain_address: String::new(),
            pubkey,
        }
    }
}

/// Legacy type alias
pub type VtxoId = VtxoOutpoint;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtxo_outpoint_parse() {
        let op = VtxoOutpoint::from_string("abc123:5").unwrap();
        assert_eq!(op.txid, "abc123");
        assert_eq!(op.vout, 5);
        assert!(VtxoOutpoint::from_string("invalid").is_none());
    }

    #[test]
    fn test_vtxo_creation() {
        let op = VtxoOutpoint::new("txid123".to_string(), 0);
        let vtxo = Vtxo::new(op.clone(), 100_000, "deadbeef".to_string());
        assert_eq!(vtxo.outpoint, op);
        assert!(vtxo.is_spendable());
    }

    #[test]
    fn test_vtxo_expiry() {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            50_000,
            "pub".to_string(),
        );
        vtxo.expires_at = 1000;
        assert!(!vtxo.is_expired_at(999));
        assert!(vtxo.is_expired_at(1000));
    }

    #[test]
    fn test_receiver() {
        let onchain = Receiver::onchain(100_000, "bc1q...".to_string());
        assert!(onchain.is_onchain());
        let offchain = Receiver::offchain(50_000, "deadbeef".to_string());
        assert!(!offchain.is_onchain());
    }
}
