//! Virtual Transaction Output (VTXO) domain model
//!
//! Aligned with Go dark: `github.com/ark-network/ark/internal/core/domain/vtxo.go`

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

    /// Generate a note URI for this VTXO using the given prefix.
    ///
    /// Only meaningful when `is_note()` returns true.
    pub fn note_uri(&self, prefix: &str) -> String {
        format!("{}:{}", prefix, self.outpoint)
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

    #[test]
    fn test_vtxo_outpoint_display() {
        let op = VtxoOutpoint::new("abc123".to_string(), 42);
        assert_eq!(op.to_string(), "abc123:42");
    }

    #[test]
    fn test_vtxo_outpoint_from_string_edge_cases() {
        // Missing vout
        assert!(VtxoOutpoint::from_string("abc123").is_none());
        // Non-numeric vout
        assert!(VtxoOutpoint::from_string("abc123:xyz").is_none());
        // Empty string
        assert!(VtxoOutpoint::from_string("").is_none());
        // Multiple colons
        assert!(VtxoOutpoint::from_string("a:b:c").is_none());
        // Valid
        assert!(VtxoOutpoint::from_string("txid:0").is_some());
    }

    #[test]
    fn test_vtxo_spendable_states() {
        let op = VtxoOutpoint::new("tx".to_string(), 0);

        // Fresh = spendable
        let vtxo = Vtxo::new(op.clone(), 1000, "pk".to_string());
        assert!(vtxo.is_spendable());

        // Spent = not spendable
        let mut vtxo = Vtxo::new(op.clone(), 1000, "pk".to_string());
        vtxo.spent = true;
        assert!(!vtxo.is_spendable());

        // Swept = not spendable
        let mut vtxo = Vtxo::new(op.clone(), 1000, "pk".to_string());
        vtxo.swept = true;
        assert!(!vtxo.is_spendable());

        // Unrolled = not spendable
        let mut vtxo = Vtxo::new(op, 1000, "pk".to_string());
        vtxo.unrolled = true;
        assert!(!vtxo.is_spendable());
    }

    #[test]
    fn test_vtxo_zero_expiry_never_expires() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            "pk".to_string(),
        );
        // expires_at = 0 means never expires
        assert!(!vtxo.is_expired_at(0));
        assert!(!vtxo.is_expired_at(i64::MAX));
    }

    #[test]
    fn test_vtxo_requires_forfeit_swept() {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            "pk".to_string(),
        );
        vtxo.commitment_txids = vec!["c1".to_string()];
        vtxo.root_commitment_txid = "c1".to_string();
        vtxo.swept = true;

        // Swept VTXOs don't require forfeit even with commitments
        assert!(!vtxo.requires_forfeit());
    }

    #[test]
    fn test_vtxo_tap_key_invalid_hex() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            "not_hex".to_string(),
        );
        assert!(vtxo.tap_key().is_none());
    }

    #[test]
    fn test_vtxo_tap_key_valid() {
        let valid_pk_hex = "0202020202020202020202020202020202020202020202020202020202020202";
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            valid_pk_hex.to_string(),
        );
        assert!(vtxo.tap_key().is_some());
    }

    #[test]
    fn test_vtxo_preconfirmed_flag() {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            "pk".to_string(),
        );
        assert!(!vtxo.preconfirmed);
        vtxo.preconfirmed = true;
        assert!(vtxo.preconfirmed);
        // Preconfirmed VTXOs are still spendable
        assert!(vtxo.is_spendable());
    }

    #[test]
    fn test_vtxo_outpoint_from_bitcoin_outpoint() {
        use bitcoin::hashes::Hash;
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [0xab; 32],
            )),
            vout: 7,
        };
        let vtxo_op = VtxoOutpoint::from_outpoint(outpoint);
        assert_eq!(vtxo_op.vout, 7);
        assert!(!vtxo_op.txid.is_empty());
    }

    // -----------------------------------------------------------------------
    // Notes system tests (#56)
    // -----------------------------------------------------------------------

    #[test]
    fn test_vtxo_is_note_default_false() {
        // A freshly created VTXO with no commitment chain is technically a note
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            50_000,
            "pk".to_string(),
        );
        // New VTXOs have empty commitment_txids and root_commitment_txid → is_note() == true
        assert!(vtxo.is_note());

        // Once a commitment chain is set, it's no longer a note
        let mut vtxo_with_chain = vtxo.clone();
        vtxo_with_chain.commitment_txids = vec!["commit_tx_1".to_string()];
        vtxo_with_chain.root_commitment_txid = "commit_tx_1".to_string();
        assert!(!vtxo_with_chain.is_note());
    }

    #[test]
    fn test_vtxo_note_uri_format() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("abc123".to_string(), 7),
            100_000,
            "deadbeef".to_string(),
        );
        let uri = vtxo.note_uri("ark-note");
        assert_eq!(uri, "ark-note:abc123:7");
    }

    #[test]
    fn test_vtxo_note_flag_roundtrip() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx_rt".to_string(), 3),
            25_000,
            "cafebabe".to_string(),
        );
        // Serialize → deserialize roundtrip
        let json = serde_json::to_string(&vtxo).expect("serialize");
        let restored: Vtxo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(vtxo, restored);
        // Note status preserved
        assert_eq!(vtxo.is_note(), restored.is_note());
    }

    #[test]
    fn test_note_validation_note_vtxo_skips_round() {
        // A note VTXO (no commitment chain) should NOT require forfeit
        let note = Vtxo::new(
            VtxoOutpoint::new("note_tx".to_string(), 0),
            10_000,
            "pk_note".to_string(),
        );
        assert!(note.is_note());
        assert!(!note.requires_forfeit(), "notes should skip forfeit/round");

        // A regular VTXO with commitment chain DOES require forfeit
        let mut regular = note.clone();
        regular.commitment_txids = vec!["c1".to_string()];
        regular.root_commitment_txid = "c1".to_string();
        assert!(!regular.is_note());
        assert!(regular.requires_forfeit(), "regular VTXOs require forfeit");
    }
}
