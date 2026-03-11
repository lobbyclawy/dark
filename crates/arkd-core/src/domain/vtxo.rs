//! Virtual Transaction Output (VTXO) domain model
//!
//! VTXOs are the core primitive of the Ark protocol, representing off-chain
//! Bitcoin outputs that can be transferred without on-chain transactions.
//!
//! # Overview
//!
//! A VTXO is a "virtual" UTXO that exists off-chain but is backed by an
//! on-chain commitment transaction. Users can:
//! - Transfer VTXOs instantly to other users (off-chain)
//! - Exit to on-chain Bitcoin at any time (collaborative or unilateral)
//! - Participate in rounds to refresh their VTXOs before expiry
//!
//! # Security Model
//!
//! Each VTXO has:
//! - An expiry height (on-chain block height when it can be unilaterally claimed)
//! - A tree path (Merkle proof to the on-chain commitment)
//! - The user's public key (for ownership verification)
//!
//! If the ASP (Ark Service Provider) becomes unresponsive, users can
//! unilaterally exit by publishing their branch of the VTXO tree.

use bitcoin::{Amount, OutPoint, ScriptBuf, Txid, XOnlyPublicKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A Virtual Transaction Output (VTXO)
///
/// The core primitive of the Ark protocol, representing an off-chain
/// Bitcoin output that can be transferred without on-chain transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vtxo {
    /// Unique identifier for this VTXO
    pub id: VtxoId,

    /// The amount in satoshis
    pub amount: Amount,

    /// Owner's public key (x-only for Taproot compatibility)
    ///
    /// **Design choice:** We use `XOnlyPublicKey` (32 bytes) instead of
    /// `PublicKey` (33 bytes) because:
    /// 1. Ark protocol requires Taproot for covenant scripts
    /// 2. Smaller size reduces on-chain footprint
    /// 3. All modern wallets support Taproot (post-2021)
    ///
    /// Legacy P2PKH/P2WPKH users must upgrade to Taproot to use Ark.
    pub owner_pubkey: XOnlyPublicKey,

    /// Block height when this VTXO expires
    ///
    /// After this height, the user can unilaterally claim the funds
    /// without ASP cooperation.
    pub expiry_height: u32,

    /// Path in the VTXO tree (Merkle proof)
    pub tree_path: TreePath,

    /// The round this VTXO was created in
    pub round_id: Uuid,

    /// Current status of the VTXO
    pub status: VtxoStatus,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Unique identifier for a VTXO
///
/// Format: `txid:vout` representing the virtual outpoint
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VtxoId(pub String);

impl VtxoId {
    /// Create a new VTXO ID from components
    pub fn new(txid: Txid, vout: u32) -> Self {
        Self(format!("{}:{}", txid, vout))
    }

    /// Create a VTXO ID from an outpoint
    pub fn from_outpoint(outpoint: OutPoint) -> Self {
        Self::new(outpoint.txid, outpoint.vout)
    }

    /// Parse a VTXO ID string
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }
}

impl std::fmt::Display for VtxoId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for VtxoId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for VtxoId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Status of a VTXO in its lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VtxoStatus {
    /// VTXO is pending (round not yet finalized)
    Pending,

    /// VTXO is active and spendable
    Active,

    /// VTXO has been spent (transferred to another user)
    Spent,

    /// VTXO is in the process of being exited on-chain
    Exiting,

    /// VTXO has been exited to on-chain Bitcoin
    Exited,

    /// VTXO has expired (no longer valid)
    Expired,
}

impl VtxoStatus {
    /// Check if this VTXO can be spent
    pub fn is_spendable(&self) -> bool {
        matches!(self, VtxoStatus::Active)
    }

    /// Check if this VTXO is terminal (no more state changes)
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            VtxoStatus::Spent | VtxoStatus::Exited | VtxoStatus::Expired
        )
    }
}

/// Path in the VTXO tree (Merkle proof)
///
/// This allows a user to prove their VTXO is part of the committed
/// VTXO tree without revealing the entire tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreePath {
    /// Position in the tree (leaf index)
    pub position: u32,

    /// Merkle proof siblings (hashes needed to reconstruct root)
    pub siblings: Vec<[u8; 32]>,

    /// The script needed to spend this VTXO
    pub witness_script: ScriptBuf,
}

impl TreePath {
    /// Create a new tree path
    pub fn new(position: u32, siblings: Vec<[u8; 32]>, witness_script: ScriptBuf) -> Self {
        Self {
            position,
            siblings,
            witness_script,
        }
    }

    /// Depth of this path in the tree
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Verify this path against a root hash
    ///
    /// TODO: Implement actual Merkle proof verification
    pub fn verify(&self, _leaf_hash: &[u8; 32], _root_hash: &[u8; 32]) -> bool {
        // Placeholder - implement actual verification
        true
    }
}

impl Default for TreePath {
    fn default() -> Self {
        Self {
            position: 0,
            siblings: Vec::new(),
            witness_script: ScriptBuf::new(),
        }
    }
}

/// A request to create a new VTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoRequest {
    /// Requested amount in satoshis
    pub amount: Amount,

    /// Recipient's public key
    pub recipient_pubkey: XOnlyPublicKey,

    /// Optional: existing VTXO to spend (for transfers)
    pub input_vtxo: Option<VtxoId>,
}

impl VtxoRequest {
    /// Create a new VTXO request
    pub fn new(amount: Amount, recipient_pubkey: XOnlyPublicKey) -> Self {
        Self {
            amount,
            recipient_pubkey,
            input_vtxo: None,
        }
    }

    /// Create a VTXO request from an existing VTXO (transfer)
    pub fn transfer(input_vtxo: VtxoId, amount: Amount, recipient_pubkey: XOnlyPublicKey) -> Self {
        Self {
            amount,
            recipient_pubkey,
            input_vtxo: Some(input_vtxo),
        }
    }
}

impl Vtxo {
    /// Create a new VTXO
    pub fn new(
        id: VtxoId,
        amount: Amount,
        owner_pubkey: XOnlyPublicKey,
        expiry_height: u32,
        round_id: Uuid,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            amount,
            owner_pubkey,
            expiry_height,
            tree_path: TreePath::default(),
            round_id,
            status: VtxoStatus::Pending,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the tree path for this VTXO
    pub fn with_tree_path(mut self, tree_path: TreePath) -> Self {
        self.tree_path = tree_path;
        self.updated_at = Utc::now();
        self
    }

    /// Activate this VTXO (round finalized)
    pub fn activate(&mut self) {
        self.status = VtxoStatus::Active;
        self.updated_at = Utc::now();
    }

    /// Mark this VTXO as spent
    pub fn mark_spent(&mut self) {
        self.status = VtxoStatus::Spent;
        self.updated_at = Utc::now();
    }

    /// Mark this VTXO as exiting
    pub fn mark_exiting(&mut self) {
        self.status = VtxoStatus::Exiting;
        self.updated_at = Utc::now();
    }

    /// Mark this VTXO as exited
    pub fn mark_exited(&mut self) {
        self.status = VtxoStatus::Exited;
        self.updated_at = Utc::now();
    }

    /// Mark this VTXO as expired
    pub fn mark_expired(&mut self) {
        self.status = VtxoStatus::Expired;
        self.updated_at = Utc::now();
    }

    /// Check if this VTXO is expired at a given block height
    pub fn is_expired_at(&self, current_height: u32) -> bool {
        current_height >= self.expiry_height
    }

    /// Calculate remaining lifetime in blocks
    pub fn blocks_until_expiry(&self, current_height: u32) -> Option<u32> {
        if current_height >= self.expiry_height {
            None
        } else {
            Some(self.expiry_height - current_height)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::Secp256k1;

    fn test_xonly_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let (_, pk) = secp.generate_keypair(&mut OsRng);
        XOnlyPublicKey::from(pk)
    }

    #[test]
    fn test_vtxo_creation() {
        let id = VtxoId::from("test:0");
        let amount = Amount::from_sat(100_000);
        let pubkey = test_xonly_pubkey();
        let round_id = Uuid::new_v4();

        let vtxo = Vtxo::new(id.clone(), amount, pubkey, 1000, round_id);

        assert_eq!(vtxo.id, id);
        assert_eq!(vtxo.amount, amount);
        assert_eq!(vtxo.status, VtxoStatus::Pending);
    }

    #[test]
    fn test_vtxo_lifecycle() {
        let id = VtxoId::from("test:0");
        let mut vtxo = Vtxo::new(
            id,
            Amount::from_sat(100_000),
            test_xonly_pubkey(),
            1000,
            Uuid::new_v4(),
        );

        // Pending -> Active
        assert!(!vtxo.status.is_spendable());
        vtxo.activate();
        assert!(vtxo.status.is_spendable());

        // Active -> Spent
        vtxo.mark_spent();
        assert!(vtxo.status.is_terminal());
    }

    #[test]
    fn test_vtxo_expiry() {
        let vtxo = Vtxo::new(
            VtxoId::from("test:0"),
            Amount::from_sat(100_000),
            test_xonly_pubkey(),
            1000,
            Uuid::new_v4(),
        );

        assert!(!vtxo.is_expired_at(500));
        assert!(!vtxo.is_expired_at(999));
        assert!(vtxo.is_expired_at(1000));
        assert!(vtxo.is_expired_at(1500));

        assert_eq!(vtxo.blocks_until_expiry(500), Some(500));
        assert_eq!(vtxo.blocks_until_expiry(1000), None);
    }

    #[test]
    fn test_vtxo_id_parsing() {
        let id = VtxoId::parse("abc123:5").unwrap();
        assert_eq!(id.0, "abc123:5");

        assert!(VtxoId::parse("invalid").is_none());
    }
}
