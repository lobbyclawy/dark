//! Wallet-side representation of a Confidential VTXO.
//!
//! This module defines the local-state record a client wallet keeps for each
//! confidential VTXO it owns. It carries the sensitive opening of the
//! Pedersen commitment (`amount`, `blinding`) plus the public anchoring
//! data (`owner_pubkey`, leaf outpoint, exit delay) needed to reconstruct
//! the unilateral-exit tapscript and authenticate the spend.
//!
//! Scope: this is the minimum surface needed by issue #548. The full type
//! used by the validation/proof pipeline (see #531/#538) may grow more
//! fields; see [`ConfidentialVtxo::new`] for the stable constructor.

use bitcoin::{OutPoint, XOnlyPublicKey};
use secp256k1::Scalar;

/// Wallet-local record for a single Confidential VTXO.
///
/// Holds both the sensitive opening (`amount`, `blinding`) and the public
/// anchoring fields (`owner_pubkey`, `leaf_outpoint`, `exit_delay_blocks`)
/// required to reconstruct the unilateral-exit tapscript leaf.
///
/// Threat-model note: callers must treat the `blinding` field as secret.
/// This type intentionally does **not** derive `Clone` to discourage
/// duplication in memory; clone explicitly via [`ConfidentialVtxo::cloned`]
/// when a copy is genuinely required (e.g. test fixtures).
#[derive(Debug)]
pub struct ConfidentialVtxo {
    /// VTXO amount in satoshis (the opening value of the Pedersen commitment).
    pub amount: u64,
    /// Blinding factor used to commit to `amount`.
    pub blinding: Scalar,
    /// Owner's x-only public key, authorised to spend the leaf.
    pub owner_pubkey: XOnlyPublicKey,
    /// On-chain outpoint of the round-tree leaf this VTXO settles to.
    pub leaf_outpoint: OutPoint,
    /// Unilateral-exit CSV delay (in blocks) baked into the leaf script.
    pub exit_delay_blocks: u32,
}

impl ConfidentialVtxo {
    /// Construct a new `ConfidentialVtxo` from its component fields.
    pub fn new(
        amount: u64,
        blinding: Scalar,
        owner_pubkey: XOnlyPublicKey,
        leaf_outpoint: OutPoint,
        exit_delay_blocks: u32,
    ) -> Self {
        Self {
            amount,
            blinding,
            owner_pubkey,
            leaf_outpoint,
            exit_delay_blocks,
        }
    }

    /// Explicit copy. Only call this when a duplicate is genuinely required.
    pub fn cloned(&self) -> Self {
        Self {
            amount: self.amount,
            blinding: self.blinding,
            owner_pubkey: self.owner_pubkey,
            leaf_outpoint: self.leaf_outpoint,
            exit_delay_blocks: self.exit_delay_blocks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{hashes::Hash, Txid};
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    fn test_xonly() -> XOnlyPublicKey {
        let secret = SecretKey::from_slice(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11,
        ])
        .unwrap();
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &secret);
        XOnlyPublicKey::from_keypair(&kp).0
    }

    #[test]
    fn new_and_cloned_round_trip() {
        let blinding = {
            let mut bytes = [0u8; 32];
            bytes[31] = 7;
            Scalar::from_be_bytes(bytes).unwrap()
        };
        let pubkey = test_xonly();
        let outpoint = OutPoint::new(Txid::all_zeros(), 1);
        let v = ConfidentialVtxo::new(12_345, blinding, pubkey, outpoint, 144);
        let c = v.cloned();
        assert_eq!(c.amount, 12_345);
        assert_eq!(c.exit_delay_blocks, 144);
        assert_eq!(c.leaf_outpoint, outpoint);
        assert_eq!(c.owner_pubkey, pubkey);
        assert_eq!(c.blinding.to_be_bytes(), v.blinding.to_be_bytes());
    }
}
