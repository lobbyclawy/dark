//! Public-input hashes for VON.
//!
//! `H_nonce(setup_id, t, b)` is a BIP-340-style tagged SHA-256 with
//! tag `DARK-VON-nonce-input-v1`. This is the hash the operator feeds
//! to [`crate::wrapper::nonce`] for each `(t, b)` slot of the schedule
//! (issue #657).
//!
//! Encoding is fixed and little-endian: `setup_id (32 B) || t (4 B LE) || b (1 B)`.
//! Total preimage length is 37 bytes. Both encoding and tag are pinned —
//! see ADR-0007 §"Cross-cutting" and the constants below.

use sha2::{Digest, Sha256};

/// Tag for [`h_nonce`]. Pinned by ADR-0007.
///
/// The tag follows the project convention `dark-<crate>/<purpose>/v1`
/// observed in `crates/dark-confidential/src/balance_proof.rs:91-96`.
/// Issue #656's reference to `b"DarkVonNonceInput"` and a `b"DarkRound*"`
/// family in `round_tree.rs` describes a state of the world that does
/// not exist on `main`.
pub const H_NONCE_TAG: &[u8] = b"DARK-VON-nonce-input-v1";

/// `H_nonce(setup_id, t, b)`.
///
/// Layout of the preimage (37 bytes):
///
/// ```text
/// |  32 B setup_id  | 4 B t (little-endian u32) | 1 B b |
/// ```
///
/// Returns the 32-byte BIP-340 tagged-SHA-256 over that preimage with
/// tag [`H_NONCE_TAG`].
pub fn h_nonce(setup_id: &[u8; 32], t: u32, b: u8) -> [u8; 32] {
    let tag_hash = Sha256::digest(H_NONCE_TAG);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(setup_id);
    hasher.update(t.to_le_bytes());
    hasher.update([b]);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_inputs_distinct_outputs() {
        let setup = [0x11u8; 32];
        let h_1_1 = h_nonce(&setup, 1, 1);
        let h_1_2 = h_nonce(&setup, 1, 2);
        let h_2_1 = h_nonce(&setup, 2, 1);
        let h_other_setup = h_nonce(&[0x22u8; 32], 1, 1);
        assert_ne!(h_1_1, h_1_2);
        assert_ne!(h_1_1, h_2_1);
        assert_ne!(h_1_1, h_other_setup);
    }

    #[test]
    fn deterministic() {
        let setup = [0x42u8; 32];
        assert_eq!(h_nonce(&setup, 7, 2), h_nonce(&setup, 7, 2));
    }

    #[test]
    fn known_value() {
        // setup_id = 0x00..0x1f (32 B), t = 0, b = 0
        let mut setup = [0u8; 32];
        for (i, byte) in setup.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let out = h_nonce(&setup, 0, 0);
        // Pinned: catch byte-layout drift.
        let expected = hex::decode(
            "1c441305 34a7cb32 8ca5f9d9 4151ec04 0f44b83b 41c63f28 f992711f b6344626"
                .replace(' ', ""),
        )
        .unwrap();
        assert_eq!(out.to_vec(), expected, "H_nonce byte layout drifted");
    }

    #[test]
    fn t_endianness_is_little() {
        let setup = [0u8; 32];
        // t=0x00000001 LE = 01 00 00 00, t=0x01000000 LE = 00 00 00 01.
        // Different encodings ⇒ different hashes.
        assert_ne!(h_nonce(&setup, 1, 0), h_nonce(&setup, 0x0100_0000, 0));
    }

    #[test]
    fn h_nonce_tag_value() {
        assert_eq!(H_NONCE_TAG, b"DARK-VON-nonce-input-v1");
    }
}
