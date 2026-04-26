//! Confidential VTXO exit script primitives.
//!
//! This module is the workspace stub for the tapscript-builder work tracked in
//! issue #547. The full builder is intentionally out of scope here — the
//! implementation we ship is just enough surface area for downstream client
//! flows (e.g. issue #548) to wire up the unilateral exit path against a
//! deterministic, well-typed signature.
//!
//! TODO(#547): replace [`build_confidential_exit_script`] with the production
//! tapscript builder that derives the leaf script from the owner pubkey, the
//! amount commitment, and the unilateral-exit timelock parameters chosen by
//! the protocol.

use bitcoin::{ScriptBuf, XOnlyPublicKey};

use crate::commitment::PedersenCommitment;

/// Domain-separation tag used by the stub script builder so a stub-built leaf
/// can never collide with a script produced by the real (#547) builder.
const STUB_DOMAIN_TAG: &[u8] = b"dark-confidential/exit-script/stub/v0";

/// Inputs required to reconstruct the confidential VTXO exit tapscript.
#[derive(Debug, Clone)]
pub struct ConfidentialExitScriptInputs<'a> {
    /// Owner x-only public key authorised to spend the leaf.
    pub owner_pubkey: &'a XOnlyPublicKey,
    /// Pedersen commitment to the VTXO amount.
    pub amount_commitment: &'a PedersenCommitment,
    /// Unilateral-exit CSV delay (in blocks) the leaf must encode.
    pub exit_delay_blocks: u32,
}

/// Build the confidential VTXO exit tapscript leaf.
///
/// **STUB**: this implementation is a deterministic placeholder so that
/// downstream client code can be written, tested, and reviewed before the
/// real tapscript builder lands in #547. The returned script is **not**
/// consensus-valid; it intentionally embeds a domain-separation tag so it
/// cannot be confused with a real exit leaf on-chain.
///
/// TODO(#547): implement the production builder. The expected signature is
/// stable: the real implementation will return a [`ScriptBuf`] derived from
/// the same `(owner_pubkey, amount_commitment, exit_delay_blocks)` triple.
pub fn build_confidential_exit_script(inputs: &ConfidentialExitScriptInputs<'_>) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(
        STUB_DOMAIN_TAG.len()
            + 1
            + 32 // x-only pubkey
            + 33 // commitment
            + 4, // exit delay
    );
    bytes.extend_from_slice(STUB_DOMAIN_TAG);
    bytes.push(0x00);
    bytes.extend_from_slice(&inputs.owner_pubkey.serialize());
    bytes.extend_from_slice(&inputs.amount_commitment.to_bytes());
    bytes.extend_from_slice(&inputs.exit_delay_blocks.to_be_bytes());
    ScriptBuf::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Scalar, Secp256k1, SecretKey};

    fn test_pubkey() -> XOnlyPublicKey {
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

    fn test_commitment() -> PedersenCommitment {
        let blinding = {
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            Scalar::from_be_bytes(bytes).unwrap()
        };
        PedersenCommitment::commit(100_000, &blinding).unwrap()
    }

    #[test]
    fn stub_is_deterministic() {
        let pubkey = test_pubkey();
        let commitment = test_commitment();
        let inputs = ConfidentialExitScriptInputs {
            owner_pubkey: &pubkey,
            amount_commitment: &commitment,
            exit_delay_blocks: 144,
        };
        let a = build_confidential_exit_script(&inputs);
        let b = build_confidential_exit_script(&inputs);
        assert_eq!(a, b, "stub builder must be deterministic");
        assert!(
            a.as_bytes().starts_with(STUB_DOMAIN_TAG),
            "stub script must be domain-separated"
        );
    }

    #[test]
    fn stub_changes_with_inputs() {
        let pubkey = test_pubkey();
        let commitment = test_commitment();
        let a = build_confidential_exit_script(&ConfidentialExitScriptInputs {
            owner_pubkey: &pubkey,
            amount_commitment: &commitment,
            exit_delay_blocks: 144,
        });
        let b = build_confidential_exit_script(&ConfidentialExitScriptInputs {
            owner_pubkey: &pubkey,
            amount_commitment: &commitment,
            exit_delay_blocks: 145,
        });
        assert_ne!(a, b);
    }
}
