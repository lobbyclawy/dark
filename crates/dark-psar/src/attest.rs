//! Slot attestation (issue #668).
//!
//! A [`SlotAttest`] is the ASP's BIP-340 Schnorr signature over a
//! cohort's `slot_root` (#667) plus the cohort metadata that pins
//! "which cohort, with which setup, for what horizon" the root belongs
//! to. The signature commits the ASP to the slot allocation; downstream
//! flows (#669 OP_RETURN publish, #670 user-side verify, #671 ASP-side
//! orchestration) consume this struct.
//!
//! # Wire format
//!
//! - **Unsigned payload** ([`SlotAttestUnsigned::SIZE`] = 104 B):
//!
//!   ```text
//!   |  32 B slot_root  |  32 B cohort_id  |  32 B setup_id  |  4 B n (LE u32)  |  4 B k (LE u32)  |
//!   ```
//!
//! - **Signed payload** ([`SlotAttest::SIZE`] = 168 B): the unsigned
//!   payload followed by the 64-byte BIP-340 Schnorr signature.
//!
//! The signature is computed over the BIP-340 tagged hash of the
//! unsigned payload with tag [`SLOT_ATTEST_TAG`]
//! (`b"DarkPsarSlotAttestV1"`).
//!
//! # OP_RETURN payload
//!
//! Issue #668 sets a target of ≤ 80 B "after Schnorr sig" so the
//! attestation fits in a single OP_RETURN output. Publishing the full
//! 168-byte signed payload requires the verifier to have the on-chain
//! data only — but it overflows the standard 80 B `-datacarriersize`
//! limit.
//!
//! [`SlotAttest::op_return_payload`] therefore emits a compact 68-byte
//! form `[ "PSAR" magic | 64 B sig ]` (4 + 64). Verifying the on-chain
//! commitment requires the verifier to have the unsigned payload from
//! off-chain context (every cohort member already does, since they
//! received it as part of boarding); the on-chain bytes are then a
//! timestamped, third-party-non-repudiable commitment to that payload
//! under the ASP's BIP-340 key.
//!
//! This deviates from issue #668's "single canonical encoding for both
//! off-chain and OP_RETURN" wording — see PR notes.
//!
//! # Round-trip + tamper guarantees
//!
//! [`SlotAttest::to_bytes`] / [`SlotAttest::from_bytes`] are inverse
//! pure functions of the struct contents. [`SlotAttest::verify`]
//! returns `Err(SlotAttestError::InvalidSignature)` for any byte
//! flipped in the unsigned payload or the signature: the signature is
//! BIP-340-bound to the digest of the unsigned bytes.

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// BIP-340 tagged-hash tag for the slot attestation digest.
pub const SLOT_ATTEST_TAG: &[u8] = b"DarkPsarSlotAttestV1";

/// 4-byte magic marking an on-chain slot-attestation OP_RETURN payload.
pub const OP_RETURN_MAGIC: [u8; 4] = *b"PSAR";

/// `SlotAttest` errors.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlotAttestError {
    #[error("malformed slot attest: got {got} bytes, expected {expected}")]
    MalformedLength { got: usize, expected: usize },

    #[error("invalid bip-340 signature on slot attest")]
    InvalidSignature,

    #[error("malformed signature bytes")]
    MalformedSignature,
}

/// Unsigned attestation payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SlotAttestUnsigned {
    pub slot_root: [u8; 32],
    pub cohort_id: [u8; 32],
    pub setup_id: [u8; 32],
    pub n: u32,
    pub k: u32,
}

impl SlotAttestUnsigned {
    /// Serialised length of the unsigned payload.
    pub const SIZE: usize = 32 + 32 + 32 + 4 + 4;

    /// Canonical 104-byte serialisation.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..32].copy_from_slice(&self.slot_root);
        out[32..64].copy_from_slice(&self.cohort_id);
        out[64..96].copy_from_slice(&self.setup_id);
        out[96..100].copy_from_slice(&self.n.to_le_bytes());
        out[100..104].copy_from_slice(&self.k.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlotAttestError> {
        if bytes.len() != Self::SIZE {
            return Err(SlotAttestError::MalformedLength {
                got: bytes.len(),
                expected: Self::SIZE,
            });
        }
        let mut slot_root = [0u8; 32];
        slot_root.copy_from_slice(&bytes[0..32]);
        let mut cohort_id = [0u8; 32];
        cohort_id.copy_from_slice(&bytes[32..64]);
        let mut setup_id = [0u8; 32];
        setup_id.copy_from_slice(&bytes[64..96]);
        let mut n_buf = [0u8; 4];
        n_buf.copy_from_slice(&bytes[96..100]);
        let mut k_buf = [0u8; 4];
        k_buf.copy_from_slice(&bytes[100..104]);
        Ok(Self {
            slot_root,
            cohort_id,
            setup_id,
            n: u32::from_le_bytes(n_buf),
            k: u32::from_le_bytes(k_buf),
        })
    }

    /// 32-byte BIP-340 tagged digest the ASP signs.
    pub fn signing_digest(&self) -> [u8; 32] {
        tagged_hash(SLOT_ATTEST_TAG, &self.to_bytes())
    }

    /// Sign with the ASP's BIP-340 keypair, producing a [`SlotAttest`].
    pub fn sign<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>, kp: &Keypair) -> SlotAttest {
        let digest = self.signing_digest();
        let msg = Message::from_digest(digest);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, kp);
        SlotAttest {
            unsigned: *self,
            sig: sig.serialize(),
        }
    }
}

/// Signed slot attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SlotAttest {
    pub unsigned: SlotAttestUnsigned,
    pub sig: [u8; 64],
}

impl SlotAttest {
    /// Full canonical wire size = unsigned (104) + Schnorr (64).
    pub const SIZE: usize = SlotAttestUnsigned::SIZE + 64;

    /// On-chain OP_RETURN payload size: 4 B magic + 64 B sig.
    pub const OP_RETURN_SIZE: usize = OP_RETURN_MAGIC.len() + 64;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..SlotAttestUnsigned::SIZE].copy_from_slice(&self.unsigned.to_bytes());
        out[SlotAttestUnsigned::SIZE..].copy_from_slice(&self.sig);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlotAttestError> {
        if bytes.len() != Self::SIZE {
            return Err(SlotAttestError::MalformedLength {
                got: bytes.len(),
                expected: Self::SIZE,
            });
        }
        let unsigned = SlotAttestUnsigned::from_bytes(&bytes[..SlotAttestUnsigned::SIZE])?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[SlotAttestUnsigned::SIZE..]);
        Ok(Self { unsigned, sig })
    }

    /// Compact on-chain payload: magic prefix + sig. The verifier needs
    /// the unsigned payload from off-chain context to fully verify.
    pub fn op_return_payload(&self) -> [u8; Self::OP_RETURN_SIZE] {
        let mut out = [0u8; Self::OP_RETURN_SIZE];
        out[..4].copy_from_slice(&OP_RETURN_MAGIC);
        out[4..].copy_from_slice(&self.sig);
        out
    }

    /// Recover a `SlotAttest` from `op_return_payload` + an off-chain
    /// unsigned payload. Validates the magic prefix and the signature.
    pub fn from_op_return_with_unsigned(
        op_return: &[u8],
        unsigned: SlotAttestUnsigned,
        pk_asp: &XOnlyPublicKey,
    ) -> Result<Self, SlotAttestError> {
        if op_return.len() != Self::OP_RETURN_SIZE {
            return Err(SlotAttestError::MalformedLength {
                got: op_return.len(),
                expected: Self::OP_RETURN_SIZE,
            });
        }
        if op_return[..4] != OP_RETURN_MAGIC {
            return Err(SlotAttestError::MalformedSignature);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&op_return[4..]);
        let attest = Self { unsigned, sig };
        attest.verify(pk_asp)?;
        Ok(attest)
    }

    /// Verify the signature against the ASP's BIP-340 x-only public key.
    pub fn verify(&self, pk_asp: &XOnlyPublicKey) -> Result<(), SlotAttestError> {
        let secp = Secp256k1::verification_only();
        let sig =
            Signature::from_slice(&self.sig).map_err(|_| SlotAttestError::MalformedSignature)?;
        let digest = self.unsigned.signing_digest();
        let msg = Message::from_digest(digest);
        secp.verify_schnorr(&sig, &msg, pk_asp)
            .map_err(|_| SlotAttestError::InvalidSignature)
    }
}

fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    fn make_unsigned(seed: u8) -> SlotAttestUnsigned {
        SlotAttestUnsigned {
            slot_root: [seed; 32],
            cohort_id: [seed.wrapping_add(1); 32],
            setup_id: [seed.wrapping_add(2); 32],
            n: 12,
            k: 100,
        }
    }

    fn fixed_keypair() -> Keypair {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xa7u8; 32]).unwrap();
        Keypair::from_secret_key(&secp, &sk)
    }

    #[test]
    fn pinned_constants() {
        assert_eq!(SLOT_ATTEST_TAG, b"DarkPsarSlotAttestV1");
        assert_eq!(OP_RETURN_MAGIC, *b"PSAR");
        assert_eq!(SlotAttestUnsigned::SIZE, 104);
        assert_eq!(SlotAttest::SIZE, 168);
        assert_eq!(SlotAttest::OP_RETURN_SIZE, 68);
    }

    #[test]
    fn unsigned_round_trip() {
        let u = make_unsigned(0xab);
        let bytes = u.to_bytes();
        assert_eq!(bytes.len(), SlotAttestUnsigned::SIZE);
        let parsed = SlotAttestUnsigned::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, u);
    }

    #[test]
    fn unsigned_le_n_and_k_layout() {
        let u = SlotAttestUnsigned {
            slot_root: [0u8; 32],
            cohort_id: [0u8; 32],
            setup_id: [0u8; 32],
            n: 0x0403_0201,
            k: 0x0807_0605,
        };
        let b = u.to_bytes();
        assert_eq!(&b[96..100], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&b[100..104], &[0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn unsigned_from_bytes_rejects_wrong_length() {
        let err = SlotAttestUnsigned::from_bytes(&[0u8; 103]).unwrap_err();
        assert_eq!(
            err,
            SlotAttestError::MalformedLength {
                got: 103,
                expected: 104,
            }
        );
    }

    #[test]
    fn signed_round_trip_and_verify() {
        let secp = Secp256k1::new();
        let kp = fixed_keypair();
        let pk = kp.x_only_public_key().0;
        let u = make_unsigned(0x42);
        let attest = u.sign(&secp, &kp);
        attest.verify(&pk).expect("valid sig");

        let bytes = attest.to_bytes();
        assert_eq!(bytes.len(), SlotAttest::SIZE);
        let parsed = SlotAttest::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, attest);
        parsed
            .verify(&pk)
            .expect("round-tripped attest still verifies");
    }

    #[test]
    fn signed_from_bytes_rejects_wrong_length() {
        let err = SlotAttest::from_bytes(&[0u8; 167]).unwrap_err();
        assert_eq!(
            err,
            SlotAttestError::MalformedLength {
                got: 167,
                expected: 168,
            }
        );
    }

    #[test]
    fn tampered_unsigned_field_fails_verify() {
        let secp = Secp256k1::new();
        let kp = fixed_keypair();
        let pk = kp.x_only_public_key().0;
        let u = make_unsigned(0x10);
        let attest = u.sign(&secp, &kp);

        // Mutate every byte position in the 104-byte unsigned payload and
        // confirm verify rejects.
        for byte_idx in 0..SlotAttestUnsigned::SIZE {
            let mut bytes = attest.to_bytes();
            bytes[byte_idx] ^= 0x01;
            // Parses fine — bytes are well-formed length.
            let tampered = SlotAttest::from_bytes(&bytes).unwrap();
            let err = tampered.verify(&pk).unwrap_err();
            assert!(
                matches!(
                    err,
                    SlotAttestError::InvalidSignature | SlotAttestError::MalformedSignature
                ),
                "byte {byte_idx}: expected verify rejection, got {err:?}"
            );
        }
    }

    #[test]
    fn tampered_signature_byte_fails_verify() {
        let secp = Secp256k1::new();
        let kp = fixed_keypair();
        let pk = kp.x_only_public_key().0;
        let attest = make_unsigned(0x77).sign(&secp, &kp);

        for byte_idx in SlotAttestUnsigned::SIZE..SlotAttest::SIZE {
            let mut bytes = attest.to_bytes();
            bytes[byte_idx] ^= 0x01;
            let tampered = SlotAttest::from_bytes(&bytes).unwrap();
            assert!(tampered.verify(&pk).is_err(), "byte {byte_idx}");
        }
    }

    #[test]
    fn wrong_pubkey_fails_verify() {
        let secp = Secp256k1::new();
        let kp = fixed_keypair();
        let attest = make_unsigned(0x33).sign(&secp, &kp);
        let other_kp = {
            let sk = SecretKey::from_slice(&[0x55u8; 32]).unwrap();
            Keypair::from_secret_key(&secp, &sk)
        };
        let other_pk = other_kp.x_only_public_key().0;
        assert_eq!(
            attest.verify(&other_pk),
            Err(SlotAttestError::InvalidSignature)
        );
    }

    #[test]
    fn op_return_payload_size_and_round_trip() {
        let secp = Secp256k1::new();
        let kp = fixed_keypair();
        let pk = kp.x_only_public_key().0;
        let u = make_unsigned(0x99);
        let attest = u.sign(&secp, &kp);

        let payload = attest.op_return_payload();
        assert_eq!(payload.len(), 68);
        assert!(
            payload.len() <= 80,
            "OP_RETURN must fit standard 80-byte cap"
        );
        assert_eq!(&payload[..4], &OP_RETURN_MAGIC);
        assert_eq!(&payload[4..], &attest.sig);

        let recovered = SlotAttest::from_op_return_with_unsigned(&payload, u, &pk).unwrap();
        assert_eq!(recovered, attest);
    }

    #[test]
    fn op_return_rejects_bad_magic() {
        let secp = Secp256k1::new();
        let kp = fixed_keypair();
        let pk = kp.x_only_public_key().0;
        let u = make_unsigned(0xaa);
        let attest = u.sign(&secp, &kp);
        let mut payload = attest.op_return_payload();
        payload[0] = b'X';
        let err = SlotAttest::from_op_return_with_unsigned(&payload, u, &pk).unwrap_err();
        assert_eq!(err, SlotAttestError::MalformedSignature);
    }

    #[test]
    fn op_return_rejects_wrong_unsigned_payload() {
        let secp = Secp256k1::new();
        let kp = fixed_keypair();
        let pk = kp.x_only_public_key().0;
        let u = make_unsigned(0xaa);
        let other = make_unsigned(0xbb);
        let attest = u.sign(&secp, &kp);
        let payload = attest.op_return_payload();
        let err = SlotAttest::from_op_return_with_unsigned(&payload, other, &pk).unwrap_err();
        assert_eq!(err, SlotAttestError::InvalidSignature);
    }

    #[test]
    fn signing_is_deterministic_no_aux_rand() {
        // BIP-340 with `sign_schnorr_no_aux_rand` is deterministic; same
        // (sk, msg) → same sig. This pins the property and lets us produce
        // golden fixtures in #669 if needed.
        let secp = Secp256k1::new();
        let kp = fixed_keypair();
        let u = make_unsigned(0x01);
        let a1 = u.sign(&secp, &kp);
        let a2 = u.sign(&secp, &kp);
        assert_eq!(a1.sig, a2.sig);
    }
}
