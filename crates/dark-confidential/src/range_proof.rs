//! Range proof primitives for Confidential VTXOs.
//!
//! # Overview
//!
//! Every confidential output carries a zero-knowledge proof that its
//! committed amount lies in `[0, 2^64)`. Without this, a malicious sender
//! could commit to a field-wrapped "negative" amount and inflate supply by
//! balancing it against legitimate outputs that the operator can only
//! validate homomorphically.
//!
//! # Construction
//!
//! Per ADR-0001 (see `docs/adr/0001-secp256k1-zkp-integration.md`), the
//! crate depends on `secp256k1-zkp = 0.11` and delegates the underlying
//! proof construction to the Back-Maxwell rangeproofs bound by that crate.
//! The issue text for #525 requests *Bulletproofs* with `~672 B` per
//! proof and log-sized aggregation; neither exists in any audited Rust
//! surface over secp256k1 today, and the ADR formally re-scopes the
//! requirement to "production-grade bounded-value range proofs on
//! secp256k1". Migration to Bulletproofs is tracked as follow-up FU-BP.
//!
//! Callers MUST treat [`RangeProof`] as opaque bytes: the wire layout is
//! an implementation detail so FU-BP can land as an internal change.
//!
//! # Relationship to [`crate::commitment`]
//!
//! This module uses its own [`ValueCommitment`] type — a thin newtype
//! over `secp256k1_zkp::PedersenCommitment`. It is **not** byte- or
//! scalar-compatible with [`crate::commitment::PedersenCommitment`]
//! (#524), which was merged prior to ADR-0001 being enforced and uses
//! the opposite scalar convention (`amount·G + blinding·H` vs zkp's
//! `value·H + blinding·G`). Until #524 is reconciled with ADR-0001,
//! range proofs operate on [`ValueCommitment`] only.
//!
//! # Threat model
//!
//! - The `nonce` passed to `RangeProof::new` is per-proof randomness, not
//!   a long-lived key. Reusing a nonce across proofs that commit to the
//!   same value leaks the blinding factor; across different values it
//!   leaks the delta. We sample a fresh nonce from the OS CSPRNG on every
//!   prove. A deterministic, protocol-scoped KDF is pinned in #529 and
//!   will replace the CSPRNG sampling once available.
//! - `verify_range` / `verify_range_aggregated` return `bool` per the
//!   issue API. They do not branch on the proof contents before the FFI
//!   boundary, so the surface-level timing is dominated by the constant
//!   parse + curve work inside `secp256k1-zkp`. Secret data (amounts,
//!   blinding factors) is not read on the verifier path.
//! - Aggregated proofs are a framed list of independent Back-Maxwell
//!   proofs. Back-Maxwell is not log-size-aggregatable; the saving over
//!   N separately-framed singles is `N - 3` bytes of framing. Ship-size
//!   improvements are gated on FU-BP.

use core::ops::RangeInclusive;

use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::Scalar;
use secp256k1_zkp::{
    Generator, PedersenCommitment as ZkpPedersenCommitment, RangeProof as ZkpRangeProof,
    Secp256k1 as ZkpSecp256k1, SecretKey as ZkpSecretKey, Tag, Tweak,
};

use crate::{ConfidentialError, Result};

/// Single-proof format tag in the opaque wire encoding.
const TAG_SINGLE: u8 = 0x01;
/// Aggregated-proof format tag in the opaque wire encoding.
const TAG_AGGREGATED: u8 = 0x02;
/// Upper bound on the number of sub-proofs in an aggregated blob.
///
/// Bounds memory during `from_bytes` parsing; well above any realistic
/// round shape. A 500-output round (ADR-0001 §"Bandwidth delta") lies
/// inside this cap with room to spare.
const AGG_MAX_PROOFS: usize = 65_535;

/// Maximum provable amount.
///
/// The issue text asks for `[0, 2^64)`. In practice `secp256k1-zkp = 0.11`'s
/// `RangeProof::verify` computes `max_value + 1` when constructing its
/// `std::ops::Range<u64>` return (`rangeproof.rs:147`), which overflows for
/// 64-bit proofs. Until that is patched upstream we cap at `2^63 - 1`.
/// Bitcoin's total supply (~2.1·10^15 sats ≈ 2^51) sits four orders of
/// magnitude below this cap — no protocol-level amount is affected.
pub const MAX_PROVABLE_AMOUNT: u64 = (1u64 << 63) - 1;

/// Value-commitment compatible with the range proof construction.
///
/// Internally a `secp256k1_zkp::PedersenCommitment` = `value · H + blind · G`
/// where `H` is the unblinded generator derived from `Tag::default()`
/// and `G` is the secp256k1 base point. **Not** byte-compatible with
/// [`crate::commitment::PedersenCommitment`]; see module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueCommitment(ZkpPedersenCommitment);

impl ValueCommitment {
    /// Commit to `amount` under `blinding`. `blinding` is interpreted as
    /// a 32-byte scalar in big-endian; the zero scalar is rejected
    /// because it collapses the binding property.
    pub fn commit(amount: u64, blinding: &Scalar) -> Result<Self> {
        let tweak = tweak_from_scalar(blinding)?;
        let ctx = ZkpSecp256k1::new();
        let generator = value_generator();
        Ok(Self(ZkpPedersenCommitment::new(
            &ctx, amount, tweak, generator,
        )))
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        self.0.serialize()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = ZkpPedersenCommitment::from_slice(bytes)
            .map_err(|_| ConfidentialError::InvalidEncoding("invalid pedersen commitment"))?;
        Ok(Self(inner))
    }

    fn as_inner(&self) -> ZkpPedersenCommitment {
        self.0
    }

    /// Crate-internal accessor for the wrapped zkp commitment. Exposed so
    /// the disclosure layer can feed it back into the FFI without
    /// re-deriving it.
    pub(crate) fn into_inner(self) -> ZkpPedersenCommitment {
        self.0
    }
}

/// Opaque range proof over a single [`ValueCommitment`] or a uniform-size
/// aggregation of them.
///
/// The wire encoding is `[tag | body]`:
/// - `tag = 0x01`: single Back-Maxwell proof; `body` is the raw zkp bytes.
/// - `tag = 0x02`: aggregated;
///   `body = [u16_be count][u16_be shared_len][count × shared_len bytes]`.
///
/// The aggregated form requires every sub-proof to have identical byte
/// length — the common case when outputs share a magnitude (same
/// `bit_width` auto-picked by Back-Maxwell). Mixed-length aggregation
/// fails at prove time with a typed `Unsupported` error so callers fall
/// back to parallel single proofs rather than producing a blob that is
/// larger than individual proofs laid end-to-end.
///
/// Callers MUST NOT parse inside the body. ADR-0001 reserves the right
/// to swap the underlying construction (Bulletproofs migration) without
/// a wire-level breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProof(Inner);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Inner {
    Single(Vec<u8>),
    Aggregated { shared_len: u16, proofs: Vec<u8> },
}

impl RangeProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.0 {
            Inner::Single(bytes) => {
                let mut out = Vec::with_capacity(1 + bytes.len());
                out.push(TAG_SINGLE);
                out.extend_from_slice(bytes);
                out
            }
            Inner::Aggregated { shared_len, proofs } => {
                let count = (proofs.len() / (*shared_len as usize)) as u16;
                let mut out = Vec::with_capacity(1 + 2 + 2 + proofs.len());
                out.push(TAG_AGGREGATED);
                out.extend_from_slice(&count.to_be_bytes());
                out.extend_from_slice(&shared_len.to_be_bytes());
                out.extend_from_slice(proofs);
                out
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (&tag, rest) = bytes
            .split_first()
            .ok_or(ConfidentialError::InvalidEncoding("empty range proof blob"))?;
        match tag {
            TAG_SINGLE => {
                ZkpRangeProof::from_slice(rest).map_err(|_| {
                    ConfidentialError::InvalidEncoding("invalid single range proof")
                })?;
                Ok(Self(Inner::Single(rest.to_vec())))
            }
            TAG_AGGREGATED => {
                if rest.len() < 4 {
                    return Err(ConfidentialError::InvalidEncoding(
                        "aggregated proof missing header",
                    ));
                }
                let count = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                let shared_len = u16::from_be_bytes([rest[2], rest[3]]);
                if count == 0 {
                    return Err(ConfidentialError::InvalidEncoding(
                        "aggregated proof has zero sub-proofs",
                    ));
                }
                if count > AGG_MAX_PROOFS {
                    return Err(ConfidentialError::InvalidEncoding(
                        "aggregated proof count exceeds maximum",
                    ));
                }
                if shared_len == 0 {
                    return Err(ConfidentialError::InvalidEncoding(
                        "aggregated proof has zero shared length",
                    ));
                }
                let body = &rest[4..];
                let expected = count.checked_mul(shared_len as usize).ok_or(
                    ConfidentialError::InvalidEncoding("aggregated proof header length overflow"),
                )?;
                if body.len() != expected {
                    return Err(ConfidentialError::InvalidEncoding(
                        "aggregated proof body length mismatch",
                    ));
                }
                for chunk in body.chunks_exact(shared_len as usize) {
                    ZkpRangeProof::from_slice(chunk).map_err(|_| {
                        ConfidentialError::InvalidEncoding("invalid aggregated sub-proof")
                    })?;
                }
                Ok(Self(Inner::Aggregated {
                    shared_len,
                    proofs: body.to_vec(),
                }))
            }
            _ => Err(ConfidentialError::InvalidEncoding(
                "unknown range proof tag",
            )),
        }
    }

    fn aggregated_sub_proofs(&self) -> Option<impl Iterator<Item = &[u8]>> {
        match &self.0 {
            Inner::Aggregated { shared_len, proofs } => {
                Some(proofs.chunks_exact(*shared_len as usize))
            }
            Inner::Single(_) => None,
        }
    }
}

/// Prove `amount ∈ [0, 2^64)` under `blinding`. Returns the proof and the
/// [`ValueCommitment`] the proof binds to — the verifier needs both and
/// recomputing the commitment on the prover side amortises its cost.
pub fn prove_range(amount: u64, blinding: &Scalar) -> Result<(RangeProof, ValueCommitment)> {
    if amount > MAX_PROVABLE_AMOUNT {
        return Err(ConfidentialError::OutOfRange(
            "amount exceeds MAX_PROVABLE_AMOUNT (2^63 - 1)",
        ));
    }
    let commitment = ValueCommitment::commit(amount, blinding)?;
    let tweak = tweak_from_scalar(blinding)?;
    let nonce = fresh_nonce()?;
    let ctx = ZkpSecp256k1::new();
    let proof = ZkpRangeProof::new(
        &ctx,
        0, // min_value
        commitment.as_inner(),
        amount,
        tweak,
        &[], // message
        &[], // additional_commitment
        nonce,
        0, // exp — library auto-sizes
        0, // min_bits — library auto-sizes
        value_generator(),
    )
    .map_err(|_| ConfidentialError::RangeProof("failed to produce range proof"))?;

    Ok((
        RangeProof(Inner::Single(proof.serialize().to_vec())),
        commitment,
    ))
}

/// Verify `proof` binds `commitment` to a value in `[0, 2^64)`.
///
/// Returns `true` iff the proof is well-formed **and** the verified range
/// sits inside `[0, 2^64)`. Back-Maxwell verify also widens the range
/// beyond the committed value depending on `exp`/`min_bits` — a caller
/// that needs the precise bounds should call [`verify_range_bounded`].
pub fn verify_range(commitment: &ValueCommitment, proof: &RangeProof) -> bool {
    verify_range_bounded(commitment, proof).is_ok()
}

/// Verify and return the verified inclusive range `[min, max]`.
///
/// Normalises the upstream `Range<u64>` (end-exclusive) to an
/// `RangeInclusive` per ADR-0001's cross-cutting constraint on #525.
pub fn verify_range_bounded(
    commitment: &ValueCommitment,
    proof: &RangeProof,
) -> Result<RangeInclusive<u64>> {
    let bytes = match &proof.0 {
        Inner::Single(b) => b,
        Inner::Aggregated { .. } => {
            return Err(ConfidentialError::InvalidInput(
                "aggregated proof passed to single-verify",
            ));
        }
    };
    let zkp_proof = ZkpRangeProof::from_slice(bytes)
        .map_err(|_| ConfidentialError::InvalidEncoding("invalid range proof bytes"))?;
    let ctx = ZkpSecp256k1::new();
    let range = zkp_proof
        .verify(&ctx, commitment.as_inner(), &[], value_generator())
        .map_err(|_| ConfidentialError::RangeProof("range proof did not verify"))?;
    // `range.end` is exclusive upstream (std::ops::Range); clamp to inclusive.
    let end_inclusive = range.end.saturating_sub(1);
    Ok(range.start..=end_inclusive)
}

/// Produce an aggregated proof over `inputs`. Each element is a
/// `(amount, blinding)` pair. Returns the proof and the commitments in
/// input order.
///
/// Back-Maxwell is not log-size-aggregatable: the aggregated proof is a
/// framed list of independent sub-proofs. It is strictly smaller than
/// `N` separate single-proof blobs by framing savings only (`N - 3`
/// bytes for `N ≥ 4`). Log-size aggregation is tracked as FU-BP.
pub fn prove_range_aggregated(
    inputs: &[(u64, Scalar)],
) -> Result<(RangeProof, Vec<ValueCommitment>)> {
    if inputs.is_empty() {
        return Err(ConfidentialError::InvalidInput("empty aggregation input"));
    }
    if inputs.len() > AGG_MAX_PROOFS {
        return Err(ConfidentialError::OutOfRange(
            "aggregation count exceeds maximum",
        ));
    }
    let ctx = ZkpSecp256k1::new();
    let generator = value_generator();
    let mut commitments = Vec::with_capacity(inputs.len());
    let mut serialized: Vec<Vec<u8>> = Vec::with_capacity(inputs.len());
    for (amount, blinding) in inputs {
        if *amount > MAX_PROVABLE_AMOUNT {
            return Err(ConfidentialError::OutOfRange(
                "amount exceeds MAX_PROVABLE_AMOUNT (2^63 - 1)",
            ));
        }
        let tweak = tweak_from_scalar(blinding)?;
        let commitment = ZkpPedersenCommitment::new(&ctx, *amount, tweak, generator);
        let nonce = fresh_nonce()?;
        let proof = ZkpRangeProof::new(
            &ctx,
            0,
            commitment,
            *amount,
            tweak,
            &[],
            &[],
            nonce,
            0,
            0,
            generator,
        )
        .map_err(|_| ConfidentialError::RangeProof("failed to produce sub-proof"))?;
        commitments.push(ValueCommitment(commitment));
        serialized.push(proof.serialize().to_vec());
    }
    let shared_len = serialized[0].len();
    if !serialized.iter().all(|p| p.len() == shared_len) {
        return Err(ConfidentialError::Unsupported(
            "aggregation requires uniform sub-proof lengths; use individual prove_range calls for mixed magnitudes",
        ));
    }
    if shared_len > u16::MAX as usize {
        return Err(ConfidentialError::OutOfRange(
            "sub-proof length exceeds wire encoding",
        ));
    }
    let mut blob = Vec::with_capacity(shared_len * serialized.len());
    for p in &serialized {
        blob.extend_from_slice(p);
    }
    Ok((
        RangeProof(Inner::Aggregated {
            shared_len: shared_len as u16,
            proofs: blob,
        }),
        commitments,
    ))
}

/// Verify an aggregated proof against its commitments. Arity and order
/// must match the `inputs` slice supplied to [`prove_range_aggregated`].
pub fn verify_range_aggregated(commitments: &[ValueCommitment], proof: &RangeProof) -> bool {
    let Some(sub_proofs) = proof.aggregated_sub_proofs() else {
        return false;
    };
    let sub_proofs: Vec<&[u8]> = sub_proofs.collect();
    if sub_proofs.len() != commitments.len() {
        return false;
    }
    let ctx = ZkpSecp256k1::new();
    let generator = value_generator();
    for (bytes, commitment) in sub_proofs.iter().zip(commitments.iter()) {
        let Ok(zkp_proof) = ZkpRangeProof::from_slice(bytes) else {
            return false;
        };
        if zkp_proof
            .verify(&ctx, commitment.as_inner(), &[], generator)
            .is_err()
        {
            return false;
        }
    }
    true
}

pub(crate) fn value_generator() -> Generator {
    // `Tag::default()` is 32 zero bytes. Picked for parity with the
    // ADR-0001 PoC; a domain-separated tag is an internal rotation and
    // does not affect the wire layout callers see.
    Generator::new_unblinded(&ZkpSecp256k1::new(), Tag::default())
}

pub(crate) fn tweak_from_scalar(scalar: &Scalar) -> Result<Tweak> {
    let bytes = scalar.to_be_bytes();
    // Reject the zero scalar up front: zkp's Tweak rejects it too, but
    // the error text from the FFI path does not surface the reason.
    if bytes.iter().all(|b| *b == 0) {
        return Err(ConfidentialError::InvalidInput(
            "blinding scalar must be non-zero",
        ));
    }
    Tweak::from_slice(&bytes)
        .map_err(|_| ConfidentialError::InvalidInput("blinding scalar outside curve order"))
}

pub(crate) fn fresh_nonce() -> Result<ZkpSecretKey> {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    ZkpSecretKey::from_slice(&buf)
        .map_err(|_| ConfidentialError::RangeProof("failed to sample rangeproof nonce"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn scalar_from_u64(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_be_bytes(bytes).unwrap()
    }

    fn scalar_from_u128(value: u128) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_be_bytes(bytes).unwrap()
    }

    #[test]
    fn single_proof_round_trip_serialization() {
        let blinding = scalar_from_u64(0xdead_beef);
        let (proof, _c) = prove_range(42, &blinding).unwrap();
        let bytes = proof.to_bytes();
        let decoded = RangeProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn verifies_boundary_values() {
        for amount in [0u64, 1, MAX_PROVABLE_AMOUNT] {
            let blinding =
                scalar_from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788 ^ amount as u128);
            let (proof, commitment) = prove_range(amount, &blinding).unwrap();
            assert!(
                verify_range(&commitment, &proof),
                "boundary value {amount} must verify"
            );
            let range = verify_range_bounded(&commitment, &proof).unwrap();
            assert!(range.contains(&amount), "verified range must cover amount");
        }
    }

    #[test]
    fn amount_above_practical_cap_is_rejected() {
        let blinding = scalar_from_u64(1);
        let err = prove_range(MAX_PROVABLE_AMOUNT + 1, &blinding);
        assert!(matches!(err, Err(ConfidentialError::OutOfRange(_))));
    }

    #[test]
    fn zero_blinding_is_rejected() {
        let zero = Scalar::from_be_bytes([0u8; 32]).unwrap();
        assert!(matches!(
            prove_range(1, &zero),
            Err(ConfidentialError::InvalidInput(_))
        ));
    }

    #[test]
    fn mismatched_commitment_fails_verification() {
        let b1 = scalar_from_u64(7);
        let b2 = scalar_from_u64(11);
        let (proof, _c1) = prove_range(100, &b1).unwrap();
        let c_wrong = ValueCommitment::commit(100, &b2).unwrap();
        assert!(!verify_range(&c_wrong, &proof));
    }

    #[test]
    fn tampered_proof_bytes_fail_verification() {
        let blinding = scalar_from_u64(0x42);
        let (proof, commitment) = prove_range(500, &blinding).unwrap();
        let mut bytes = proof.to_bytes();
        // Flip a bit deep inside the Back-Maxwell payload.
        let idx = bytes.len() / 2;
        bytes[idx] ^= 0x01;
        // Some tampers land in header fields and fail parse before verify;
        // those that parse MUST fail verification.
        if let Ok(tp) = RangeProof::from_bytes(&bytes) {
            assert!(!verify_range(&commitment, &tp));
        }
    }

    #[test]
    fn aggregated_proof_verifies_for_sixteen_outputs() {
        let inputs: Vec<(u64, Scalar)> = (0..16)
            .map(|i| (1_000_000u64 + i as u64, scalar_from_u64(0x100 + i as u64)))
            .collect();
        let (agg_proof, commitments) = prove_range_aggregated(&inputs).unwrap();
        assert!(verify_range_aggregated(&commitments, &agg_proof));

        // Round-trip serialization preserves the aggregated blob.
        let bytes = agg_proof.to_bytes();
        let decoded = RangeProof::from_bytes(&bytes).unwrap();
        assert_eq!(agg_proof, decoded);
    }

    #[test]
    fn aggregated_blob_smaller_than_sum_of_individual_blobs() {
        // Same-magnitude values → identical bit_width → identical sub-proof
        // sizes → aggregation uses its shared-length wire encoding and
        // saves `16 − 5 = 11` bytes of framing versus 16 separately-tagged
        // single blobs. This is a framing delta, not log-size aggregation;
        // see module docs for the ADR-0001 rescope and FU-BP.
        let inputs: Vec<(u64, Scalar)> = (0..16u64)
            .map(|i| (1_000_000 + i, scalar_from_u64(0x200 + i)))
            .collect();
        let (agg, _c) = prove_range_aggregated(&inputs).unwrap();

        let agg_len = agg.to_bytes().len();
        let mut sum_individual = 0usize;
        for (amount, blinding) in &inputs {
            let (p, _c) = prove_range(*amount, blinding).unwrap();
            sum_individual += p.to_bytes().len();
        }
        assert!(
            agg_len < sum_individual,
            "aggregated {agg_len}B must be strictly smaller than sum-of-individual {sum_individual}B"
        );
    }

    #[test]
    fn mixed_magnitude_aggregation_is_rejected() {
        // Values straddling bit_width boundaries (2^16, 2^32) force
        // different Back-Maxwell sub-proof sizes; the aggregator refuses
        // rather than emitting a blob larger than individual proofs.
        let inputs: Vec<(u64, Scalar)> = vec![
            (1, scalar_from_u64(1)),
            (1_000_000_000_000, scalar_from_u64(2)),
        ];
        let err = prove_range_aggregated(&inputs);
        assert!(matches!(err, Err(ConfidentialError::Unsupported(_))));
    }

    #[test]
    fn aggregated_verify_rejects_mismatched_arity() {
        let inputs: Vec<(u64, Scalar)> = (0..4u64)
            .map(|i| (1_000_000 + i, scalar_from_u64(0x300 + i)))
            .collect();
        let (agg, mut commitments) = prove_range_aggregated(&inputs).unwrap();
        commitments.pop();
        assert!(!verify_range_aggregated(&commitments, &agg));
    }

    #[test]
    fn aggregated_verify_rejects_reordered_commitments() {
        let inputs: Vec<(u64, Scalar)> = vec![
            (1_000_010, scalar_from_u64(0x401)),
            (1_000_020, scalar_from_u64(0x402)),
            (1_000_030, scalar_from_u64(0x403)),
        ];
        let (agg, mut commitments) = prove_range_aggregated(&inputs).unwrap();
        commitments.swap(0, 2);
        assert!(!verify_range_aggregated(&commitments, &agg));
    }

    #[test]
    fn from_bytes_rejects_unknown_tag() {
        let blob = [0xffu8, 0x00];
        assert!(RangeProof::from_bytes(&blob).is_err());
    }

    #[test]
    fn from_bytes_rejects_truncated_aggregated() {
        // Claims 2 sub-proofs of 100 bytes each (200B body) but supplies 3B.
        let blob = vec![TAG_AGGREGATED, 0x00, 0x02, 0x00, 0x64, 0xaa, 0xbb, 0xcc];
        assert!(RangeProof::from_bytes(&blob).is_err());
    }

    #[test]
    fn from_bytes_rejects_zero_count_aggregated() {
        let blob = vec![TAG_AGGREGATED, 0x00, 0x00, 0x00, 0x10];
        assert!(RangeProof::from_bytes(&blob).is_err());
    }

    #[test]
    fn cross_verify_single_against_aggregated_fails() {
        let blinding = scalar_from_u64(1);
        let (single, commitment) = prove_range(7, &blinding).unwrap();
        assert!(!verify_range_aggregated(
            std::slice::from_ref(&commitment),
            &single
        ));

        let (agg, commitments) = prove_range_aggregated(&[(7, blinding)]).unwrap();
        let err = verify_range_bounded(&commitments[0], &agg);
        assert!(matches!(err, Err(ConfidentialError::InvalidInput(_))));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        #[test]
        fn proofs_verify_for_arbitrary_amount(
            amount in 0u64..=MAX_PROVABLE_AMOUNT,
            blinding_lo in 1u64..u64::MAX,
        ) {
            let blinding = scalar_from_u64(blinding_lo);
            let (proof, commitment) = prove_range(amount, &blinding).unwrap();
            prop_assert!(verify_range(&commitment, &proof));
            let range = verify_range_bounded(&commitment, &proof).unwrap();
            prop_assert!(range.contains(&amount));
        }
    }
}
