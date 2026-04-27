//! Bounded-range compliance proofs.
//!
//! A wallet proves to an auditor that the cleartext amount of a VTXO
//! falls in `[lower, upper]` — for example, "this output is below the
//! Travel Rule threshold" — without revealing the exact amount.
//!
//! # Construction
//!
//! Built on the same `secp256k1-zkp` Back-Maxwell range-proof primitive
//! that backs [`crate::range_proof`]. The bounded case differs only in
//! how the prover parameterises the FFI:
//!
//! - `min_value = lower` (instead of the hardcoded `0`).
//! - The auto-sized bit width yields a proven max of `lower + 2^bits − 1`.
//! - The verifier rejects the proof unless the proven `[min, max]`
//!   range fits inside the asserted `[lower, upper]` interval.
//!
//! Per ADR-0001, `RangeProof` migration to Bulletproofs is tracked as
//! follow-up FU-BP; this module deliberately holds an opaque proof blob
//! so the wire layout is stable across that migration.
//!
//! # Tightness caveat
//!
//! Back-Maxwell proofs cover ranges sized at `2^k`. If the asserted
//! `upper` is not of the form `lower + 2^k − 1`, the verifier may still
//! accept a slightly wider proven range (always inside `[lower, upper]`),
//! or reject when the auto-sized bit width overshoots `upper`. Callers
//! that need tight non-power-of-two upper bounds must compose two
//! shifted range proofs — not in scope for this issue.
//!
//! # Transcript binding
//!
//! The proof carries a `transcript_hash` computed by tagged-hashing
//! `(commitment ‖ lower ‖ upper ‖ range_proof_blob)` under the DST
//! [`BOUNDED_RANGE_TRANSCRIPT_DST`]. Verifiers recompute it from the
//! disclosed fields and reject any mismatch — this catches in-flight
//! tampering of the bounds or the proof bytes even when the underlying
//! range proof would still verify in isolation.

use secp256k1::hashes::{sha256, Hash, HashEngine};
use secp256k1_zkp::{RangeProof as ZkpRangeProof, Secp256k1 as ZkpSecp256k1};

use crate::{
    disclosure::{DisclosureError, PedersenOpening},
    range_proof::{
        fresh_nonce, tweak_from_scalar, value_generator, ValueCommitment, MAX_PROVABLE_AMOUNT,
    },
};

/// Domain-separation tag for the bounded-range transcript hash.
///
/// Any change here is a wire-format break: previously-issued proofs no
/// longer verify under the new tag.
pub const BOUNDED_RANGE_TRANSCRIPT_DST: &[u8] = b"dark-disclosure/bounded-range/v1";

/// Compliance proof that a committed amount lies in `[lower_bound, upper_bound]`.
///
/// Self-contained: a verifier with this struct, the asserted commitment,
/// and the DST can run [`verify_bounded_range`] without further context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedRangeProof {
    pub commitment: ValueCommitment,
    pub lower_bound: u64,
    pub upper_bound: u64,
    pub range_proof_blob: Vec<u8>,
    pub transcript_hash: [u8; 32],
}

/// Prove `lower_bound ≤ opening.amount ≤ upper_bound` against `commitment`.
///
/// Fails fast if:
/// - `lower > upper` or `upper > MAX_PROVABLE_AMOUNT`,
/// - `amount` lies outside `[lower, upper]` (the prover would otherwise
///   produce a proof the verifier must reject — refuse here for clarity),
/// - the supplied opening does not actually open the supplied commitment.
pub fn prove_bounded_range(
    opening: &PedersenOpening,
    commitment: &ValueCommitment,
    lower: u64,
    upper: u64,
) -> Result<BoundedRangeProof, DisclosureError> {
    validate_bounds(lower, upper)?;
    if opening.amount < lower || opening.amount > upper {
        return Err(DisclosureError::AmountOutOfRange {
            amount: opening.amount,
            lower,
            upper,
        });
    }

    let derived = ValueCommitment::commit(opening.amount, &opening.blinding)?;
    if derived != *commitment {
        return Err(DisclosureError::OpeningMismatch);
    }

    let proof_blob = build_range_proof_blob(opening, commitment, lower)?;
    let transcript_hash = bind_transcript(commitment, lower, upper, &proof_blob);

    Ok(BoundedRangeProof {
        commitment: *commitment,
        lower_bound: lower,
        upper_bound: upper,
        range_proof_blob: proof_blob,
        transcript_hash,
    })
}

/// Verify `proof` certifies `expected_commitment ∈ [lower, upper]`.
///
/// Returns `Ok(())` iff every check passes:
/// 1. The proof's `commitment` matches `expected_commitment`.
/// 2. The transcript hash matches the recomputed digest of the disclosed fields.
/// 3. The underlying range proof verifies against the commitment.
/// 4. The proven `[verified_min, verified_max]` is contained in `[lower, upper]`.
pub fn verify_bounded_range(
    proof: &BoundedRangeProof,
    expected_commitment: &ValueCommitment,
) -> Result<(), DisclosureError> {
    if proof.commitment != *expected_commitment {
        return Err(DisclosureError::OpeningMismatch);
    }
    validate_bounds(proof.lower_bound, proof.upper_bound)?;

    let recomputed = bind_transcript(
        &proof.commitment,
        proof.lower_bound,
        proof.upper_bound,
        &proof.range_proof_blob,
    );
    if recomputed != proof.transcript_hash {
        return Err(DisclosureError::TranscriptMismatch);
    }

    let (verified_min, verified_max) =
        verify_range_proof_blob(&proof.range_proof_blob, &proof.commitment)?;
    if verified_min < proof.lower_bound || verified_max > proof.upper_bound {
        return Err(DisclosureError::RangeNotCertified {
            lower: proof.lower_bound,
            upper: proof.upper_bound,
            verified_min,
            verified_max,
        });
    }
    Ok(())
}

fn validate_bounds(lower: u64, upper: u64) -> Result<(), DisclosureError> {
    if lower > upper {
        return Err(DisclosureError::InvalidBounds("lower exceeds upper"));
    }
    if upper > MAX_PROVABLE_AMOUNT {
        return Err(DisclosureError::InvalidBounds(
            "upper exceeds MAX_PROVABLE_AMOUNT (2^63 - 1)",
        ));
    }
    Ok(())
}

fn build_range_proof_blob(
    opening: &PedersenOpening,
    commitment: &ValueCommitment,
    lower: u64,
) -> Result<Vec<u8>, DisclosureError> {
    let tweak = tweak_from_scalar(&opening.blinding)?;
    let nonce = fresh_nonce()?;
    let ctx = ZkpSecp256k1::new();
    let zkp_commitment = (*commitment).into_inner();
    let proof = ZkpRangeProof::new(
        &ctx,
        lower,
        zkp_commitment,
        opening.amount,
        tweak,
        &[],
        &[],
        nonce,
        0, // exp — library auto-sizes
        0, // min_bits — library auto-sizes from `amount`
        value_generator(),
    )
    .map_err(|_| {
        DisclosureError::Underlying(crate::ConfidentialError::RangeProof(
            "failed to produce bounded range proof",
        ))
    })?;
    Ok(proof.serialize().to_vec())
}

fn verify_range_proof_blob(
    blob: &[u8],
    commitment: &ValueCommitment,
) -> Result<(u64, u64), DisclosureError> {
    let zkp_proof = ZkpRangeProof::from_slice(blob)
        .map_err(|_| DisclosureError::InvalidEncoding("invalid bounded range proof bytes"))?;
    let ctx = ZkpSecp256k1::new();
    let zkp_commitment = (*commitment).into_inner();
    let range = zkp_proof
        .verify(&ctx, zkp_commitment, &[], value_generator())
        .map_err(|_| {
            DisclosureError::Underlying(crate::ConfidentialError::RangeProof(
                "bounded range proof did not verify",
            ))
        })?;
    // `range.end` is exclusive upstream; clamp to inclusive per ADR-0001.
    let verified_max = range.end.saturating_sub(1);
    Ok((range.start, verified_max))
}

/// Tagged-hash transcript binding for [`BoundedRangeProof`].
///
/// `SHA256(SHA256(DST) ‖ SHA256(DST) ‖ commitment ‖ lower_be ‖ upper_be ‖ blob)`.
fn bind_transcript(commitment: &ValueCommitment, lower: u64, upper: u64, blob: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(BOUNDED_RANGE_TRANSCRIPT_DST);
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_ref());
    engine.input(tag.as_ref());
    engine.input(&commitment.to_bytes());
    engine.input(&lower.to_be_bytes());
    engine.input(&upper.to_be_bytes());
    engine.input(blob);
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Scalar;

    fn scalar_from_u64(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_be_bytes(bytes).unwrap()
    }

    fn commit(amount: u64, blinding_seed: u64) -> (PedersenOpening, ValueCommitment) {
        let blinding = scalar_from_u64(blinding_seed);
        let commitment = ValueCommitment::commit(amount, &blinding).unwrap();
        (PedersenOpening::new(amount, blinding), commitment)
    }

    #[test]
    fn in_range_opening_proves_and_verifies() {
        let (opening, commitment) = commit(1_000_000, 0xdead_beef);
        let proof = prove_bounded_range(&opening, &commitment, 0, u32::MAX as u64).unwrap();
        verify_bounded_range(&proof, &commitment).expect("valid proof must verify");
    }

    #[test]
    fn lower_bound_only_constraint_holds() {
        // Travel-Rule-style "amount ≥ 100_000" expressed as a tight upper.
        let (opening, commitment) = commit(150_000, 0x424242);
        let proof = prove_bounded_range(&opening, &commitment, 100_000, u32::MAX as u64).unwrap();
        verify_bounded_range(&proof, &commitment).unwrap();
    }

    #[test]
    fn out_of_range_amount_below_lower_fails_to_prove() {
        let (opening, commitment) = commit(50, 0x99);
        let err = prove_bounded_range(&opening, &commitment, 100, 10_000);
        assert!(matches!(
            err,
            Err(DisclosureError::AmountOutOfRange {
                amount: 50,
                lower: 100,
                upper: 10_000
            })
        ));
    }

    #[test]
    fn out_of_range_amount_above_upper_fails_to_prove() {
        let (opening, commitment) = commit(20_000, 0x77);
        let err = prove_bounded_range(&opening, &commitment, 0, 10_000);
        assert!(matches!(
            err,
            Err(DisclosureError::AmountOutOfRange {
                amount: 20_000,
                lower: 0,
                upper: 10_000
            })
        ));
    }

    #[test]
    fn inverted_bounds_are_rejected() {
        let (opening, commitment) = commit(500, 0x1234);
        let err = prove_bounded_range(&opening, &commitment, 1_000, 100);
        assert!(matches!(err, Err(DisclosureError::InvalidBounds(_))));
    }

    #[test]
    fn opening_mismatch_is_rejected_at_prove() {
        let (opening, _commitment) = commit(500, 0x1234);
        // Build a commitment under a *different* blinding so the opening
        // no longer opens it.
        let other_commitment = ValueCommitment::commit(500, &scalar_from_u64(0xbeef)).unwrap();
        let err = prove_bounded_range(&opening, &other_commitment, 0, 1_000);
        assert!(matches!(err, Err(DisclosureError::OpeningMismatch)));
    }

    #[test]
    fn verifier_rejects_proof_against_different_commitment() {
        let (opening, commitment) = commit(750_000, 0xaa);
        let proof = prove_bounded_range(&opening, &commitment, 0, u32::MAX as u64).unwrap();

        // Different (amount, blinding) → different commitment.
        let unrelated = ValueCommitment::commit(750_000, &scalar_from_u64(0xbb)).unwrap();
        let err = verify_bounded_range(&proof, &unrelated);
        assert!(matches!(err, Err(DisclosureError::OpeningMismatch)));
    }

    #[test]
    fn verifier_rejects_tampered_transcript() {
        let (opening, commitment) = commit(123_456, 0xc0ffee);
        let mut proof = prove_bounded_range(&opening, &commitment, 0, u32::MAX as u64).unwrap();

        // Flip a byte in the transcript hash.
        proof.transcript_hash[0] ^= 0x01;
        assert!(matches!(
            verify_bounded_range(&proof, &commitment),
            Err(DisclosureError::TranscriptMismatch)
        ));
    }

    #[test]
    fn verifier_rejects_tampered_bounds() {
        let (opening, commitment) = commit(123_456, 0xc0ffee);
        let mut proof = prove_bounded_range(&opening, &commitment, 0, u32::MAX as u64).unwrap();

        // Bumping the upper bound without rebinding the transcript must fail.
        proof.upper_bound = u32::MAX as u64 - 1;
        assert!(matches!(
            verify_bounded_range(&proof, &commitment),
            Err(DisclosureError::TranscriptMismatch)
        ));
    }

    #[test]
    fn verifier_rejects_tampered_proof_blob() {
        let (opening, commitment) = commit(123_456, 0xc0ffee);
        let mut proof = prove_bounded_range(&opening, &commitment, 0, u32::MAX as u64).unwrap();

        // Flip a byte deep inside the underlying Back-Maxwell payload.
        let idx = proof.range_proof_blob.len() / 2;
        proof.range_proof_blob[idx] ^= 0x01;
        // The transcript hash binds the blob, so a tampered blob *also*
        // fails the transcript check before any FFI work.
        assert!(matches!(
            verify_bounded_range(&proof, &commitment),
            Err(DisclosureError::TranscriptMismatch)
        ));
    }

    #[test]
    fn verifier_rejects_proof_whose_proven_range_overshoots_upper() {
        // Construct a "well-formed" disclosure that asserts a tighter
        // upper than the underlying range proof actually certifies.
        // Verifier must catch this even though every other check passes.
        let (opening, commitment) = commit(1_000_000, 0xfeed);
        // Honest range proof for 1_000_000: auto-bit-width covers
        // [0, 2^20 - 1] = [0, 1_048_575].
        let blob = build_range_proof_blob(&opening, &commitment, 0).unwrap();
        let lower = 0;
        let undersized_upper = 10; // intentionally below 1_048_575
        let transcript_hash = bind_transcript(&commitment, lower, undersized_upper, &blob);
        let proof = BoundedRangeProof {
            commitment,
            lower_bound: lower,
            upper_bound: undersized_upper,
            range_proof_blob: blob,
            transcript_hash,
        };
        assert!(matches!(
            verify_bounded_range(&proof, &commitment),
            Err(DisclosureError::RangeNotCertified { .. })
        ));
    }

    #[test]
    fn verifier_rejects_blob_tamper_with_recomputed_transcript() {
        // A sophisticated attacker who flips a byte in the proof blob
        // *and* recomputes the transcript hash bypasses the transcript
        // check — but the underlying range proof verification still
        // rejects, giving us a second line of defence.
        let (opening, commitment) = commit(123_456, 0xc0ffee);
        let mut proof = prove_bounded_range(&opening, &commitment, 0, u32::MAX as u64).unwrap();

        let idx = proof.range_proof_blob.len() / 2;
        proof.range_proof_blob[idx] ^= 0x01;
        proof.transcript_hash = bind_transcript(
            &proof.commitment,
            proof.lower_bound,
            proof.upper_bound,
            &proof.range_proof_blob,
        );

        // Some byte flips land in framing fields (parse fails) and others
        // in the body (verify fails); both surface as DisclosureError.
        match verify_bounded_range(&proof, &commitment) {
            Err(DisclosureError::Underlying(_)) | Err(DisclosureError::InvalidEncoding(_)) => {}
            other => panic!("expected underlying/encoding rejection, got {other:?}"),
        }
    }

    #[test]
    fn power_of_two_amount_round_trips() {
        // Sanity at a bit-width boundary: 2^16 sits exactly on the edge
        // of the auto-sized range, exercising the verified-max clamp.
        let exact = 1u64 << 16;
        let (opening, commitment) = commit(exact, 0x55);
        let proof = prove_bounded_range(&opening, &commitment, 0, u32::MAX as u64).unwrap();
        verify_bounded_range(&proof, &commitment).unwrap();
    }

    #[test]
    fn upper_above_max_provable_is_rejected() {
        let (opening, commitment) = commit(1, 0x01);
        let err = prove_bounded_range(&opening, &commitment, 0, MAX_PROVABLE_AMOUNT + 1);
        assert!(matches!(err, Err(DisclosureError::InvalidBounds(_))));
    }

    #[test]
    fn transcript_dst_is_stable() {
        // Pinning the DST guards against accidental rotation: any rename
        // is a wire break for already-issued proofs.
        assert_eq!(
            BOUNDED_RANGE_TRANSCRIPT_DST,
            b"dark-disclosure/bounded-range/v1"
        );
    }
}
