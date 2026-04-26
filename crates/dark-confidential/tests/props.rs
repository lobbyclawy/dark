//! Property-based test suite for `dark-confidential` (issue #528).
//!
//! Case count is configurable via the `PROPTEST_CASES` environment
//! variable. Default is **256**, tuned for fast PR-time CI runs. The
//! heavy 10_000-case sweep that issue #528 promises runs nightly via a
//! scheduled workflow that exports `PROPTEST_CASES=10000`. Override
//! locally with `PROPTEST_CASES=N cargo test -p dark-confidential --test props`.
//!
//! Why this is configurable: the heavy properties (range-proof and
//! balance-proof prove+verify) are 5–15 ms per case in debug mode. At
//! 10 000 cases × 4 heavy properties they take ~20 minutes on the GitHub
//! Actions Test job, which dominated CI wall time after #597 landed. A
//! 256-case smoke run still flushes out almost every regression at a
//! tiny fraction of the cost; the nightly 10 000-case run keeps the
//! formal coverage AC live.
//!
//! Coverage map (matches AC of #528):
//! - `homomorphism_holds_over_pedersen`            — commitment module
//! - `range_proof_completeness_for_any_amount`     — range_proof (completeness)
//! - `range_proof_soundness_against_tampered_bytes` — range_proof (soundness)
//! - `balance_proof_excess_round_trip`             — balance_proof (correctness)
//! - `balance_proof_rejects_unbalanced_amounts`    — balance_proof (soundness)
//! - `nullifier_is_deterministic`                  — nullifier
//! - `nullifier_is_unique_for_distinct_inputs`     — nullifier (uniqueness)

use dark_confidential::balance_proof::{prove_balance, verify_balance};
use dark_confidential::commitment::PedersenCommitment;
use dark_confidential::nullifier::{compute_nullifier, encode_vtxo_id, VTXO_ID_LEN};
use dark_confidential::range_proof::{
    prove_range, verify_range, RangeProof, ValueCommitment, MAX_PROVABLE_AMOUNT,
};
use proptest::prelude::*;
use proptest::test_runner::Config as PropConfig;
use secp256k1::{Scalar, SecretKey};

/// Default number of proptest cases when `PROPTEST_CASES` is unset.
///
/// Tuned for PR-time CI: 256 cases catches almost every regression in
/// the curve-arithmetic and HMAC paths while keeping the Test job under
/// ~5 minutes. The nightly heavy sweep overrides this via
/// `PROPTEST_CASES=10000`.
const DEFAULT_CASES: u32 = 256;

/// Read the case count once per test invocation. Honours the standard
/// proptest `PROPTEST_CASES` env var (which `PropConfig::with_cases`
/// otherwise overrides).
fn case_count() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_CASES)
}

fn heavy_config() -> PropConfig {
    PropConfig::with_cases(case_count())
}

fn very_heavy_config() -> PropConfig {
    PropConfig::with_cases(case_count())
}

fn scalar_from_u64(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).unwrap()
}

// =====================================================================
// Pedersen homomorphism
// =====================================================================
proptest! {
    #![proptest_config(heavy_config())]

    /// `commit(a, r1) + commit(b, r2) == commit(a + b, r1 + r2)` over
    /// the field used by the commitment module. Runs a u64-bounded
    /// version of the same identity exercised by the unit test in
    /// `commitment::tests::homomorphic_property_holds` but at 10_000
    /// cases. Uses 32-bit summands so `a + b` fits in u64 and the
    /// blinding sum stays bounded.
    #[test]
    fn homomorphism_holds_over_pedersen(
        a in 0u64..(1u64 << 31),
        b in 0u64..(1u64 << 31),
        r1 in 1u64..(1u64 << 32),
        r2 in 1u64..(1u64 << 32),
    ) {
        let r1_s = scalar_from_u64(r1);
        let r2_s = scalar_from_u64(r2);
        let rsum_s = scalar_from_u64(r1 + r2);

        let lhs = PedersenCommitment::commit(a + b, &rsum_s).unwrap();
        let lhs_a = PedersenCommitment::commit(a, &r1_s).unwrap();
        let lhs_b = PedersenCommitment::commit(b, &r2_s).unwrap();
        let rhs = PedersenCommitment::add(&lhs_a, &lhs_b).unwrap();
        prop_assert_eq!(lhs, rhs);
    }
}

// =====================================================================
// Range proof completeness + soundness
// =====================================================================

/// Heavier: prove+verify is ~3 ms per case on x86_64, so 10 000 cases
/// is ~30 s. Separate config so we can dial this down independently if
/// the suite ever breaches a CI budget.
fn range_proof_config() -> PropConfig {
    PropConfig::with_cases(case_count())
}

proptest! {
    #![proptest_config(range_proof_config())]

    /// Completeness: every honest `(amount, blinding)` with
    /// `amount ∈ [0, MAX_PROVABLE_AMOUNT]` produces a proof that
    /// verifies against the matched `ValueCommitment`.
    #[test]
    fn range_proof_completeness_for_any_amount(
        amount in 0u64..=MAX_PROVABLE_AMOUNT,
        blinding_seed in 1u64..u64::MAX,
    ) {
        let blinding = scalar_from_u64(blinding_seed);
        let (proof, commitment) = prove_range(amount, &blinding).unwrap();
        prop_assert!(verify_range(&commitment, &proof));
    }

    /// Soundness against bit-flips: any single-bit tamper on the
    /// committed value or on the proof bytes that still parses as a
    /// `RangeProof` MUST fail verification. Bit flips that land on
    /// header/structure fields are rejected at parse and excluded.
    #[test]
    fn range_proof_soundness_against_tampered_bytes(
        amount in 0u64..=MAX_PROVABLE_AMOUNT,
        blinding_seed in 1u64..u64::MAX,
        // Pick a flip position inside the body. Larger ranges are
        // truncated by modulo at runtime once the proof size is known.
        flip_offset in 1usize..2048usize,
        flip_bit in 0u8..8,
    ) {
        let blinding = scalar_from_u64(blinding_seed);
        let (proof, commitment) = prove_range(amount, &blinding).unwrap();
        let mut bytes = proof.to_bytes();
        let idx = flip_offset.rem_euclid(bytes.len());
        bytes[idx] ^= 1 << flip_bit;
        // Some tamper positions lead to a parse failure (invalid
        // proof header) — those satisfy soundness trivially. Only
        // assert verification fails when the tampered blob still
        // parses.
        if let Ok(tampered) = RangeProof::from_bytes(&bytes) {
            prop_assert!(!verify_range(&commitment, &tampered));
        }
    }

    /// Soundness against commitment swap: a proof bound to one
    /// (amount, blinding) MUST NOT verify against an unrelated
    /// commitment.
    #[test]
    fn range_proof_soundness_against_unrelated_commitment(
        amount in 0u64..=MAX_PROVABLE_AMOUNT,
        blinding_seed in 1u64..u64::MAX,
        other_amount in 0u64..=MAX_PROVABLE_AMOUNT,
        other_blinding_seed in 1u64..u64::MAX,
    ) {
        // Force the alternate (amount, blinding) to differ from the
        // original. Equality is astronomically rare with random seeds
        // but we'd rather not chase a 1-in-2^64 false-positive.
        prop_assume!(amount != other_amount || blinding_seed != other_blinding_seed);
        let blinding = scalar_from_u64(blinding_seed);
        let (proof, _committed) = prove_range(amount, &blinding).unwrap();
        let other = ValueCommitment::commit(other_amount, &scalar_from_u64(other_blinding_seed)).unwrap();
        prop_assert!(!verify_range(&other, &proof));
    }
}

// =====================================================================
// Balance proof correctness + soundness
// =====================================================================

fn balance_proof_config() -> PropConfig {
    PropConfig::with_cases(case_count())
}

proptest! {
    #![proptest_config(balance_proof_config())]

    /// Excess correctness: build a balanced transaction
    /// (`Σ v_in = Σ v_out + fee`), prove, verify. Proof MUST verify.
    #[test]
    fn balance_proof_excess_round_trip(
        // Bound amounts so the input sum fits in u64 with room for
        // outputs + fee.
        in_a in 1u64..1_000_000_000,
        in_b in 1u64..1_000_000_000,
        fee in 0u64..1_000_000,
        split_seed in any::<u64>(),
        r_in_a_seed in 1u64..u64::MAX,
        r_in_b_seed in 1u64..u64::MAX,
        r_out_a_seed in 1u64..u64::MAX,
        r_out_b_seed in 1u64..u64::MAX,
        tx_hash in proptest::array::uniform32(any::<u8>()),
    ) {
        let total_in: u128 = in_a as u128 + in_b as u128;
        prop_assume!(total_in > fee as u128);
        let payable = total_in - fee as u128;
        let first = (split_seed as u128) % payable;
        let second = payable - first;
        prop_assume!(first > 0 && second > 0);

        let in_blindings = [scalar_from_u64(r_in_a_seed), scalar_from_u64(r_in_b_seed)];
        let out_blindings = [scalar_from_u64(r_out_a_seed), scalar_from_u64(r_out_b_seed)];

        // Reject the (vanishingly unlikely) excess-zero case so the
        // prover can run.
        prop_assume!(r_in_a_seed.wrapping_add(r_in_b_seed) != r_out_a_seed.wrapping_add(r_out_b_seed));

        let inputs = [
            PedersenCommitment::commit(in_a, &in_blindings[0]).unwrap(),
            PedersenCommitment::commit(in_b, &in_blindings[1]).unwrap(),
        ];
        let outputs = [
            PedersenCommitment::commit(first as u64, &out_blindings[0]).unwrap(),
            PedersenCommitment::commit(second as u64, &out_blindings[1]).unwrap(),
        ];

        let proof = prove_balance(&in_blindings, &out_blindings, fee, &tx_hash).unwrap();
        prop_assert!(verify_balance(&inputs, &outputs, fee, &tx_hash, &proof));
    }

    /// Soundness against amount tamper: prove with one balanced set,
    /// then bump any input amount by `delta` (≠ 0) — verifier MUST
    /// reject.
    #[test]
    fn balance_proof_rejects_unbalanced_amounts(
        in_a in 1u64..1_000_000_000,
        in_b in 1u64..1_000_000_000,
        fee in 0u64..1_000_000,
        split_seed in any::<u64>(),
        delta in 1u64..1_000_000_000,
        r_in_a_seed in 1u64..u64::MAX,
        r_in_b_seed in 1u64..u64::MAX,
        r_out_a_seed in 1u64..u64::MAX,
        r_out_b_seed in 1u64..u64::MAX,
        tx_hash in proptest::array::uniform32(any::<u8>()),
    ) {
        let total_in: u128 = in_a as u128 + in_b as u128;
        prop_assume!(total_in > fee as u128);
        let payable = total_in - fee as u128;
        let first = (split_seed as u128) % payable;
        let second = payable - first;
        prop_assume!(first > 0 && second > 0);
        prop_assume!(in_a.checked_add(delta).is_some());
        prop_assume!(r_in_a_seed.wrapping_add(r_in_b_seed) != r_out_a_seed.wrapping_add(r_out_b_seed));

        let in_blindings = [scalar_from_u64(r_in_a_seed), scalar_from_u64(r_in_b_seed)];
        let out_blindings = [scalar_from_u64(r_out_a_seed), scalar_from_u64(r_out_b_seed)];

        let proof = prove_balance(&in_blindings, &out_blindings, fee, &tx_hash).unwrap();

        // Verify against tampered inputs (first amount +delta).
        let tampered_inputs = [
            PedersenCommitment::commit(in_a + delta, &in_blindings[0]).unwrap(),
            PedersenCommitment::commit(in_b, &in_blindings[1]).unwrap(),
        ];
        let outputs = [
            PedersenCommitment::commit(first as u64, &out_blindings[0]).unwrap(),
            PedersenCommitment::commit(second as u64, &out_blindings[1]).unwrap(),
        ];
        prop_assert!(!verify_balance(&tampered_inputs, &outputs, fee, &tx_hash, &proof));
    }
}

// =====================================================================
// Nullifier determinism + uniqueness
// =====================================================================
proptest! {
    #![proptest_config(very_heavy_config())]

    /// `compute_nullifier` is a pure function of `(sk, vtxo_id)`.
    #[test]
    fn nullifier_is_deterministic(
        sk_bytes in proptest::array::uniform32(any::<u8>()),
        txid in proptest::array::uniform32(any::<u8>()),
        vout in any::<u32>(),
    ) {
        prop_assume!(sk_bytes != [0u8; 32]);
        let Ok(sk) = SecretKey::from_slice(&sk_bytes) else { return Ok(()); };
        let id = encode_vtxo_id(&txid, vout);
        let a = compute_nullifier(&sk, &id);
        let b = compute_nullifier(&sk, &id);
        prop_assert_eq!(a, b);
    }

    /// Distinct `(sk, vtxo_id)` inputs MUST produce distinct
    /// 32-byte nullifiers under the SHA-256 collision-resistance
    /// assumption.
    #[test]
    fn nullifier_is_unique_for_distinct_inputs(
        sk_bytes_a in proptest::array::uniform32(any::<u8>()),
        sk_bytes_b in proptest::array::uniform32(any::<u8>()),
        txid_a in proptest::array::uniform32(any::<u8>()),
        txid_b in proptest::array::uniform32(any::<u8>()),
        vout_a in any::<u32>(),
        vout_b in any::<u32>(),
    ) {
        prop_assume!(sk_bytes_a != [0u8; 32] && sk_bytes_b != [0u8; 32]);
        prop_assume!(sk_bytes_a != sk_bytes_b || txid_a != txid_b || vout_a != vout_b);
        let Ok(sk_a) = SecretKey::from_slice(&sk_bytes_a) else { return Ok(()); };
        let Ok(sk_b) = SecretKey::from_slice(&sk_bytes_b) else { return Ok(()); };
        let id_a = encode_vtxo_id(&txid_a, vout_a);
        let id_b = encode_vtxo_id(&txid_b, vout_b);
        let n_a = compute_nullifier(&sk_a, &id_a);
        let n_b = compute_nullifier(&sk_b, &id_b);
        prop_assert_ne!(n_a, n_b);
    }
}

// `VTXO_ID_LEN` is referenced indirectly via `encode_vtxo_id`; pull it
// in to keep the import explicit for the reader.
const _: usize = VTXO_ID_LEN;
