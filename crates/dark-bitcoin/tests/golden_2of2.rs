//! Standard-mode parity gate (issue #678 / ADR-0009).
//!
//! These tests pin observable invariants of the standard MuSig2 path
//! exposed by `dark_bitcoin::signing` so an inadvertent dependency
//! bump (e.g. `musig2 = 0.3.1` → some future `0.3.x`) trips a test
//! rather than silently changing wire-compatible behaviour for cohorts
//! running in `AspMode::Standard`.
//!
//! ADR-0009 calls this out as the verification mechanism for the
//! parity claim that `dark-psar` Phase 5 leaves the standard-mode
//! signing flow bit-identical: if the aggregated pubkey for a fixed
//! 2-of-2 input set ever changes, the integration story breaks.

use dark_bitcoin::signing::{build_key_agg_ctx, sign_full_session};
use musig2::secp256k1::{PublicKey, Secp256k1, SecretKey};

const SK1_BYTES: [u8; 32] = [0x01; 32];
const SK2_BYTES: [u8; 32] = [0x02; 32];

/// Pinned aggregated pubkey for `KeyAggContext::new([pk1, pk2])` where
/// `pk_i = G * sk_i` and `sk_i` are the constants above. Bound to
/// `musig2 = 0.3.1`; if the underlying crate changes its key-agg
/// hashing this constant must be updated and the change reviewed.
const PINNED_AGG_PK_HEX: &str =
    "031fc559d9c96c5953895d3150e64ebf3dd696a0b08e758650b48ff6251d7e60d1";

fn fixed_pubkeys() -> (PublicKey, PublicKey) {
    let secp = Secp256k1::new();
    let sk1 = SecretKey::from_byte_array(SK1_BYTES).expect("sk1 valid");
    let sk2 = SecretKey::from_byte_array(SK2_BYTES).expect("sk2 valid");
    (
        PublicKey::from_secret_key(&secp, &sk1),
        PublicKey::from_secret_key(&secp, &sk2),
    )
}

#[test]
fn standard_2of2_aggregate_pubkey_is_byte_stable() {
    let (pk1, pk2) = fixed_pubkeys();
    let ctx = build_key_agg_ctx(&[pk1, pk2]).unwrap();
    let agg: PublicKey = ctx.aggregated_pubkey();
    let actual = hex::encode(agg.serialize());
    assert_eq!(
        actual, PINNED_AGG_PK_HEX,
        "musig2 = 0.3.1 KeyAggContext::aggregated_pubkey output drifted; \
         standard-mode AspMode parity gate broken (ADR-0009). actual = {actual}"
    );
}

#[test]
fn standard_2of2_full_session_verifies_against_pinned_agg() {
    let sk1 = SecretKey::from_byte_array(SK1_BYTES).unwrap();
    let sk2 = SecretKey::from_byte_array(SK2_BYTES).unwrap();
    let msg = [0x42u8; 32];

    let (agg_pk_bytes, sig_bytes) =
        sign_full_session(&[sk1, sk2], &msg).expect("sign_full_session");

    // The aggregate pubkey must match the pinned constant — this is
    // the byte-pin part of the parity gate.
    assert_eq!(hex::encode(agg_pk_bytes), PINNED_AGG_PK_HEX);

    // The signature must verify under that pubkey — this is the
    // BIP-340 conformance part of the parity gate.
    let agg_pk = PublicKey::from_slice(&agg_pk_bytes).unwrap();
    musig2::verify_single(agg_pk, sig_bytes, msg).expect("BIP-340 verify");
}

#[test]
fn standard_2of2_keyagg_is_order_sensitive() {
    // Reordering the participant pubkey list yields a different
    // aggregate — confirms `musig2 = 0.3.1` follows BIP-327's
    // ordered key aggregation. If a future crate version becomes
    // unordered, this test would need an explicit re-evaluation.
    let (pk1, pk2) = fixed_pubkeys();
    let agg12 = build_key_agg_ctx(&[pk1, pk2])
        .unwrap()
        .aggregated_pubkey::<PublicKey>()
        .serialize();
    let agg21 = build_key_agg_ctx(&[pk2, pk1])
        .unwrap()
        .aggregated_pubkey::<PublicKey>()
        .serialize();
    assert_ne!(agg12, agg21);
}
