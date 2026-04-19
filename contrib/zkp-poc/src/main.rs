//! Smoke test: build Pedersen commitment + range proof using secp256k1-zkp 0.11
//! while also using secp256k1 0.29 keys in the same process.
//!
//! Purpose: validate ADR-0001 claim that the two crates coexist without feature
//! conflicts and that a value can be committed and verified end-to-end.

use rand::rngs::OsRng;
use secp256k1::{rand::RngCore, Secp256k1};
use secp256k1_zkp::{
    Generator, PedersenCommitment, RangeProof, Secp256k1 as ZkpSecp256k1, Tag, Tweak,
};

fn main() {
    let plain = Secp256k1::new();
    let zkp = ZkpSecp256k1::new();

    // Same seed feeds both crates; public keys must match byte-for-byte.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sk_plain = secp256k1::SecretKey::from_slice(&seed).expect("valid sk");
    let pk_plain = secp256k1::PublicKey::from_secret_key(&plain, &sk_plain);

    let sk_zkp = secp256k1_zkp::SecretKey::from_slice(&seed).expect("valid sk");
    let pk_zkp = secp256k1_zkp::PublicKey::from_secret_key(&zkp, &sk_zkp);

    // ADR-0001 load-bearing check: a SecretKey minted by the workspace-wide
    // secp256k1 = 0.29 must feed unchanged into secp256k1-zkp sign sites.
    // If this ever diverges we do not have the single curve context we
    // rely on to avoid carrying two stacks — that failure mode is a hard
    // reopen of ADR-0001, not a fix in downstream crates.
    assert_eq!(
        pk_plain.serialize(),
        pk_zkp.serialize(),
        "ADR-0001 invariant violated: secp256k1 0.29 and secp256k1-zkp 0.11 \
         disagreed on pubkey derivation from the same seed — single-curve \
         interoperability is broken; do not proceed with #523/#524"
    );

    // Commit to a value under a fresh blinding factor and an unblinded generator.
    let value: u64 = 42_000;
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let blind = Tweak::from_slice(&buf).expect("valid tweak");

    let generator = Generator::new_unblinded(&zkp, Tag::default());
    let commitment = PedersenCommitment::new(&zkp, value, blind, generator);

    // `nonce` here is a per-proof random scalar, NOT a long-lived signing
    // key. The Rust binding reuses `SecretKey` for its 32-byte shape; the
    // underlying C API calls this argument `nonce`. Leaking it does not
    // compromise the committer's keys but does leak the committed value.
    // #524/#525 MUST derive it from a protocol-scoped KDF per commitment
    // (the exact scheme is pinned in #529).
    OsRng.fill_bytes(&mut buf);
    let nonce = secp256k1_zkp::SecretKey::from_slice(&buf).expect("valid nonce");

    let proof = RangeProof::new(
        &zkp,
        /* min_value */ 0,
        commitment,
        value,
        blind,
        /* message */ &[],
        /* additional_commitment */ &[],
        nonce,
        /* exp */ 0,
        /* min_bits */ 0,
        generator,
    )
    .expect("range proof");

    let range = proof
        .verify(&zkp, commitment, &[], generator)
        .expect("range proof verifies");

    // Semantic note for #525: the upstream C API documents the verified
    // bound as `[min_value, max_value]` (max INCLUSIVE). The Rust wrapper
    // packs it into `std::ops::Range<u64>` whose `.end` is EXCLUSIVE. We
    // therefore assert `value < range.end`, not `<=`. #525's domain
    // wrapper MUST normalise back to inclusive-max on the way out so the
    // dark-owned `RangeProof` type does not silently off-by-one callers.
    assert!(
        range.start <= value && value < range.end,
        "committed value must fall inside verified range, got {:?}",
        range
    );

    println!(
        "OK: committed {value} under generator; verified range = [{}, {}); proof = {} bytes",
        range.start,
        range.end,
        proof.serialize().len()
    );
    let _ = pk_plain;
}
