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

    assert_eq!(
        pk_plain.serialize(),
        pk_zkp.serialize(),
        "secp256k1 0.29 and secp256k1-zkp 0.11 must agree on pubkey derivation"
    );

    // Commit to a value under a fresh blinding factor and an unblinded generator.
    let value: u64 = 42_000;
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let blind = Tweak::from_slice(&buf).expect("valid tweak");

    let generator = Generator::new_unblinded(&zkp, Tag::default());
    let commitment = PedersenCommitment::new(&zkp, value, blind, generator);

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

    assert!(
        range.start <= value && range.end >= value,
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
