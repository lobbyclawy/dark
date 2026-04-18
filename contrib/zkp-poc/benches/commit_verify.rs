//! Placeholder benchmark harness called out by ADR-0001 acceptance criteria.
//!
//! Measures commit + prove + verify cost on a single scalar so we know the
//! chosen stack is invokable from Criterion. Parameter sweeps (bit-width,
//! min_bits, exp) and apples-to-apples comparisons against Bulletproofs
//! land once #523 + #525 are in.

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use secp256k1::rand::RngCore;
use secp256k1_zkp::{
    Generator, PedersenCommitment, RangeProof, Secp256k1 as ZkpSecp256k1, SecretKey, Tag, Tweak,
};

fn fresh_scalars() -> (Tweak, SecretKey) {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    let blind = Tweak::from_slice(&b).unwrap();
    OsRng.fill_bytes(&mut b);
    let nonce = SecretKey::from_slice(&b).unwrap();
    (blind, nonce)
}

fn bench_commit_verify(c: &mut Criterion) {
    let zkp = ZkpSecp256k1::new();
    let generator = Generator::new_unblinded(&zkp, Tag::default());
    let value: u64 = 1_000_000;

    c.bench_function("pedersen_commit", |b| {
        b.iter(|| {
            let (blind, _) = fresh_scalars();
            let _ = PedersenCommitment::new(&zkp, value, blind, generator);
        });
    });

    c.bench_function("rangeproof_prove_verify", |b| {
        b.iter(|| {
            let (blind, nonce) = fresh_scalars();
            let commitment = PedersenCommitment::new(&zkp, value, blind, generator);
            let proof = RangeProof::new(
                &zkp,
                0,
                commitment,
                value,
                blind,
                &[],
                &[],
                nonce,
                0,
                0,
                generator,
            )
            .unwrap();
            let _ = proof.verify(&zkp, commitment, &[], generator).unwrap();
        });
    });
}

criterion_group!(benches, bench_commit_verify);
criterion_main!(benches);
