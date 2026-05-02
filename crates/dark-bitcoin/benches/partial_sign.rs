//! Criterion benchmarks for MuSig2 partial signing.
//!
//! Covers the two paths used by DARK's tree-signing flow:
//! - `participant_path`: regular cosigner partial signing
//! - `operator_path`: ASP/operator partial signing
//!
//! Both paths exercise the same cryptographic primitive with different
//! deterministic fixtures so they show up as separate series in the
//! generated Criterion report.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dark_bitcoin::signing::{
    aggregate_nonces, build_key_agg_ctx, create_partial_sig, generate_nonce,
};
use musig2::secp256k1::{PublicKey, Secp256k1, SecretKey};

#[derive(Clone)]
struct SigningFixture {
    key_agg_ctx: musig2::KeyAggContext,
    secret_keys: Vec<SecretKey>,
    agg_nonce: musig2::AggNonce,
    sec_nonces: Vec<musig2::SecNonce>,
    msg: [u8; 32],
}

fn secret_key(tag: u8) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = tag;
    SecretKey::from_byte_array(bytes).expect("valid benchmark secret key")
}

fn fixture(tags: &[u8], msg_byte: u8) -> SigningFixture {
    let secp = Secp256k1::new();
    let secret_keys: Vec<SecretKey> = tags.iter().copied().map(secret_key).collect();
    let public_keys: Vec<PublicKey> = secret_keys
        .iter()
        .map(|sk| PublicKey::from_secret_key(&secp, sk))
        .collect();
    let key_agg_ctx = build_key_agg_ctx(&public_keys).expect("benchmark key aggregation");
    let msg = [msg_byte; 32];
    let nonce_pairs: Vec<(musig2::SecNonce, musig2::PubNonce)> = secret_keys
        .iter()
        .map(|sk| generate_nonce(sk, &msg))
        .collect();
    let sec_nonces: Vec<musig2::SecNonce> = nonce_pairs.iter().map(|(sn, _)| sn.clone()).collect();
    let pub_nonces: Vec<musig2::PubNonce> = nonce_pairs.iter().map(|(_, pn)| pn.clone()).collect();
    let agg_nonce = aggregate_nonces(&pub_nonces);

    let _ = public_keys;
    let _ = pub_nonces;

    SigningFixture {
        key_agg_ctx,
        secret_keys,
        agg_nonce,
        sec_nonces,
        msg,
    }
}

fn bench_partial_sign(c: &mut Criterion) {
    let participant = fixture(&[1, 2, 3], 0x42);
    let operator = fixture(&[11, 12, 13], 0xA5);

    let mut group = c.benchmark_group("musig2_partial_sign");
    group.bench_function("participant_path", |b| {
        b.iter_batched(
            || participant.sec_nonces[0].clone(),
            |sec_nonce| {
                let sig = create_partial_sig(
                    black_box(&participant.key_agg_ctx),
                    black_box(&participant.secret_keys[0]),
                    sec_nonce,
                    black_box(&participant.agg_nonce),
                    black_box(&participant.msg),
                )
                .expect("participant partial signature");
                black_box(sig);
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.bench_function("operator_path", |b| {
        b.iter_batched(
            || operator.sec_nonces[0].clone(),
            |sec_nonce| {
                let sig = create_partial_sig(
                    black_box(&operator.key_agg_ctx),
                    black_box(&operator.secret_keys[0]),
                    sec_nonce,
                    black_box(&operator.agg_nonce),
                    black_box(&operator.msg),
                )
                .expect("operator partial signature");
                black_box(sig);
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, bench_partial_sign);
criterion_main!(benches);
