//! Criterion benchmarks for MuSig2 nonce and signature aggregation.
//!
//! These primitives are independent of cohort size `K` and horizon `N`.
//! The fixture uses a fixed 3-party signing set so repeated benchmark
//! runs stay comparable.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dark_bitcoin::signing::{
    aggregate_nonces, aggregate_signatures, build_key_agg_ctx, create_partial_sig, generate_nonce,
};
use musig2::secp256k1::{PublicKey, Secp256k1, SecretKey};

struct AggregateFixture {
    key_agg_ctx: musig2::KeyAggContext,
    agg_nonce: musig2::AggNonce,
    partial_sigs: Vec<musig2::PartialSignature>,
    msg: [u8; 32],
}

fn secret_key(tag: u8) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = tag;
    SecretKey::from_byte_array(bytes).expect("valid benchmark secret key")
}

fn fixture() -> AggregateFixture {
    let secp = Secp256k1::new();
    let msg = [0x5Au8; 32];
    let secret_keys: Vec<SecretKey> = [21u8, 22, 23].into_iter().map(secret_key).collect();
    let public_keys: Vec<PublicKey> = secret_keys
        .iter()
        .map(|sk| PublicKey::from_secret_key(&secp, sk))
        .collect();
    let key_agg_ctx = build_key_agg_ctx(&public_keys).expect("benchmark key aggregation");
    let nonce_pairs: Vec<(musig2::SecNonce, musig2::PubNonce)> = secret_keys
        .iter()
        .map(|sk| generate_nonce(sk, &msg))
        .collect();
    let pub_nonces: Vec<musig2::PubNonce> = nonce_pairs.iter().map(|(_, pn)| pn.clone()).collect();
    let agg_nonce = aggregate_nonces(&pub_nonces);
    let partial_sigs = secret_keys
        .iter()
        .zip(nonce_pairs)
        .map(|(sk, (sec_nonce, _))| {
            create_partial_sig(&key_agg_ctx, sk, sec_nonce, &agg_nonce, &msg)
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("benchmark partial signatures");

    AggregateFixture {
        key_agg_ctx,
        agg_nonce,
        partial_sigs,
        msg,
    }
}

fn bench_aggregate(c: &mut Criterion) {
    let fixture = fixture();

    let mut nonce_group = c.benchmark_group("musig2_nonce_aggregate");
    let pub_nonces: Vec<musig2::PubNonce> = [31u8, 32, 33]
        .into_iter()
        .map(secret_key)
        .map(|sk| generate_nonce(&sk, &fixture.msg).1)
        .collect();
    nonce_group.bench_function("aggregate", |b| {
        b.iter(|| {
            let agg = aggregate_nonces(black_box(&pub_nonces));
            black_box(agg);
        })
    });
    nonce_group.finish();

    let mut sig_group = c.benchmark_group("musig2_signature_aggregate");
    sig_group.bench_function("aggregate", |b| {
        b.iter(|| {
            let sig = aggregate_signatures(
                black_box(&fixture.key_agg_ctx),
                black_box(&fixture.agg_nonce),
                black_box(&fixture.partial_sigs),
                black_box(&fixture.msg),
            )
            .expect("aggregate signature");
            black_box(sig);
        })
    });
    sig_group.finish();
}

#[test]
fn aggregate_fixture_produces_valid_signature() {
    let fixture = fixture();
    let sig = aggregate_signatures(
        &fixture.key_agg_ctx,
        &fixture.agg_nonce,
        &fixture.partial_sigs,
        &fixture.msg,
    )
    .expect("aggregate signature");
    let agg_pubkey = fixture.key_agg_ctx.aggregated_pubkey();
    assert!(musig2::verify_single(agg_pubkey, sig, fixture.msg).is_ok());
}

criterion_group!(benches, bench_aggregate);
criterion_main!(benches);
