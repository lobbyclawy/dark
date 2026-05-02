//! Criterion benches for VON-MuSig2 partial-sign primitives (issue #681).
//!
//! Measures the cost of one operator-side and one participant-side
//! partial signature in isolation, plus the participant horizon as a
//! parameterised group over `N ∈ {1, 4, 12, 50}` so the per-call cost
//! can be derived (`per_call ≈ horizon_cost / N`).
//!
//! Pairs with `crates/dark-von/benches/von.rs` (#658) for the
//! cryptographic primitives that underlie these — ECVRF prove/verify
//! and `wrapper::nonce` are benched there; this file measures the
//! BIP-327 signing layer on top.
//!
//! Run with:
//!
//! ```bash
//! cargo bench -p dark-von-musig2 --bench partial_sign
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{Keypair, Parity, PublicKey, Secp256k1, SecretKey};

use dark_von_musig2::nonces::{AggNonce, PubNonce};
use dark_von_musig2::presign::presign_horizon;
use dark_von_musig2::setup::Setup;
use dark_von_musig2::sign::{build_key_agg_ctx, sign_partial_with_von};

const SETUP_ID: [u8; 32] = [0x42; 32];
const MSG: [u8; 32] = [0x77; 32];

fn even_parity_keypair(secp: &Secp256k1<secp256k1::All>, seed: u8) -> Keypair {
    for offset in 0u32..1024 {
        let mut bytes = [seed; 32];
        bytes[28..32].copy_from_slice(&offset.to_le_bytes());
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            let kp = Keypair::from_secret_key(secp, &sk);
            if kp.x_only_public_key().1 == Parity::Even {
                return kp;
            }
        }
    }
    panic!("no even-parity keypair within counter range");
}

fn partial_sign_operator_benchmark(c: &mut Criterion) {
    // ─── Inline setup so we don't need to expose KeyAggCtx ────────────
    let secp = Secp256k1::new();
    let op_kp = even_parity_keypair(&secp, 0xa0);
    let participant_kp = even_parity_keypair(&secp, 0xb0);
    let op_pk = op_kp.public_key();
    let participant_pk = participant_kp.public_key();
    let op_sk = SecretKey::from_keypair(&op_kp);
    let participant_sk = SecretKey::from_keypair(&participant_kp);

    // 2-of-2 key aggregation.
    let ctx = build_key_agg_ctx(&[op_pk, participant_pk]).expect("key agg");

    // Setup at N=1 to get one (r_op1, r_op2) pair.
    let (schedule, retained) = Setup::run(&op_sk, &SETUP_ID, 1).expect("setup N=1");

    // Participant pre-signs the single epoch — gives us the participant's
    // PubNonce so we can build the AggNonce the operator will sign against.
    let messages = [MSG];
    let mut rng = StdRng::seed_from_u64(0xcafe);
    let presigned = presign_horizon(
        &participant_sk,
        &op_pk,
        &ctx,
        &schedule,
        &messages,
        &mut rng,
    )
    .expect("presign_horizon N=1");
    let participant_pubnonce = presigned[0].pub_nonce.clone();

    // Operator's VON-bound `(r1, r2)` for epoch 1.
    let r_op1 = retained.r(1, 1).expect("r(1,1)").to_owned();
    let r_op2 = retained.r(1, 2).expect("r(1,2)").to_owned();
    let r_op1_p = PublicKey::from_secret_key(&secp, &r_op1);
    let r_op2_p = PublicKey::from_secret_key(&secp, &r_op2);
    let op_pubnonce = PubNonce {
        r1: r_op1_p,
        r2: r_op2_p,
    };
    let agg_nonce = AggNonce::sum(&[op_pubnonce, participant_pubnonce]).expect("agg_nonce");

    let mut group = c.benchmark_group("partial_sign");
    group.bench_function("operator", |b| {
        b.iter(|| {
            sign_partial_with_von(
                black_box(&ctx),
                black_box(&op_sk),
                (black_box(&r_op1), black_box(&r_op2)),
                black_box(&agg_nonce),
                black_box(&MSG),
            )
            .unwrap()
        })
    });
    group.finish();
}

fn partial_sign_participant_horizon_benchmark(c: &mut Criterion) {
    let secp = Secp256k1::new();
    let op_kp = even_parity_keypair(&secp, 0xa0);
    let participant_kp = even_parity_keypair(&secp, 0xb0);
    let op_pk = op_kp.public_key();
    let participant_pk = participant_kp.public_key();
    let op_sk = SecretKey::from_keypair(&op_kp);
    let participant_sk = SecretKey::from_keypair(&participant_kp);
    let ctx = build_key_agg_ctx(&[op_pk, participant_pk]).expect("key agg");

    let mut group = c.benchmark_group("partial_sign_participant_horizon");
    for &n in &[1u32, 4, 12, 50] {
        let (schedule, _retained) = Setup::run(&op_sk, &SETUP_ID, n).expect("setup");
        let messages: Vec<[u8; 32]> = (0..n as usize).map(|i| [(0x40 + i as u8); 32]).collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let mut rng = StdRng::seed_from_u64(0xface);
                presign_horizon(
                    black_box(&participant_sk),
                    black_box(&op_pk),
                    black_box(&ctx),
                    black_box(&schedule),
                    black_box(&messages),
                    &mut rng,
                )
                .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    partial_sign_operator_benchmark,
    partial_sign_participant_horizon_benchmark
);
criterion_main!(benches);
