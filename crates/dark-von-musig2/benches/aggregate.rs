//! Criterion bench for VON-MuSig2 partial-sig aggregation (issue #681).
//!
//! Measures `sign::aggregate` — combining the operator's and the
//! participant's partial signatures into a single 64-byte BIP-340
//! signature. The aggregation step has no per-N or per-K dependence
//! (it always touches exactly two partials in PSAR's 2-of-2 setting),
//! so this bench reports a single point estimate.
//!
//! Run with:
//!
//! ```bash
//! cargo bench -p dark-von-musig2 --bench aggregate
//! ```

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{Keypair, Parity, PublicKey, Secp256k1, SecretKey};

use dark_von_musig2::nonces::{AggNonce, PubNonce};
use dark_von_musig2::presign::presign_horizon;
use dark_von_musig2::setup::Setup;
use dark_von_musig2::sign::{
    aggregate, build_key_agg_ctx, sign_partial_with_von, PartialSignature,
};

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

fn aggregate_2of2_benchmark(c: &mut Criterion) {
    // Build a complete 2-of-2 fixture once: agg_nonce, op partial,
    // participant partial. The bench just measures the final
    // `aggregate` call.
    let secp = Secp256k1::new();
    let op_kp = even_parity_keypair(&secp, 0xa0);
    let participant_kp = even_parity_keypair(&secp, 0xb0);
    let op_pk = op_kp.public_key();
    let participant_pk = participant_kp.public_key();
    let op_sk = SecretKey::from_keypair(&op_kp);
    let participant_sk = SecretKey::from_keypair(&participant_kp);
    let ctx = build_key_agg_ctx(&[op_pk, participant_pk]).expect("key agg");

    // Setup at N=1 — the smallest horizon that gives us a usable
    // schedule + retained scalars.
    let (schedule, retained) = Setup::run(&op_sk, &SETUP_ID, 1).expect("setup");

    // Participant pre-signs.
    let mut rng = StdRng::seed_from_u64(0xcafe);
    let presigned = presign_horizon(&participant_sk, &op_pk, &ctx, &schedule, &[MSG], &mut rng)
        .expect("presign_horizon");
    let participant_partial: PartialSignature = presigned[0].partial_sig;
    let participant_pubnonce = presigned[0].pub_nonce.clone();

    // Operator builds its own partial against the same agg_nonce.
    let r_op1 = retained.r(1, 1).expect("r(1,1)").to_owned();
    let r_op2 = retained.r(1, 2).expect("r(1,2)").to_owned();
    let op_pubnonce = PubNonce {
        r1: PublicKey::from_secret_key(&secp, &r_op1),
        r2: PublicKey::from_secret_key(&secp, &r_op2),
    };
    let agg_nonce = AggNonce::sum(&[op_pubnonce, participant_pubnonce]).expect("agg_nonce");
    let op_partial =
        sign_partial_with_von(&ctx, &op_sk, (&r_op1, &r_op2), &agg_nonce, &MSG).expect("op sign");

    let partials = [op_partial, participant_partial];

    let mut group = c.benchmark_group("aggregate");
    group.bench_function("2of2", |b| {
        b.iter(|| {
            aggregate(
                black_box(&ctx),
                black_box(&agg_nonce),
                black_box(&MSG),
                black_box(&partials),
            )
            .unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, aggregate_2of2_benchmark);
criterion_main!(benches);
