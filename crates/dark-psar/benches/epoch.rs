//! ASP per-epoch processing latency parameterised over `K ∈ {100, 1000}`
//! (issue #683).
//!
//! Measures `dark_psar::process_epoch` — one full epoch of MuSig2
//! partial-sign-and-aggregate over every member of the cohort. The
//! `ActiveCohort` is built once outside the timed loop via
//! `dark_psar::asp_board`; the bench iterates `process_epoch(t = 1)`
//! repeatedly because the cohort lifecycle returns to `Active` after
//! every successful epoch (so `t = 1` is replayable).
//!
//! `K = 10000` lives in a separate `--bench long` group, opt-in via
//! `BENCH_LONG=1`. Without the env var the long group degenerates to
//! a no-op so default `cargo bench` runs in minutes, not hours.
//!
//! Run with:
//!
//! ```bash
//! cargo bench -p dark-psar --bench epoch
//! BENCH_LONG=1 cargo bench -p dark-psar --bench epoch -- long
//! ```
//!
//! Numbers feed `docs/benchmarks/psar-epoch.md`.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{Keypair, Parity, Secp256k1, SecretKey};

use dark_psar::{asp_board, process_epoch, ActiveCohort, CohortMember, HibernationHorizon};

const SETUP_ID: [u8; 32] = [0xc4; 32];
const COHORT_ID: [u8; 32] = [0xab; 32];
/// Horizon for the per-epoch bench. `N` does not change the per-epoch
/// cost (one epoch's worth of work regardless of horizon length); the
/// smallest legal value (N=2) keeps boarding-side setup fast.
const HORIZON_N: u32 = 2;

fn even_parity_keypair(secp: &Secp256k1<secp256k1::All>, seed: u64) -> Keypair {
    for offset in 0u32..1024 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[28..32].copy_from_slice(&offset.to_le_bytes());
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            let kp = Keypair::from_secret_key(secp, &sk);
            if kp.x_only_public_key().1 == Parity::Even {
                return kp;
            }
        }
    }
    panic!("no even-parity keypair within counter range")
}

fn build_members(secp: &Secp256k1<secp256k1::All>, k: u32) -> Vec<(CohortMember, Keypair)> {
    (0..k)
        .map(|i| {
            let kp = even_parity_keypair(secp, 0x1000_0001_u64.wrapping_mul(i as u64 + 1));
            let xonly = kp.x_only_public_key().0.serialize();
            let mut user_id = [0u8; 32];
            user_id[0] = ((i >> 8) & 0xff) as u8;
            user_id[1] = (i & 0xff) as u8;
            (
                CohortMember {
                    user_id,
                    pk_user: xonly,
                    slot_index: i,
                },
                kp,
            )
        })
        .collect()
}

fn build_active_cohort(k: u32) -> (Keypair, ActiveCohort) {
    let secp = Secp256k1::new();
    let asp_kp = even_parity_keypair(&secp, 0xa0);
    let horizon = HibernationHorizon::new(HORIZON_N, HORIZON_N.max(12)).unwrap();
    let members_kps = build_members(&secp, k);
    let mut rng = StdRng::seed_from_u64(0xdada);
    let active = asp_board(
        &asp_kp,
        COHORT_ID,
        members_kps,
        horizon,
        SETUP_ID,
        None,
        &mut rng,
    )
    .expect("asp_board");
    (asp_kp, active)
}

fn process_epoch_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_epoch");
    // Per-K wall-clock at K=1000 is ~500 ms × 10 samples ≈ 5 s + warm-up.
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(8));
    for &k in &[100u32, 1000] {
        let (asp_kp, mut active) = build_active_cohort(k);
        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, _| {
            b.iter(|| process_epoch(black_box(&mut active), black_box(&asp_kp), 1).unwrap())
        });
    }
    group.finish();
}

/// `BENCH_LONG=1 cargo bench -p dark-psar --bench epoch -- long` opts
/// into the K=10000 measurement. Setup runs ~5 minutes; per-iter
/// process_epoch ~5 s; total ~10 min.
fn process_epoch_long_benchmark(c: &mut Criterion) {
    if std::env::var("BENCH_LONG").ok().as_deref() != Some("1") {
        return; // Skipped — set BENCH_LONG=1 to opt in.
    }
    let mut group = c.benchmark_group("process_epoch_long");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(120));
    let k = 10_000u32;
    let (asp_kp, mut active) = build_active_cohort(k);
    group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, _| {
        b.iter(|| process_epoch(black_box(&mut active), black_box(&asp_kp), 1).unwrap())
    });
    group.finish();
}

criterion_group!(
    benches,
    process_epoch_benchmark,
    process_epoch_long_benchmark
);
criterion_main!(benches);
