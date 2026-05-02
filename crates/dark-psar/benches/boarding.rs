//! Single-user boarding latency parameterised over `N ∈ {4, 12, 50}`
//! (issue #682).
//!
//! Measures the wall-clock cost of `dark_psar::user_board` — the
//! end-to-end client-side boarding call: verify Λ, derive `N`
//! per-epoch messages, pre-sign the horizon, hash-chain a schedule
//! witness. Setup (cohort construction, ASP attestation, schedule
//! generation) happens once outside the timed loop; only `user_board`
//! is timed.
//!
//! Run with:
//!
//! ```bash
//! cargo bench -p dark-psar --bench boarding
//! ```
//!
//! Numbers feed `docs/benchmarks/psar-boarding.md`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{Keypair, Parity, Secp256k1, SecretKey};

use dark_psar::{
    user_board, Cohort, CohortMember, HibernationHorizon, SlotAttest, SlotAttestUnsigned, SlotRoot,
    SlotTree,
};
use dark_von_musig2::setup::{PublishedSchedule, Setup};

const SETUP_ID: [u8; 32] = [0xc4; 32];
const COHORT_ID: [u8; 32] = [0xab; 32];

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

struct Fixture {
    cohort: Cohort,
    attest: SlotAttest,
    schedule: PublishedSchedule,
    user_kp: Keypair,
    asp_xonly: secp256k1::XOnlyPublicKey,
    batch_root: [u8; 32],
}

fn build_fixture(n: u32) -> Fixture {
    let secp = Secp256k1::new();
    let asp_kp = even_parity_keypair(&secp, 0x77);
    let asp_xonly = asp_kp.x_only_public_key().0;

    // 2-member cohort is the smallest legal one — boarding cost is
    // dominated by `N`, not `K`, so this isolates the per-user cost.
    let user_kp = even_parity_keypair(&secp, 0x80);
    let other_kp = even_parity_keypair(&secp, 0x81);
    let user_xonly = user_kp.x_only_public_key().0.serialize();
    let other_xonly = other_kp.x_only_public_key().0.serialize();
    let members = vec![
        CohortMember {
            user_id: [0x01; 32],
            pk_user: user_xonly,
            slot_index: 0,
        },
        CohortMember {
            user_id: [0x02; 32],
            pk_user: other_xonly,
            slot_index: 1,
        },
    ];
    let horizon = HibernationHorizon::new(n, n.max(50)).expect("horizon");
    let cohort = Cohort::new(COHORT_ID, members, horizon).expect("cohort");

    // Slot root + signed SlotAttest.
    let tree = SlotTree::from_members(&cohort.members);
    let SlotRoot(slot_root) = tree.root();
    let unsigned = SlotAttestUnsigned {
        slot_root,
        cohort_id: COHORT_ID,
        setup_id: SETUP_ID,
        n: horizon.n,
        k: cohort.k(),
    };
    let attest = unsigned.sign(&secp, &asp_kp);

    // Λ generation at horizon `n`.
    let asp_sk = SecretKey::from_keypair(&asp_kp);
    let (schedule, _retained) = Setup::run(&asp_sk, &SETUP_ID, n).expect("setup");

    let batch_root = dark_psar::compute_batch_tree_root(&cohort);
    Fixture {
        cohort,
        attest,
        schedule,
        user_kp,
        asp_xonly,
        batch_root,
    }
}

fn user_board_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("user_board");
    for &n in &[4u32, 12, 50] {
        let fx = build_fixture(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let mut rng = StdRng::seed_from_u64(0xface);
                user_board(
                    black_box(&fx.cohort),
                    black_box(&fx.attest),
                    black_box(&fx.asp_xonly),
                    black_box(&fx.schedule),
                    black_box(&fx.user_kp),
                    black_box(0u32),
                    black_box(fx.batch_root),
                    &mut rng,
                )
                .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, user_board_benchmark);
criterion_main!(benches);
