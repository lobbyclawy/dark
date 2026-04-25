//! Membership benchmark for `NullifierSet` (issue #534 AC).
//!
//! Acceptance criterion: `contains` lookup must be < 1 µs on a
//! 10 million-entry set. The bench uses
//! [`InMemoryNullifierStore`] so that DB latency does not skew the
//! number — the AC measures the in-memory hot path, not the DB write
//! path.
//!
//! Two groups:
//!   - `contains/hit`     — looking up a nullifier known to be in the set.
//!   - `contains/miss`    — looking up a fresh nullifier that is not in the set.
//!
//! Both should land below 1 µs on commodity hardware. If hit/miss
//! diverge by more than ~30%, the shard distribution has likely
//! degraded.
//!
//! By default the bench builds a 10M-entry set. Override with
//! `DARK_NULLIFIER_BENCH_SIZE` for quick local iteration; CI keeps the
//! 10M default to enforce the AC.

use std::env;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dark_live_store::nullifier_set::{
    InMemoryNullifierStore, Nullifier, NullifierSet, NullifierStore, NULLIFIER_LEN,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::runtime::Runtime;

fn make_nullifier(rng: &mut StdRng) -> Nullifier {
    let mut n = [0u8; NULLIFIER_LEN];
    rng.fill(&mut n);
    n
}

fn build_set(rt: &Runtime, n: usize) -> (Arc<NullifierSet>, Vec<Nullifier>) {
    let store: Arc<dyn NullifierStore> = Arc::new(InMemoryNullifierStore::new());
    let mut rng = StdRng::seed_from_u64(0xCAFE_F00D);
    let nullifiers: Vec<Nullifier> = (0..n).map(|_| make_nullifier(&mut rng)).collect();

    rt.block_on(async {
        store
            .persist_batch(&nullifiers, Some("bench"))
            .await
            .unwrap();
    });

    let set = rt.block_on(async {
        Arc::new(
            NullifierSet::load_from_db(Arc::clone(&store))
                .await
                .unwrap(),
        )
    });

    (set, nullifiers)
}

fn bench_contains(c: &mut Criterion) {
    let n: usize = env::var("DARK_NULLIFIER_BENCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000_000);

    let rt = Runtime::new().expect("tokio runtime");
    let (set, nullifiers) = build_set(&rt, n);

    let mut group = c.benchmark_group("contains");
    group.throughput(Throughput::Elements(1));

    // Hit: known nullifier
    let hit_index = nullifiers.len() / 2;
    let hit_target = nullifiers[hit_index];
    group.bench_with_input(BenchmarkId::new("hit", n), &hit_target, |b, target| {
        b.to_async(&rt).iter(|| async {
            let r = set.contains(black_box(target)).await;
            black_box(r)
        });
    });

    // Miss: fresh random nullifier
    let mut rng = StdRng::seed_from_u64(0x0BAD_CAFE);
    let miss_target = make_nullifier(&mut rng);
    group.bench_with_input(BenchmarkId::new("miss", n), &miss_target, |b, target| {
        b.to_async(&rt).iter(|| async {
            let r = set.contains(black_box(target)).await;
            black_box(r)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_contains);
criterion_main!(benches);
