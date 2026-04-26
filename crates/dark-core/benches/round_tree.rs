//! Criterion benchmarks for the round Merkle tree (issue #540).
//!
//! Acceptance criterion: build a tree of 10_000 transparent leaves in <50 ms.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dark_core::domain::vtxo::{
    ConfidentialPayload, Vtxo, VtxoOutpoint, EPHEMERAL_PUBKEY_LEN, NULLIFIER_LEN,
    PEDERSEN_COMMITMENT_LEN,
};
use dark_core::round_tree::{tree_leaf_hash, RoundTree};

fn make_transparent(seed: u32) -> Vtxo {
    let txid = format!("{:064x}", seed as u64);
    let pubkey = format!("{:064x}", (seed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    Vtxo::new(
        VtxoOutpoint::new(txid, seed),
        1_000 + u64::from(seed),
        pubkey,
    )
}

fn make_confidential(seed: u32) -> Vtxo {
    let txid = format!("{:064x}", u64::from(seed) + 0x10_0000);
    let pubkey = format!("{:02x}", (seed as u8).wrapping_add(1)).repeat(32);
    let payload = ConfidentialPayload::new(
        [(seed & 0xff) as u8; PEDERSEN_COMMITMENT_LEN],
        vec![(seed & 0xff) as u8; 16],
        [((seed & 0xff) as u8).wrapping_add(2); NULLIFIER_LEN],
        [((seed & 0xff) as u8).wrapping_add(3); EPHEMERAL_PUBKEY_LEN],
    );
    Vtxo::new_confidential(VtxoOutpoint::new(txid, seed), pubkey, payload)
}

fn bench_build_tree_transparent(c: &mut Criterion) {
    let mut group = c.benchmark_group("round_tree_build_transparent");
    // Configure the budget for the 10_000-leaf case so a single bench
    // iteration captures a clean wall-clock measurement.
    group.measurement_time(Duration::from_secs(8));
    for &n in &[1_000usize, 10_000usize] {
        let vtxos: Vec<Vtxo> = (0..n).map(|i| make_transparent(i as u32)).collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &vtxos, |b, vtxos| {
            b.iter(|| {
                let t = RoundTree::from_vtxos(black_box(vtxos)).unwrap();
                black_box(t.root());
            });
        });
    }
    group.finish();
}

fn bench_build_tree_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("round_tree_build_mixed");
    group.measurement_time(Duration::from_secs(8));
    for &n in &[1_000usize, 10_000usize] {
        let vtxos: Vec<Vtxo> = (0..n)
            .map(|i| {
                if i.is_multiple_of(2) {
                    make_transparent(i as u32)
                } else {
                    make_confidential(i as u32)
                }
            })
            .collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &vtxos, |b, vtxos| {
            b.iter(|| {
                let t = RoundTree::from_vtxos(black_box(vtxos)).unwrap();
                black_box(t.root());
            });
        });
    }
    group.finish();
}

fn bench_leaf_hash_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("leaf_hash");
    let v_t = make_transparent(0);
    group.bench_function("transparent", |b| {
        b.iter(|| black_box(tree_leaf_hash(black_box(&v_t)).unwrap()));
    });
    let v_c = make_confidential(0);
    group.bench_function("confidential", |b| {
        b.iter(|| black_box(tree_leaf_hash(black_box(&v_c)).unwrap()));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_build_tree_transparent,
    bench_build_tree_mixed,
    bench_leaf_hash_only,
);
criterion_main!(benches);
