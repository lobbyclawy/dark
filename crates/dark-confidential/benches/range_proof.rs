//! Criterion benchmarks for range-proof prove/verify.
//!
//! Covers the shapes called out by issue #528:
//! - single proof
//! - aggregated proof for 2, 4, 16 outputs (uniform amounts so the
//!   shared-length aggregation path applies)
//!
//! Regression policy (informational, enforced externally — see
//! `docs/benchmarks/confidential-primitives.md`):
//! a +25 % regression on median prove time fails CI.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dark_confidential::range_proof::{
    prove_range, prove_range_aggregated, verify_range, verify_range_aggregated,
};
use secp256k1::Scalar;

fn scalar_from_u64(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).unwrap()
}

fn range_proof_single_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_single");
    let amount: u64 = 1_000_000;
    let blinding = scalar_from_u64(0x00c0_ffee);

    group.bench_function("prove", |b| {
        b.iter(|| {
            let _ = prove_range(black_box(amount), black_box(&blinding)).unwrap();
        });
    });

    let (proof, commitment) = prove_range(amount, &blinding).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| assert!(verify_range(black_box(&commitment), black_box(&proof))));
    });
    group.bench_function(BenchmarkId::new("proof_size_bytes", amount), |b| {
        let len = proof.to_bytes().len();
        b.iter(|| black_box(len))
    });
    group.finish();
}

fn range_proof_aggregated_benchmark(c: &mut Criterion) {
    for n in [2usize, 4, 16] {
        let mut group = c.benchmark_group(format!("range_proof_aggregated_{n}"));
        let inputs: Vec<(u64, Scalar)> = (0..n as u64)
            .map(|i| (1_000_000 + i, scalar_from_u64(0x0200 + i)))
            .collect();
        group.bench_function("prove", |b| {
            b.iter(|| {
                let _ = prove_range_aggregated(black_box(&inputs)).unwrap();
            });
        });
        let (proof, commitments) = prove_range_aggregated(&inputs).unwrap();
        group.bench_function("verify", |b| {
            b.iter(|| {
                assert!(verify_range_aggregated(
                    black_box(&commitments),
                    black_box(&proof)
                ))
            });
        });
        group.bench_function(BenchmarkId::new("proof_size_bytes", n), |b| {
            let len = proof.to_bytes().len();
            b.iter(|| black_box(len))
        });
        group.finish();
    }
}

criterion_group!(
    benches,
    range_proof_single_benchmark,
    range_proof_aggregated_benchmark
);
criterion_main!(benches);
