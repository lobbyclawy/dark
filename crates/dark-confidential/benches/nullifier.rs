//! Criterion benchmark for nullifier hash rate (issue #528).
//!
//! Reports HMAC-SHA256 derivations per second under the canonical
//! 36-byte vtxo_id encoding. Throughput driver is set to 1 nullifier
//! per iteration so Criterion's report shows ops/s directly.
//!
//! Regression policy (informational, enforced externally — see
//! `docs/benchmarks/confidential-primitives.md`):
//! a +25 % regression on median latency fails CI.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use dark_confidential::nullifier::{compute_nullifier, encode_vtxo_id};
use secp256k1::SecretKey;

fn nullifier_benchmark(c: &mut Criterion) {
    let sk = SecretKey::from_slice(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ])
    .unwrap();
    let vtxo_id = encode_vtxo_id(&[0x42u8; 32], 7);

    let mut group = c.benchmark_group("nullifier");
    group.throughput(Throughput::Elements(1));
    group.bench_function("compute_nullifier", |b| {
        b.iter(|| compute_nullifier(black_box(&sk), black_box(&vtxo_id)))
    });
    group.finish();
}

criterion_group!(benches, nullifier_benchmark);
criterion_main!(benches);
