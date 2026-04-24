//! Criterion benchmarks for balance-proof prove/verify.
//!
//! Covers the shapes called out by issue #528: 1, 4, 8, 16 inputs and
//! a matching number of outputs. Each fixture is balanced (so prove
//! and verify both run successfully) and the verifier walks `Σ C_in −
//! Σ C_out − fee·G`, so the commitment count drives both prove- and
//! verify-side work.
//!
//! Regression policy (informational, enforced externally — see
//! `docs/benchmarks/confidential-primitives.md`):
//! a +25 % regression on median prove time fails CI.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dark_confidential::balance_proof::{prove_balance, verify_balance, BalanceProof};
use dark_confidential::commitment::PedersenCommitment;
use secp256k1::Scalar;

fn scalar(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).unwrap()
}

struct Fixture {
    in_blindings: Vec<Scalar>,
    out_blindings: Vec<Scalar>,
    inputs: Vec<PedersenCommitment>,
    outputs: Vec<PedersenCommitment>,
    fee: u64,
    tx_hash: [u8; 32],
    proof: BalanceProof,
}

fn balanced_fixture(n: usize) -> Fixture {
    // Inputs total 100·n + 50. Outputs total 100·n + 40, fee = 10.
    let in_blindings: Vec<Scalar> = (0..n as u64).map(|i| scalar(0x1111_0000 + i)).collect();
    let out_blindings: Vec<Scalar> = (0..n as u64).map(|i| scalar(0x2222_0000 + i)).collect();
    let inputs: Vec<PedersenCommitment> = (0..n as u64)
        .map(|i| PedersenCommitment::commit(100 + i, &in_blindings[i as usize]).unwrap())
        .collect();
    let total_in: u64 = (0..n as u64).map(|i| 100 + i).sum();
    let fee: u64 = 10;
    let payable = total_in - fee;
    let out_amounts: Vec<u64> = if n == 1 {
        vec![payable]
    } else {
        // Spread the output total roughly evenly.
        let base = payable / n as u64;
        let mut v: Vec<u64> = std::iter::repeat_n(base, n - 1).collect();
        v.push(payable - base * (n as u64 - 1));
        v
    };
    let outputs: Vec<PedersenCommitment> = out_amounts
        .iter()
        .zip(out_blindings.iter())
        .map(|(amt, r)| PedersenCommitment::commit(*amt, r).unwrap())
        .collect();
    let tx_hash = [0x5au8; 32];
    let proof = prove_balance(&in_blindings, &out_blindings, fee, &tx_hash).unwrap();
    Fixture {
        in_blindings,
        out_blindings,
        inputs,
        outputs,
        fee,
        tx_hash,
        proof,
    }
}

fn balance_proof_benchmark(c: &mut Criterion) {
    for n in [1usize, 4, 8, 16] {
        let f = balanced_fixture(n);
        let mut group = c.benchmark_group(format!("balance_proof_n{n}"));
        group.bench_function(BenchmarkId::new("prove", n), |b| {
            b.iter(|| {
                let _ = prove_balance(
                    black_box(&f.in_blindings),
                    black_box(&f.out_blindings),
                    black_box(f.fee),
                    black_box(&f.tx_hash),
                )
                .unwrap();
            });
        });
        group.bench_function(BenchmarkId::new("verify", n), |b| {
            b.iter(|| {
                assert!(verify_balance(
                    black_box(&f.inputs),
                    black_box(&f.outputs),
                    black_box(f.fee),
                    black_box(&f.tx_hash),
                    black_box(&f.proof),
                ))
            });
        });
        group.finish();
    }
}

criterion_group!(benches, balance_proof_benchmark);
criterion_main!(benches);
