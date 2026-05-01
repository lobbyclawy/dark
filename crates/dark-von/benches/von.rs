use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dark_von::ecvrf;
use dark_von::hash::h_nonce;
use dark_von::schedule;
use dark_von::wrapper;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

const SETUP_ID: [u8; 32] = [0x42; 32];

fn fixed_sk() -> SecretKey {
    SecretKey::from_slice(&[0x99u8; 32]).unwrap()
}

fn fixed_pk(sk: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(&Secp256k1::new(), sk)
}

fn ecvrf_benchmark(c: &mut Criterion) {
    let sk = fixed_sk();
    let pk = fixed_pk(&sk);
    let alpha = b"DARK-VON-bench-alpha";

    let mut group = c.benchmark_group("ecvrf");
    group.bench_function("prove", |b| {
        b.iter(|| ecvrf::prove(black_box(&sk), black_box(alpha)).unwrap())
    });

    let (beta, proof) = ecvrf::prove(&sk, alpha).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| {
            ecvrf::verify(
                black_box(&pk),
                black_box(alpha),
                black_box(&beta),
                black_box(&proof),
            )
            .unwrap()
        })
    });
    group.finish();
}

fn von_nonce_benchmark(c: &mut Criterion) {
    let sk = fixed_sk();
    let x = h_nonce(&SETUP_ID, 1, 1);

    let mut group = c.benchmark_group("von_nonce");
    group.bench_function("nonce", |b| {
        b.iter(|| wrapper::nonce(black_box(&sk), black_box(&x)).unwrap())
    });
    group.finish();
}

fn von_verify_benchmark(c: &mut Criterion) {
    let sk = fixed_sk();
    let pk = fixed_pk(&sk);
    let x = h_nonce(&SETUP_ID, 1, 1);
    let n = wrapper::nonce(&sk, &x).unwrap();

    let mut group = c.benchmark_group("von_verify");
    group.bench_function("verify", |b| {
        b.iter(|| {
            wrapper::verify(
                black_box(&pk),
                black_box(&x),
                black_box(&n.r_point),
                black_box(&n.proof),
            )
            .unwrap()
        })
    });
    group.finish();
}

fn schedule_generate_benchmark(c: &mut Criterion) {
    let sk = fixed_sk();
    let mut group = c.benchmark_group("schedule_generate");
    for n in [4u32, 12, 50] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| schedule::generate(black_box(&sk), black_box(&SETUP_ID), n).unwrap());
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    ecvrf_benchmark,
    von_nonce_benchmark,
    von_verify_benchmark,
    schedule_generate_benchmark
);
criterion_main!(benches);
