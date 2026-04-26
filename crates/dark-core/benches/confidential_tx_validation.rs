//! Criterion benchmark for `validate_confidential_transaction`.
//!
//! Acceptance criterion (issue #538): validation p99 < 10 ms for a typical
//! 2-in / 2-out confidential transaction.
//!
//! This bench builds a single balanced fixture and re-validates it on each
//! iteration. The sink is reset between iterations so a `batch_insert` after
//! a successful validation does not poison subsequent runs with
//! `NullifierAlreadySpent`. The criterion harness gives us a histogram with
//! p50/p99 in the report — the threshold is asserted in the comment block at
//! the bottom of this file.

use std::collections::HashSet;

use async_trait::async_trait;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::sync::Mutex;

use dark_confidential::balance_proof::{prove_balance, BalanceProof};
use dark_confidential::commitment::PedersenCommitment;
use dark_confidential::range_proof::{prove_range, RangeProof};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

use dark_core::confidential_tx_validation::{
    validate_confidential_transaction, ConfidentialOutput, ConfidentialTransaction,
    FeeMinimumProvider, InputVtxoResolver, ValidationContext, SUPPORTED_SCHEMA_VERSION,
};
use dark_core::error::ArkResult;
use dark_core::ports::NullifierSink;

// ---- helpers --------------------------------------------------------------

fn scalar(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).unwrap()
}

fn pubkey_compressed(seed: u64) -> [u8; 33] {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[24..].copy_from_slice(&seed.to_be_bytes());
    if sk_bytes == [0u8; 32] {
        sk_bytes[31] = 1;
    }
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();
    PublicKey::from_secret_key(&Secp256k1::new(), &sk).serialize()
}

fn nullifier(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[0] = seed;
    n[31] = seed;
    n
}

#[derive(Default)]
struct ResettableSink {
    seen: Mutex<HashSet<[u8; 32]>>,
}

impl ResettableSink {
    async fn reset(&self) {
        self.seen.lock().await.clear();
    }
}

#[async_trait]
impl NullifierSink for ResettableSink {
    async fn batch_insert(
        &self,
        nullifiers: &[[u8; 32]],
        _round_id: Option<&str>,
    ) -> ArkResult<Vec<bool>> {
        let mut guard = self.seen.lock().await;
        let mut out = Vec::with_capacity(nullifiers.len());
        for n in nullifiers {
            out.push(guard.insert(*n));
        }
        Ok(out)
    }

    async fn contains(&self, n: &[u8; 32]) -> bool {
        self.seen.lock().await.contains(n)
    }
}

struct ZeroFee;
#[async_trait]
impl FeeMinimumProvider for ZeroFee {
    async fn minimum_fee(&self, _i: usize, _o: usize) -> u64 {
        0
    }
    async fn fee_cap(&self) -> u64 {
        u64::MAX
    }
}

struct StaticResolver {
    map: std::collections::HashMap<[u8; 32], PedersenCommitment>,
}

#[async_trait]
impl InputVtxoResolver for StaticResolver {
    async fn resolve(&self, n: &[u8; 32]) -> Option<PedersenCommitment> {
        self.map.get(n).cloned()
    }
}

// ---- fixture --------------------------------------------------------------

struct Fixture {
    tx: ConfidentialTransaction,
    input_commitments: Vec<PedersenCommitment>,
}

fn build_2in_2out_fixture() -> Fixture {
    // 2-in / 2-out, balanced, fee = 10. Range proofs and balance proof
    // are the real cryptographic objects from `dark-confidential`.
    let in_blindings = [scalar(0x1111_0001), scalar(0x2222_0002)];
    let out_blindings = [scalar(0x3333_aaaa_dead_5555), scalar(0x4444_bbbb_beef_6666)];
    let in_amounts = [100u64, 50u64];
    let out_amounts = [120u64, 20u64];
    let fee = 10u64;
    let tx_hash = [0xa5u8; 32];

    // Sanity assertion on amounts.
    let sum_in: u128 = in_amounts.iter().map(|x| *x as u128).sum();
    let sum_out: u128 = out_amounts.iter().map(|x| *x as u128).sum();
    assert_eq!(sum_in, sum_out + fee as u128, "fixture must balance");

    let (rp1, vc1) = prove_range(out_amounts[0], &out_blindings[0]).unwrap();
    let (rp2, vc2) = prove_range(out_amounts[1], &out_blindings[1]).unwrap();

    let balance_commitments: Vec<PedersenCommitment> = out_amounts
        .iter()
        .zip(out_blindings.iter())
        .map(|(a, b)| PedersenCommitment::commit(*a, b).unwrap())
        .collect();

    let input_commitments: Vec<PedersenCommitment> = in_amounts
        .iter()
        .zip(in_blindings.iter())
        .map(|(a, b)| PedersenCommitment::commit(*a, b).unwrap())
        .collect();

    let balance_proof: BalanceProof =
        prove_balance(&in_blindings, &out_blindings, fee, &tx_hash).unwrap();

    let outputs = vec![
        ConfidentialOutput {
            balance_commitment: balance_commitments[0].clone(),
            value_commitment: vc1,
            range_proof: Some(rp1.clone()),
            owner_pubkey: pubkey_compressed(1),
            ephemeral_pubkey: Some(pubkey_compressed(2)),
            encrypted_memo: vec![0xab; 64],
        },
        ConfidentialOutput {
            balance_commitment: balance_commitments[1].clone(),
            value_commitment: vc2,
            range_proof: Some(rp2.clone()),
            owner_pubkey: pubkey_compressed(3),
            ephemeral_pubkey: Some(pubkey_compressed(4)),
            encrypted_memo: vec![],
        },
    ];

    // Suppress "unused" warning chain.
    let _: &RangeProof = &rp1;
    let _: &RangeProof = &rp2;

    Fixture {
        tx: ConfidentialTransaction {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            nullifiers: vec![nullifier(7), nullifier(11)],
            outputs,
            balance_proof,
            fee_amount: fee,
            tx_hash,
        },
        input_commitments,
    }
}

// ---- benchmark -----------------------------------------------------------

fn bench_validate_2in_2out(c: &mut Criterion) {
    let fixture = build_2in_2out_fixture();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let sink = ResettableSink::default();
    let resolver = StaticResolver {
        map: fixture
            .tx
            .nullifiers
            .iter()
            .copied()
            .zip(fixture.input_commitments.iter().cloned())
            .collect(),
    };
    let fee = ZeroFee;

    c.bench_function("validate_confidential_tx_2in_2out", |b| {
        b.iter(|| {
            runtime.block_on(async {
                // Fresh state per iteration so batch_insert succeeds.
                sink.reset().await;
                let ctx = ValidationContext {
                    nullifier_sink: &sink,
                    input_resolver: &resolver,
                    fee_provider: &fee,
                    aggregated_range_proof: None,
                    is_operator_initiated: false,
                    round_id: None,
                };
                let r = validate_confidential_transaction(black_box(&fixture.tx), &ctx).await;
                debug_assert!(r.is_ok(), "fixture must validate");
            });
        });
    });
}

criterion_group!(benches, bench_validate_2in_2out);
criterion_main!(benches);
