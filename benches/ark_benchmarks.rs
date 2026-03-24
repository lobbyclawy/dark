//! Performance benchmarks for the Ark protocol implementation.
//!
//! Run with: `cargo bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;

use dark_core::domain::{ForfeitTx, Intent, Receiver, Round, TxTreeNode, Vtxo, VtxoOutpoint};

// ─── Helpers ────────────────────────────────────────────────────────

fn make_vtxo(i: usize) -> Vtxo {
    let mut vtxo = Vtxo::new(
        VtxoOutpoint::new(format!("tx_{i:064x}"), 0),
        (i as u64 + 1) * 10_000,
        format!("pk_{i:064x}"),
    );
    vtxo.expires_at = 1700000000 + i as i64;
    vtxo.created_at = 1699000000;
    vtxo.commitment_txids = vec![format!("commit_{i}")];
    vtxo.root_commitment_txid = format!("commit_{i}");
    vtxo
}

fn make_intent(i: usize, receiver_count: usize) -> Intent {
    let receivers: Vec<Receiver> = (0..receiver_count)
        .map(|j| Receiver::offchain((j as u64 + 1) * 50_000, format!("pk_recv_{i}_{j}")))
        .collect();

    Intent {
        id: format!("intent_{i}"),
        inputs: vec![make_vtxo(i)],
        receivers,
        proof: format!("proof_{i}"),
        message: format!("msg_{i}"),
        txid: format!("txid_{i}"),
        leaf_tx_asset_packet: String::new(),
        cosigners_public_keys: Vec::new(),
        delegate_pubkey: None,
    }
}

fn make_tree_node(i: usize, child_count: usize) -> TxTreeNode {
    let mut children = HashMap::new();
    for c in 0..child_count {
        children.insert(c as u32, format!("child_{i}_{c}"));
    }
    TxTreeNode {
        txid: format!("node_{i}"),
        tx: "a".repeat(200), // Simulated PSBT data
        children,
    }
}

// ─── VTXO Tree Construction ────────────────────────────────────────

fn bench_vtxo_tree_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("vtxo_tree_construction");

    for size in [10, 50, 100, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &n| {
            b.iter(|| {
                let tree: Vec<TxTreeNode> = (0..n)
                    .map(|i| {
                        let child_count = if i < n - 1 { 2 } else { 0 };
                        make_tree_node(i, child_count)
                    })
                    .collect();
                black_box(tree)
            });
        });
    }

    group.finish();
}

// ─── Round Lifecycle ────────────────────────────────────────────────

fn bench_round_lifecycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("round_lifecycle");

    for intent_count in [1, 10, 50, 128] {
        group.bench_with_input(
            BenchmarkId::new("register_intents", intent_count),
            &intent_count,
            |b, &n| {
                b.iter(|| {
                    let mut round = Round::new();
                    round.start_registration().unwrap();

                    for i in 0..n {
                        let intent = make_intent(i, 2);
                        round.register_intent(intent).unwrap();
                    }

                    round.start_finalization().unwrap();
                    round.end_successfully();
                    black_box(&round);
                });
            },
        );
    }

    group.finish();
}

// ─── Round Serialization ────────────────────────────────────────────

fn bench_round_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("round_serialization");

    for intent_count in [1, 10, 50] {
        // Build a round
        let mut round = Round::new();
        round.start_registration().unwrap();
        for i in 0..intent_count {
            round.register_intent(make_intent(i, 3)).unwrap();
        }
        round.vtxo_tree = (0..intent_count * 2)
            .map(|i| make_tree_node(i, 2))
            .collect();
        round.forfeit_txs = (0..intent_count)
            .map(|i| ForfeitTx {
                txid: format!("ftx_{i}"),
                tx: "deadbeef".repeat(20),
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("serialize", intent_count),
            &round,
            |b, round| {
                b.iter(|| {
                    let json = serde_json::to_string(black_box(round)).unwrap();
                    black_box(json)
                });
            },
        );

        let json = serde_json::to_string(&round).unwrap();
        group.bench_with_input(
            BenchmarkId::new("deserialize", intent_count),
            &json,
            |b, json| {
                b.iter(|| {
                    let round: Round = serde_json::from_str(black_box(json)).unwrap();
                    black_box(round)
                });
            },
        );
    }

    group.finish();
}

// ─── VTXO Operations ───────────────────────────────────────────────

fn bench_vtxo_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("vtxo_operations");

    // Benchmark VTXO creation
    group.bench_function("create_1000_vtxos", |b| {
        b.iter(|| {
            let vtxos: Vec<Vtxo> = (0..1000).map(make_vtxo).collect();
            black_box(vtxos)
        });
    });

    // Benchmark outpoint parsing
    group.bench_function("parse_outpoint", |b| {
        let input = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:42";
        b.iter(|| {
            let op = VtxoOutpoint::from_string(black_box(input)).unwrap();
            black_box(op)
        });
    });

    // Benchmark VTXO spendability checks
    let vtxos: Vec<Vtxo> = (0..1000).map(make_vtxo).collect();
    group.bench_function("check_spendable_1000", |b| {
        b.iter(|| {
            let count = vtxos.iter().filter(|v| v.is_spendable()).count();
            black_box(count)
        });
    });

    // Benchmark expiry checks
    group.bench_function("check_expired_1000", |b| {
        let now = 1700000500i64;
        b.iter(|| {
            let count = vtxos
                .iter()
                .filter(|v| v.is_expired_at(black_box(now)))
                .count();
            black_box(count)
        });
    });

    group.finish();
}

// ─── Database Benchmarks (SQLite in-memory) ─────────────────────────

fn bench_db_operations(c: &mut Criterion) {
    use dark_core::ports::{RoundRepository, VtxoRepository};
    use dark_db::repos::{SqliteRoundRepository, SqliteVtxoRepository};
    use dark_db::Database;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("database");

    // VTXO insert benchmark
    for count in [10, 100, 500] {
        group.bench_with_input(BenchmarkId::new("insert_vtxos", count), &count, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let db = Database::connect_in_memory().await.unwrap();
                    let repo = SqliteVtxoRepository::new(db.sqlite_pool().unwrap().clone());
                    let vtxos: Vec<Vtxo> = (0..n).map(make_vtxo).collect();
                    repo.add_vtxos(&vtxos).await.unwrap();
                });
            });
        });
    }

    // VTXO query benchmark
    for count in [10, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("query_vtxos_by_pubkey", count),
            &count,
            |b, &n| {
                let db = rt.block_on(async {
                    let db = Database::connect_in_memory().await.unwrap();
                    let repo = SqliteVtxoRepository::new(db.sqlite_pool().unwrap().clone());
                    let vtxos: Vec<Vtxo> = (0..n)
                        .map(|i| {
                            let mut v = make_vtxo(i);
                            v.pubkey = "target_pubkey".to_string();
                            v
                        })
                        .collect();
                    repo.add_vtxos(&vtxos).await.unwrap();
                    db
                });

                b.iter(|| {
                    rt.block_on(async {
                        let repo = SqliteVtxoRepository::new(db.sqlite_pool().unwrap().clone());
                        let (spendable, spent) = repo
                            .get_all_vtxos_for_pubkey(black_box("target_pubkey"))
                            .await
                            .unwrap();
                        black_box((spendable, spent));
                    });
                });
            },
        );
    }

    // Round persistence benchmark
    for intent_count in [1, 10, 50] {
        group.bench_with_input(
            BenchmarkId::new("persist_round", intent_count),
            &intent_count,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let db = Database::connect_in_memory().await.unwrap();
                        let repo = SqliteRoundRepository::new(db.sqlite_pool().unwrap().clone());

                        let mut round = Round::new();
                        round.start_registration().unwrap();
                        for i in 0..n {
                            round.register_intent(make_intent(i, 2)).unwrap();
                        }
                        round.vtxo_tree = (0..n * 2).map(|i| make_tree_node(i, 2)).collect();

                        repo.add_or_update_round(&round).await.unwrap();
                    });
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_vtxo_tree_construction,
    bench_round_lifecycle,
    bench_round_serialization,
    bench_vtxo_operations,
    bench_db_operations,
);
criterion_main!(benches);
