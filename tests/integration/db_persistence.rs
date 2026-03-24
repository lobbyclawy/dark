//! Database persistence integration tests.
//!
//! Tests write → read back consistency for rounds and VTXOs using SQLite in-memory.

use dark_core::domain::{
    ForfeitTx, Intent, Receiver, Round, RoundStage, TxTreeNode, Vtxo, VtxoOutpoint,
};
use dark_core::ports::{RoundRepository, VtxoRepository};
use dark_db::repos::{SqliteRoundRepository, SqliteVtxoRepository};
use dark_db::Database;
use std::collections::HashMap;

async fn setup() -> (Database, SqliteVtxoRepository, SqliteRoundRepository) {
    let db = Database::connect_in_memory().await.unwrap();
    let vtxo_repo = SqliteVtxoRepository::new(db.sqlite_pool().unwrap().clone());
    let round_repo = SqliteRoundRepository::new(db.sqlite_pool().unwrap().clone());
    (db, vtxo_repo, round_repo)
}

fn make_vtxo(txid: &str, vout: u32, pubkey: &str, amount: u64) -> Vtxo {
    let mut vtxo = Vtxo::new(
        VtxoOutpoint::new(txid.to_string(), vout),
        amount,
        pubkey.to_string(),
    );
    vtxo.expires_at = 1700000000;
    vtxo.created_at = 1699000000;
    vtxo
}

fn make_round(id: &str) -> Round {
    let mut round = Round::new();
    round.id = id.to_string();
    round.starting_timestamp = 1700000000;
    round
}

// ─── Full Round + VTXO Persistence ──────────────────────────────────

#[tokio::test]
async fn test_round_with_vtxos_full_persistence() {
    let (_db, vtxo_repo, round_repo) = setup().await;

    // Create and persist a round with intents
    let mut round = make_round("persist-round-1");
    round.start_registration().unwrap();
    round.commitment_txid = "ctxid_persist".to_string();
    round.commitment_tx = "raw_commitment_hex".to_string();
    round.connector_address = "bc1q_connector_persist".to_string();
    round.vtxo_tree_expiration = 1700604800;

    // Add forfeit transactions
    round.forfeit_txs = vec![
        ForfeitTx {
            txid: "ftx1".to_string(),
            tx: "raw_ftx1".to_string(),
        },
        ForfeitTx {
            txid: "ftx2".to_string(),
            tx: "raw_ftx2".to_string(),
        },
    ];

    // Add VTXO tree
    let mut children = HashMap::new();
    children.insert(0, "child1".to_string());
    children.insert(1, "child2".to_string());
    round.vtxo_tree = vec![
        TxTreeNode {
            txid: "root".to_string(),
            tx: "psbt_root".to_string(),
            children,
        },
        TxTreeNode {
            txid: "child1".to_string(),
            tx: "psbt_child1".to_string(),
            children: HashMap::new(),
        },
        TxTreeNode {
            txid: "child2".to_string(),
            tx: "psbt_child2".to_string(),
            children: HashMap::new(),
        },
    ];

    // Add intents with receivers
    let intent = Intent {
        id: "persist-intent-1".to_string(),
        inputs: vec![],
        receivers: vec![
            Receiver::offchain(100_000, "pk_alice".to_string()),
            Receiver::offchain(200_000, "pk_bob".to_string()),
            Receiver::onchain(50_000, "bc1q_charlie".to_string()),
        ],
        proof: "proof_data".to_string(),
        message: "intent_msg".to_string(),
        txid: "proof_txid".to_string(),
        leaf_tx_asset_packet: "asset_pkt".to_string(),
        cosigners_public_keys: Vec::new(),
        delegate_pubkey: None,
    };
    round.intents.insert(intent.id.clone(), intent);

    // Persist
    round_repo.add_or_update_round(&round).await.unwrap();

    // Read back and verify everything
    let fetched = round_repo
        .get_round_with_id("persist-round-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.commitment_txid, "ctxid_persist");
    assert_eq!(fetched.commitment_tx, "raw_commitment_hex");
    assert_eq!(fetched.connector_address, "bc1q_connector_persist");
    assert_eq!(fetched.stage.code, RoundStage::Registration);
    assert_eq!(fetched.forfeit_txs.len(), 2);
    assert_eq!(fetched.vtxo_tree.len(), 3);
    assert_eq!(fetched.vtxo_tree[0].children.len(), 2);
    assert_eq!(fetched.intents.len(), 1);

    let fi = fetched.intents.get("persist-intent-1").unwrap();
    assert_eq!(fi.receivers.len(), 3);
    assert_eq!(fi.proof, "proof_data");
    assert_eq!(fi.leaf_tx_asset_packet, "asset_pkt");

    // Now add VTXOs for the round's outputs
    let vtxos = vec![
        make_vtxo("vtxo_tx1", 0, "pk_alice", 100_000),
        make_vtxo("vtxo_tx2", 0, "pk_bob", 200_000),
    ];
    vtxo_repo.add_vtxos(&vtxos).await.unwrap();

    // Verify VTXOs persisted
    let alice = vtxo_repo
        .get_vtxos(&[VtxoOutpoint::new("vtxo_tx1".to_string(), 0)])
        .await
        .unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].amount, 100_000);

    let (alice_spendable, _) = vtxo_repo
        .get_all_vtxos_for_pubkey("pk_alice")
        .await
        .unwrap();
    assert_eq!(alice_spendable.len(), 1);
}

#[tokio::test]
async fn test_vtxo_lifecycle_persistence() {
    let (_db, vtxo_repo, _) = setup().await;

    // Create VTXOs
    let mut v1 = make_vtxo("lifecycle_tx", 0, "pk_user", 500_000);
    v1.commitment_txids = vec!["commit1".to_string(), "commit2".to_string()];
    v1.root_commitment_txid = "commit1".to_string();
    vtxo_repo.add_vtxos(&[v1]).await.unwrap();

    // Verify initial state
    let (spendable, spent) = vtxo_repo.get_all_vtxos_for_pubkey("pk_user").await.unwrap();
    assert_eq!(spendable.len(), 1);
    assert_eq!(spent.len(), 0);
    assert_eq!(spendable[0].commitment_txids.len(), 2);

    // Spend the VTXO
    vtxo_repo
        .spend_vtxos(
            &[(
                VtxoOutpoint::new("lifecycle_tx".to_string(), 0),
                "forfeit_tx_1".to_string(),
            )],
            "ark_tx_abc",
        )
        .await
        .unwrap();

    // Verify spent state
    let (spendable, spent) = vtxo_repo.get_all_vtxos_for_pubkey("pk_user").await.unwrap();
    assert_eq!(spendable.len(), 0);
    assert_eq!(spent.len(), 1);
    assert!(spent[0].spent);
    assert_eq!(spent[0].spent_by, "forfeit_tx_1");
    assert_eq!(spent[0].ark_txid, "ark_tx_abc");
}

#[tokio::test]
async fn test_find_expired_vtxos_persistence() {
    let (_db, vtxo_repo, _) = setup().await;

    let mut v1 = make_vtxo("exp_tx1", 0, "pk1", 100_000);
    v1.expires_at = 1000;

    let mut v2 = make_vtxo("exp_tx2", 0, "pk2", 200_000);
    v2.expires_at = 2000;

    let mut v3 = make_vtxo("exp_tx3", 0, "pk3", 300_000);
    v3.expires_at = 3000;

    vtxo_repo.add_vtxos(&[v1, v2, v3]).await.unwrap();

    let expired = vtxo_repo.find_expired_vtxos(2500).await.unwrap();
    assert_eq!(expired.len(), 2);

    // Expired VTXOs should be those with expires_at < 2500 (v1 and v2)
    let amounts: Vec<u64> = expired.iter().map(|v| v.amount).collect();
    assert!(amounts.contains(&100_000));
    assert!(amounts.contains(&200_000));
}

#[tokio::test]
async fn test_round_stats_persistence() {
    let (_db, _, round_repo) = setup().await;

    let mut round = make_round("stats-round");
    round.start_registration().unwrap();
    round.starting_timestamp = 1700000000;
    round.commitment_txid = "stats_ctxid".to_string();
    round.vtxo_tree_expiration = 1700604800;

    // Multiple intents
    for i in 0..3 {
        let intent = Intent {
            id: format!("stats-intent-{i}"),
            inputs: vec![],
            receivers: vec![Receiver::offchain(
                (i as u64 + 1) * 100_000,
                format!("pk_{i}"),
            )],
            proof: "p".to_string(),
            message: "m".to_string(),
            txid: "t".to_string(),
            leaf_tx_asset_packet: String::new(),
            cosigners_public_keys: Vec::new(),
            delegate_pubkey: None,
        };
        round.intents.insert(intent.id.clone(), intent);
    }

    round_repo.add_or_update_round(&round).await.unwrap();

    let stats = round_repo
        .get_round_stats("stats_ctxid")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stats.total_output_vtxos, 3);
    assert_eq!(stats.total_batch_amount, 100_000 + 200_000 + 300_000);
    assert_eq!(stats.expires_at, 1700604800);
}

#[tokio::test]
async fn test_round_update_overwrites_children() {
    let (_db, _, round_repo) = setup().await;

    let mut round = make_round("overwrite-round");
    round.start_registration().unwrap();
    round.forfeit_txs = vec![ForfeitTx {
        txid: "old_ftx".to_string(),
        tx: "old".to_string(),
    }];
    round_repo.add_or_update_round(&round).await.unwrap();

    // Update with new forfeit txs
    round.forfeit_txs = vec![
        ForfeitTx {
            txid: "new_ftx1".to_string(),
            tx: "new1".to_string(),
        },
        ForfeitTx {
            txid: "new_ftx2".to_string(),
            tx: "new2".to_string(),
        },
    ];
    round_repo.add_or_update_round(&round).await.unwrap();

    let fetched = round_repo
        .get_round_with_id("overwrite-round")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.forfeit_txs.len(), 2);
    assert_eq!(fetched.forfeit_txs[0].txid, "new_ftx1");
}

#[tokio::test]
async fn test_multiple_rounds_persistence() {
    let (_db, _, round_repo) = setup().await;

    // Persist multiple rounds
    for i in 0..5 {
        let mut round = make_round(&format!("multi-round-{i}"));
        round.start_registration().unwrap();
        round.commitment_txid = format!("ctxid_{i}");
        round_repo.add_or_update_round(&round).await.unwrap();
    }

    // Verify each round is independently retrievable
    for i in 0..5 {
        let fetched = round_repo
            .get_round_with_id(&format!("multi-round-{i}"))
            .await
            .unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().commitment_txid, format!("ctxid_{i}"));
    }

    // Non-existent round
    assert!(round_repo
        .get_round_with_id("nonexistent")
        .await
        .unwrap()
        .is_none());
}
