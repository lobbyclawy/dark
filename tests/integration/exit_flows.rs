//! Integration tests for collaborative and unilateral exit flows.

use std::sync::Arc;

use dark_core::domain::{
    CollaborativeExitRequest, Exit, ExitStatus, ExitType, UnilateralExitRequest, Vtxo, VtxoOutpoint,
};

use crate::helpers::{build_service, make_vtxo, test_address, test_xonly_pubkey, InMemoryVtxoRepo};

// ─── Collaborative Exit Tests ───────────────────────────────────────

#[tokio::test]
async fn test_collaborative_exit_flow() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    // Seed spendable VTXOs
    let vtxo = make_vtxo("exit_tx1", 0, "pk_exiter", 500_000);
    vtxo_repo.seed_vtxos(vec![vtxo]).await;

    let service = build_service(vtxo_repo.clone());
    let requester_pk = test_xonly_pubkey();

    let request = CollaborativeExitRequest {
        vtxo_ids: vec![VtxoOutpoint::new("exit_tx1".to_string(), 0)],
        destination: test_address(),
    };

    let exit = service
        .request_collaborative_exit(request, requester_pk)
        .await
        .unwrap();
    assert_eq!(exit.exit_type, ExitType::Collaborative);
    assert_eq!(exit.status, ExitStatus::Pending);
    assert_eq!(exit.amount, bitcoin::Amount::from_sat(500_000));

    // Retrieve the exit
    let fetched = service.get_exit(exit.id).await.unwrap();
    assert_eq!(fetched.id, exit.id);

    // Complete the exit
    service
        .complete_exit(exit.id, bitcoin::Amount::from_sat(1_000))
        .await
        .unwrap();
    let completed = service.get_exit(exit.id).await.unwrap();
    assert_eq!(completed.status, ExitStatus::Completed);
}

#[tokio::test]
async fn test_collaborative_exit_no_vtxos() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = CollaborativeExitRequest {
        vtxo_ids: vec![VtxoOutpoint::new("nonexistent".to_string(), 0)],
        destination: test_address(),
    };

    let result = service
        .request_collaborative_exit(request, requester_pk)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_collaborative_exit_spent_vtxo() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    let mut vtxo = make_vtxo("spent_tx", 0, "pk_spent", 100_000);
    vtxo.spent = true;
    vtxo_repo.seed_vtxos(vec![vtxo]).await;

    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = CollaborativeExitRequest {
        vtxo_ids: vec![VtxoOutpoint::new("spent_tx".to_string(), 0)],
        destination: test_address(),
    };

    let result = service
        .request_collaborative_exit(request, requester_pk)
        .await;
    assert!(result.is_err());
}

// ─── Unilateral Exit Tests ──────────────────────────────────────────

#[tokio::test]
async fn test_unilateral_exit_flow() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    let vtxo = make_vtxo("uni_tx1", 0, "pk_uni", 300_000);
    vtxo_repo.seed_vtxos(vec![vtxo]).await;

    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = UnilateralExitRequest {
        vtxo_id: VtxoOutpoint::new("uni_tx1".to_string(), 0),
        destination: test_address(),
        fee_rate_sat_vb: 10,
    };

    let exit = service
        .request_unilateral_exit(request, requester_pk)
        .await
        .unwrap();
    assert_eq!(exit.exit_type, ExitType::Unilateral);
    assert_eq!(exit.status, ExitStatus::Pending);
    assert_eq!(exit.amount, bitcoin::Amount::from_sat(300_000));
    // claimable_height = 800_000 (mock block height) + 512 (default delay)
    assert_eq!(exit.claimable_height, Some(800_512));
}

#[tokio::test]
async fn test_unilateral_exit_not_found() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = UnilateralExitRequest {
        vtxo_id: VtxoOutpoint::new("nope".to_string(), 0),
        destination: test_address(),
        fee_rate_sat_vb: 10,
    };

    assert!(service
        .request_unilateral_exit(request, requester_pk)
        .await
        .is_err());
}

// ─── Cancel Exit Tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_cancel_exit() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let vtxo = make_vtxo("cancel_tx", 0, "pk", 100_000);
    vtxo_repo.seed_vtxos(vec![vtxo]).await;

    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = CollaborativeExitRequest {
        vtxo_ids: vec![VtxoOutpoint::new("cancel_tx".to_string(), 0)],
        destination: test_address(),
    };

    let exit = service
        .request_collaborative_exit(request, requester_pk)
        .await
        .unwrap();
    service.cancel_exit(exit.id).await.unwrap();

    let cancelled = service.get_exit(exit.id).await.unwrap();
    assert_eq!(cancelled.status, ExitStatus::Cancelled);
}

#[tokio::test]
async fn test_cancel_nonexistent_exit() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);
    assert!(service.cancel_exit(uuid::Uuid::new_v4()).await.is_err());
}

// ─── Exit Domain Model Tests ────────────────────────────────────────

#[tokio::test]
async fn test_exit_blocks_until_claimable() {
    let mut exit = Exit::unilateral(
        VtxoOutpoint::new("blk_tx".to_string(), 0),
        test_address(),
        test_xonly_pubkey(),
        bitcoin::Amount::from_sat(100_000),
        1000,
    );

    assert_eq!(exit.blocks_until_claimable(900), Some(100));
    assert_eq!(exit.blocks_until_claimable(1000), None);
    assert_eq!(exit.blocks_until_claimable(1100), None);

    exit.mark_processing();
    use bitcoin::hashes::Hash;
    let txid =
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]));
    exit.mark_waiting_timelock(txid);

    assert!(!exit.can_claim(999));
    assert!(exit.can_claim(1000));
}

#[tokio::test]
async fn test_get_pending_collaborative_exits() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    // Seed multiple VTXOs
    for i in 0..3 {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new(format!("pending_tx_{i}"), 0),
            100_000 * (i as u64 + 1),
            "pk".to_string(),
        );
        vtxo_repo.seed_vtxos(vec![vtxo]).await;
    }

    let service = build_service(vtxo_repo);
    let pk = test_xonly_pubkey();

    // Create 3 exits
    for i in 0..3 {
        let request = CollaborativeExitRequest {
            vtxo_ids: vec![VtxoOutpoint::new(format!("pending_tx_{i}"), 0)],
            destination: test_address(),
        };
        service
            .request_collaborative_exit(request, pk)
            .await
            .unwrap();
    }

    let pending = service.get_pending_collaborative_exits().await;
    assert_eq!(pending.len(), 3);
}
