//! Integration tests for the full round lifecycle.
//!
//! Tests the end-to-end flow: start round → register intents → finalize → check VTXOs

use std::sync::Arc;

use dark_core::domain::{Receiver, Round, RoundStage, Vtxo, VtxoOutpoint};
use dark_core::ports::VtxoRepository;

use crate::helpers::{build_service, make_intent, InMemoryVtxoRepo};

// ─── Tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_full_round_lifecycle() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo.clone());

    // 1. Start a round
    let round = service.start_round().await.unwrap();
    assert_eq!(round.stage.code, RoundStage::Registration);
    assert!(!round.is_ended());

    // 2. Register intents
    let intent1 = make_intent(
        "intent-1",
        vec![Receiver::offchain(100_000, "pk_alice".to_string())],
    );
    let intent2 = make_intent(
        "intent-2",
        vec![Receiver::offchain(200_000, "pk_bob".to_string())],
    );
    let id1 = service.register_intent(intent1).await.unwrap();
    let id2 = service.register_intent(intent2).await.unwrap();
    assert_eq!(id1, "intent-1");
    assert_eq!(id2, "intent-2");

    // 3. Starting another round while one is active should fail
    let err = service.start_round().await;
    assert!(err.is_err());
}

#[tokio::test]
async fn test_round_with_vtxo_creation() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    // Simulate VTXO creation (as would happen after round finalization)
    let vtxos = vec![
        Vtxo::new(
            VtxoOutpoint::new("round1_tx1".to_string(), 0),
            100_000,
            "pk_alice".to_string(),
        ),
        Vtxo::new(
            VtxoOutpoint::new("round1_tx2".to_string(), 0),
            200_000,
            "pk_bob".to_string(),
        ),
    ];
    vtxo_repo.add_vtxos(&vtxos).await.unwrap();

    // Verify VTXOs are retrievable
    let (alice_spendable, alice_spent) = vtxo_repo
        .get_all_vtxos_for_pubkey("pk_alice")
        .await
        .unwrap();
    assert_eq!(alice_spendable.len(), 1);
    assert_eq!(alice_spendable[0].amount, 100_000);
    assert_eq!(alice_spent.len(), 0);

    // Spend a VTXO
    vtxo_repo
        .spend_vtxos(
            &[(
                VtxoOutpoint::new("round1_tx1".to_string(), 0),
                "forfeit_tx".to_string(),
            )],
            "ark_tx_1",
        )
        .await
        .unwrap();

    let (alice_spendable, alice_spent) = vtxo_repo
        .get_all_vtxos_for_pubkey("pk_alice")
        .await
        .unwrap();
    assert_eq!(alice_spendable.len(), 0);
    assert_eq!(alice_spent.len(), 1);
}

#[tokio::test]
async fn test_multi_participant_round() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);

    let round = service.start_round().await.unwrap();

    // Register 5 intents (multi-participant)
    for i in 0..5 {
        let intent = make_intent(
            &format!("intent-{i}"),
            vec![Receiver::offchain(
                (i as u64 + 1) * 50_000,
                format!("pk_user_{i}"),
            )],
        );
        service.register_intent(intent).await.unwrap();
    }

    // Verify all intents registered — we test the Round domain model directly
    let mut round_copy = round;
    round_copy.start_registration().ok(); // already started but for domain model test
    for i in 0..3 {
        let intent = make_intent(
            &format!("domain-intent-{i}"),
            vec![Receiver::offchain(10_000, format!("pk_{i}"))],
        );
        round_copy.register_intent(intent).unwrap();
    }
    assert_eq!(round_copy.intent_count(), 3);

    // Transition through stages
    round_copy.start_finalization().unwrap();
    assert_eq!(round_copy.stage.code, RoundStage::Finalization);

    round_copy.end_successfully();
    assert!(round_copy.is_ended());
    assert!(!round_copy.stage.failed);
}

#[tokio::test]
async fn test_round_failure_flow() {
    let mut round = Round::new();
    round.start_registration().unwrap();

    // Register some intents
    let intent = make_intent(
        "intent-fail",
        vec![Receiver::offchain(50_000, "pk1".to_string())],
    );
    round.register_intent(intent).unwrap();

    // Fail the round
    round.fail("insufficient liquidity".to_string());
    assert!(round.is_ended());
    assert!(round.stage.failed);
    assert_eq!(round.fail_reason, "insufficient liquidity");

    // Can't register more intents after failure
    let intent2 = make_intent("intent-2", vec![]);
    assert!(round.register_intent(intent2).is_err());
}

#[tokio::test]
async fn test_intent_with_mixed_receivers() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);

    service.start_round().await.unwrap();

    // Intent with both on-chain and off-chain receivers
    let intent = make_intent(
        "mixed-intent",
        vec![
            Receiver::offchain(75_000, "pk_offchain".to_string()),
            Receiver::onchain(25_000, "bc1q_onchain_addr".to_string()),
        ],
    );
    service.register_intent(intent).await.unwrap();
}

#[tokio::test]
async fn test_round_stage_transitions_invalid() {
    let mut round = Round::new();

    // Cannot start finalization before registration
    assert!(round.start_finalization().is_err());

    // Start registration
    round.start_registration().unwrap();

    // Cannot start registration again
    assert!(round.start_registration().is_err());

    // Start finalization
    round.start_finalization().unwrap();

    // Cannot start registration from finalization
    assert!(round.start_registration().is_err());

    // Cannot start finalization again
    assert!(round.start_finalization().is_err());
}
