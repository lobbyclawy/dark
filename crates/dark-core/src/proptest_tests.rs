//! Property-based tests for dark-core domain models using proptest.

#[cfg(test)]
mod tests {
    use crate::domain::{
        Intent, Receiver, Round, RoundStage, Stage, TxTreeNode, Vtxo, VtxoOutpoint,
    };
    use proptest::prelude::*;

    // ─── Strategies ─────────────────────────────────────────────────

    fn arb_vtxo_outpoint() -> impl Strategy<Value = VtxoOutpoint> {
        ("[a-f0-9]{64}", 0u32..10).prop_map(|(txid, vout)| VtxoOutpoint::new(txid, vout))
    }

    fn arb_receiver() -> impl Strategy<Value = Receiver> {
        prop_oneof![
            // Off-chain receiver
            (1000u64..10_000_000, "[a-f0-9]{64}")
                .prop_map(|(amount, pk)| Receiver::offchain(amount, pk)),
            // On-chain receiver
            (1000u64..10_000_000, "bc1q[a-z0-9]{38}")
                .prop_map(|(amount, addr)| Receiver::onchain(amount, addr)),
        ]
    }

    fn arb_intent() -> impl Strategy<Value = Intent> {
        ("[a-f0-9]{8}", prop::collection::vec(arb_receiver(), 1..5)).prop_map(|(id, receivers)| {
            Intent {
                id,
                inputs: vec![],
                receivers,
                proof: "proof".to_string(),
                message: "msg".to_string(),
                txid: "txid".to_string(),
                leaf_tx_asset_packet: String::new(),
            }
        })
    }

    fn arb_tx_tree_node() -> impl Strategy<Value = TxTreeNode> {
        (
            "[a-f0-9]{64}",
            "[a-f0-9]{100,200}",
            prop::collection::hash_map(0u32..4, "[a-f0-9]{64}", 0..3),
        )
            .prop_map(|(txid, tx, children)| TxTreeNode { txid, tx, children })
    }

    fn arb_vtxo() -> impl Strategy<Value = Vtxo> {
        (
            arb_vtxo_outpoint(),
            546u64..21_000_000,
            "[a-f0-9]{64}",
            prop::collection::vec("[a-f0-9]{64}", 0..5),
            0i64..2_000_000_000,
        )
            .prop_map(|(outpoint, amount, pubkey, commitments, expires_at)| {
                let mut vtxo = Vtxo::new(outpoint, amount, pubkey);
                vtxo.commitment_txids = commitments.clone();
                vtxo.root_commitment_txid = commitments.first().cloned().unwrap_or_default();
                vtxo.expires_at = expires_at;
                vtxo
            })
    }

    // ─── VTXO Properties ───────────────────────────────────────────

    proptest! {
        #[test]
        fn vtxo_outpoint_roundtrip(txid in "[a-f0-9]{64}", vout in 0u32..100) {
            let op = VtxoOutpoint::new(txid.clone(), vout);
            let display = format!("{op}");
            let parsed = VtxoOutpoint::from_string(&display).unwrap();
            prop_assert_eq!(parsed.txid, txid);
            prop_assert_eq!(parsed.vout, vout);
        }

        #[test]
        fn vtxo_spendable_invariant(vtxo in arb_vtxo()) {
            // A fresh VTXO should always be spendable
            prop_assert!(vtxo.is_spendable());
            prop_assert!(!vtxo.spent);
            prop_assert!(!vtxo.swept);
            prop_assert!(!vtxo.unrolled);
        }

        #[test]
        fn vtxo_is_note_when_no_commitments(
            outpoint in arb_vtxo_outpoint(),
            amount in 546u64..10_000_000,
            pubkey in "[a-f0-9]{64}"
        ) {
            let vtxo = Vtxo::new(outpoint, amount, pubkey);
            // A fresh VTXO with no commitments is a "note"
            prop_assert!(vtxo.is_note());
            // And therefore does not require a forfeit
            prop_assert!(!vtxo.requires_forfeit());
        }

        #[test]
        fn vtxo_requires_forfeit_with_commitments(
            outpoint in arb_vtxo_outpoint(),
            amount in 546u64..10_000_000,
            pubkey in "[a-f0-9]{64}",
            commit in "[a-f0-9]{64}"
        ) {
            let mut vtxo = Vtxo::new(outpoint, amount, pubkey);
            vtxo.commitment_txids = vec![commit.clone()];
            vtxo.root_commitment_txid = commit;
            // With commitments, it's not a note and requires forfeit
            prop_assert!(!vtxo.is_note());
            prop_assert!(vtxo.requires_forfeit());
        }

        #[test]
        fn vtxo_expiry_monotonic(
            outpoint in arb_vtxo_outpoint(),
            expires_at in 1i64..1_000_000_000
        ) {
            let mut vtxo = Vtxo::new(outpoint, 1000, "pk".to_string());
            vtxo.expires_at = expires_at;

            // Not expired before the expiry time
            prop_assert!(!vtxo.is_expired_at(expires_at - 1));
            // Expired at or after the expiry time
            prop_assert!(vtxo.is_expired_at(expires_at));
            prop_assert!(vtxo.is_expired_at(expires_at + 1));
        }
    }

    // ─── Round Serialization Roundtrip ──────────────────────────────

    proptest! {
        #[test]
        fn round_serialization_roundtrip(
            id in "[a-f0-9]{8}",
            timestamp in 1_600_000_000i64..1_800_000_000,
            version in 0u32..100,
            vtxo_exp in 0i64..2_000_000_000
        ) {
            let mut round = Round::new();
            round.id = id.clone();
            round.starting_timestamp = timestamp;
            round.version = version;
            round.vtxo_tree_expiration = vtxo_exp;

            // Serialize to JSON and back
            let json = serde_json::to_string(&round).unwrap();
            let deserialized: Round = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(deserialized.id, id);
            prop_assert_eq!(deserialized.starting_timestamp, timestamp);
            prop_assert_eq!(deserialized.version, version);
            prop_assert_eq!(deserialized.vtxo_tree_expiration, vtxo_exp);
        }

        #[test]
        fn round_with_intents_roundtrip(
            intents in prop::collection::vec(arb_intent(), 1..10)
        ) {
            let mut round = Round::new();
            round.start_registration().unwrap();

            for intent in &intents {
                round.register_intent(intent.clone()).unwrap();
            }

            let json = serde_json::to_string(&round).unwrap();
            let deserialized: Round = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(deserialized.intent_count(), intents.len());
        }

        #[test]
        fn round_with_tree_roundtrip(
            nodes in prop::collection::vec(arb_tx_tree_node(), 0..8)
        ) {
            let mut round = Round::new();
            round.vtxo_tree = nodes.clone();

            let json = serde_json::to_string(&round).unwrap();
            let deserialized: Round = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(deserialized.vtxo_tree.len(), nodes.len());
            for (orig, deser) in nodes.iter().zip(deserialized.vtxo_tree.iter()) {
                prop_assert_eq!(&orig.txid, &deser.txid);
                prop_assert_eq!(&orig.tx, &deser.tx);
                prop_assert_eq!(orig.children.len(), deser.children.len());
            }
        }
    }

    // ─── Amount Conservation ────────────────────────────────────────

    proptest! {
        #[test]
        fn receiver_amounts_conserved(
            amounts in prop::collection::vec(1000u64..10_000_000, 1..20)
        ) {
            let receivers: Vec<Receiver> = amounts.iter()
                .enumerate()
                .map(|(i, &amt)| Receiver::offchain(amt, format!("pk_{i}")))
                .collect();

            let total: u64 = receivers.iter().map(|r| r.amount).sum();
            let expected: u64 = amounts.iter().sum();

            prop_assert_eq!(total, expected);
        }

        #[test]
        fn vtxo_tree_node_children_preserved(
            children in prop::collection::hash_map(0u32..10, "[a-f0-9]{64}", 0..5)
        ) {
            let node = TxTreeNode {
                txid: "test_txid".to_string(),
                tx: "test_tx".to_string(),
                children: children.clone(),
            };

            let json = serde_json::to_string(&node).unwrap();
            let deserialized: TxTreeNode = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(deserialized.children.len(), children.len());
            for (k, v) in &children {
                prop_assert_eq!(deserialized.children.get(k).unwrap(), v);
            }
        }
    }

    // ─── Stage Invariants ───────────────────────────────────────────

    proptest! {
        #[test]
        fn stage_terminal_states(ended in any::<bool>(), failed in any::<bool>()) {
            let stage = Stage {
                code: RoundStage::Registration,
                ended,
                failed,
            };

            if ended || failed {
                prop_assert!(stage.is_terminal());
            } else {
                prop_assert!(!stage.is_terminal());
            }
        }
    }
}
