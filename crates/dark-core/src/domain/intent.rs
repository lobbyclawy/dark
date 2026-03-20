//! Intent domain model — replaces the previous "Participant" model
//!
//! See Go: `github.com/ark-network/ark/internal/core/domain/intent.go`

use super::vtxo::{Receiver, Vtxo};
use serde::{Deserialize, Serialize};

/// An Intent to participate in a round (matches Go's `domain.Intent`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    /// Unique identifier
    pub id: String,
    /// Input VTXOs being spent
    pub inputs: Vec<Vtxo>,
    /// Output receivers
    pub receivers: Vec<Receiver>,
    /// Authorization proof
    pub proof: String,
    /// Authorization message
    pub message: String,
    /// Transaction ID for the proof
    pub txid: String,
    /// Asset packet for the leaf transaction
    pub leaf_tx_asset_packet: String,
}

impl Intent {
    /// Create a new intent
    pub fn new(
        proof_txid: String,
        proof: String,
        message: String,
        inputs: Vec<Vtxo>,
    ) -> Result<Self, String> {
        let intent = Self {
            id: uuid::Uuid::new_v4().to_string(),
            inputs,
            receivers: Vec::new(),
            proof,
            message,
            txid: proof_txid,
            leaf_tx_asset_packet: String::new(),
        };
        intent.validate(true)?;
        Ok(intent)
    }

    /// Add receivers
    pub fn add_receivers(&mut self, receivers: Vec<Receiver>) -> Result<(), String> {
        let count = receivers.len();
        self.receivers.extend(receivers);
        if let Err(e) = self.validate(false) {
            self.receivers
                .truncate(self.receivers.len().saturating_sub(count));
            return Err(e);
        }
        Ok(())
    }

    /// Total input amount
    pub fn total_input_amount(&self) -> u64 {
        self.inputs.iter().map(|v| v.amount).sum()
    }

    /// Total output amount
    pub fn total_output_amount(&self) -> u64 {
        self.receivers.iter().map(|r| r.amount).sum()
    }

    /// Check if all outputs are on-chain
    pub fn has_only_onchain_outputs(&self) -> bool {
        self.receivers.iter().all(|r| r.is_onchain())
    }

    fn validate(&self, ignore_outputs: bool) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("Missing id".to_string());
        }
        if self.proof.is_empty() {
            return Err("Missing proof".to_string());
        }
        if self.message.is_empty() {
            return Err("Missing message".to_string());
        }
        if self.txid.is_empty() {
            return Err("Missing txid".to_string());
        }
        if ignore_outputs {
            return Ok(());
        }
        if self.receivers.is_empty() {
            return Err("Missing outputs".to_string());
        }
        for r in &self.receivers {
            if r.onchain_address.is_empty() && r.pubkey.is_empty() {
                return Err("Missing receiver destination".to_string());
            }
            if r.amount == 0 {
                return Err("Missing receiver amount".to_string());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vtxo::VtxoOutpoint;

    fn make_vtxo(amount: u64) -> Vtxo {
        Vtxo::new(
            VtxoOutpoint::new("tx1".to_string(), 0),
            amount,
            "pub".to_string(),
        )
    }

    #[test]
    fn test_intent_creation() {
        let vtxo = make_vtxo(50_000);
        let intent = Intent::new(
            "txid".to_string(),
            "proof".to_string(),
            "msg".to_string(),
            vec![vtxo],
        )
        .unwrap();
        assert_eq!(intent.total_input_amount(), 50_000);
    }

    #[test]
    fn test_intent_validation() {
        assert!(Intent::new(String::new(), "p".to_string(), "m".to_string(), vec![]).is_err());
    }

    #[test]
    fn test_intent_missing_proof() {
        assert!(Intent::new("txid".to_string(), String::new(), "msg".to_string(), vec![]).is_err());
    }

    #[test]
    fn test_intent_missing_message() {
        assert!(Intent::new(
            "txid".to_string(),
            "proof".to_string(),
            String::new(),
            vec![]
        )
        .is_err());
    }

    #[test]
    fn test_intent_add_receivers() {
        let vtxo = make_vtxo(100_000);
        let mut intent = Intent::new(
            "txid".to_string(),
            "proof".to_string(),
            "msg".to_string(),
            vec![vtxo],
        )
        .unwrap();

        let receivers = vec![
            Receiver::offchain(50_000, "pk1".to_string()),
            Receiver::offchain(30_000, "pk2".to_string()),
        ];
        intent.add_receivers(receivers).unwrap();
        assert_eq!(intent.total_output_amount(), 80_000);
        assert_eq!(intent.receivers.len(), 2);
    }

    #[test]
    fn test_intent_add_invalid_receivers_rollback() {
        let vtxo = make_vtxo(100_000);
        let mut intent = Intent::new(
            "txid".to_string(),
            "proof".to_string(),
            "msg".to_string(),
            vec![vtxo],
        )
        .unwrap();

        // Receiver with no destination should fail
        let bad_receivers = vec![Receiver {
            amount: 1000,
            onchain_address: String::new(),
            pubkey: String::new(),
        }];
        assert!(intent.add_receivers(bad_receivers).is_err());
        // Should have rolled back
        assert_eq!(intent.receivers.len(), 0);
    }

    #[test]
    fn test_intent_add_zero_amount_receiver() {
        let vtxo = make_vtxo(100_000);
        let mut intent = Intent::new(
            "txid".to_string(),
            "proof".to_string(),
            "msg".to_string(),
            vec![vtxo],
        )
        .unwrap();

        let bad = vec![Receiver::offchain(0, "pk".to_string())];
        assert!(intent.add_receivers(bad).is_err());
    }

    #[test]
    fn test_intent_has_only_onchain_outputs() {
        let vtxo = make_vtxo(100_000);
        let mut intent = Intent::new(
            "txid".to_string(),
            "proof".to_string(),
            "msg".to_string(),
            vec![vtxo],
        )
        .unwrap();

        // No receivers = vacuously true
        assert!(intent.has_only_onchain_outputs());

        // Add on-chain
        intent
            .add_receivers(vec![Receiver::onchain(50_000, "bc1q_addr".to_string())])
            .unwrap();
        assert!(intent.has_only_onchain_outputs());

        // Add off-chain → not all on-chain
        intent
            .add_receivers(vec![Receiver::offchain(25_000, "pk".to_string())])
            .unwrap();
        assert!(!intent.has_only_onchain_outputs());
    }

    #[test]
    fn test_intent_total_with_multiple_inputs() {
        let vtxo1 = make_vtxo(100_000);
        let vtxo2 = Vtxo::new(
            VtxoOutpoint::new("tx2".to_string(), 0),
            200_000,
            "pub".to_string(),
        );

        let intent = Intent::new(
            "txid".to_string(),
            "proof".to_string(),
            "msg".to_string(),
            vec![vtxo1, vtxo2],
        )
        .unwrap();
        assert_eq!(intent.total_input_amount(), 300_000);
    }

    #[test]
    fn test_intent_serialization_roundtrip() {
        let vtxo = make_vtxo(75_000);
        let mut intent = Intent::new(
            "txid".to_string(),
            "proof".to_string(),
            "msg".to_string(),
            vec![vtxo],
        )
        .unwrap();
        intent
            .add_receivers(vec![Receiver::offchain(50_000, "pk".to_string())])
            .unwrap();

        let json = serde_json::to_string(&intent).unwrap();
        let deserialized: Intent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, intent.id);
        assert_eq!(deserialized.total_input_amount(), 75_000);
        assert_eq!(deserialized.total_output_amount(), 50_000);
    }
}

#[cfg(test)]
mod proptest_intent {
    use super::*;
    use crate::domain::vtxo::VtxoOutpoint;
    use proptest::prelude::*;

    /// Strategy for generating valid VTXOs
    fn vtxo_strategy() -> impl Strategy<Value = Vtxo> {
        (
            "[a-f0-9]{64}",                   // txid (64 hex chars)
            0u32..100,                        // vout
            1u64..=21_000_000_000_000_000u64, // amount (1 sat to 21M BTC)
            "[a-f0-9]{64}",                   // pubkey (64 hex chars)
        )
            .prop_map(|(txid, vout, amount, pubkey)| {
                Vtxo::new(VtxoOutpoint::new(txid, vout), amount, pubkey)
            })
    }

    /// Strategy for generating valid offchain receivers
    fn receiver_offchain_strategy() -> impl Strategy<Value = Receiver> {
        (
            1u64..=21_000_000_000_000_000u64, // amount
            "[a-f0-9]{64}",                   // pubkey
        )
            .prop_map(|(amount, pubkey)| Receiver::offchain(amount, pubkey))
    }

    /// Strategy for generating valid onchain receivers
    fn receiver_onchain_strategy() -> impl Strategy<Value = Receiver> {
        (
            1u64..=21_000_000_000_000_000u64, // amount
            "bc1q[a-z0-9]{8,40}",             // address
        )
            .prop_map(|(amount, addr)| Receiver::onchain(amount, addr))
    }

    /// Strategy for generating valid receivers (either on-chain or off-chain)
    fn receiver_strategy() -> impl Strategy<Value = Receiver> {
        prop_oneof![receiver_offchain_strategy(), receiver_onchain_strategy(),]
    }

    /// Strategy for generating valid Intents
    fn intent_strategy() -> impl Strategy<Value = Intent> {
        (
            proptest::collection::vec(vtxo_strategy(), 0..5), // inputs
            proptest::collection::vec(receiver_strategy(), 1..10), // receivers (at least 1)
            "[a-zA-Z0-9_-]{1,32}",                            // proof
            "[a-zA-Z0-9_-]{1,32}",                            // message
            "[a-f0-9]{64}",                                   // txid
            proptest::option::of("[a-zA-Z0-9+/=]{0,100}"),    // leaf_tx_asset_packet
        )
            .prop_map(
                |(inputs, receivers, proof, message, txid, leaf_pkt)| Intent {
                    id: uuid::Uuid::new_v4().to_string(),
                    inputs,
                    receivers,
                    proof,
                    message,
                    txid,
                    leaf_tx_asset_packet: leaf_pkt.unwrap_or_default(),
                },
            )
    }

    proptest! {
        /// Property test: Intent serialization roundtrip preserves total_input_amount()
        #[test]
        fn intent_roundtrip_preserves_input_amount(intent in intent_strategy()) {
            let original_input = intent.total_input_amount();
            let json = serde_json::to_string(&intent).expect("serialization should succeed");
            let deserialized: Intent = serde_json::from_str(&json).expect("deserialization should succeed");
            prop_assert_eq!(deserialized.total_input_amount(), original_input);
        }

        /// Property test: Intent serialization roundtrip preserves total_output_amount()
        #[test]
        fn intent_roundtrip_preserves_output_amount(intent in intent_strategy()) {
            let original_output = intent.total_output_amount();
            let json = serde_json::to_string(&intent).expect("serialization should succeed");
            let deserialized: Intent = serde_json::from_str(&json).expect("deserialization should succeed");
            prop_assert_eq!(deserialized.total_output_amount(), original_output);
        }

        /// Property test: Intent serialization roundtrip preserves all fields
        #[test]
        fn intent_roundtrip_preserves_all_fields(intent in intent_strategy()) {
            let json = serde_json::to_string(&intent).expect("serialization should succeed");
            let deserialized: Intent = serde_json::from_str(&json).expect("deserialization should succeed");

            prop_assert_eq!(deserialized.id, intent.id);
            prop_assert_eq!(deserialized.proof, intent.proof);
            prop_assert_eq!(deserialized.message, intent.message);
            prop_assert_eq!(deserialized.txid, intent.txid);
            prop_assert_eq!(deserialized.leaf_tx_asset_packet, intent.leaf_tx_asset_packet);
            prop_assert_eq!(deserialized.inputs.len(), intent.inputs.len());
            prop_assert_eq!(deserialized.receivers.len(), intent.receivers.len());
        }

        /// Property test: has_only_onchain_outputs is preserved through serialization
        #[test]
        fn intent_roundtrip_preserves_has_only_onchain(intent in intent_strategy()) {
            let original = intent.has_only_onchain_outputs();
            let json = serde_json::to_string(&intent).expect("serialization should succeed");
            let deserialized: Intent = serde_json::from_str(&json).expect("deserialization should succeed");
            prop_assert_eq!(deserialized.has_only_onchain_outputs(), original);
        }

        /// Property test: Receiver amounts sum correctly after roundtrip
        #[test]
        fn receiver_amounts_sum_correctly(
            receivers in proptest::collection::vec(receiver_strategy(), 1..20)
        ) {
            let total: u64 = receivers.iter().map(|r| r.amount).sum();

            let intent = Intent {
                id: "test".to_string(),
                inputs: vec![],
                receivers,
                proof: "proof".to_string(),
                message: "msg".to_string(),
                txid: "txid".to_string(),
                leaf_tx_asset_packet: String::new(),
            };

            let json = serde_json::to_string(&intent).expect("serialization should succeed");
            let deserialized: Intent = serde_json::from_str(&json).expect("deserialization should succeed");
            prop_assert_eq!(deserialized.total_output_amount(), total);
        }

        /// Property test: VTXO amounts sum correctly after roundtrip
        #[test]
        fn vtxo_amounts_sum_correctly(
            vtxos in proptest::collection::vec(vtxo_strategy(), 1..20)
        ) {
            let total: u64 = vtxos.iter().map(|v| v.amount).sum();

            let intent = Intent {
                id: "test".to_string(),
                inputs: vtxos,
                receivers: vec![Receiver::offchain(1000, "pk".to_string())],
                proof: "proof".to_string(),
                message: "msg".to_string(),
                txid: "txid".to_string(),
                leaf_tx_asset_packet: String::new(),
            };

            let json = serde_json::to_string(&intent).expect("serialization should succeed");
            let deserialized: Intent = serde_json::from_str(&json).expect("deserialization should succeed");
            prop_assert_eq!(deserialized.total_input_amount(), total);
        }
    }
}
