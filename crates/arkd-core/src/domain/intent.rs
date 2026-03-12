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

    #[test]
    fn test_intent_creation() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx1".to_string(), 0),
            50_000,
            "pub".to_string(),
        );
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
}
