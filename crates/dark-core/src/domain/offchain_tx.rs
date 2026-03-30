//! Offchain transaction domain model
//!
//! An offchain transaction allows spending VTXOs peer-to-peer without waiting
//! for a round. This is the core building block for instant transfers.
//!
//! Lifecycle: Requested → Accepted → Finalized (or Rejected at any point)

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Error type for offchain transaction state transitions
#[derive(Debug, thiserror::Error)]
pub enum OffchainTxError {
    /// Invalid state transition
    #[error("Invalid state transition: cannot move from {from} to {to}")]
    InvalidTransition {
        /// Current stage
        from: String,
        /// Attempted stage
        to: String,
    },
    /// Validation error
    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// An offchain transaction allows spending VTXOs without waiting for a round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffchainTx {
    /// Unique transaction identifier
    pub id: String,
    /// VTXO inputs being spent
    pub inputs: Vec<VtxoInput>,
    /// Outputs created by this transaction
    pub outputs: Vec<VtxoOutput>,
    /// Current lifecycle stage
    pub stage: OffchainTxStage,
    /// Creation timestamp (unix seconds)
    pub created_at: u64,
    /// Last update timestamp (unix seconds)
    pub updated_at: u64,
    /// Cosigned ark tx PSBT (base64), stored at SubmitTx time
    #[serde(default)]
    pub signed_ark_tx: String,
    /// Final checkpoint tx PSBTs (base64), stored at FinalizeTx time
    #[serde(default)]
    pub checkpoint_txs: Vec<String>,
}

/// Lifecycle stage of an offchain transaction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OffchainTxStage {
    /// Transaction has been submitted and is awaiting processing
    Requested,
    /// Transaction has been accepted by the server
    Accepted {
        /// Timestamp when accepted
        accepted_at: u64,
    },
    /// Transaction has been finalized on-chain
    Finalized {
        /// On-chain transaction ID
        txid: String,
        /// Timestamp when finalized
        finalized_at: u64,
    },
    /// Transaction was rejected
    Rejected {
        /// Reason for rejection
        reason: String,
    },
}

/// A VTXO input being spent in an offchain transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoInput {
    /// The VTXO outpoint ID being spent
    pub vtxo_id: String,
    /// The signed spending transaction
    pub signed_tx: Vec<u8>,
}

/// An output created by an offchain transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoOutput {
    /// Destination public key or address
    pub pubkey: String,
    /// Output amount in satoshis
    pub amount_sats: u64,
}

impl OffchainTx {
    /// Create a new offchain transaction in the Requested stage.
    pub fn new(inputs: Vec<VtxoInput>, outputs: Vec<VtxoOutput>) -> Self {
        Self::new_with_id(Uuid::new_v4().to_string(), inputs, outputs)
    }

    /// Create with a specific ID (e.g. the ark_txid from SubmitTx).
    pub fn new_with_id(id: String, inputs: Vec<VtxoInput>, outputs: Vec<VtxoOutput>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            id,
            inputs,
            outputs,
            stage: OffchainTxStage::Requested,
            created_at: now,
            updated_at: now,
            signed_ark_tx: String::new(),
            checkpoint_txs: Vec::new(),
        }
    }

    /// Transition from Requested to Accepted.
    pub fn accept(&mut self) -> Result<(), OffchainTxError> {
        match &self.stage {
            OffchainTxStage::Requested => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                self.stage = OffchainTxStage::Accepted { accepted_at: now };
                self.updated_at = now;
                Ok(())
            }
            other => Err(OffchainTxError::InvalidTransition {
                from: stage_name(other),
                to: "Accepted".to_string(),
            }),
        }
    }

    /// Transition from Requested or Accepted to Finalized with the given txid.
    pub fn finalize(&mut self, txid: String) -> Result<(), OffchainTxError> {
        match &self.stage {
            OffchainTxStage::Requested | OffchainTxStage::Accepted { .. } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                self.stage = OffchainTxStage::Finalized {
                    txid,
                    finalized_at: now,
                };
                self.updated_at = now;
                Ok(())
            }
            other => Err(OffchainTxError::InvalidTransition {
                from: stage_name(other),
                to: "Finalized".to_string(),
            }),
        }
    }

    /// Reject the transaction with a reason. Cannot reject if already finalized or rejected.
    pub fn reject(&mut self, reason: String) -> Result<(), OffchainTxError> {
        match &self.stage {
            OffchainTxStage::Finalized { .. } | OffchainTxStage::Rejected { .. } => {
                Err(OffchainTxError::InvalidTransition {
                    from: stage_name(&self.stage),
                    to: "Rejected".to_string(),
                })
            }
            _ => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                self.stage = OffchainTxStage::Rejected { reason };
                self.updated_at = now;
                Ok(())
            }
        }
    }

    /// Returns true if the transaction is in the Finalized stage.
    pub fn is_finalized(&self) -> bool {
        matches!(self.stage, OffchainTxStage::Finalized { .. })
    }

    /// Returns the VTXO IDs from all inputs.
    pub fn input_vtxo_ids(&self) -> Vec<String> {
        self.inputs.iter().map(|i| i.vtxo_id.clone()).collect()
    }
}

fn stage_name(stage: &OffchainTxStage) -> String {
    match stage {
        OffchainTxStage::Requested => "Requested".to_string(),
        OffchainTxStage::Accepted { .. } => "Accepted".to_string(),
        OffchainTxStage::Finalized { .. } => "Finalized".to_string(),
        OffchainTxStage::Rejected { .. } => "Rejected".to_string(),
    }
}

impl std::fmt::Display for OffchainTxStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", stage_name(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_tx() -> OffchainTx {
        OffchainTx::new(
            vec![VtxoInput {
                vtxo_id: "abc123:0".to_string(),
                signed_tx: vec![1, 2, 3],
            }],
            vec![VtxoOutput {
                pubkey: "02deadbeef".to_string(),
                amount_sats: 10_000,
            }],
        )
    }

    #[test]
    fn test_new_offchain_tx() {
        let tx = make_test_tx();
        assert!(!tx.id.is_empty());
        assert_eq!(tx.stage, OffchainTxStage::Requested);
        assert!(!tx.is_finalized());
    }

    #[test]
    fn test_accept() {
        let mut tx = make_test_tx();
        assert!(tx.accept().is_ok());
        assert!(matches!(tx.stage, OffchainTxStage::Accepted { .. }));
    }

    #[test]
    fn test_finalize_from_requested() {
        let mut tx = make_test_tx();
        assert!(tx.finalize("txid123".to_string()).is_ok());
        assert!(tx.is_finalized());
    }

    #[test]
    fn test_finalize_from_accepted() {
        let mut tx = make_test_tx();
        tx.accept().unwrap();
        assert!(tx.finalize("txid123".to_string()).is_ok());
        assert!(tx.is_finalized());
    }

    #[test]
    fn test_reject() {
        let mut tx = make_test_tx();
        assert!(tx.reject("invalid".to_string()).is_ok());
        assert!(matches!(tx.stage, OffchainTxStage::Rejected { .. }));
    }

    #[test]
    fn test_cannot_accept_after_finalize() {
        let mut tx = make_test_tx();
        tx.finalize("txid123".to_string()).unwrap();
        assert!(tx.accept().is_err());
    }

    #[test]
    fn test_cannot_reject_after_finalize() {
        let mut tx = make_test_tx();
        tx.finalize("txid123".to_string()).unwrap();
        assert!(tx.reject("reason".to_string()).is_err());
    }

    #[test]
    fn test_cannot_finalize_after_reject() {
        let mut tx = make_test_tx();
        tx.reject("bad".to_string()).unwrap();
        assert!(tx.finalize("txid".to_string()).is_err());
    }

    #[test]
    fn test_input_vtxo_ids() {
        let tx = make_test_tx();
        assert_eq!(tx.input_vtxo_ids(), vec!["abc123:0"]);
    }

    #[test]
    fn test_stage_display() {
        assert_eq!(OffchainTxStage::Requested.to_string(), "Requested");
    }
}
