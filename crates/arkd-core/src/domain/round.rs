//! Round domain model — aligned with Go arkd
//!
//! See Go: `github.com/ark-network/ark/internal/core/domain/round.go`

use super::intent::Intent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Round stage (matches Go's `RoundStage`)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RoundStage {
    /// Undefined (initial state)
    #[default]
    Undefined,
    /// Registration stage
    Registration,
    /// Finalization stage
    Finalization,
}

impl std::fmt::Display for RoundStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundStage::Undefined => write!(f, "UNDEFINED_STAGE"),
            RoundStage::Registration => write!(f, "REGISTRATION_STAGE"),
            RoundStage::Finalization => write!(f, "FINALIZATION_STAGE"),
        }
    }
}

/// Stage state (matches Go's `Stage`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Stage {
    /// Stage code
    pub code: RoundStage,
    /// Whether ended
    pub ended: bool,
    /// Whether failed
    pub failed: bool,
}

impl Stage {
    /// Check if terminal
    pub fn is_terminal(&self) -> bool {
        self.ended || self.failed
    }
}

/// A forfeit transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForfeitTx {
    /// Transaction ID
    pub txid: String,
    /// Serialized transaction
    pub tx: String,
}

/// A node in a flattened transaction tree (NOT a Merkle hash tree)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxTreeNode {
    /// Transaction ID
    pub txid: String,
    /// Base64-encoded PSBT transaction
    pub tx: String,
    /// Maps output index -> child txid
    pub children: HashMap<u32, String>,
}

/// Flattened transaction tree
pub type FlatTxTree = Vec<TxTreeNode>;

/// A Round (matches Go's `domain.Round`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round {
    /// Unique round identifier
    pub id: String,
    /// Unix timestamp when started
    pub starting_timestamp: i64,
    /// Unix timestamp when ended
    pub ending_timestamp: i64,
    /// Current stage
    pub stage: Stage,
    /// Registered intents (id -> Intent)
    pub intents: HashMap<String, Intent>,
    /// Commitment transaction ID
    pub commitment_txid: String,
    /// Commitment transaction (serialized)
    pub commitment_tx: String,
    /// Forfeit transactions
    pub forfeit_txs: Vec<ForfeitTx>,
    /// VTXO transaction tree
    pub vtxo_tree: FlatTxTree,
    /// Connector transaction tree
    pub connectors: FlatTxTree,
    /// Connector address
    pub connector_address: String,
    /// Round version
    pub version: u32,
    /// Whether swept
    pub swept: bool,
    /// VTXO tree expiration (unix timestamp)
    pub vtxo_tree_expiration: i64,
    /// Sweep transactions
    pub sweep_txs: HashMap<String, String>,
    /// Failure reason
    pub fail_reason: String,
}

impl Round {
    /// Create a new round
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            starting_timestamp: 0,
            ending_timestamp: 0,
            stage: Stage::default(),
            intents: HashMap::new(),
            commitment_txid: String::new(),
            commitment_tx: String::new(),
            forfeit_txs: Vec::new(),
            vtxo_tree: Vec::new(),
            connectors: Vec::new(),
            connector_address: String::new(),
            version: 0,
            swept: false,
            vtxo_tree_expiration: 0,
            sweep_txs: HashMap::new(),
            fail_reason: String::new(),
        }
    }

    /// Start registration
    pub fn start_registration(&mut self) -> Result<(), String> {
        if self.stage != Stage::default() {
            return Err("Invalid stage for registration".to_string());
        }
        self.stage = Stage {
            code: RoundStage::Registration,
            ended: false,
            failed: false,
        };
        self.starting_timestamp = chrono::Utc::now().timestamp();
        Ok(())
    }

    /// Start finalization
    pub fn start_finalization(&mut self) -> Result<(), String> {
        if self.stage.code != RoundStage::Registration || self.stage.ended || self.stage.failed {
            return Err("Not in registration stage".to_string());
        }
        self.stage = Stage {
            code: RoundStage::Finalization,
            ended: false,
            failed: false,
        };
        Ok(())
    }

    /// End successfully
    pub fn end_successfully(&mut self) {
        self.stage.ended = true;
        self.ending_timestamp = chrono::Utc::now().timestamp();
    }

    /// Fail the round
    pub fn fail(&mut self, reason: String) {
        self.stage.failed = true;
        self.fail_reason = reason;
        self.ending_timestamp = chrono::Utc::now().timestamp();
    }

    /// Register an intent
    pub fn register_intent(&mut self, intent: Intent) -> Result<(), String> {
        if self.stage.code != RoundStage::Registration {
            return Err("Not in registration stage".to_string());
        }
        if self.stage.ended || self.stage.failed {
            return Err("Stage has ended or failed".to_string());
        }
        self.intents.insert(intent.id.clone(), intent);
        Ok(())
    }

    /// Check if ended
    pub fn is_ended(&self) -> bool {
        self.stage.is_terminal()
    }

    /// Intent count
    pub fn intent_count(&self) -> usize {
        self.intents.len()
    }
}

impl Default for Round {
    fn default() -> Self {
        Self::new()
    }
}

/// Round configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundConfig {
    /// Min intents
    pub min_intents: u32,
    /// Max intents
    pub max_intents: u32,
    /// Session duration (seconds)
    pub session_duration_secs: u64,
    /// VTXO tree expiry (seconds)
    pub vtxo_tree_expiry_secs: i64,
    /// Unilateral exit delay
    pub unilateral_exit_delay: u32,
}

impl Default for RoundConfig {
    fn default() -> Self {
        Self {
            min_intents: 1,
            max_intents: 128,
            session_duration_secs: 10,
            vtxo_tree_expiry_secs: 604_800,
            unilateral_exit_delay: 512,
        }
    }
}

/// Round statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundStats {
    /// Whether swept
    pub swept: bool,
    /// Total forfeit amount
    pub total_forfeit_amount: u64,
    /// Total input VTXOs
    pub total_input_vtxos: i32,
    /// Total batch amount
    pub total_batch_amount: u64,
    /// Total output VTXOs
    pub total_output_vtxos: i32,
    /// Expiration
    pub expires_at: i64,
    /// Started
    pub started: i64,
    /// Ended
    pub ended: i64,
}

/// Legacy alias
pub type RoundStatus = RoundStage;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_lifecycle() {
        let mut round = Round::new();
        round.start_registration().unwrap();
        round.start_finalization().unwrap();
        round.end_successfully();
        assert!(round.is_ended());
    }

    #[test]
    fn test_round_failure() {
        let mut round = Round::new();
        round.start_registration().unwrap();
        round.fail("test".to_string());
        assert!(round.is_ended());
    }
}
