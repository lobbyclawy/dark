//! Round domain model — aligned with Go dark
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

/// Confirmation status for an intent in a round
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfirmationStatus {
    /// Awaiting confirmation from the participant
    #[default]
    Pending,
    /// Participant has confirmed
    Confirmed {
        /// Unix timestamp when confirmation was received
        confirmed_at: u64,
    },
    /// Participant did not confirm within the timeout
    TimedOut,
}

/// Errors specific to the round confirmation phase
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundError {
    /// The round is not in a stage that accepts confirmations
    InvalidStage,
    /// The given intent ID was not found in this round
    IntentNotFound(String),
    /// The intent has already been confirmed
    AlreadyConfirmed(String),
    /// The intent has already timed out
    AlreadyTimedOut(String),
}

impl std::fmt::Display for RoundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundError::InvalidStage => write!(f, "Round is not in confirmation stage"),
            RoundError::IntentNotFound(id) => write!(f, "Intent not found: {id}"),
            RoundError::AlreadyConfirmed(id) => write!(f, "Intent already confirmed: {id}"),
            RoundError::AlreadyTimedOut(id) => write!(f, "Intent already timed out: {id}"),
        }
    }
}

impl std::error::Error for RoundError {}

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
    /// Confirmation status per intent (intent_id -> status)
    pub confirmation_status: HashMap<String, ConfirmationStatus>,
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
            confirmation_status: HashMap::new(),
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

    /// Begin the confirmation phase: sets all current intents to Pending.
    ///
    /// Must be called after registration ends and before finalization begins.
    /// Typically called when the round transitions out of registration.
    /// # Note
    /// The caller MUST schedule a timeout to call [`Self::drop_unconfirmed`]
    /// after `confirmation_timeout_secs` have elapsed. This domain method does
    /// not enforce the timeout itself.
    pub fn start_confirmation(&mut self) {
        for intent_id in self.intents.keys() {
            self.confirmation_status
                .entry(intent_id.clone())
                .or_insert(ConfirmationStatus::Pending);
        }
    }

    /// Mark an intent as confirmed by the participant.
    ///
    /// The round must be in the Finalization stage (confirmation happens
    /// between registration close and tree construction).
    pub fn confirm_intent(&mut self, intent_id: &str) -> Result<(), RoundError> {
        if self.stage.code != RoundStage::Finalization {
            return Err(RoundError::InvalidStage);
        }

        if !self.intents.contains_key(intent_id) {
            return Err(RoundError::IntentNotFound(intent_id.to_string()));
        }

        match self.confirmation_status.get(intent_id) {
            Some(ConfirmationStatus::Confirmed { .. }) => {
                return Err(RoundError::AlreadyConfirmed(intent_id.to_string()));
            }
            Some(ConfirmationStatus::TimedOut) => {
                return Err(RoundError::AlreadyTimedOut(intent_id.to_string()));
            }
            _ => {}
        }

        let now = chrono::Utc::now().timestamp() as u64;
        self.confirmation_status.insert(
            intent_id.to_string(),
            ConfirmationStatus::Confirmed { confirmed_at: now },
        );
        Ok(())
    }

    /// Returns intent IDs that have NOT confirmed yet (status is Pending).
    pub fn pending_confirmations(&self) -> Vec<&str> {
        self.confirmation_status
            .iter()
            .filter(|(_, status)| matches!(status, ConfirmationStatus::Pending))
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Drop unconfirmed participants: marks Pending intents as TimedOut
    /// and removes them from the intents map.
    ///
    /// Returns the number of intents dropped.
    pub fn drop_unconfirmed(&mut self) -> usize {
        let pending_ids: Vec<String> = self
            .confirmation_status
            .iter()
            .filter(|(_, status)| matches!(status, ConfirmationStatus::Pending))
            .map(|(id, _)| id.clone())
            .collect();

        let count = pending_ids.len();
        for id in &pending_ids {
            self.confirmation_status
                .insert(id.clone(), ConfirmationStatus::TimedOut);
            self.intents.remove(id);
        }
        count
    }

    /// Whether all registered intents have confirmed.
    ///
    /// Returns true if there are no Pending confirmations.
    /// Also returns true if there are no intents at all.
    pub fn all_confirmed(&self) -> bool {
        self.confirmation_status
            .values()
            .all(|s| matches!(s, ConfirmationStatus::Confirmed { .. }))
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
    /// Unilateral exit delay (seconds)
    pub unilateral_exit_delay: u32,
    /// How long participants have to confirm after selection (seconds)
    pub confirmation_timeout_secs: u64,
}

impl Default for RoundConfig {
    fn default() -> Self {
        Self {
            min_intents: 1,
            max_intents: 128,
            session_duration_secs: 10,
            vtxo_tree_expiry_secs: 604_800,
            unilateral_exit_delay: 512,
            confirmation_timeout_secs: 10,
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

    #[test]
    fn test_round_default_stage() {
        let round = Round::new();
        assert_eq!(round.stage.code, RoundStage::Undefined);
        assert!(!round.stage.ended);
        assert!(!round.stage.failed);
        assert!(!round.is_ended());
    }

    #[test]
    fn test_round_timestamps() {
        let mut round = Round::new();
        assert_eq!(round.starting_timestamp, 0);
        assert_eq!(round.ending_timestamp, 0);

        round.start_registration().unwrap();
        assert!(round.starting_timestamp > 0);

        round.end_successfully();
        assert!(round.ending_timestamp > 0);
        assert!(round.ending_timestamp >= round.starting_timestamp);
    }

    #[test]
    fn test_round_fail_timestamps() {
        let mut round = Round::new();
        round.start_registration().unwrap();
        round.fail("err".to_string());
        assert!(round.ending_timestamp > 0);
    }

    #[test]
    fn test_register_intent_not_in_registration() {
        let mut round = Round::new();
        let intent = Intent {
            id: "test".to_string(),
            inputs: vec![],
            receivers: vec![],
            proof: String::new(),
            message: String::new(),
            txid: String::new(),
            leaf_tx_asset_packet: String::new(),
        };
        // Undefined stage
        assert!(round.register_intent(intent.clone()).is_err());

        // After finalization
        round.start_registration().unwrap();
        round.start_finalization().unwrap();
        assert!(round.register_intent(intent.clone()).is_err());
    }

    #[test]
    fn test_register_intent_after_end() {
        let mut round = Round::new();
        round.start_registration().unwrap();
        round.end_successfully();

        let intent = Intent {
            id: "test".to_string(),
            inputs: vec![],
            receivers: vec![],
            proof: String::new(),
            message: String::new(),
            txid: String::new(),
            leaf_tx_asset_packet: String::new(),
        };
        assert!(round.register_intent(intent).is_err());
    }

    #[test]
    fn test_round_intent_count() {
        let mut round = Round::new();
        round.start_registration().unwrap();
        assert_eq!(round.intent_count(), 0);

        for i in 0..5 {
            let intent = Intent {
                id: format!("intent_{i}"),
                inputs: vec![],
                receivers: vec![],
                proof: String::new(),
                message: String::new(),
                txid: String::new(),
                leaf_tx_asset_packet: String::new(),
            };
            round.register_intent(intent).unwrap();
        }
        assert_eq!(round.intent_count(), 5);
    }

    #[test]
    fn test_round_duplicate_intent_overwrites() {
        let mut round = Round::new();
        round.start_registration().unwrap();

        let intent = Intent {
            id: "same-id".to_string(),
            inputs: vec![],
            receivers: vec![],
            proof: "v1".to_string(),
            message: String::new(),
            txid: String::new(),
            leaf_tx_asset_packet: String::new(),
        };
        round.register_intent(intent).unwrap();

        let intent2 = Intent {
            id: "same-id".to_string(),
            inputs: vec![],
            receivers: vec![],
            proof: "v2".to_string(),
            message: String::new(),
            txid: String::new(),
            leaf_tx_asset_packet: String::new(),
        };
        round.register_intent(intent2).unwrap();

        // Same ID, so intent_count should still be 1
        assert_eq!(round.intent_count(), 1);
        assert_eq!(round.intents.get("same-id").unwrap().proof, "v2");
    }

    #[test]
    fn test_stage_display() {
        assert_eq!(RoundStage::Undefined.to_string(), "UNDEFINED_STAGE");
        assert_eq!(RoundStage::Registration.to_string(), "REGISTRATION_STAGE");
        assert_eq!(RoundStage::Finalization.to_string(), "FINALIZATION_STAGE");
    }

    #[test]
    fn test_stage_terminal() {
        let stage = Stage {
            code: RoundStage::Registration,
            ended: false,
            failed: false,
        };
        assert!(!stage.is_terminal());

        let stage = Stage {
            code: RoundStage::Registration,
            ended: true,
            failed: false,
        };
        assert!(stage.is_terminal());

        let stage = Stage {
            code: RoundStage::Registration,
            ended: false,
            failed: true,
        };
        assert!(stage.is_terminal());
    }

    #[test]
    fn test_round_config_defaults() {
        let config = RoundConfig::default();
        assert_eq!(config.min_intents, 1);
        assert_eq!(config.max_intents, 128);
        assert!(config.session_duration_secs > 0);
        assert!(config.vtxo_tree_expiry_secs > 0);
        assert!(config.unilateral_exit_delay > 0);
    }

    #[test]
    fn test_round_swept_flag() {
        let mut round = Round::new();
        assert!(!round.swept);
        round.swept = true;
        assert!(round.swept);
    }
}
