//! Exit domain model
//!
//! Exits allow users to withdraw their VTXOs to on-chain Bitcoin.
//!
//! # Exit Types
//!
//! 1. **Collaborative Exit**: Fast, cheap exit with ASP cooperation
//!    - User requests exit
//!    - ASP includes exit in next round
//!    - User receives on-chain output
//!
//! 2. **Unilateral Exit**: Fallback when ASP is unresponsive
//!    - User publishes their branch of the VTXO tree
//!    - Requires waiting for timelock
//!    - More expensive (more on-chain transactions)
//!
//! 3. **Boarding**: User adds funds to existing VTXOs
//!    - Atomic swap from on-chain to VTXO

use bitcoin::{Address, Amount, Txid, XOnlyPublicKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::vtxo::VtxoId;

/// An exit request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exit {
    /// Unique identifier
    pub id: Uuid,

    /// Type of exit
    pub exit_type: ExitType,

    /// Current status
    pub status: ExitStatus,

    /// VTXOs being exited
    pub vtxo_ids: Vec<VtxoId>,

    /// Total amount being exited
    pub amount: Amount,

    /// Destination address (for on-chain output)
    pub destination: Address<bitcoin::address::NetworkUnchecked>,

    /// Requester's public key
    pub requester_pubkey: XOnlyPublicKey,

    /// Associated round ID (for collaborative exit)
    pub round_id: Option<Uuid>,

    /// Exit transaction ID (for unilateral exit)
    pub exit_txid: Option<Txid>,

    /// Block height when exit can be claimed (for unilateral)
    pub claimable_height: Option<u32>,

    /// Fee paid
    pub fee: Amount,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Completion timestamp
    pub completed_at: Option<DateTime<Utc>>,

    /// Failure reason (if failed)
    pub failure_reason: Option<String>,
}

/// Type of exit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitType {
    /// Collaborative exit (through a round)
    Collaborative,

    /// Unilateral exit (direct on-chain)
    Unilateral,

    /// Boarding (adding funds to VTXO)
    Boarding,
}

impl ExitType {
    /// Check if this exit type requires ASP cooperation
    pub fn requires_asp(&self) -> bool {
        matches!(self, ExitType::Collaborative | ExitType::Boarding)
    }

    /// Check if this exit type has a timelock
    pub fn has_timelock(&self) -> bool {
        matches!(self, ExitType::Unilateral)
    }
}

impl std::fmt::Display for ExitType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitType::Collaborative => write!(f, "collaborative"),
            ExitType::Unilateral => write!(f, "unilateral"),
            ExitType::Boarding => write!(f, "boarding"),
        }
    }
}

/// Status of an exit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    /// Exit requested, waiting for processing
    Pending,

    /// Exit is being processed (collaborative: in round; unilateral: tx broadcast)
    Processing,

    /// Waiting for timelock (unilateral only)
    WaitingTimelock,

    /// Exit completed successfully
    Completed,

    /// Exit failed
    Failed,

    /// Exit cancelled by user
    Cancelled,
}

impl ExitStatus {
    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ExitStatus::Completed | ExitStatus::Failed | ExitStatus::Cancelled
        )
    }

    /// Check if exit can be cancelled
    pub fn can_cancel(&self) -> bool {
        matches!(self, ExitStatus::Pending)
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitStatus::Pending => write!(f, "pending"),
            ExitStatus::Processing => write!(f, "processing"),
            ExitStatus::WaitingTimelock => write!(f, "waiting_timelock"),
            ExitStatus::Completed => write!(f, "completed"),
            ExitStatus::Failed => write!(f, "failed"),
            ExitStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Request to create a collaborative exit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborativeExitRequest {
    /// VTXOs to exit
    pub vtxo_ids: Vec<VtxoId>,

    /// Destination address
    pub destination: Address<bitcoin::address::NetworkUnchecked>,
}

/// Request to create a unilateral exit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnilateralExitRequest {
    /// VTXO to exit
    pub vtxo_id: VtxoId,

    /// Destination address
    pub destination: Address<bitcoin::address::NetworkUnchecked>,

    /// Fee rate for the exit transaction
    pub fee_rate_sat_vb: u64,
}

/// Request to board (add on-chain funds to VTXO)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardingRequest {
    /// Recipient's public key (who will own the VTXO)
    pub recipient_pubkey: XOnlyPublicKey,

    /// Amount to board
    pub amount: Amount,
}

/// A boarding transaction (on-chain to VTXO)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardingTransaction {
    /// Unique identifier
    pub id: Uuid,

    /// Status
    pub status: BoardingStatus,

    /// Amount being boarded
    pub amount: Amount,

    /// Recipient's public key
    pub recipient_pubkey: XOnlyPublicKey,

    /// On-chain funding transaction ID
    pub funding_txid: Option<Txid>,

    /// Output index in funding transaction
    pub funding_vout: Option<u32>,

    /// Round ID where VTXO will be created
    pub round_id: Option<Uuid>,

    /// Resulting VTXO ID
    pub vtxo_id: Option<VtxoId>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Status of a boarding transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardingStatus {
    /// Waiting for on-chain funding
    AwaitingFunding,

    /// Funding received, waiting for round
    Funded,

    /// Included in a round
    InRound,

    /// Boarding completed, VTXO created
    Completed,

    /// Boarding failed
    Failed,

    /// Funding expired/refunded
    Expired,
}

impl BoardingStatus {
    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            BoardingStatus::Completed | BoardingStatus::Failed | BoardingStatus::Expired
        )
    }
}

impl std::fmt::Display for BoardingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoardingStatus::AwaitingFunding => write!(f, "awaiting_funding"),
            BoardingStatus::Funded => write!(f, "funded"),
            BoardingStatus::InRound => write!(f, "in_round"),
            BoardingStatus::Completed => write!(f, "completed"),
            BoardingStatus::Failed => write!(f, "failed"),
            BoardingStatus::Expired => write!(f, "expired"),
        }
    }
}

impl BoardingTransaction {
    /// Create a new boarding transaction
    pub fn new(recipient_pubkey: XOnlyPublicKey, amount: Amount) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            status: BoardingStatus::AwaitingFunding,
            amount,
            recipient_pubkey,
            funding_txid: None,
            funding_vout: None,
            round_id: None,
            vtxo_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}

impl Exit {
    /// Create a new collaborative exit
    pub fn collaborative(
        vtxo_ids: Vec<VtxoId>,
        destination: Address<bitcoin::address::NetworkUnchecked>,
        requester_pubkey: XOnlyPublicKey,
        amount: Amount,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            exit_type: ExitType::Collaborative,
            status: ExitStatus::Pending,
            vtxo_ids,
            amount,
            destination,
            requester_pubkey,
            round_id: None,
            exit_txid: None,
            claimable_height: None,
            fee: Amount::ZERO,
            created_at: now,
            updated_at: now,
            completed_at: None,
            failure_reason: None,
        }
    }

    /// Create a new unilateral exit
    pub fn unilateral(
        vtxo_id: VtxoId,
        destination: Address<bitcoin::address::NetworkUnchecked>,
        requester_pubkey: XOnlyPublicKey,
        amount: Amount,
        claimable_height: u32,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            exit_type: ExitType::Unilateral,
            status: ExitStatus::Pending,
            vtxo_ids: vec![vtxo_id],
            amount,
            destination,
            requester_pubkey,
            round_id: None,
            exit_txid: None,
            claimable_height: Some(claimable_height),
            fee: Amount::ZERO,
            created_at: now,
            updated_at: now,
            completed_at: None,
            failure_reason: None,
        }
    }

    /// Mark exit as processing
    pub fn mark_processing(&mut self) {
        self.status = ExitStatus::Processing;
        self.updated_at = Utc::now();
    }

    /// Mark exit as waiting for timelock (unilateral)
    pub fn mark_waiting_timelock(&mut self, exit_txid: Txid) {
        self.status = ExitStatus::WaitingTimelock;
        self.exit_txid = Some(exit_txid);
        self.updated_at = Utc::now();
    }

    /// Assign to a round (collaborative)
    pub fn assign_to_round(&mut self, round_id: Uuid) {
        self.round_id = Some(round_id);
        self.status = ExitStatus::Processing;
        self.updated_at = Utc::now();
    }

    /// Complete the exit
    pub fn complete(&mut self, fee: Amount) {
        self.status = ExitStatus::Completed;
        self.fee = fee;
        let now = Utc::now();
        self.completed_at = Some(now);
        self.updated_at = now;
    }

    /// Fail the exit
    pub fn fail(&mut self, reason: String) {
        self.status = ExitStatus::Failed;
        self.failure_reason = Some(reason);
        self.updated_at = Utc::now();
    }

    /// Cancel the exit
    pub fn cancel(&mut self) -> Result<(), ExitError> {
        if !self.status.can_cancel() {
            return Err(ExitError::CannotCancel(self.status));
        }
        self.status = ExitStatus::Cancelled;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Check if exit can be claimed (unilateral only)
    pub fn can_claim(&self, current_height: u32) -> bool {
        match (self.exit_type, self.claimable_height, self.status) {
            (ExitType::Unilateral, Some(height), ExitStatus::WaitingTimelock) => {
                current_height >= height
            }
            _ => false,
        }
    }

    /// Get blocks until claimable (unilateral only)
    pub fn blocks_until_claimable(&self, current_height: u32) -> Option<u32> {
        match (self.exit_type, self.claimable_height) {
            (ExitType::Unilateral, Some(height)) if current_height < height => {
                Some(height - current_height)
            }
            _ => None,
        }
    }
}

/// Errors specific to exit operations
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ExitError {
    #[error("Cannot cancel exit in {0} status")]
    CannotCancel(ExitStatus),

    #[error("VTXO not found: {0}")]
    VtxoNotFound(String),

    #[error("VTXO already in exit: {0}")]
    VtxoAlreadyExiting(String),

    #[error("Invalid destination address")]
    InvalidDestination,

    #[error("Insufficient VTXO balance")]
    InsufficientBalance,
}

/// Summary of an exit (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct ExitSummary {
    pub id: Uuid,
    pub exit_type: ExitType,
    pub status: ExitStatus,
    pub amount: Amount,
    pub vtxo_count: usize,
    pub created_at: DateTime<Utc>,
}

impl From<&Exit> for ExitSummary {
    fn from(exit: &Exit) -> Self {
        Self {
            id: exit.id,
            exit_type: exit.exit_type,
            status: exit.status,
            amount: exit.amount,
            vtxo_count: exit.vtxo_ids.len(),
            created_at: exit.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::Secp256k1;
    use std::str::FromStr;

    fn test_xonly_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let (_, pk) = secp.generate_keypair(&mut OsRng);
        XOnlyPublicKey::from(pk)
    }

    fn test_address() -> Address<bitcoin::address::NetworkUnchecked> {
        // Regtest address
        Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap()
    }

    #[test]
    fn test_collaborative_exit_creation() {
        let exit = Exit::collaborative(
            vec![VtxoId::new("test".to_string(), 0)],
            test_address(),
            test_xonly_pubkey(),
            Amount::from_sat(100_000),
        );

        assert_eq!(exit.exit_type, ExitType::Collaborative);
        assert_eq!(exit.status, ExitStatus::Pending);
        assert!(exit.claimable_height.is_none());
    }

    #[test]
    fn test_unilateral_exit_creation() {
        let exit = Exit::unilateral(
            VtxoId::new("test".to_string(), 0),
            test_address(),
            test_xonly_pubkey(),
            Amount::from_sat(100_000),
            1000, // Claimable at block 1000
        );

        assert_eq!(exit.exit_type, ExitType::Unilateral);
        assert_eq!(exit.status, ExitStatus::Pending);
        assert_eq!(exit.claimable_height, Some(1000));
    }

    #[test]
    fn test_exit_lifecycle_collaborative() {
        let mut exit = Exit::collaborative(
            vec![VtxoId::new("test".to_string(), 0)],
            test_address(),
            test_xonly_pubkey(),
            Amount::from_sat(100_000),
        );

        // Assign to round
        let round_id = Uuid::new_v4();
        exit.assign_to_round(round_id);
        assert_eq!(exit.status, ExitStatus::Processing);
        assert_eq!(exit.round_id, Some(round_id));

        // Complete
        exit.complete(Amount::from_sat(500));
        assert_eq!(exit.status, ExitStatus::Completed);
        assert!(exit.completed_at.is_some());
    }

    #[test]
    fn test_exit_lifecycle_unilateral() {
        let mut exit = Exit::unilateral(
            VtxoId::new("test".to_string(), 0),
            test_address(),
            test_xonly_pubkey(),
            Amount::from_sat(100_000),
            1000,
        );

        // Mark processing
        exit.mark_processing();
        assert_eq!(exit.status, ExitStatus::Processing);

        // Mark waiting timelock
        let txid = bitcoin::Txid::all_zeros();
        exit.mark_waiting_timelock(txid);
        assert_eq!(exit.status, ExitStatus::WaitingTimelock);
        assert_eq!(exit.exit_txid, Some(txid));

        // Check claimability
        assert!(!exit.can_claim(999));
        assert!(exit.can_claim(1000));
        assert!(exit.can_claim(1001));

        assert_eq!(exit.blocks_until_claimable(900), Some(100));
        assert_eq!(exit.blocks_until_claimable(1000), None);
    }

    #[test]
    fn test_exit_cancellation() {
        let mut exit = Exit::collaborative(
            vec![VtxoId::new("test".to_string(), 0)],
            test_address(),
            test_xonly_pubkey(),
            Amount::from_sat(100_000),
        );

        // Can cancel when pending
        assert!(exit.cancel().is_ok());
        assert_eq!(exit.status, ExitStatus::Cancelled);

        // Cannot cancel again
        let mut exit2 = Exit::collaborative(
            vec![VtxoId::new("test".to_string(), 1)],
            test_address(),
            test_xonly_pubkey(),
            Amount::from_sat(100_000),
        );
        exit2.mark_processing();
        assert!(exit2.cancel().is_err());
    }
}
