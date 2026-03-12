//! Round domain model
//!
//! Rounds are the batching mechanism of the Ark protocol. Multiple users'
//! VTXO requests are collected and settled together in a single on-chain
//! transaction, dramatically reducing fees.
//!
//! # Round Lifecycle
//!
//! ```text
//! Pending -> Started -> Signing -> Finalized
//!              |          |           |
//!              v          v           v
//!           Failed     Failed      Failed
//! ```
//!
//! 1. **Pending**: Collecting participant registrations
//! 2. **Started**: Registration closed, building VTXO tree
//! 3. **Signing**: Collecting signatures from all participants
//! 4. **Finalized**: Commitment transaction broadcast and confirmed
//! 5. **Failed**: Round failed at any stage

use bitcoin::{Amount, Txid};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::participant::Participant;
use super::vtxo::VtxoId;

/// A round in the Ark protocol
///
/// Rounds batch multiple VTXO operations into a single on-chain transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round {
    /// Unique identifier for this round
    pub id: Uuid,

    /// Current status of the round
    pub status: RoundStatus,

    /// Participants in this round
    pub participants: Vec<Participant>,

    /// VTXO tree root hash (set when tree is constructed)
    pub vtxo_tree_root: Option<[u8; 32]>,

    /// Commitment transaction ID (set when finalized)
    pub commitment_txid: Option<Txid>,

    /// Block height when VTXOs from this round expire
    pub vtxo_expiry_height: u32,

    /// Minimum number of participants required
    pub min_participants: u32,

    /// Maximum number of participants allowed
    pub max_participants: u32,

    /// Registration deadline
    pub registration_deadline: DateTime<Utc>,

    /// Signing deadline (set when status becomes Signing)
    pub signing_deadline: Option<DateTime<Utc>>,

    /// Total input amount (sum of all VTXOs being spent)
    pub total_input_amount: Amount,

    /// Total output amount (sum of all VTXOs being created)
    pub total_output_amount: Amount,

    /// Fee paid for the commitment transaction
    pub fee: Amount,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Failure reason (if status is Failed)
    pub failure_reason: Option<String>,
}

/// Status of a round in its lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStatus {
    /// Accepting participant registrations
    Pending,

    /// Registration closed, building VTXO tree
    Started,

    /// Collecting signatures from participants
    Signing,

    /// Commitment transaction broadcast and confirmed
    Finalized,

    /// Round failed
    Failed,
}

impl RoundStatus {
    /// Check if registration is allowed in this status
    pub fn accepts_registration(&self) -> bool {
        matches!(self, RoundStatus::Pending)
    }

    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, RoundStatus::Finalized | RoundStatus::Failed)
    }

    /// Get valid next states from this state
    pub fn valid_transitions(&self) -> Vec<RoundStatus> {
        match self {
            RoundStatus::Pending => vec![RoundStatus::Started, RoundStatus::Failed],
            RoundStatus::Started => vec![RoundStatus::Signing, RoundStatus::Failed],
            RoundStatus::Signing => vec![RoundStatus::Finalized, RoundStatus::Failed],
            RoundStatus::Finalized => vec![],
            RoundStatus::Failed => vec![],
        }
    }

    /// Check if a transition to another state is valid
    pub fn can_transition_to(&self, target: RoundStatus) -> bool {
        self.valid_transitions().contains(&target)
    }
}

impl std::fmt::Display for RoundStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundStatus::Pending => write!(f, "pending"),
            RoundStatus::Started => write!(f, "started"),
            RoundStatus::Signing => write!(f, "signing"),
            RoundStatus::Finalized => write!(f, "finalized"),
            RoundStatus::Failed => write!(f, "failed"),
        }
    }
}

/// Configuration for creating a new round
#[derive(Debug, Clone)]
pub struct RoundConfig {
    /// Minimum participants required
    pub min_participants: u32,

    /// Maximum participants allowed
    pub max_participants: u32,

    /// Registration window duration
    pub registration_duration: Duration,

    /// Signing window duration
    pub signing_duration: Duration,

    /// VTXO lifetime in blocks
    pub vtxo_lifetime_blocks: u32,

    /// Current block height
    pub current_height: u32,
}

impl Default for RoundConfig {
    fn default() -> Self {
        Self {
            min_participants: 1,
            max_participants: 128,
            registration_duration: Duration::seconds(30),
            signing_duration: Duration::minutes(2),
            vtxo_lifetime_blocks: 144 * 7, // ~7 days (matches upstream arkd)
            current_height: 0,
        }
    }
}

impl Round {
    /// Create a new round
    pub fn new(config: RoundConfig) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            status: RoundStatus::Pending,
            participants: Vec::new(),
            vtxo_tree_root: None,
            commitment_txid: None,
            vtxo_expiry_height: config.current_height + config.vtxo_lifetime_blocks,
            min_participants: config.min_participants,
            max_participants: config.max_participants,
            registration_deadline: now + config.registration_duration,
            signing_deadline: None,
            total_input_amount: Amount::ZERO,
            total_output_amount: Amount::ZERO,
            fee: Amount::ZERO,
            created_at: now,
            updated_at: now,
            failure_reason: None,
        }
    }

    /// Create a round with a specific ID (for testing/replay)
    pub fn with_id(id: Uuid, config: RoundConfig) -> Self {
        let mut round = Self::new(config);
        round.id = id;
        round
    }

    /// Add a participant to the round
    ///
    /// Returns an error if registration is closed or the round is full.
    pub fn add_participant(&mut self, participant: Participant) -> Result<(), RoundError> {
        if !self.status.accepts_registration() {
            return Err(RoundError::RegistrationClosed);
        }

        if Utc::now() > self.registration_deadline {
            return Err(RoundError::RegistrationDeadlinePassed);
        }

        if self.participants.len() >= self.max_participants as usize {
            return Err(RoundError::RoundFull);
        }

        // Check for duplicate
        if self
            .participants
            .iter()
            .any(|p| p.pubkey == participant.pubkey)
        {
            return Err(RoundError::AlreadyRegistered);
        }

        // Update totals
        self.total_input_amount += participant.total_input_amount();
        self.total_output_amount += participant.total_output_amount();

        self.participants.push(participant);
        self.updated_at = Utc::now();

        Ok(())
    }

    /// Remove a participant from the round
    pub fn remove_participant(&mut self, pubkey: &bitcoin::XOnlyPublicKey) -> Option<Participant> {
        if let Some(pos) = self.participants.iter().position(|p| &p.pubkey == pubkey) {
            let participant = self.participants.remove(pos);

            // Update totals
            self.total_input_amount -= participant.total_input_amount();
            self.total_output_amount -= participant.total_output_amount();
            self.updated_at = Utc::now();

            Some(participant)
        } else {
            None
        }
    }

    /// Transition to Started status
    pub fn start(&mut self, signing_duration: Duration) -> Result<(), RoundError> {
        self.transition_to(RoundStatus::Started)?;

        // Check minimum participants
        if self.participants.len() < self.min_participants as usize {
            self.fail("Insufficient participants".to_string());
            return Err(RoundError::InsufficientParticipants);
        }

        self.signing_deadline = Some(Utc::now() + signing_duration);
        Ok(())
    }

    /// Transition to Signing status
    pub fn begin_signing(&mut self, vtxo_tree_root: [u8; 32]) -> Result<(), RoundError> {
        self.transition_to(RoundStatus::Signing)?;
        self.vtxo_tree_root = Some(vtxo_tree_root);
        Ok(())
    }

    /// Finalize the round
    pub fn finalize(&mut self, commitment_txid: Txid, fee: Amount) -> Result<(), RoundError> {
        self.transition_to(RoundStatus::Finalized)?;
        self.commitment_txid = Some(commitment_txid);
        self.fee = fee;
        Ok(())
    }

    /// Mark the round as failed
    pub fn fail(&mut self, reason: String) {
        self.status = RoundStatus::Failed;
        self.failure_reason = Some(reason);
        self.updated_at = Utc::now();
    }

    /// Perform a status transition
    fn transition_to(&mut self, new_status: RoundStatus) -> Result<(), RoundError> {
        if !self.status.can_transition_to(new_status) {
            return Err(RoundError::InvalidTransition {
                from: self.status,
                to: new_status,
            });
        }

        self.status = new_status;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Get the number of participants
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Check if the round has enough participants
    pub fn has_minimum_participants(&self) -> bool {
        self.participants.len() >= self.min_participants as usize
    }

    /// Check if registration deadline has passed
    pub fn is_registration_expired(&self) -> bool {
        Utc::now() > self.registration_deadline
    }

    /// Check if signing deadline has passed
    pub fn is_signing_expired(&self) -> bool {
        self.signing_deadline
            .map(|deadline| Utc::now() > deadline)
            .unwrap_or(false)
    }

    /// Get participants who have submitted signatures
    pub fn signed_participants(&self) -> impl Iterator<Item = &Participant> {
        self.participants.iter().filter(|p| p.has_signed())
    }

    /// Get participants who have NOT submitted signatures
    pub fn unsigned_participants(&self) -> impl Iterator<Item = &Participant> {
        self.participants.iter().filter(|p| !p.has_signed())
    }

    /// Check if all participants have signed
    pub fn all_signed(&self) -> bool {
        self.participants.iter().all(|p| p.has_signed())
    }

    /// Get all VTXO IDs created in this round
    pub fn vtxo_ids(&self) -> Vec<VtxoId> {
        self.participants
            .iter()
            .flat_map(|p| p.vtxo_requests.iter())
            .enumerate()
            .map(|(i, _)| VtxoId::from(format!("{}:{}", self.id, i)))
            .collect()
    }
}

/// Errors specific to round operations
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum RoundError {
    #[error("Registration is closed")]
    RegistrationClosed,

    #[error("Registration deadline has passed")]
    RegistrationDeadlinePassed,

    #[error("Round is full")]
    RoundFull,

    #[error("Already registered for this round")]
    AlreadyRegistered,

    #[error("Insufficient participants")]
    InsufficientParticipants,

    #[error("Invalid status transition from {from} to {to}")]
    InvalidTransition { from: RoundStatus, to: RoundStatus },

    #[error("Participant not found")]
    ParticipantNotFound,
}

/// Summary of a round (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct RoundSummary {
    pub id: Uuid,
    pub status: RoundStatus,
    pub participant_count: usize,
    pub total_amount: Amount,
    pub created_at: DateTime<Utc>,
    pub registration_deadline: DateTime<Utc>,
}

impl From<&Round> for RoundSummary {
    fn from(round: &Round) -> Self {
        Self {
            id: round.id,
            status: round.status,
            participant_count: round.participants.len(),
            total_amount: round.total_output_amount,
            created_at: round.created_at,
            registration_deadline: round.registration_deadline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::Secp256k1;

    fn test_xonly_pubkey() -> bitcoin::XOnlyPublicKey {
        let secp = Secp256k1::new();
        let (_, pk) = secp.generate_keypair(&mut OsRng);
        bitcoin::XOnlyPublicKey::from(pk)
    }

    fn test_participant() -> Participant {
        Participant::new(test_xonly_pubkey())
    }

    #[test]
    fn test_round_creation() {
        let config = RoundConfig::default();
        let round = Round::new(config);

        assert_eq!(round.status, RoundStatus::Pending);
        assert!(round.participants.is_empty());
    }

    #[test]
    fn test_round_state_machine() {
        assert!(RoundStatus::Pending.can_transition_to(RoundStatus::Started));
        assert!(RoundStatus::Pending.can_transition_to(RoundStatus::Failed));
        assert!(!RoundStatus::Pending.can_transition_to(RoundStatus::Finalized));

        assert!(RoundStatus::Started.can_transition_to(RoundStatus::Signing));
        assert!(RoundStatus::Signing.can_transition_to(RoundStatus::Finalized));

        assert!(!RoundStatus::Finalized.can_transition_to(RoundStatus::Pending));
        assert!(!RoundStatus::Failed.can_transition_to(RoundStatus::Started));
    }

    #[test]
    fn test_add_participant() {
        let config = RoundConfig::default();
        let mut round = Round::new(config);

        let participant = test_participant();
        round.add_participant(participant).unwrap();

        assert_eq!(round.participant_count(), 1);
    }

    #[test]
    fn test_duplicate_participant_rejected() {
        let config = RoundConfig::default();
        let mut round = Round::new(config);

        let pubkey = test_xonly_pubkey();
        let participant1 = Participant::new(pubkey);
        let participant2 = Participant::new(pubkey);

        round.add_participant(participant1).unwrap();
        assert!(matches!(
            round.add_participant(participant2),
            Err(RoundError::AlreadyRegistered)
        ));
    }

    #[test]
    fn test_round_lifecycle() {
        let config = RoundConfig::default();
        let mut round = Round::new(config);

        // Add participant
        round.add_participant(test_participant()).unwrap();

        // Start
        round.start(chrono::Duration::minutes(2)).unwrap();
        assert_eq!(round.status, RoundStatus::Started);

        // Begin signing
        let tree_root = [0u8; 32];
        round.begin_signing(tree_root).unwrap();
        assert_eq!(round.status, RoundStatus::Signing);

        // Finalize
        let txid = bitcoin::Txid::all_zeros();
        round.finalize(txid, Amount::from_sat(1000)).unwrap();
        assert_eq!(round.status, RoundStatus::Finalized);
    }

    #[test]
    fn test_insufficient_participants() {
        let mut config = RoundConfig::default();
        config.min_participants = 5;
        let mut round = Round::new(config);

        // Only 1 participant
        round.add_participant(test_participant()).unwrap();

        // Should fail due to insufficient participants
        assert!(round.start(chrono::Duration::minutes(2)).is_err());
        assert_eq!(round.status, RoundStatus::Failed);
    }
}
