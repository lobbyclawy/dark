//! Participant domain model
//!
//! Represents a user participating in an Ark round.

use bitcoin::{Amount, XOnlyPublicKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::vtxo::{VtxoId, VtxoRequest};

/// A participant in an Ark round
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Participant's public key (x-only for Taproot)
    pub pubkey: XOnlyPublicKey,

    /// VTXOs being spent (inputs)
    pub input_vtxos: Vec<VtxoId>,

    /// VTXO requests (outputs)
    pub vtxo_requests: Vec<VtxoRequest>,

    /// Signature for the round (None until signed)
    pub signature: Option<ParticipantSignature>,

    /// Registration timestamp
    pub registered_at: DateTime<Utc>,

    /// Ban status
    pub ban_status: Option<BanStatus>,
}

/// Participant's signature for a round
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantSignature {
    /// The signature bytes
    pub signature: Vec<u8>,

    /// The message that was signed (tree root hash)
    pub message: [u8; 32],

    /// When the signature was submitted
    pub signed_at: DateTime<Utc>,
}

/// Ban status for a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanStatus {
    /// Reason for the ban
    pub reason: BanReason,

    /// When the ban expires (None = permanent)
    pub expires_at: Option<DateTime<Utc>>,

    /// When the ban was issued
    pub issued_at: DateTime<Utc>,
}

/// Reasons for banning a participant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BanReason {
    /// Failed to sign during signing phase
    FailedToSign,

    /// Submitted invalid signature
    InvalidSignature,

    /// Double-spend attempt detected
    DoubleSpendAttempt,

    /// Repeated misbehavior
    RepeatedMisbehavior,

    /// Manual ban by operator
    ManualBan,
}

impl BanReason {
    /// Get the default ban duration for this reason
    pub fn default_duration(&self) -> Option<chrono::Duration> {
        match self {
            BanReason::FailedToSign => Some(chrono::Duration::hours(1)),
            BanReason::InvalidSignature => Some(chrono::Duration::hours(24)),
            BanReason::DoubleSpendAttempt => None, // Permanent
            BanReason::RepeatedMisbehavior => Some(chrono::Duration::days(7)),
            BanReason::ManualBan => None, // Depends on operator
        }
    }
}

impl Participant {
    /// Create a new participant
    pub fn new(pubkey: XOnlyPublicKey) -> Self {
        Self {
            pubkey,
            input_vtxos: Vec::new(),
            vtxo_requests: Vec::new(),
            signature: None,
            registered_at: Utc::now(),
            ban_status: None,
        }
    }

    /// Add an input VTXO (being spent)
    pub fn with_input(mut self, vtxo_id: VtxoId) -> Self {
        self.input_vtxos.push(vtxo_id);
        self
    }

    /// Add multiple input VTXOs
    pub fn with_inputs(mut self, vtxo_ids: Vec<VtxoId>) -> Self {
        self.input_vtxos.extend(vtxo_ids);
        self
    }

    /// Add a VTXO request (output)
    pub fn with_request(mut self, request: VtxoRequest) -> Self {
        self.vtxo_requests.push(request);
        self
    }

    /// Add multiple VTXO requests
    pub fn with_requests(mut self, requests: Vec<VtxoRequest>) -> Self {
        self.vtxo_requests.extend(requests);
        self
    }

    /// Check if participant has signed
    pub fn has_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Submit a signature
    pub fn sign(&mut self, signature: Vec<u8>, message: [u8; 32]) {
        self.signature = Some(ParticipantSignature {
            signature,
            message,
            signed_at: Utc::now(),
        });
    }

    /// Calculate total input amount (for validation)
    ///
    /// Note: This requires looking up the actual VTXO amounts from storage.
    /// Returns ZERO here - caller should compute actual values.
    pub fn total_input_amount(&self) -> Amount {
        // Placeholder - actual implementation needs VTXO lookup
        Amount::ZERO
    }

    /// Calculate total output amount
    pub fn total_output_amount(&self) -> Amount {
        self.vtxo_requests.iter().map(|r| r.amount).sum::<Amount>()
    }

    /// Check if participant is banned
    pub fn is_banned(&self) -> bool {
        match &self.ban_status {
            None => false,
            Some(status) => match status.expires_at {
                None => true, // Permanent ban
                Some(expires) => Utc::now() < expires,
            },
        }
    }

    /// Ban this participant
    pub fn ban(&mut self, reason: BanReason) {
        let expires_at = reason.default_duration().map(|d| Utc::now() + d);
        self.ban_status = Some(BanStatus {
            reason,
            expires_at,
            issued_at: Utc::now(),
        });
    }

    /// Ban this participant with a specific expiry
    pub fn ban_until(&mut self, reason: BanReason, expires_at: Option<DateTime<Utc>>) {
        self.ban_status = Some(BanStatus {
            reason,
            expires_at,
            issued_at: Utc::now(),
        });
    }

    /// Remove ban
    pub fn unban(&mut self) {
        self.ban_status = None;
    }
}

/// Summary of participant status (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantSummary {
    /// Participant's public key (hex)
    pub pubkey: String,

    /// Number of input VTXOs
    pub input_count: usize,

    /// Number of output VTXO requests
    pub output_count: usize,

    /// Total output amount
    pub total_amount: Amount,

    /// Has signed
    pub signed: bool,

    /// Registration timestamp
    pub registered_at: DateTime<Utc>,
}

impl From<&Participant> for ParticipantSummary {
    fn from(p: &Participant) -> Self {
        Self {
            pubkey: p.pubkey.to_string(),
            input_count: p.input_vtxos.len(),
            output_count: p.vtxo_requests.len(),
            total_amount: p.total_output_amount(),
            signed: p.has_signed(),
            registered_at: p.registered_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::Secp256k1;

    fn test_xonly_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let (_, pk) = secp.generate_keypair(&mut OsRng);
        XOnlyPublicKey::from(pk)
    }

    #[test]
    fn test_participant_creation() {
        let pubkey = test_xonly_pubkey();
        let participant = Participant::new(pubkey);

        assert_eq!(participant.pubkey, pubkey);
        assert!(!participant.has_signed());
        assert!(!participant.is_banned());
    }

    #[test]
    fn test_participant_signing() {
        let pubkey = test_xonly_pubkey();
        let mut participant = Participant::new(pubkey);

        assert!(!participant.has_signed());

        participant.sign(vec![1, 2, 3], [0u8; 32]);

        assert!(participant.has_signed());
        assert!(participant.signature.is_some());
    }

    #[test]
    fn test_participant_banning() {
        let pubkey = test_xonly_pubkey();
        let mut participant = Participant::new(pubkey);

        assert!(!participant.is_banned());

        participant.ban(BanReason::FailedToSign);
        assert!(participant.is_banned());

        // Unban
        participant.unban();
        assert!(!participant.is_banned());
    }

    #[test]
    fn test_participant_builder_pattern() {
        let pubkey = test_xonly_pubkey();
        let participant = Participant::new(pubkey)
            .with_input(VtxoId::from("test:0"))
            .with_request(VtxoRequest::new(
                Amount::from_sat(100_000),
                test_xonly_pubkey(),
            ));

        assert_eq!(participant.input_vtxos.len(), 1);
        assert_eq!(participant.vtxo_requests.len(), 1);
    }

    #[test]
    fn test_total_output_amount() {
        let pubkey = test_xonly_pubkey();
        let participant = Participant::new(pubkey)
            .with_request(VtxoRequest::new(
                Amount::from_sat(50_000),
                test_xonly_pubkey(),
            ))
            .with_request(VtxoRequest::new(
                Amount::from_sat(30_000),
                test_xonly_pubkey(),
            ));

        assert_eq!(participant.total_output_amount(), Amount::from_sat(80_000));
    }
}
