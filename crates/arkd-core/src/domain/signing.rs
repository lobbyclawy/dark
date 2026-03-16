//! MuSig2 signing session domain types.

/// Status of a MuSig2 signing session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningSessionStatus {
    /// Collecting nonces from participants.
    CollectingNonces,
    /// All nonces collected; now collecting partial signatures.
    CollectingSignatures,
    /// Session completed with an aggregated signature.
    Complete,
    /// Session failed or was aborted.
    Failed,
}

/// A MuSig2 tree signing session.
///
/// Tracks nonces and partial signatures from round participants so that the
/// ASP can aggregate them into a final Schnorr signature for the round
/// transaction tree.
#[derive(Debug, Clone)]
pub struct SigningSession {
    /// Round / batch ID this session belongs to.
    pub round_id: String,
    /// Expected number of participants.
    pub participant_count: usize,
    /// Collected nonces keyed by participant ID.
    pub tree_nonces: Vec<(String, Vec<u8>)>,
    /// Collected partial signatures keyed by participant ID.
    pub tree_signatures: Vec<(String, Vec<u8>)>,
    /// Final aggregated signature (set on completion).
    pub combined_sig: Option<Vec<u8>>,
    /// Current session status.
    pub status: SigningSessionStatus,
}

impl SigningSession {
    /// Create a new signing session in the `CollectingNonces` state.
    pub fn new(round_id: impl Into<String>, participant_count: usize) -> Self {
        Self {
            round_id: round_id.into(),
            participant_count,
            tree_nonces: Vec::new(),
            tree_signatures: Vec::new(),
            combined_sig: None,
            status: SigningSessionStatus::CollectingNonces,
        }
    }

    /// Whether all expected nonces have been received.
    pub fn all_nonces_collected(&self) -> bool {
        self.tree_nonces.len() >= self.participant_count
    }

    /// Whether all expected signatures have been received.
    pub fn all_signatures_collected(&self) -> bool {
        self.tree_signatures.len() >= self.participant_count
    }
}
