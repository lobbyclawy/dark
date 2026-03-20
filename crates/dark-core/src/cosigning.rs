//! MuSig2 Cosigning Session Management
//!
//! Manages the cooperative signing sessions for Ark protocol.
//! See Go: `github.com/ark-network/ark/internal/core/application/cosigner.go`

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::domain::VtxoOutpoint;
use crate::error::{ArkError, ArkResult};

/// Nonce commitment from a participant
#[derive(Debug, Clone)]
pub struct NonceCommitment {
    /// Participant pubkey
    pub pubkey: String,
    /// Nonce commitment (hex-encoded)
    pub commitment: String,
    /// Timestamp
    pub timestamp: i64,
}

/// Partial signature from a participant
#[derive(Debug, Clone)]
pub struct PartialSignature {
    /// Participant pubkey
    pub pubkey: String,
    /// Partial signature (hex-encoded)
    pub signature: String,
    /// Timestamp
    pub timestamp: i64,
}

/// State of a cosigning session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CosigningState {
    /// Collecting nonce commitments
    CollectingNonces,
    /// Nonces received, ready for signing
    ReadyForSigning,
    /// Collecting partial signatures
    CollectingSignatures,
    /// All signatures collected, ready to aggregate
    ReadyToAggregate,
    /// Session completed successfully
    Completed,
    /// Session failed
    Failed,
}

/// A cosigning session for a specific transaction
#[derive(Debug, Clone)]
pub struct CosigningSession {
    /// Unique session identifier
    pub id: String,
    /// Round ID this session belongs to
    pub round_id: String,
    /// Transaction being signed (PSBT hex)
    pub tx: String,
    /// Current state
    pub state: CosigningState,
    /// Expected signers (pubkeys)
    pub expected_signers: Vec<String>,
    /// Collected nonce commitments
    pub nonce_commitments: HashMap<String, NonceCommitment>,
    /// Aggregated public nonce (after all nonces collected)
    pub aggregated_nonce: Option<String>,
    /// Collected partial signatures
    pub partial_signatures: HashMap<String, PartialSignature>,
    /// Final aggregated signature
    pub final_signature: Option<String>,
    /// Created timestamp
    pub created_at: i64,
    /// Failure reason if failed
    pub failure_reason: Option<String>,
}

impl CosigningSession {
    /// Create a new cosigning session
    pub fn new(round_id: String, tx: String, expected_signers: Vec<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            round_id,
            tx,
            state: CosigningState::CollectingNonces,
            expected_signers,
            nonce_commitments: HashMap::new(),
            aggregated_nonce: None,
            partial_signatures: HashMap::new(),
            final_signature: None,
            created_at: chrono::Utc::now().timestamp(),
            failure_reason: None,
        }
    }

    /// Add a nonce commitment
    pub fn add_nonce_commitment(&mut self, commitment: NonceCommitment) -> ArkResult<()> {
        if self.state != CosigningState::CollectingNonces {
            return Err(ArkError::Internal(format!(
                "Cannot add nonce in state {:?}",
                self.state
            )));
        }

        if !self.expected_signers.contains(&commitment.pubkey) {
            return Err(ArkError::Internal(format!(
                "Unexpected signer: {}",
                commitment.pubkey
            )));
        }

        self.nonce_commitments
            .insert(commitment.pubkey.clone(), commitment);

        // Check if all nonces collected
        if self.nonce_commitments.len() == self.expected_signers.len() {
            self.state = CosigningState::ReadyForSigning;
            debug!(session_id = %self.id, "All nonce commitments collected");
        }

        Ok(())
    }

    /// Aggregate nonces and transition to signature collection
    pub fn aggregate_nonces(&mut self, aggregated: String) -> ArkResult<()> {
        if self.state != CosigningState::ReadyForSigning {
            return Err(ArkError::Internal(format!(
                "Cannot aggregate nonces in state {:?}",
                self.state
            )));
        }

        self.aggregated_nonce = Some(aggregated);
        self.state = CosigningState::CollectingSignatures;
        debug!(session_id = %self.id, "Nonces aggregated, collecting signatures");
        Ok(())
    }

    /// Add a partial signature
    pub fn add_partial_signature(&mut self, signature: PartialSignature) -> ArkResult<()> {
        if self.state != CosigningState::CollectingSignatures {
            return Err(ArkError::Internal(format!(
                "Cannot add signature in state {:?}",
                self.state
            )));
        }

        if !self.expected_signers.contains(&signature.pubkey) {
            return Err(ArkError::Internal(format!(
                "Unexpected signer: {}",
                signature.pubkey
            )));
        }

        self.partial_signatures
            .insert(signature.pubkey.clone(), signature);

        // Check if all signatures collected
        if self.partial_signatures.len() == self.expected_signers.len() {
            self.state = CosigningState::ReadyToAggregate;
            debug!(session_id = %self.id, "All partial signatures collected");
        }

        Ok(())
    }

    /// Aggregate signatures and complete the session
    pub fn aggregate_signatures(&mut self, final_sig: String) -> ArkResult<()> {
        if self.state != CosigningState::ReadyToAggregate {
            return Err(ArkError::Internal(format!(
                "Cannot aggregate signatures in state {:?}",
                self.state
            )));
        }

        self.final_signature = Some(final_sig);
        self.state = CosigningState::Completed;
        info!(session_id = %self.id, "Cosigning session completed");
        Ok(())
    }

    /// Fail the session
    pub fn fail(&mut self, reason: String) {
        self.state = CosigningState::Failed;
        self.failure_reason = Some(reason);
        warn!(session_id = %self.id, "Cosigning session failed");
    }

    /// Check if session is complete
    pub fn is_complete(&self) -> bool {
        self.state == CosigningState::Completed
    }

    /// Check if session has failed
    pub fn has_failed(&self) -> bool {
        self.state == CosigningState::Failed
    }
}

/// Manager for cosigning sessions
pub struct CosigningManager {
    /// Active sessions by ID
    sessions: Arc<RwLock<HashMap<String, CosigningSession>>>,
    /// Sessions by round ID
    sessions_by_round: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl CosigningManager {
    /// Create a new cosigning manager
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            sessions_by_round: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a cosigning session for a transaction
    #[instrument(skip(self, tx))]
    pub async fn create_session(
        &self,
        round_id: String,
        tx: String,
        expected_signers: Vec<String>,
    ) -> ArkResult<String> {
        let session = CosigningSession::new(round_id.clone(), tx, expected_signers);
        let session_id = session.id.clone();

        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session);

        self.sessions_by_round
            .write()
            .await
            .entry(round_id)
            .or_default()
            .push(session_id.clone());

        debug!(session_id = %session_id, "Created cosigning session");
        Ok(session_id)
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<CosigningSession> {
        self.sessions.read().await.get(session_id).cloned()
    }

    /// Get all sessions for a round
    pub async fn get_sessions_for_round(&self, round_id: &str) -> Vec<CosigningSession> {
        let session_ids = self
            .sessions_by_round
            .read()
            .await
            .get(round_id)
            .cloned()
            .unwrap_or_default();

        let sessions = self.sessions.read().await;
        session_ids
            .iter()
            .filter_map(|id| sessions.get(id).cloned())
            .collect()
    }

    /// Submit a nonce commitment
    #[instrument(skip(self))]
    pub async fn submit_nonce(
        &self,
        session_id: &str,
        commitment: NonceCommitment,
    ) -> ArkResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| ArkError::Internal(format!("Session not found: {session_id}")))?;

        session.add_nonce_commitment(commitment)
    }

    /// Submit a partial signature
    #[instrument(skip(self))]
    pub async fn submit_signature(
        &self,
        session_id: &str,
        signature: PartialSignature,
    ) -> ArkResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| ArkError::Internal(format!("Session not found: {session_id}")))?;

        session.add_partial_signature(signature)
    }

    /// Check if all sessions for a round are complete
    pub async fn all_sessions_complete(&self, round_id: &str) -> bool {
        let sessions = self.get_sessions_for_round(round_id).await;
        if sessions.is_empty() {
            return false;
        }
        sessions.iter().all(|s| s.is_complete())
    }

    /// Clean up sessions for a completed/failed round
    pub async fn cleanup_round(&self, round_id: &str) {
        let session_ids = self
            .sessions_by_round
            .write()
            .await
            .remove(round_id)
            .unwrap_or_default();

        let mut sessions = self.sessions.write().await;
        for id in session_ids {
            sessions.remove(&id);
        }
        debug!(round_id = %round_id, "Cleaned up cosigning sessions");
    }
}

impl Default for CosigningManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Forfeit transaction builder and validator
pub struct ForfeitTxManager {
    /// Collected forfeit transactions by round
    forfeit_txs: Arc<RwLock<HashMap<String, Vec<ForfeitTxEntry>>>>,
}

/// A forfeit transaction entry
#[derive(Debug, Clone)]
pub struct ForfeitTxEntry {
    /// VTXO outpoint this forfeit covers
    pub vtxo_outpoint: VtxoOutpoint,
    /// Connector outpoint this forfeit uses
    pub connector_outpoint: VtxoOutpoint,
    /// Signed forfeit transaction (hex)
    pub tx: String,
    /// Submitter pubkey
    pub submitter: String,
    /// Timestamp
    pub timestamp: i64,
}

impl ForfeitTxManager {
    /// Create a new forfeit tx manager
    pub fn new() -> Self {
        Self {
            forfeit_txs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Submit a forfeit transaction
    #[instrument(skip(self, tx))]
    pub async fn submit_forfeit(
        &self,
        round_id: &str,
        vtxo_outpoint: VtxoOutpoint,
        connector_outpoint: VtxoOutpoint,
        tx: String,
        submitter: String,
    ) -> ArkResult<()> {
        // TODO: Validate forfeit transaction structure
        // - Verify it spends the correct VTXO
        // - Verify it uses the correct connector
        // - Verify signature is valid

        let entry = ForfeitTxEntry {
            vtxo_outpoint,
            connector_outpoint,
            tx,
            submitter,
            timestamp: chrono::Utc::now().timestamp(),
        };

        self.forfeit_txs
            .write()
            .await
            .entry(round_id.to_string())
            .or_default()
            .push(entry);

        debug!(round_id = %round_id, "Forfeit tx submitted");
        Ok(())
    }

    /// Get all forfeit transactions for a round
    pub async fn get_forfeits(&self, round_id: &str) -> Vec<ForfeitTxEntry> {
        self.forfeit_txs
            .read()
            .await
            .get(round_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Validate all forfeits for a round cover the expected VTXOs
    pub async fn validate_round_forfeits(
        &self,
        round_id: &str,
        expected_vtxos: &[VtxoOutpoint],
    ) -> ArkResult<()> {
        let forfeits = self.get_forfeits(round_id).await;

        let submitted: std::collections::HashSet<_> =
            forfeits.iter().map(|f| &f.vtxo_outpoint).collect();

        for expected in expected_vtxos {
            if !submitted.contains(expected) {
                return Err(ArkError::Internal(format!(
                    "Missing forfeit tx for VTXO {}",
                    expected
                )));
            }
        }

        debug!(
            round_id = %round_id,
            count = forfeits.len(),
            "All forfeit transactions validated"
        );
        Ok(())
    }

    /// Clean up forfeits for a completed/failed round
    pub async fn cleanup_round(&self, round_id: &str) {
        self.forfeit_txs.write().await.remove(round_id);
        debug!(round_id = %round_id, "Cleaned up forfeit transactions");
    }
}

impl Default for ForfeitTxManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosigning_session_creation() {
        let session = CosigningSession::new(
            "round1".to_string(),
            "tx_hex".to_string(),
            vec!["signer1".to_string(), "signer2".to_string()],
        );

        assert_eq!(session.state, CosigningState::CollectingNonces);
        assert_eq!(session.expected_signers.len(), 2);
    }

    #[test]
    fn test_nonce_commitment_flow() {
        let mut session = CosigningSession::new(
            "round1".to_string(),
            "tx_hex".to_string(),
            vec!["signer1".to_string()],
        );

        let commitment = NonceCommitment {
            pubkey: "signer1".to_string(),
            commitment: "nonce_hex".to_string(),
            timestamp: 0,
        };

        session.add_nonce_commitment(commitment).unwrap();
        assert_eq!(session.state, CosigningState::ReadyForSigning);
    }

    #[test]
    fn test_invalid_signer_rejected() {
        let mut session = CosigningSession::new(
            "round1".to_string(),
            "tx_hex".to_string(),
            vec!["signer1".to_string()],
        );

        let commitment = NonceCommitment {
            pubkey: "unknown".to_string(),
            commitment: "nonce_hex".to_string(),
            timestamp: 0,
        };

        assert!(session.add_nonce_commitment(commitment).is_err());
    }

    #[tokio::test]
    async fn test_cosigning_manager() {
        let manager = CosigningManager::new();

        let session_id = manager
            .create_session(
                "round1".to_string(),
                "tx".to_string(),
                vec!["s1".to_string()],
            )
            .await
            .unwrap();

        let session = manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.round_id, "round1");

        let sessions = manager.get_sessions_for_round("round1").await;
        assert_eq!(sessions.len(), 1);

        manager.cleanup_round("round1").await;
        assert!(manager.get_session(&session_id).await.is_none());
    }

    #[tokio::test]
    async fn test_forfeit_manager() {
        let manager = ForfeitTxManager::new();

        let vtxo = VtxoOutpoint::new("vtxo_txid".to_string(), 0);
        let connector = VtxoOutpoint::new("connector_txid".to_string(), 0);

        manager
            .submit_forfeit(
                "round1",
                vtxo.clone(),
                connector,
                "forfeit_tx".to_string(),
                "submitter".to_string(),
            )
            .await
            .unwrap();

        let forfeits = manager.get_forfeits("round1").await;
        assert_eq!(forfeits.len(), 1);

        // Validate round forfeits
        manager
            .validate_round_forfeits("round1", &[vtxo])
            .await
            .unwrap();

        manager.cleanup_round("round1").await;
        assert!(manager.get_forfeits("round1").await.is_empty());
    }
}
