//! Error types for the Ark protocol core

use thiserror::Error;

/// Core domain errors
#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum ArkError {
    #[error("Round not found: {0}")]
    RoundNotFound(String),
    #[error("Invalid round state transition from {from:?} to {to:?}")]
    InvalidRoundTransition {
        from: crate::domain::round::RoundStage,
        to: crate::domain::round::RoundStage,
    },
    #[error("Round {round_id} is full (max: {max_intents})")]
    RoundFull { round_id: String, max_intents: u32 },
    #[error("Round {0} has expired")]
    RoundExpired(String),
    #[error("Round {0} is not accepting registrations")]
    RoundRegistrationClosed(String),
    #[error("VTXO not found: {0}")]
    VtxoNotFound(String),
    #[error("VTXO {0} has already been spent")]
    VtxoAlreadySpent(String),
    #[error("VTXO {vtxo_id} has expired at timestamp {expires_at}")]
    VtxoExpired { vtxo_id: String, expires_at: i64 },
    #[error("Invalid VTXO proof: {0}")]
    InvalidVtxoProof(String),
    #[error("Exit not found: {0}")]
    ExitNotFound(String),
    #[error("Exit already in progress for VTXO {0}")]
    ExitInProgress(String),
    #[error("Invalid exit request: {0}")]
    InvalidExitRequest(String),
    #[error("Exit {0} timed out")]
    ExitTimeout(String),
    #[error("Participant not found: {0}")]
    ParticipantNotFound(String),
    #[error("Participant {pubkey} is banned until {until}")]
    ParticipantBanned { pubkey: String, until: String },
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("VTXO tree construction failed: {0}")]
    TreeConstructionFailed(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpcError(String),
    #[error("Wallet error: {0}")]
    WalletError(String),
    #[error("Amount {amount} sats is below minimum {minimum} sats")]
    AmountTooSmall { amount: u64, minimum: u64 },
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Operation timed out after {0}ms")]
    Timeout(u64),
}

/// Result type for Ark core operations
pub type ArkResult<T> = Result<T, ArkError>;

impl From<serde_json::Error> for ArkError {
    fn from(err: serde_json::Error) -> Self {
        ArkError::SerializationError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ArkError::RoundNotFound("test".to_string());
        assert!(err.to_string().contains("Round not found"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ArkError>();
    }
}
