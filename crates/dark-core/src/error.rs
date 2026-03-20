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
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Not found: {0}")]
    NotFound(String),
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

    #[test]
    fn test_all_error_variants_display() {
        use crate::domain::round::RoundStage;

        let errors: Vec<ArkError> = vec![
            ArkError::RoundNotFound("r1".to_string()),
            ArkError::InvalidRoundTransition {
                from: RoundStage::Undefined,
                to: RoundStage::Finalization,
            },
            ArkError::RoundFull {
                round_id: "r1".to_string(),
                max_intents: 128,
            },
            ArkError::RoundExpired("r1".to_string()),
            ArkError::RoundRegistrationClosed("r1".to_string()),
            ArkError::VtxoNotFound("v1".to_string()),
            ArkError::VtxoAlreadySpent("v1".to_string()),
            ArkError::VtxoExpired {
                vtxo_id: "v1".to_string(),
                expires_at: 1000,
            },
            ArkError::InvalidVtxoProof("bad".to_string()),
            ArkError::ExitNotFound("e1".to_string()),
            ArkError::ExitInProgress("v1".to_string()),
            ArkError::InvalidExitRequest("bad".to_string()),
            ArkError::ExitTimeout("e1".to_string()),
            ArkError::ParticipantNotFound("p1".to_string()),
            ArkError::ParticipantBanned {
                pubkey: "pk".to_string(),
                until: "2030".to_string(),
            },
            ArkError::InvalidSignature("bad".to_string()),
            ArkError::TreeConstructionFailed("fail".to_string()),
            ArkError::DatabaseError("db".to_string()),
            ArkError::CacheError("cache".to_string()),
            ArkError::BitcoinRpcError("rpc".to_string()),
            ArkError::WalletError("wallet".to_string()),
            ArkError::AmountTooSmall {
                amount: 100,
                minimum: 546,
            },
            ArkError::InvalidPublicKey("pk".to_string()),
            ArkError::InvalidConfiguration("cfg".to_string()),
            ArkError::Internal("oops".to_string()),
            ArkError::SerializationError("ser".to_string()),
            ArkError::Timeout(5000),
            ArkError::Validation("bad input".to_string()),
            ArkError::NotFound("thing".to_string()),
        ];

        for err in &errors {
            let display = err.to_string();
            assert!(
                !display.is_empty(),
                "Error variant should have display: {:?}",
                err
            );
        }
    }

    #[test]
    fn test_from_serde_error() {
        let serde_err = serde_json::from_str::<String>("not valid json").unwrap_err();
        let ark_err: ArkError = serde_err.into();
        match ark_err {
            ArkError::SerializationError(msg) => assert!(!msg.is_empty()),
            _ => panic!("Expected SerializationError"),
        }
    }

    #[test]
    fn test_error_debug_format() {
        let err = ArkError::AmountTooSmall {
            amount: 100,
            minimum: 546,
        };
        let debug = format!("{:?}", err);
        assert!(debug.contains("AmountTooSmall"));
    }
}
