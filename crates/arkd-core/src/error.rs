//! Error types for the Ark protocol core
//!
//! This module defines all errors that can occur in the core domain logic,
//! following Rust best practices with `thiserror` for ergonomic error handling.

use thiserror::Error;
use uuid::Uuid;

/// Core domain errors for the Ark protocol
#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum ArkError {
    // ========================================================================
    // Round Errors
    // ========================================================================
    /// Round not found
    #[error("Round not found: {0}")]
    RoundNotFound(Uuid),

    /// Invalid round state transition
    #[error("Invalid round state transition from {from:?} to {to:?}")]
    InvalidRoundTransition {
        from: crate::domain::round::RoundStatus,
        to: crate::domain::round::RoundStatus,
    },

    /// Round is full (maximum participants reached)
    #[error("Round {round_id} is full (max: {max_participants})")]
    RoundFull {
        round_id: Uuid,
        max_participants: u32,
    },

    /// Round has expired
    #[error("Round {0} has expired")]
    RoundExpired(Uuid),

    /// Round registration is closed
    #[error("Round {0} is not accepting registrations")]
    RoundRegistrationClosed(Uuid),

    // ========================================================================
    // VTXO Errors
    // ========================================================================
    /// VTXO not found
    #[error("VTXO not found: {0}")]
    VtxoNotFound(String),

    /// VTXO already spent
    #[error("VTXO {0} has already been spent")]
    VtxoAlreadySpent(String),

    /// VTXO expired
    #[error("VTXO {vtxo_id} has expired at height {expiry_height}")]
    VtxoExpired { vtxo_id: String, expiry_height: u32 },

    /// Invalid VTXO proof
    #[error("Invalid VTXO proof: {0}")]
    InvalidVtxoProof(String),

    // ========================================================================
    // Exit Errors
    // ========================================================================
    /// Exit not found
    #[error("Exit not found: {0}")]
    ExitNotFound(Uuid),

    /// Exit already in progress
    #[error("Exit already in progress for VTXO {0}")]
    ExitInProgress(String),

    /// Invalid exit request
    #[error("Invalid exit request: {0}")]
    InvalidExitRequest(String),

    /// Exit timeout
    #[error("Exit {0} timed out")]
    ExitTimeout(Uuid),

    // ========================================================================
    // Participant Errors
    // ========================================================================
    /// Participant not found
    #[error("Participant not found: {0}")]
    ParticipantNotFound(String),

    /// Participant already registered
    #[error("Participant {0} already registered for this round")]
    ParticipantAlreadyRegistered(String),

    /// Participant banned
    #[error("Participant {pubkey} is banned until {until}")]
    ParticipantBanned { pubkey: String, until: String },

    // ========================================================================
    // Signature Errors
    // ========================================================================
    /// Missing signature
    #[error("Missing signature from participant {0}")]
    MissingSignature(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    // ========================================================================
    // Tree Errors
    // ========================================================================
    /// VTXO tree construction failed
    #[error("VTXO tree construction failed: {0}")]
    TreeConstructionFailed(String),

    /// Invalid tree path
    #[error("Invalid tree path: {0}")]
    InvalidTreePath(String),

    /// Merkle proof verification failed
    #[error("Merkle proof verification failed")]
    MerkleProofFailed,

    // ========================================================================
    // Infrastructure Errors
    // ========================================================================
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// Bitcoin RPC error
    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpcError(String),

    /// Wallet error
    #[error("Wallet error: {0}")]
    WalletError(String),

    // ========================================================================
    // Validation Errors
    // ========================================================================
    /// Invalid amount
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Amount too small
    #[error("Amount {amount} sats is below minimum {minimum} sats")]
    AmountTooSmall { amount: u64, minimum: u64 },

    /// Amount too large
    #[error("Amount {amount} sats exceeds maximum {maximum} sats")]
    AmountTooLarge { amount: u64, maximum: u64 },

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    // ========================================================================
    // Internal Errors
    // ========================================================================
    /// Internal error (catch-all)
    #[error("Internal error: {0}")]
    Internal(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Timeout
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
        let err = ArkError::RoundNotFound(Uuid::nil());
        assert!(err.to_string().contains("Round not found"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ArkError>();
    }
}

/// Error category for programmatic handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Resource not found (404-equivalent)
    NotFound,

    /// Invalid state transition or operation
    InvalidState,

    /// Operation timeout
    Timeout,

    /// Validation failure
    Validation,

    /// Insufficient funds or capacity
    Insufficient,

    /// Authentication/authorization failure
    Unauthorized,

    /// Internal service error
    Internal,
}

impl ArkError {
    /// Get the category of this error for programmatic handling
    ///
    /// Useful for API responses and monitoring/alerting.
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::RoundNotFound(_)
            | Self::VtxoNotFound(_)
            | Self::ExitNotFound(_)
            | Self::ParticipantNotFound(_) => ErrorCategory::NotFound,

            Self::InvalidRoundTransition { .. }
            | Self::VtxoAlreadySpent(_)
            | Self::VtxoExpired { .. }
            | Self::InvalidVtxoProof(_)
            | Self::InvalidExitRequest(_)
            | Self::ExitInProgress(_)
            | Self::RoundRegistrationClosed(_)
            | Self::ParticipantAlreadyRegistered(_) => ErrorCategory::InvalidState,

            Self::RoundExpired(_) | Self::ExitTimeout(_) => ErrorCategory::Timeout,

            Self::InvalidAmount(_)
            | Self::InvalidPublicKey(_)
            | Self::InvalidSignature(_)
            | Self::SignatureVerificationFailed(_)
            | Self::MissingSignature(_)
            | Self::TreeConstructionFailed(_)
            | Self::InvalidTreePath(_)
            | Self::MerkleProofFailed => ErrorCategory::Validation,

            Self::RoundFull { .. } | Self::AmountTooSmall { .. } | Self::AmountTooLarge { .. } => {
                ErrorCategory::Insufficient
            }

            Self::ParticipantBanned { .. } => ErrorCategory::Unauthorized,

            Self::DatabaseError(_)
            | Self::WalletError(_)
            | Self::BitcoinRpcError(_)
            | Self::CacheError(_)
            | Self::InvalidConfiguration(_)
            | Self::Internal(_)
            | Self::SerializationError(_) => ErrorCategory::Internal,

            Self::Timeout(_) => ErrorCategory::Timeout,
        }
    }

    /// Check if this error represents a temporary/retriable condition
    pub fn is_retriable(&self) -> bool {
        matches!(
            self.category(),
            ErrorCategory::Timeout | ErrorCategory::Internal
        )
    }
}
