//! Error types for Bitcoin operations

use thiserror::Error;

/// Bitcoin-specific errors
#[derive(Error, Debug)]
pub enum BitcoinError {
    /// Transaction building error
    #[error("Transaction build failed: {0}")]
    TransactionBuildError(String),

    /// PSBT error
    #[error("PSBT error: {0}")]
    PsbtError(String),

    /// Script error
    #[error("Script error: {0}")]
    ScriptError(String),

    /// UTXO error
    #[error("UTXO error: {0}")]
    UtxoError(String),

    /// RPC error
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Insufficient funds
    #[error("Insufficient funds: required {required} sats, available {available} sats")]
    InsufficientFunds { required: u64, available: u64 },

    /// Invalid address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid amount
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for Bitcoin operations
pub type BitcoinResult<T> = Result<T, BitcoinError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<BitcoinError> = vec![
            BitcoinError::TransactionBuildError("build fail".to_string()),
            BitcoinError::PsbtError("psbt fail".to_string()),
            BitcoinError::ScriptError("script fail".to_string()),
            BitcoinError::UtxoError("utxo fail".to_string()),
            BitcoinError::RpcError("rpc fail".to_string()),
            BitcoinError::InsufficientFunds {
                required: 100_000,
                available: 50_000,
            },
            BitcoinError::InvalidAddress("bad addr".to_string()),
            BitcoinError::InvalidAmount("bad amount".to_string()),
            BitcoinError::SerializationError("ser fail".to_string()),
        ];

        for err in &errors {
            let display = err.to_string();
            assert!(!display.is_empty(), "Error should have display: {:?}", err);
        }
    }

    #[test]
    fn test_insufficient_funds_details() {
        let err = BitcoinError::InsufficientFunds {
            required: 100_000,
            available: 50_000,
        };
        let display = err.to_string();
        assert!(display.contains("100000"));
        assert!(display.contains("50000"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BitcoinError>();
    }
}
