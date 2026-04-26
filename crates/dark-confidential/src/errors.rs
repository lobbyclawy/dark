use thiserror::Error;

pub type Result<T> = core::result::Result<T, ConfidentialError>;

#[derive(Debug, Error)]
pub enum ConfidentialError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid encoding: {0}")]
    InvalidEncoding(&'static str),
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
    #[error("balance proof: {0}")]
    BalanceProof(&'static str),
    #[error("value out of range: {0}")]
    OutOfRange(&'static str),
    #[error("range proof failed: {0}")]
    RangeProof(&'static str),
    #[error("stealth address: {0}")]
    Stealth(&'static str),
}
