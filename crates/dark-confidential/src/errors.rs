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
}
