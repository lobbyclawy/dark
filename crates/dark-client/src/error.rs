use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Connection failed: {0}")]
    Connection(String),
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Wallet error: {0}")]
    Wallet(String),
    #[error("Explorer error: {0}")]
    Explorer(String),
    #[error("Store error: {0}")]
    Store(String),
}

pub type ClientResult<T> = Result<T, ClientError>;
