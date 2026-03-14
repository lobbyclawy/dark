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
}

pub type ClientResult<T> = Result<T, ClientError>;
