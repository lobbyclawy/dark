//! Hex / base64 helpers for the REST ⇄ gRPC boundary.
//!
//! All binary fields (PSBTs, pubkeys, signatures) travel as hex strings over
//! REST and bytes over gRPC. Centralising encoding here keeps silent
//! encoding bugs from spreading across handlers.

use crate::error::ApiError;

pub fn hex_decode(s: &str) -> Result<Vec<u8>, ApiError> {
    hex::decode(s).map_err(|e| ApiError::BadRequest(format!("invalid hex: {e}")))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, ApiError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| ApiError::BadRequest(format!("invalid base64: {e}")))
}

pub fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
