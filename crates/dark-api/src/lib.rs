//! # dark-api
//!
//! gRPC and REST API layer for the Ark protocol server.
//!
//! This crate provides the external interface for:
//!
//! - **User API**: Round registration, exits, VTXO queries
//! - **Admin API**: Server management, monitoring
//!
//! ## Protocol Buffers
//!
//! The API is defined using Protocol Buffers (see `proto/` directory).
//! Generated Rust code is created at build time using `tonic-build`.
//!
//! ## Authentication
//!
//! Uses macaroons for authentication (compatible with original arkd).

use thiserror::Error;

pub mod auth;
pub mod config;
pub mod grpc;
pub mod handlers;
pub mod monitoring;
pub mod notes;
pub mod rest;
pub mod server;

/// Generated protobuf types and service traits.
pub mod proto {
    /// ark.v1 package
    pub mod ark_v1 {
        tonic::include_proto!("ark.v1");
    }
}

pub use config::ServerConfig;
pub use grpc::broker::{
    EventBroker, SharedEventBroker, SharedTransactionEventBroker, TransactionEventBroker,
};
pub use grpc::signer_client::RemoteSignerClient;
pub use grpc::wallet_service::WalletGrpcService;
pub use monitoring::{spawn_monitoring_server, MonitoringConfig};
pub use server::Server;

/// API-specific errors
#[derive(Error, Debug)]
pub enum ApiError {
    /// Server failed to start
    #[error("Server startup failed: {0}")]
    StartupError(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Internal server error
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Service unavailable
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Rate limited
    #[error("Rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u32 },

    /// Transport error
    #[error("Transport error: {0}")]
    TransportError(#[from] tonic::transport::Error),
}

impl From<ApiError> for tonic::Status {
    fn from(err: ApiError) -> Self {
        match err {
            ApiError::AuthenticationError(_) => tonic::Status::unauthenticated(err.to_string()),
            ApiError::InvalidRequest(_) => tonic::Status::invalid_argument(err.to_string()),
            ApiError::ServiceUnavailable(_) => tonic::Status::unavailable(err.to_string()),
            ApiError::RateLimited { .. } => tonic::Status::resource_exhausted(err.to_string()),
            _ => tonic::Status::internal(err.to_string()),
        }
    }
}

/// Result type for API operations
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_to_status() {
        let err = ApiError::AuthenticationError("Invalid token".to_string());
        let status: tonic::Status = err.into();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_proto_types_exist() {
        // Verify proto types compile and are accessible
        let _outpoint = proto::ark_v1::Outpoint {
            txid: "abc".to_string(),
            vout: 0,
        };
        let _req = proto::ark_v1::GetInfoRequest {};
        let _status_req = proto::ark_v1::GetStatusRequest {};
    }

    #[test]
    fn test_confidential_proto_types_exist() {
        // Verify the confidential primitives added in #531 compile and round-trip.
        use prost::Message;

        let cv = proto::ark_v1::ConfidentialVtxo {
            amount_commitment: Some(proto::ark_v1::PedersenCommitment {
                point: vec![0u8; 33],
            }),
            range_proof: Some(proto::ark_v1::RangeProof {
                proof: vec![1u8, 2, 3, 4],
            }),
            owner_pubkey: vec![2u8; 33],
            ephemeral_pubkey: vec![3u8; 33],
            encrypted_memo: Some(proto::ark_v1::EncryptedMemo { ciphertext: vec![] }),
            nullifier: Some(proto::ark_v1::Nullifier {
                value: vec![4u8; 32],
            }),
        };
        let bytes = cv.encode_to_vec();
        let decoded = proto::ark_v1::ConfidentialVtxo::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.owner_pubkey.len(), 33);
        assert_eq!(decoded.ephemeral_pubkey.len(), 33);
        assert_eq!(decoded.nullifier.as_ref().unwrap().value.len(), 32);
        assert_eq!(decoded.amount_commitment.as_ref().unwrap().point.len(), 33);

        let bp = proto::ark_v1::BalanceProof { sig: vec![5u8; 65] };
        assert_eq!(bp.sig.len(), 65);
    }

    /// Wire-compat test (#531 acceptance criterion): a transparent `Vtxo`
    /// serialised under the *old* schema (only fields 1-14 set) still decodes
    /// cleanly under the new schema, and the new `vtxo_body` oneof is `None`.
    #[test]
    fn test_transparent_vtxo_wire_compat() {
        use prost::Message;

        // Encode a transparent VTXO using only the legacy fields.
        let legacy = proto::ark_v1::Vtxo {
            outpoint: Some(proto::ark_v1::Outpoint {
                txid: "deadbeef".to_string(),
                vout: 7,
            }),
            amount: 12_345,
            script: "5120abcdef".to_string(),
            created_at: 1_700_000_000,
            expires_at: 1_700_001_000,
            commitment_txids: vec!["commit-1".to_string()],
            is_preconfirmed: true,
            is_swept: false,
            is_unrolled: false,
            is_spent: false,
            spent_by: String::new(),
            settled_by: String::new(),
            ark_txid: String::new(),
            assets: vec![],
            vtxo_body: None, // simulates an old client that does not know the field
        };
        let bytes = legacy.encode_to_vec();

        // Decode back under the new schema.
        let decoded = proto::ark_v1::Vtxo::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.amount, 12_345);
        assert_eq!(decoded.script, "5120abcdef");
        assert_eq!(decoded.outpoint.as_ref().unwrap().vout, 7);
        assert!(decoded.is_preconfirmed);
        // Crucial: the new oneof is unset for legacy wire data.
        assert!(decoded.vtxo_body.is_none());

        // And a fresh VTXO with the new oneof set still round-trips.
        let with_marker = proto::ark_v1::Vtxo {
            vtxo_body: Some(proto::ark_v1::vtxo::VtxoBody::Transparent(
                proto::ark_v1::TransparentVtxoMarker {},
            )),
            ..legacy
        };
        let bytes = with_marker.encode_to_vec();
        let decoded = proto::ark_v1::Vtxo::decode(bytes.as_slice()).unwrap();
        assert!(matches!(
            decoded.vtxo_body,
            Some(proto::ark_v1::vtxo::VtxoBody::Transparent(_))
        ));
    }
}
