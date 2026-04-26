//! ComplianceService gRPC implementation — public bundle verification (#569).
//!
//! See `proto/ark/v1/compliance_service.proto` for the wire contract and the
//! auth/DoS posture rationale. The handler does three things:
//!
//! 1. Enforce the bundle size cap (DoS budget on an unauthenticated RPC).
//! 2. Decode the bundle via `compliance_verifier::decode_bundle`.
//! 3. Dispatch each proof to its type-specific verifier and assemble the
//!    response, preserving bundle order.
//!
//! All cryptographic work lives in [`super::compliance_verifier`]; this file
//! is purely transport plumbing.
//!
//! ## Auth posture
//!
//! `ComplianceService::VerifyComplianceProof` is **unauthenticated**. The
//! middleware's permission table returns `None` for this method (see
//! `required_permission_for_path`), so the interceptor lets it through even
//! when the server is configured to require auth on `ArkService`. Any caller
//! holding a bundle the bundle issuer has shared with them MAY verify it.

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use super::compliance_verifier::{decode_bundle, verify_bundle, BundleDecodeError, ProofOutcome};
use crate::proto::ark_v1::compliance_service_server::ComplianceService as ComplianceServiceTrait;
use crate::proto::ark_v1::{
    ProofResult, VerifyComplianceProofRequest, VerifyComplianceProofResponse,
};

/// Maximum accepted bundle size in bytes. Bundles larger than this are
/// rejected with `RESOURCE_EXHAUSTED` to bound DoS exposure on the
/// unauthenticated verification path.
pub const MAX_BUNDLE_BYTES: usize = 1 << 20; // 1 MiB.

/// Stateless ComplianceService handler. Holds no state because every
/// verification is fully self-contained in the bundle plus public verifier
/// logic (see service-level proto comment for the rationale).
#[derive(Default)]
pub struct ComplianceGrpcService;

impl ComplianceGrpcService {
    /// Construct a fresh handler. The service is stateless; callers may
    /// instantiate one per server or share via `Arc` indistinguishably.
    pub fn new() -> Self {
        Self
    }
}

#[tonic::async_trait]
impl ComplianceServiceTrait for ComplianceGrpcService {
    async fn verify_compliance_proof(
        &self,
        request: Request<VerifyComplianceProofRequest>,
    ) -> Result<Response<VerifyComplianceProofResponse>, Status> {
        let bundle = request.into_inner().bundle;

        if bundle.len() > MAX_BUNDLE_BYTES {
            warn!(
                bundle_bytes = bundle.len(),
                cap = MAX_BUNDLE_BYTES,
                "VerifyComplianceProof: bundle exceeds size cap"
            );
            return Err(Status::resource_exhausted(format!(
                "bundle exceeds maximum size of {MAX_BUNDLE_BYTES} bytes"
            )));
        }

        let decoded = decode_bundle(&bundle).map_err(decode_error_to_status)?;
        let outcomes = verify_bundle(&decoded);

        info!(
            proof_count = outcomes.len(),
            passed = outcomes.iter().filter(|o| o.passed).count(),
            "VerifyComplianceProof: bundle verified"
        );

        Ok(Response::new(VerifyComplianceProofResponse {
            results: outcomes.into_iter().map(outcome_to_proto).collect(),
        }))
    }
}

fn outcome_to_proto(outcome: ProofOutcome) -> ProofResult {
    ProofResult {
        proof_index: outcome.proof_index,
        proof_type: outcome.proof_type,
        passed: outcome.passed,
        error: outcome.error,
    }
}

#[allow(clippy::result_large_err)] // tonic::Status is inherently large
fn decode_error_to_status(err: BundleDecodeError) -> Status {
    Status::invalid_argument(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn well_formed_bundle() -> Vec<u8> {
        json!({
            "proofs": [
                {
                    "proof_type": "source_of_funds",
                    "payload": {
                        "commitment_path": ["c0", "c1"],
                        "owner_signature": "deadbeef",
                    },
                }
            ]
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn well_formed_bundle_returns_passed_results() {
        let svc = ComplianceGrpcService::new();
        let resp = svc
            .verify_compliance_proof(Request::new(VerifyComplianceProofRequest {
                bundle: well_formed_bundle(),
            }))
            .await
            .expect("well-formed bundle must verify")
            .into_inner();

        assert_eq!(resp.results.len(), 1);
        let r = &resp.results[0];
        assert_eq!(r.proof_index, 0);
        assert_eq!(r.proof_type, "source_of_funds");
        assert!(r.passed);
        assert!(r.error.is_none());
    }

    #[tokio::test]
    async fn empty_bundle_is_invalid_argument() {
        let svc = ComplianceGrpcService::new();
        let err = svc
            .verify_compliance_proof(Request::new(VerifyComplianceProofRequest {
                bundle: vec![],
            }))
            .await
            .expect_err("empty bundle must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn malformed_bundle_is_invalid_argument() {
        let svc = ComplianceGrpcService::new();
        let err = svc
            .verify_compliance_proof(Request::new(VerifyComplianceProofRequest {
                bundle: b"not-json".to_vec(),
            }))
            .await
            .expect_err("malformed bundle must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn oversized_bundle_is_resource_exhausted() {
        let svc = ComplianceGrpcService::new();
        let err = svc
            .verify_compliance_proof(Request::new(VerifyComplianceProofRequest {
                bundle: vec![0u8; MAX_BUNDLE_BYTES + 1],
            }))
            .await
            .expect_err("oversized bundle must be rejected");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn bundle_at_size_cap_is_decoded() {
        // The cap is inclusive — a bundle exactly at the cap proceeds to
        // decoding (and predictably fails decode here, since 1 MiB of zeros
        // is not valid JSON). What matters is that we do *not* return
        // ResourceExhausted.
        let svc = ComplianceGrpcService::new();
        let err = svc
            .verify_compliance_proof(Request::new(VerifyComplianceProofRequest {
                bundle: vec![0u8; MAX_BUNDLE_BYTES],
            }))
            .await
            .expect_err("zero-bytes-at-cap is not valid JSON");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
