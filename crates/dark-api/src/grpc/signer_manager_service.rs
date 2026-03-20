//! SignerManagerService gRPC implementation — runtime signer hot-swap.
//!
//! Exposed on the admin port (7071) to allow operators to replace the
//! active ASP signer without restarting the server.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::proto::ark_v1::signer_manager_service_server::SignerManagerService as SignerManagerServiceTrait;
use crate::proto::ark_v1::{LoadSignerRequest, LoadSignerResponse};

use dark_core::signer::{LocalSigner, SwappableSigner};

/// gRPC service for runtime signer management.
pub struct SignerManagerGrpcService {
    swappable_signer: Arc<SwappableSigner>,
}

impl SignerManagerGrpcService {
    /// Create a new `SignerManagerGrpcService`.
    pub fn new(swappable_signer: Arc<SwappableSigner>) -> Self {
        Self { swappable_signer }
    }
}

#[tonic::async_trait]
impl SignerManagerServiceTrait for SignerManagerGrpcService {
    async fn load_signer(
        &self,
        request: Request<LoadSignerRequest>,
    ) -> Result<Response<LoadSignerResponse>, Status> {
        let req = request.into_inner();

        let signer_source = req
            .signer_source
            .ok_or_else(|| Status::invalid_argument("signer_source is required"))?;

        match signer_source {
            crate::proto::ark_v1::load_signer_request::SignerSource::PrivateKeyHex(hex_key) => {
                info!("Loading signer from private key");

                let new_signer = LocalSigner::from_hex(&hex_key).map_err(|e| {
                    Status::invalid_argument(format!("Invalid private key hex: {e}"))
                })?;

                let pubkey_bytes = new_signer.public_key_bytes();
                // x-only pubkey is bytes [1..33] of the compressed pubkey
                let xonly_hex = hex::encode(&pubkey_bytes[1..33]);

                self.swappable_signer.swap(Box::new(new_signer)).await;
                info!(pubkey = %xonly_hex, "Signer swapped successfully");

                Ok(Response::new(LoadSignerResponse { pubkey: xonly_hex }))
            }
            crate::proto::ark_v1::load_signer_request::SignerSource::RemoteUrl(url) => {
                // TODO(#239): Connect to remote signer via gRPC, verify it responds,
                // then swap in a RemoteSignerAdapter that implements SignerService.
                warn!(url = %url, "Remote signer hot-swap not yet implemented");
                Err(Status::unimplemented(
                    "Remote signer hot-swap is not yet implemented (see #239)",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_creation() {
        let signer = LocalSigner::random();
        let swappable = Arc::new(SwappableSigner::new(Box::new(signer)));
        let _svc = SignerManagerGrpcService::new(swappable);
    }
}
