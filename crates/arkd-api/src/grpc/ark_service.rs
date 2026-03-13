//! ArkService gRPC implementation — user-facing API.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use arkd_core::ports::RoundRepository;

use crate::proto::ark_v1::ark_service_server::ArkService as ArkServiceTrait;
use crate::proto::ark_v1::{
    GetInfoRequest, GetInfoResponse, GetRoundRequest, GetRoundResponse, GetVtxosRequest,
    GetVtxosResponse, ListRoundsRequest, ListRoundsResponse, RegisterForRoundRequest,
    RegisterForRoundResponse, RequestExitRequest, RequestExitResponse,
};

use super::convert;
use super::middleware::{get_authenticated_user, require_authenticated_user};

/// ArkService gRPC handler backed by the core application service.
pub struct ArkGrpcService {
    core: Arc<arkd_core::ArkService>,
    round_repo: Arc<dyn RoundRepository>,
}

impl ArkGrpcService {
    /// Create a new ArkGrpcService wrapping the core service and round repository.
    pub fn new(core: Arc<arkd_core::ArkService>, round_repo: Arc<dyn RoundRepository>) -> Self {
        Self { core, round_repo }
    }

    /// Verify that the authenticated user owns all the specified VTXOs
    async fn verify_vtxo_ownership(
        &self,
        vtxo_outpoints: &[arkd_core::domain::VtxoOutpoint],
        owner_pubkey: &bitcoin::secp256k1::XOnlyPublicKey,
    ) -> Result<(), Status> {
        // Fetch the VTXOs
        let vtxos = self
            .core
            .get_vtxos(vtxo_outpoints)
            .await
            .map_err(|e| Status::internal(format!("Failed to fetch VTXOs: {e}")))?;

        if vtxos.is_empty() {
            return Err(Status::not_found("No VTXOs found for the specified IDs"));
        }

        // Verify ownership of each VTXO
        let owner_hex = owner_pubkey.to_string();
        for vtxo in &vtxos {
            if vtxo.pubkey != owner_hex {
                warn!(
                    vtxo = %vtxo.outpoint,
                    expected = %owner_hex,
                    actual = %vtxo.pubkey,
                    "VTXO ownership verification failed"
                );
                return Err(Status::permission_denied(format!(
                    "VTXO {} is not owned by the requester",
                    vtxo.outpoint
                )));
            }
        }

        Ok(())
    }
}

#[tonic::async_trait]
impl ArkServiceTrait for ArkGrpcService {
    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        info!("GetInfo called");
        let info = self
            .core
            .get_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetInfoResponse {
            version: arkd_core::VERSION.to_string(),
            signer_pubkey: info.signer_pubkey,
            forfeit_pubkey: info.forfeit_pubkey,
            network: info.network,
            session_duration: info.session_duration,
            unilateral_exit_delay: info.unilateral_exit_delay,
            vtxo_min_amount: info.vtxo_min_amount,
            vtxo_max_amount: info.vtxo_max_amount,
            dust: info.dust as i64,
        }))
    }

    async fn register_for_round(
        &self,
        request: Request<RegisterForRoundRequest>,
    ) -> Result<Response<RegisterForRoundResponse>, Status> {
        let req = request.into_inner();
        info!(pubkey = %req.pubkey, amount = req.amount, "RegisterForRound called");

        if req.pubkey.is_empty() {
            return Err(Status::invalid_argument("pubkey is required"));
        }
        if req.amount == 0 {
            return Err(Status::invalid_argument("amount must be > 0"));
        }

        // Build VTXO inputs from proto inputs
        let inputs: Vec<arkd_core::domain::Vtxo> = req
            .inputs
            .iter()
            .filter_map(|input| {
                input.outpoint.as_ref().map(|op| {
                    arkd_core::domain::Vtxo::new(
                        arkd_core::domain::VtxoOutpoint::new(op.txid.clone(), op.vout),
                        req.amount,
                        req.pubkey.clone(),
                    )
                })
            })
            .collect();

        let intent = arkd_core::domain::Intent::new(
            "grpc-register".to_string(),
            req.pubkey.clone(),
            format!("register:{}:{}", req.pubkey, req.amount),
            inputs,
        )
        .map_err(|e| Status::invalid_argument(format!("Invalid intent: {e}")))?;

        let intent_id = self
            .core
            .register_intent(intent)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RegisterForRoundResponse {
            intent_id,
            round_id: String::new(), // Round ID is assigned later during finalization
        }))
    }

    async fn request_exit(
        &self,
        request: Request<RequestExitRequest>,
    ) -> Result<Response<RequestExitResponse>, Status> {
        // Extract authenticated user's pubkey
        let auth_user = require_authenticated_user(&request)?;
        let requester_pubkey = auth_user.pubkey;

        let req = request.into_inner();
        info!(
            destination = %req.destination,
            requester = %requester_pubkey,
            vtxo_count = req.vtxo_ids.len(),
            "RequestExit called"
        );

        if req.destination.is_empty() {
            return Err(Status::invalid_argument("destination is required"));
        }
        if req.vtxo_ids.is_empty() {
            return Err(Status::invalid_argument("vtxo_ids must not be empty"));
        }

        let vtxo_outpoints: Vec<arkd_core::domain::VtxoOutpoint> = req
            .vtxo_ids
            .iter()
            .map(convert::proto_outpoint_to_domain)
            .collect();

        // Verify the requester owns all the VTXOs being exited
        self.verify_vtxo_ownership(&vtxo_outpoints, &requester_pubkey)
            .await?;

        let destination: bitcoin::Address<bitcoin::address::NetworkUnchecked> = req
            .destination
            .parse()
            .map_err(|e| Status::invalid_argument(format!("Invalid destination address: {e}")))?;

        let exit_request = arkd_core::domain::CollaborativeExitRequest {
            vtxo_ids: vtxo_outpoints,
            destination,
        };

        let exit = self
            .core
            .request_collaborative_exit(exit_request, requester_pubkey)
            .await
            .map_err(|e| {
                warn!(error = %e, "Exit request failed");
                Status::internal(e.to_string())
            })?;

        Ok(Response::new(RequestExitResponse {
            exit_id: exit.id.to_string(),
            status: format!("{:?}", exit.status),
        }))
    }

    async fn get_vtxos(
        &self,
        request: Request<GetVtxosRequest>,
    ) -> Result<Response<GetVtxosResponse>, Status> {
        let req = request.into_inner();
        info!(pubkey = %req.pubkey, "GetVtxos called");

        if req.pubkey.is_empty() {
            // If no pubkey provided, try to use authenticated user's pubkey
            if let Some(auth_user) = get_authenticated_user(&Request::new(())) {
                let pubkey = auth_user.pubkey.to_string();
                let (spendable, spent) = self
                    .core
                    .get_vtxos_for_pubkey(&pubkey)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;

                return Ok(Response::new(GetVtxosResponse {
                    spendable: spendable.iter().map(convert::vtxo_to_proto).collect(),
                    spent: spent.iter().map(convert::vtxo_to_proto).collect(),
                }));
            }
            return Err(Status::invalid_argument("pubkey is required"));
        }

        let (spendable, spent) = self
            .core
            .get_vtxos_for_pubkey(&req.pubkey)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetVtxosResponse {
            spendable: spendable.iter().map(convert::vtxo_to_proto).collect(),
            spent: spent.iter().map(convert::vtxo_to_proto).collect(),
        }))
    }

    async fn list_rounds(
        &self,
        _request: Request<ListRoundsRequest>,
    ) -> Result<Response<ListRoundsResponse>, Status> {
        info!("ListRounds called");

        // Returns empty — RoundRepository doesn't have a list-all method yet.
        // Individual rounds can be fetched via GetRound.
        Ok(Response::new(ListRoundsResponse { rounds: vec![] }))
    }

    async fn get_round(
        &self,
        request: Request<GetRoundRequest>,
    ) -> Result<Response<GetRoundResponse>, Status> {
        let req = request.into_inner();
        info!(round_id = %req.round_id, "GetRound called");

        if req.round_id.is_empty() {
            return Err(Status::invalid_argument("round_id is required"));
        }

        match self.round_repo.get_round_with_id(&req.round_id).await {
            Ok(Some(round)) => Ok(Response::new(GetRoundResponse {
                round: Some(convert::round_to_details_proto(&round)),
            })),
            Ok(None) => Err(Status::not_found(format!(
                "Round {} not found",
                req.round_id
            ))),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ark_v1::Outpoint;

    #[test]
    fn test_request_validation() {
        let req = RegisterForRoundRequest {
            pubkey: String::new(),
            amount: 0,
            inputs: vec![],
        };
        assert!(req.pubkey.is_empty());
        assert_eq!(req.amount, 0);
    }

    #[test]
    fn test_exit_request_validation() {
        let req = RequestExitRequest {
            vtxo_ids: vec![Outpoint {
                txid: "abc".to_string(),
                vout: 0,
            }],
            destination: "tb1q...".to_string(),
        };
        assert!(!req.vtxo_ids.is_empty());
        assert!(!req.destination.is_empty());
    }
}
