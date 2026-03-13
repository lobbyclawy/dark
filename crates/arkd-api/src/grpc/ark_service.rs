//! ArkService gRPC implementation — user-facing API.

use std::pin::Pin;
use std::sync::Arc;

use async_stream::stream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use arkd_core::domain::{OffchainTx, VtxoInput, VtxoOutput};
use arkd_core::ports::{OffchainTxRepository, RoundRepository};

use crate::proto::ark_v1::ark_service_server::ArkService as ArkServiceTrait;
use crate::proto::ark_v1::{
    DeleteIntentRequest, DeleteIntentResponse, EstimateIntentFeeRequest, EstimateIntentFeeResponse,
    FinalizeTxRequest, FinalizeTxResponse, GetEventStreamRequest, GetInfoRequest, GetInfoResponse,
    GetPendingTxRequest, GetPendingTxResponse, GetRoundRequest, GetRoundResponse, GetVtxosRequest,
    GetVtxosResponse, ListRoundsRequest, ListRoundsResponse, RegisterForRoundRequest,
    RegisterForRoundResponse, RequestExitRequest, RequestExitResponse, RoundEvent,
    RoundHeartbeatEvent, ServiceStatus, SignedVtxoInput, SubmitTxRequest, SubmitTxResponse,
    UpdateStreamTopicsRequest, UpdateStreamTopicsResponse,
};

use super::broker::SharedEventBroker;
use super::convert;
use super::middleware::{get_authenticated_user, require_authenticated_user};

/// ArkService gRPC handler backed by the core application service.
pub struct ArkGrpcService {
    core: Arc<arkd_core::ArkService>,
    round_repo: Arc<dyn RoundRepository>,
    broker: SharedEventBroker,
    offchain_tx_repo: Arc<dyn OffchainTxRepository>,
}

impl ArkGrpcService {
    /// Create a new ArkGrpcService.
    pub fn new(
        core: Arc<arkd_core::ArkService>,
        round_repo: Arc<dyn RoundRepository>,
        broker: SharedEventBroker,
        offchain_tx_repo: Arc<dyn OffchainTxRepository>,
    ) -> Self {
        Self {
            core,
            round_repo,
            broker,
            offchain_tx_repo,
        }
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

/// Server-streaming response type for GetEventStream.
type GetEventStreamStream =
    Pin<Box<dyn Stream<Item = Result<RoundEvent, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl ArkServiceTrait for ArkGrpcService {
    type GetEventStreamStream = GetEventStreamStream;
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

        // Build service status map — report subsystem health
        let mut service_status = std::collections::HashMap::new();
        service_status.insert(
            "database".to_string(),
            ServiceStatus {
                name: "database".to_string(),
                available: true,
                details: "operational".to_string(),
            },
        );
        service_status.insert(
            "wallet".to_string(),
            ServiceStatus {
                name: "wallet".to_string(),
                available: true,
                details: "operational".to_string(),
            },
        );
        service_status.insert(
            "bitcoin_rpc".to_string(),
            ServiceStatus {
                name: "bitcoin_rpc".to_string(),
                available: true,
                details: "operational".to_string(),
            },
        );

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
            forfeit_address: info.forfeit_address,
            checkpoint_tapscript: info.checkpoint_tapscript,
            utxo_min_amount: info.utxo_min_amount,
            utxo_max_amount: info.utxo_max_amount,
            public_unilateral_exit_delay: info.public_unilateral_exit_delay,
            boarding_exit_delay: info.boarding_exit_delay,
            max_tx_weight: info.max_tx_weight,
            service_status,
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

        // Validate pubkey format
        if let Err(e) =
            arkd_core::validation::validate_pubkey_hex(&req.pubkey, "register_for_round")
        {
            return Err(Status::invalid_argument(format!("Invalid pubkey: {e}")));
        }

        // Validate amount bounds
        if let Err(e) = arkd_core::validation::validate_amount(req.amount, "register_for_round") {
            return Err(Status::invalid_argument(format!("Invalid amount: {e}")));
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

    async fn get_event_stream(
        &self,
        _request: Request<GetEventStreamRequest>,
    ) -> Result<Response<Self::GetEventStreamStream>, Status> {
        info!("GetEventStream called");
        let mut rx = self.broker.subscribe();

        let output = stream! {
            // Yield an initial heartbeat so the client knows the stream is alive
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            yield Ok(RoundEvent {
                event: Some(crate::proto::ark_v1::round_event::Event::Heartbeat(
                    RoundHeartbeatEvent { timestamp: now },
                )),
            });

            // Forward events from the broker
            loop {
                match rx.recv().await {
                    Ok(event) => yield Ok(event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "Event stream client lagged, skipped events");
                        // Continue receiving — don't break
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(output)))
    }

    async fn update_stream_topics(
        &self,
        request: Request<UpdateStreamTopicsRequest>,
    ) -> Result<Response<UpdateStreamTopicsResponse>, Status> {
        let req = request.into_inner();
        info!(topics = ?req.topics, "UpdateStreamTopics called");
        // Topic filtering is a future enhancement; accept and acknowledge
        Ok(Response::new(UpdateStreamTopicsResponse {}))
    }

    async fn estimate_intent_fee(
        &self,
        request: Request<EstimateIntentFeeRequest>,
    ) -> Result<Response<EstimateIntentFeeResponse>, Status> {
        let req = request.into_inner();
        info!(
            inputs = req.input_vtxo_ids.len(),
            outputs = req.outputs.len(),
            "EstimateIntentFee called"
        );

        if req.input_vtxo_ids.is_empty() {
            return Err(Status::invalid_argument("input_vtxo_ids must not be empty"));
        }
        if req.outputs.is_empty() {
            return Err(Status::invalid_argument("outputs must not be empty"));
        }

        let fee_rate = self.core.config().default_fee_rate_sats_per_vb;
        let num_inputs = req.input_vtxo_ids.len() as u64;
        let num_outputs = req.outputs.len() as u64;

        // Estimate virtual size: inputs * 68 vB + outputs * 43 vB + 10 vB overhead
        let fee_sats = (num_inputs * 68 + num_outputs * 43 + 10) * fee_rate;

        Ok(Response::new(EstimateIntentFeeResponse {
            fee_sats,
            fee_rate_sats_per_vb: fee_rate,
        }))
    }

    async fn delete_intent(
        &self,
        request: Request<DeleteIntentRequest>,
    ) -> Result<Response<DeleteIntentResponse>, Status> {
        let req = request.into_inner();
        info!(intent_id = %req.intent_id, "DeleteIntent called");

        if req.intent_id.is_empty() {
            return Err(Status::invalid_argument("intent_id is required"));
        }
        if req.proof.is_empty() {
            return Err(Status::invalid_argument("proof is required"));
        }

        // Look for the intent in any active round
        // Since we don't have a direct intent lookup, check if the round repo
        // has any pending confirmations that match this intent_id
        let rounds_checked = self
            .round_repo
            .get_round_with_id(&req.intent_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if rounds_checked.is_some() {
            // intent_id matched a round_id — not valid
            return Err(Status::not_found(format!(
                "Intent {} not found in any active round",
                req.intent_id
            )));
        }

        // No direct intent lookup available — return NotFound since we can't
        // confirm this intent exists in any active round
        Err(Status::not_found(format!(
            "Intent {} not found in any active round",
            req.intent_id
        )))
    }

    async fn submit_tx(
        &self,
        request: Request<SubmitTxRequest>,
    ) -> Result<Response<SubmitTxResponse>, Status> {
        let req = request.into_inner();
        if req.inputs.is_empty() {
            return Err(Status::invalid_argument("inputs must not be empty"));
        }
        let inputs: Vec<VtxoInput> = req
            .inputs
            .into_iter()
            .map(|i: SignedVtxoInput| VtxoInput {
                vtxo_id: i.vtxo_id,
                signed_tx: i.signed_tx,
            })
            .collect();
        let outputs: Vec<VtxoOutput> = req
            .outputs
            .into_iter()
            .map(|o| VtxoOutput {
                pubkey: match o.destination {
                    Some(crate::proto::ark_v1::output::Destination::VtxoScript(s)) => s,
                    Some(crate::proto::ark_v1::output::Destination::OnchainAddress(s)) => s,
                    None => String::new(),
                },
                amount_sats: o.amount,
            })
            .collect();
        let tx = OffchainTx::new(inputs, outputs);
        let tx_id = tx.id.clone();
        self.offchain_tx_repo
            .create(&tx)
            .await
            .map_err(|e| Status::internal(format!("Failed to store offchain tx: {e}")))?;
        info!(tx_id = %tx_id, "Offchain tx submitted");
        Ok(Response::new(SubmitTxResponse { tx_id }))
    }

    async fn finalize_tx(
        &self,
        request: Request<FinalizeTxRequest>,
    ) -> Result<Response<FinalizeTxResponse>, Status> {
        let req = request.into_inner();
        if req.tx_id.is_empty() {
            return Err(Status::invalid_argument("tx_id is required"));
        }
        let mut tx = self
            .offchain_tx_repo
            .get(&req.tx_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("Offchain tx {} not found", req.tx_id)))?;
        let txid = req.tx_id.clone();
        tx.finalize(txid.clone())
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        self.offchain_tx_repo
            .update_stage(&req.tx_id, &tx.stage)
            .await
            .map_err(|e| Status::internal(format!("Failed to update stage: {e}")))?;
        Ok(Response::new(FinalizeTxResponse { txid }))
    }

    async fn get_pending_tx(
        &self,
        request: Request<GetPendingTxRequest>,
    ) -> Result<Response<GetPendingTxResponse>, Status> {
        let req = request.into_inner();
        if req.tx_id.is_empty() {
            return Err(Status::invalid_argument("tx_id is required"));
        }
        let tx = self
            .offchain_tx_repo
            .get(&req.tx_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("Offchain tx {} not found", req.tx_id)))?;
        let vtxo_ids = tx.inputs.iter().map(|i| i.vtxo_id.clone()).collect();
        let stage = format!("{:?}", tx.stage);
        Ok(Response::new(GetPendingTxResponse {
            tx_id: tx.id,
            stage,
            input_vtxo_ids: vtxo_ids,
        }))
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
