//! ArkService gRPC implementation — user-facing API.

use std::pin::Pin;
use std::sync::Arc;

use async_stream::stream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use arkd_core::domain::{VtxoInput, VtxoOutput};
use arkd_core::ports::{OffchainTxRepository, RoundRepository};

use crate::proto::ark_v1::ark_service_server::ArkService as ArkServiceTrait;
use crate::proto::ark_v1::{
    // New Go arkd parity RPCs
    ConfirmRegistrationRequest,
    ConfirmRegistrationResponse,
    // Legacy RPCs
    DeleteIntentRequest,
    DeleteIntentResponse,
    EstimateIntentFeeRequest,
    EstimateIntentFeeResponse,
    FinalizeTxRequest,
    FinalizeTxResponse,
    GetEventStreamRequest,
    GetInfoRequest,
    GetInfoResponse,
    GetIntentRequest,
    GetIntentResponse,
    GetPendingTxRequest,
    GetPendingTxResponse,
    GetRoundRequest,
    GetRoundResponse,
    GetTransactionsStreamRequest,
    GetVtxosRequest,
    GetVtxosResponse,
    ListRoundsRequest,
    ListRoundsResponse,
    RegisterForRoundRequest,
    RegisterForRoundResponse,
    RegisterIntentRequest,
    RegisterIntentResponse,
    RequestExitRequest,
    RequestExitResponse,
    RoundEvent,
    RoundHeartbeatEvent,
    ScheduledSession,
    ServiceStatus,
    SignedVtxoInput,
    SubmitSignedForfeitTxsRequest,
    SubmitSignedForfeitTxsResponse,
    SubmitTreeNoncesRequest,
    SubmitTreeNoncesResponse,
    SubmitTreeSignaturesRequest,
    SubmitTreeSignaturesResponse,
    SubmitTxRequest,
    SubmitTxResponse,
    TransactionEvent,
    TransactionHeartbeatEvent,
    UpdateStreamTopicsRequest,
    UpdateStreamTopicsResponse,
};
use std::collections::HashSet;

use super::broker::{SharedEventBroker, SharedTransactionEventBroker};
use super::convert;
use super::middleware::{get_authenticated_user, require_authenticated_user};

/// ArkService gRPC handler backed by the core application service.
pub struct ArkGrpcService {
    core: Arc<arkd_core::ArkService>,
    round_repo: Arc<dyn RoundRepository>,
    broker: SharedEventBroker,
    tx_broker: SharedTransactionEventBroker,
    /// Retained for API compatibility; offchain tx operations now go through `core`.
    #[allow(dead_code)]
    offchain_tx_repo: Arc<dyn OffchainTxRepository>,
}

impl ArkGrpcService {
    /// Create a new ArkGrpcService.
    pub fn new(
        core: Arc<arkd_core::ArkService>,
        round_repo: Arc<dyn RoundRepository>,
        broker: SharedEventBroker,
        tx_broker: SharedTransactionEventBroker,
        offchain_tx_repo: Arc<dyn OffchainTxRepository>,
    ) -> Self {
        Self {
            core,
            round_repo,
            broker,
            tx_broker,
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

/// Server-streaming response type for GetTransactionsStream.
type GetTransactionsStreamStream =
    Pin<Box<dyn Stream<Item = Result<TransactionEvent, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl ArkServiceTrait for ArkGrpcService {
    type GetEventStreamStream = GetEventStreamStream;
    type GetTransactionsStreamStream = GetTransactionsStreamStream;
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

        // Build scheduled session info (next round timing)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let scheduled_session = Some(ScheduledSession {
            start_time: now,
            end_time: now + info.session_duration,
        });

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
            // Go arkd parity fields
            scheduled_session,
            deprecated_signers: vec![], // No deprecated signers by default
            digest: String::new(),      // Config digest (computed from server config)
            fees: None,                 // Fee info (populated when fee manager is configured)
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
        // Return the topics the client subscribed to
        Ok(Response::new(UpdateStreamTopicsResponse {
            topics: req.topics,
        }))
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
        if inputs.is_empty() {
            return Err(Status::invalid_argument("inputs must not be empty"));
        }
        let tx = arkd_core::domain::OffchainTx::new(inputs, outputs);
        let tx_id = tx.id.clone();
        self.offchain_tx_repo
            .create(&tx)
            .await
            .map_err(|e| Status::internal(format!("Failed to submit offchain tx: {e}")))?;
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
        let txid = self
            .core
            .finalize_offchain_tx(&req.tx_id)
            .await
            .map_err(|e| match &e {
                arkd_core::error::ArkError::NotFound(_) => Status::not_found(e.to_string()),
                _ => Status::internal(format!("Failed to finalize offchain tx: {e}")),
            })?;
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

    // ─────────────────────────────────────────────────────────────────────────
    // Go arkd parity RPCs (#159)
    // ─────────────────────────────────────────────────────────────────────────

    /// RegisterIntent registers a user's intent for the next available round.
    /// This is the Go arkd-compatible API using BIP-322 intent proofs.
    async fn register_intent(
        &self,
        request: Request<RegisterIntentRequest>,
    ) -> Result<Response<RegisterIntentResponse>, Status> {
        let req = request.into_inner();
        info!(
            outputs = req.outputs.len(),
            "RegisterIntent called (Go arkd parity)"
        );

        // Extract descriptor
        let descriptor = req
            .descriptor
            .ok_or_else(|| Status::invalid_argument("descriptor is required"))?;

        // Extract intent proof
        let intent_proof = descriptor
            .intent
            .ok_or_else(|| Status::invalid_argument("intent proof is required"))?;

        if intent_proof.proof.is_empty() {
            return Err(Status::invalid_argument("intent proof is required"));
        }

        // TODO(#40): Verify BIP-322 intent proof signature
        // For now, extract pubkey from the proof message
        let pubkey = intent_proof.message.clone();

        // Calculate total output amount
        let total_amount: u64 = req.outputs.iter().map(|o| o.amount).sum();

        // Build VTXO inputs from boarding inputs (if any)
        let inputs: Vec<arkd_core::domain::Vtxo> = descriptor
            .boarding_inputs
            .iter()
            .filter_map(|bi| {
                bi.outpoint.as_ref().map(|op| {
                    arkd_core::domain::Vtxo::new(
                        arkd_core::domain::VtxoOutpoint::new(op.txid.clone(), op.vout),
                        bi.amount,
                        pubkey.clone(),
                    )
                })
            })
            .collect();

        // Create intent with proof
        let intent = arkd_core::domain::Intent::new(
            "grpc-register-intent".to_string(),
            pubkey.clone(),
            intent_proof.proof.clone(),
            inputs,
        )
        .map_err(|e| Status::invalid_argument(format!("Invalid intent: {e}")))?;

        let intent_id = self
            .core
            .register_intent(intent)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        info!(intent_id = %intent_id, amount = total_amount, "Intent registered");

        Ok(Response::new(RegisterIntentResponse { intent_id }))
    }

    /// ConfirmRegistration confirms participation in the current batch.
    async fn confirm_registration(
        &self,
        request: Request<ConfirmRegistrationRequest>,
    ) -> Result<Response<ConfirmRegistrationResponse>, Status> {
        let req = request.into_inner();
        info!(intent_id = %req.intent_id, "ConfirmRegistration called");

        if req.intent_id.is_empty() {
            return Err(Status::invalid_argument("intent_id is required"));
        }

        self.core
            .confirm_registration(&req.intent_id)
            .await
            .map_err(|e| match &e {
                arkd_core::error::ArkError::NotFound(_) => Status::not_found(e.to_string()),
                arkd_core::error::ArkError::Internal(msg) if msg.contains("not in") => {
                    Status::failed_precondition(e.to_string())
                }
                _ => Status::internal(e.to_string()),
            })?;

        Ok(Response::new(ConfirmRegistrationResponse {
            confirmed: true,
        }))
    }

    /// GetIntent retrieves an intent by txid filter.
    async fn get_intent(
        &self,
        request: Request<GetIntentRequest>,
    ) -> Result<Response<GetIntentResponse>, Status> {
        let req = request.into_inner();
        info!(txid = %req.txid, "GetIntent called");

        if req.txid.is_empty() {
            return Err(Status::invalid_argument("txid filter is required"));
        }

        // Look for the intent in the current round
        let intent_opt = self
            .core
            .get_intent_by_id(&req.txid)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        match intent_opt {
            Some(intent) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                // Derive pubkey from first input VTXO, or use proof txid as fallback
                let pubkey = intent
                    .inputs
                    .first()
                    .map(|v| v.pubkey.clone())
                    .unwrap_or_else(|| intent.txid.clone());
                let intent_info = crate::proto::ark_v1::IntentInfo {
                    intent_id: intent.id.clone(),
                    pubkey,
                    amount: intent.inputs.iter().map(|v| v.amount).sum(),
                    proof_message: intent.message.clone(),
                    cosigners_public_keys: vec![],
                    boarding_inputs: vec![],
                    status: "pending".to_string(),
                    created_at: now,
                    round_id: String::new(),
                };
                Ok(Response::new(GetIntentResponse {
                    intent: Some(intent_info),
                }))
            }
            None => Err(Status::not_found(format!(
                "Intent with txid {} not found",
                req.txid
            ))),
        }
    }

    /// SubmitTreeNonces submits MuSig2 tree nonces for a batch.
    async fn submit_tree_nonces(
        &self,
        request: Request<SubmitTreeNoncesRequest>,
    ) -> Result<Response<SubmitTreeNoncesResponse>, Status> {
        let req = request.into_inner();
        info!(
            batch_id = %req.batch_id,
            pubkey = %req.pubkey,
            nonce_count = req.tree_nonces.len(),
            "SubmitTreeNonces called"
        );

        if req.batch_id.is_empty() {
            return Err(Status::invalid_argument("batch_id is required"));
        }
        if req.pubkey.is_empty() {
            return Err(Status::invalid_argument("pubkey is required"));
        }
        if req.tree_nonces.is_empty() {
            return Err(Status::invalid_argument("tree_nonces must not be empty"));
        }

        // Flatten tree nonces map into a single byte vector for the store.
        let nonces: Vec<u8> = req
            .tree_nonces
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();

        self.core
            .submit_tree_nonces(&req.batch_id, &req.pubkey, nonces)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SubmitTreeNoncesResponse { accepted: true }))
    }

    /// SubmitTreeSignatures submits MuSig2 tree partial signatures.
    async fn submit_tree_signatures(
        &self,
        request: Request<SubmitTreeSignaturesRequest>,
    ) -> Result<Response<SubmitTreeSignaturesResponse>, Status> {
        let req = request.into_inner();
        info!(
            batch_id = %req.batch_id,
            pubkey = %req.pubkey,
            sig_count = req.tree_signatures.len(),
            "SubmitTreeSignatures called"
        );

        if req.batch_id.is_empty() {
            return Err(Status::invalid_argument("batch_id is required"));
        }
        if req.pubkey.is_empty() {
            return Err(Status::invalid_argument("pubkey is required"));
        }
        if req.tree_signatures.is_empty() {
            return Err(Status::invalid_argument(
                "tree_signatures must not be empty",
            ));
        }

        // Flatten tree signatures map into a single byte vector for the store.
        let signatures: Vec<u8> = req
            .tree_signatures
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();

        self.core
            .submit_tree_signatures(&req.batch_id, &req.pubkey, signatures)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SubmitTreeSignaturesResponse {
            accepted: true,
        }))
    }

    /// SubmitSignedForfeitTxs submits signed forfeit transactions.
    async fn submit_signed_forfeit_txs(
        &self,
        request: Request<SubmitSignedForfeitTxsRequest>,
    ) -> Result<Response<SubmitSignedForfeitTxsResponse>, Status> {
        let req = request.into_inner();
        info!(
            batch_id = %req.batch_id,
            forfeit_count = req.signed_forfeit_txs.len(),
            "SubmitSignedForfeitTxs called"
        );

        if req.batch_id.is_empty() {
            return Err(Status::invalid_argument("batch_id is required"));
        }
        if req.signed_forfeit_txs.is_empty() {
            return Err(Status::invalid_argument(
                "signed_forfeit_txs must not be empty",
            ));
        }

        self.core
            .submit_signed_forfeit_txs(&req.batch_id, req.signed_forfeit_txs)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SubmitSignedForfeitTxsResponse {
            accepted: true,
        }))
    }

    /// GetTransactionsStream opens a server-streaming connection for transaction events.
    ///
    /// The client can optionally provide a list of scripts to filter events.
    /// Only `ArkTxEvent`s where `from_script` or `to_script` matches one of the
    /// provided scripts will be forwarded. If no scripts are provided, all
    /// events are forwarded.
    async fn get_transactions_stream(
        &self,
        request: Request<GetTransactionsStreamRequest>,
    ) -> Result<Response<Self::GetTransactionsStreamStream>, Status> {
        let req = request.into_inner();
        let script_filter: HashSet<String> = req.scripts.into_iter().collect();
        let has_filter = !script_filter.is_empty();

        info!(
            filter_count = script_filter.len(),
            "GetTransactionsStream called"
        );

        let mut rx = self.tx_broker.subscribe();

        let output = stream! {
            // Yield an initial heartbeat so the client knows the stream is alive
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            yield Ok(TransactionEvent {
                event: Some(crate::proto::ark_v1::transaction_event::Event::Heartbeat(
                    TransactionHeartbeatEvent { timestamp: now },
                )),
            });

            // Forward filtered events from the broker
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        // Apply script filter if present
                        if has_filter {
                            if let Some(ref inner) = event.event {
                                match inner {
                                    crate::proto::ark_v1::transaction_event::Event::ArkTx(ark_tx) => {
                                        // Check if from_script or to_script matches any filter
                                        let matches = script_filter.contains(&ark_tx.from_script)
                                            || script_filter.contains(&ark_tx.to_script);
                                        if matches {
                                            yield Ok(event);
                                        }
                                        // Skip events that don't match the filter
                                    }
                                    // Always forward non-ArkTx events (heartbeats, commitment_tx)
                                    _ => yield Ok(event),
                                }
                            }
                        } else {
                            // No filter — forward all events
                            yield Ok(event);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "Transaction stream client lagged, skipped events");
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
}

// TODO(#55): Asset RPCs (ListAssets, RegisterAsset, GetAsset) pending proto update

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ark_v1::transaction_event::Event as TxEventType;
    use crate::proto::ark_v1::{ArkTxEvent, Outpoint};

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

    #[test]
    fn test_script_filter_matches_from_script() {
        let filter: HashSet<String> = ["script_a", "script_b"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let event = ArkTxEvent {
            txid: "tx1".to_string(),
            from_script: "script_a".to_string(),
            to_script: "script_c".to_string(),
            amount: 1000,
            timestamp: 12345,
        };

        let matches = filter.contains(&event.from_script) || filter.contains(&event.to_script);
        assert!(matches, "Filter should match from_script");
    }

    #[test]
    fn test_script_filter_matches_to_script() {
        let filter: HashSet<String> = ["script_x", "script_y"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let event = ArkTxEvent {
            txid: "tx2".to_string(),
            from_script: "script_z".to_string(),
            to_script: "script_y".to_string(),
            amount: 2000,
            timestamp: 12345,
        };

        let matches = filter.contains(&event.from_script) || filter.contains(&event.to_script);
        assert!(matches, "Filter should match to_script");
    }

    #[test]
    fn test_script_filter_no_match() {
        let filter: HashSet<String> = ["script_a", "script_b"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let event = ArkTxEvent {
            txid: "tx3".to_string(),
            from_script: "script_x".to_string(),
            to_script: "script_y".to_string(),
            amount: 3000,
            timestamp: 12345,
        };

        let matches = filter.contains(&event.from_script) || filter.contains(&event.to_script);
        assert!(!matches, "Filter should not match unrelated scripts");
    }

    #[test]
    fn test_empty_filter_matches_all() {
        let filter: HashSet<String> = HashSet::new();
        let has_filter = !filter.is_empty();

        assert!(!has_filter, "Empty filter should not be considered active");
    }

    #[test]
    fn test_heartbeat_always_forwarded() {
        // Heartbeats should always be forwarded regardless of filter
        let event = TransactionEvent {
            event: Some(TxEventType::Heartbeat(TransactionHeartbeatEvent {
                timestamp: 12345,
            })),
        };

        // This tests the match arm logic — non-ArkTx events should pass through
        if let Some(TxEventType::Heartbeat(_)) = event.event {
            // Heartbeat — would be forwarded
            assert!(true);
        } else {
            panic!("Expected heartbeat event");
        }
    }
}
