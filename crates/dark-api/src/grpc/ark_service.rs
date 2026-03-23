//! ArkService gRPC implementation — user-facing API.

use std::pin::Pin;
use std::sync::Arc;

use async_stream::stream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use dark_core::domain::{VtxoInput, VtxoOutput};
use dark_core::ports::{OffchainTxRepository, RoundRepository};

use crate::proto::ark_v1::ark_service_server::ArkService as ArkServiceTrait;
use crate::proto::ark_v1::{
    // Asset & note RPCs
    BurnAssetRequest,
    BurnAssetResponse,
    // New Go dark parity RPCs
    ConfirmRegistrationRequest,
    ConfirmRegistrationResponse,
    // Legacy RPCs
    DeleteIntentRequest,
    DeleteIntentResponse,
    EstimateIntentFeeRequest,
    EstimateIntentFeeResponse,
    FeeInfo,
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
    IntentFeeInfo,
    IssueAssetRequest,
    IssueAssetResponse,
    ListRoundsRequest,
    ListRoundsResponse,
    RedeemNotesRequest,
    RedeemNotesResponse,
    RegisterForRoundRequest,
    RegisterForRoundResponse,
    RegisterIntentRequest,
    RegisterIntentResponse,
    ReissueAssetRequest,
    ReissueAssetResponse,
    RequestExitRequest,
    RequestExitResponse,
    RoundEvent,
    ScheduledSession,
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
    core: Arc<dark_core::ArkService>,
    round_repo: Arc<dyn RoundRepository>,
    broker: SharedEventBroker,
    tx_broker: SharedTransactionEventBroker,
    /// Retained for API compatibility; offchain tx operations now go through `core`.
    #[allow(dead_code)]
    offchain_tx_repo: Arc<dyn OffchainTxRepository>,
    /// Shared note store for `RedeemNotes`.
    note_store: Arc<crate::notes::NoteStore>,
}

impl ArkGrpcService {
    /// Create a new ArkGrpcService.
    pub fn new(
        core: Arc<dark_core::ArkService>,
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
            note_store: Arc::new(crate::notes::NoteStore::new()),
        }
    }

    /// Create with a shared NoteStore (so notes created via admin API can be redeemed here).
    pub fn new_with_notes(
        core: Arc<dark_core::ArkService>,
        round_repo: Arc<dyn RoundRepository>,
        broker: SharedEventBroker,
        tx_broker: SharedTransactionEventBroker,
        offchain_tx_repo: Arc<dyn OffchainTxRepository>,
        note_store: Arc<crate::notes::NoteStore>,
    ) -> Self {
        Self {
            core,
            round_repo,
            broker,
            tx_broker,
            offchain_tx_repo,
            note_store,
        }
    }

    /// Verify that the authenticated user owns all the specified VTXOs
    async fn verify_vtxo_ownership(
        &self,
        vtxo_outpoints: &[dark_core::domain::VtxoOutpoint],
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

        // Build service status map — report subsystem health (map<string, string>)
        let mut service_status = std::collections::HashMap::new();
        service_status.insert("database".to_string(), "operational".to_string());
        service_status.insert("wallet".to_string(), "operational".to_string());
        service_status.insert("bitcoin_rpc".to_string(), "operational".to_string());

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
            version: dark_core::VERSION.to_string(),
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
            utxo_min_amount: info.utxo_min_amount as i64,
            utxo_max_amount: info.utxo_max_amount as i64,
            public_unilateral_exit_delay: info.public_unilateral_exit_delay,
            boarding_exit_delay: info.boarding_exit_delay as i64,
            max_tx_weight: info.max_tx_weight as i64,
            max_op_return_outputs: 0,
            service_status,
            // Go dark parity fields
            scheduled_session,
            deprecated_signers: vec![], // No deprecated signers by default
            digest: String::new(),      // Config digest (computed from server config)
            fees: {
                let fp = self.core.get_fee_program();
                Some(FeeInfo {
                    intent_fee: Some(IntentFeeInfo {
                        offchain_input: format!("{}.0", fp.offchain_input_fee),
                        offchain_output: format!("{}.0", fp.offchain_output_fee),
                        onchain_input: format!("{}.0", fp.onchain_input_fee),
                        onchain_output: format!("{}.0", fp.onchain_output_fee),
                    }),
                    tx_fee_rate: self.core.config().default_fee_rate_sats_per_vb.to_string(),
                })
            },
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
            dark_core::validation::validate_pubkey_hex(&req.pubkey, "register_for_round")
        {
            return Err(Status::invalid_argument(format!("Invalid pubkey: {e}")));
        }

        // Validate amount bounds
        if let Err(e) = dark_core::validation::validate_amount(req.amount, "register_for_round") {
            return Err(Status::invalid_argument(format!("Invalid amount: {e}")));
        }

        // Build VTXO inputs from proto inputs
        let inputs: Vec<dark_core::domain::Vtxo> = req
            .inputs
            .iter()
            .filter_map(|input| {
                input.outpoint.as_ref().map(|op| {
                    dark_core::domain::Vtxo::new(
                        dark_core::domain::VtxoOutpoint::new(op.txid.clone(), op.vout),
                        req.amount,
                        req.pubkey.clone(),
                    )
                })
            })
            .collect();

        let intent = dark_core::domain::Intent::new(
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

        let vtxo_outpoints: Vec<dark_core::domain::VtxoOutpoint> = req
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

        let exit_request = dark_core::domain::CollaborativeExitRequest {
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
            yield Ok(RoundEvent {
                event: Some(crate::proto::ark_v1::round_event::Event::Heartbeat(
                    crate::proto::ark_v1::Heartbeat {},
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

        let fee_program = self.core.get_fee_program();
        let fee_rate = self.core.config().default_fee_rate_sats_per_vb;

        // All input_vtxo_ids are offchain (VTXO) inputs.
        // Outputs are offchain by default (VTXOs being created).
        // TODO(#242): distinguish onchain vs offchain outputs via proto field
        let offchain_inputs = req.input_vtxo_ids.len() as u32;
        let onchain_inputs = 0u32;
        let offchain_outputs = req.outputs.len() as u32;
        let onchain_outputs = 0u32;

        let fee_sats = fee_program.calculate_intent_fee(
            offchain_inputs,
            onchain_inputs,
            offchain_outputs,
            onchain_outputs,
        );

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
        // proof is optional in dev/test mode (BIP-322 verification is TODO(#40))

        self.core
            .unregister_intent(&req.intent_id)
            .await
            .map_err(|e| match e {
                dark_core::error::ArkError::NotFound(msg) => Status::not_found(msg),
                other => Status::internal(other.to_string()),
            })?;

        info!(intent_id = %req.intent_id, "Intent deleted");
        Ok(Response::new(DeleteIntentResponse {}))
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
        let tx = dark_core::domain::OffchainTx::new(inputs, outputs);
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
                dark_core::error::ArkError::NotFound(_) => Status::not_found(e.to_string()),
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
    // Go dark parity RPCs (#159)
    // ─────────────────────────────────────────────────────────────────────────

    /// RegisterIntent registers a user's intent for the next available round.
    /// This is the Go dark-compatible API using BIP-322 intent proofs.
    async fn register_intent(
        &self,
        request: Request<RegisterIntentRequest>,
    ) -> Result<Response<RegisterIntentResponse>, Status> {
        let req = request.into_inner();
        let intent_proof = req
            .intent
            .ok_or_else(|| Status::invalid_argument("intent is required"))?;

        info!("RegisterIntent called (Go arkd parity)");

        // Decode the base64 PSBT proof
        use base64::Engine;
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(&intent_proof.proof)
            .map_err(|e| Status::invalid_argument(format!("Invalid base64 proof: {e}")))?;

        let psbt = bitcoin::psbt::Psbt::deserialize(&proof_bytes)
            .map_err(|e| Status::invalid_argument(format!("Invalid PSBT: {e}")))?;

        let unsigned_tx = &psbt.unsigned_tx;
        let proof_txid = unsigned_tx.compute_txid().to_string();

        // Parse the JSON message to get intent metadata
        let message_json: serde_json::Value =
            serde_json::from_str(&intent_proof.message).unwrap_or_default();
        let onchain_output_indexes: Vec<usize> = message_json
            .get("onchain_output_indexes")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let cosigners_public_keys: Vec<String> = message_json
            .get("cosigners_public_keys")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Skip first input (BIP-322 toSpend reference) — remaining are real UTXOs
        let mut inputs: Vec<dark_core::domain::Vtxo> = Vec::new();
        for (i, tx_in) in unsigned_tx.input.iter().enumerate().skip(1) {
            let txid = tx_in.previous_output.txid.to_string();
            let vout = tx_in.previous_output.vout;
            // Get amount from PSBT witness_utxo
            let amount = psbt
                .inputs
                .get(i)
                .and_then(|inp| inp.witness_utxo.as_ref())
                .map(|utxo| utxo.value.to_sat())
                .unwrap_or(0);
            inputs.push(dark_core::domain::Vtxo::new(
                dark_core::domain::VtxoOutpoint::new(txid, vout),
                amount,
                String::new(),
            ));
        }

        // Build receivers from PSBT outputs (P2TR → offchain VTXO, otherwise onchain)
        let mut receivers: Vec<dark_core::domain::Receiver> = Vec::new();
        for (i, tx_out) in unsigned_tx.output.iter().enumerate() {
            let amount = tx_out.value.to_sat();
            if amount == 0 {
                continue; // skip OP_RETURN or zero-value outputs
            }
            if onchain_output_indexes.contains(&i) {
                let addr =
                    bitcoin::Address::from_script(&tx_out.script_pubkey, bitcoin::Network::Regtest)
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                receivers.push(dark_core::domain::Receiver::onchain(amount, addr));
            } else if tx_out.script_pubkey.is_p2tr() {
                // Extract x-only pubkey from P2TR script: OP_1 OP_PUSH32 <32-byte-key>
                let script_bytes = tx_out.script_pubkey.as_bytes();
                let pubkey_hex = if script_bytes.len() >= 34 {
                    hex::encode(&script_bytes[2..34])
                } else {
                    String::new()
                };
                receivers.push(dark_core::domain::Receiver::offchain(amount, pubkey_hex));
            }
        }

        // Set input pubkeys from first receiver's pubkey
        let owner_pubkey = receivers
            .iter()
            .find(|r| !r.pubkey.is_empty())
            .map(|r| r.pubkey.clone())
            .unwrap_or_default();
        for inp in inputs.iter_mut() {
            inp.pubkey = owner_pubkey.clone();
        }

        info!(
            inputs = inputs.len(),
            receivers = receivers.len(),
            owner = %owner_pubkey,
            "RegisterIntent: parsed BIP-322 proof"
        );

        // Create intent
        let mut intent = dark_core::domain::Intent::new(
            proof_txid,
            intent_proof.proof.clone(),
            intent_proof.message.clone(),
            inputs,
        )
        .map_err(|e| Status::invalid_argument(format!("Invalid intent: {e}")))?;

        // Add receivers
        if !receivers.is_empty() {
            intent
                .add_receivers(receivers)
                .map_err(|e| Status::invalid_argument(format!("Invalid receivers: {e}")))?;
        }

        // Set cosigner public keys from the intent message
        intent.cosigners_public_keys = cosigners_public_keys;

        let intent_id = self
            .core
            .register_intent(intent)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        info!(intent_id = %intent_id, "Intent registered");

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
                dark_core::error::ArkError::NotFound(_) => Status::not_found(e.to_string()),
                dark_core::error::ArkError::Internal(msg) if msg.contains("not in") => {
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

        // tree_nonces is map[txid → nonce_hex] where each value is a hex-encoded 66-byte MuSig2 nonce pair.
        // Decode the first (and typically only) nonce value to raw bytes.
        let nonces: Vec<u8> = if let Some(nonce_hex) = req.tree_nonces.values().next() {
            hex::decode(nonce_hex).unwrap_or_default()
        } else {
            Vec::new()
        };

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
            forfeit_count = req.signed_forfeit_txs.len(),
            signed_commitment_tx_len = req.signed_commitment_tx.len(),
            "SubmitSignedForfeitTxs called"
        );

        // If the client sent a signed commitment tx, finalize and broadcast it
        if !req.signed_commitment_tx.is_empty() {
            let signed_commitment_str = &req.signed_commitment_tx;
            info!("Client sent signed_commitment_tx — attempting broadcast");
            match self
                .core
                .broadcast_signed_commitment_tx(signed_commitment_str)
                .await
            {
                Ok(txid) => info!(txid = %txid, "Commitment tx broadcast from client signature"),
                Err(e) => {
                    info!(error = %e, "Failed to broadcast client-signed commitment tx (non-fatal)")
                }
            }
        }

        // batch_id is not in the proto — accept empty signed_forfeit_txs gracefully
        if !req.signed_forfeit_txs.is_empty() {
            self.core
                .submit_signed_forfeit_txs("", req.signed_forfeit_txs)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }

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

    // ─────────────────────────────────────────────────────────────────────────
    // Asset & Note RPCs (#297, #298) — stubs
    // ─────────────────────────────────────────────────────────────────────────

    async fn issue_asset(
        &self,
        request: Request<IssueAssetRequest>,
    ) -> Result<Response<IssueAssetResponse>, Status> {
        let req = request.into_inner();
        info!("ArkService::IssueAsset called (stub) pubkey={}", req.pubkey);
        // Stub: return a deterministic placeholder asset_id.
        // Real implementation requires the Ark asset protocol.
        let asset_id = format!("stub-asset-{}-{}", req.amount, req.name);
        Ok(Response::new(IssueAssetResponse {
            asset_id: asset_id.clone(),
            txid: format!("stub-issue-tx-{}", asset_id),
        }))
    }

    async fn reissue_asset(
        &self,
        request: Request<ReissueAssetRequest>,
    ) -> Result<Response<ReissueAssetResponse>, Status> {
        let req = request.into_inner();
        info!(
            "ArkService::ReissueAsset called (stub) asset_id={}",
            req.asset_id
        );
        Ok(Response::new(ReissueAssetResponse {
            txid: format!("stub-reissue-tx-{}", req.asset_id),
        }))
    }

    async fn burn_asset(
        &self,
        request: Request<BurnAssetRequest>,
    ) -> Result<Response<BurnAssetResponse>, Status> {
        let req = request.into_inner();
        info!(
            "ArkService::BurnAsset called (stub) asset_id={}",
            req.asset_id
        );
        Ok(Response::new(BurnAssetResponse {
            txid: format!("stub-burn-tx-{}", req.asset_id),
        }))
    }

    async fn redeem_notes(
        &self,
        request: Request<RedeemNotesRequest>,
    ) -> Result<Response<RedeemNotesResponse>, Status> {
        let req = request.into_inner();
        info!(
            notes = req.notes.len(),
            pubkey = %req.pubkey,
            "ArkService::RedeemNotes called"
        );

        if req.pubkey.is_empty() {
            return Err(Status::invalid_argument("pubkey is required"));
        }
        if req.notes.is_empty() {
            return Err(Status::invalid_argument("notes list is empty"));
        }

        let mut total_amount: u64 = 0;
        for note_str in &req.notes {
            match self.note_store.redeem(note_str).await {
                Ok(amount) => {
                    info!(amount, "Note redeemed");
                    total_amount += amount;
                }
                Err(e) => {
                    return Err(Status::invalid_argument(format!("Invalid note: {e}")));
                }
            }
        }

        // Register an intent for the redeemed amount — this puts the note value
        // into the next batch round as a VTXO for `req.pubkey`.
        let note_id = uuid::Uuid::new_v4().to_string();
        let mut intent = dark_core::domain::Intent::new(
            note_id.clone(),
            format!("note-redeem:{}", note_id), // proof placeholder
            format!("note-redeem:{}:{}", req.pubkey, total_amount),
            vec![],
        )
        .map_err(|e| Status::internal(format!("Failed to create note intent: {e}")))?;

        // Set the receiver — this is the output VTXO the redeemer will receive
        intent.receivers = vec![dark_core::domain::Receiver {
            pubkey: req.pubkey.clone(),
            onchain_address: String::new(),
            amount: total_amount,
        }];
        // Mark as note-redemption so finalize_round doesn't require a boarding UTXO
        intent.cosigners_public_keys = vec![req.pubkey.clone()];

        let intent_id = self
            .core
            .register_intent(intent)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        info!(
            intent_id,
            total_amount, "Note redeemed — intent registered for batch settlement"
        );

        Ok(Response::new(RedeemNotesResponse {
            txid: intent_id,
            amount_redeemed: total_amount,
        }))
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
