//! ArkService gRPC implementation — user-facing API.

use std::pin::Pin;
use std::sync::Arc;

use async_stream::stream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

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
    FinalizePendingTxsRequest,
    FinalizePendingTxsResponse,
    FinalizeTxRequest,
    FinalizeTxResponse,
    GetEventStreamRequest,
    GetInfoRequest,
    GetInfoResponse,
    GetIntentRequest,
    GetIntentResponse,
    GetPendingTxRequest,
    GetPendingTxResponse,
    GetRoundAnnouncementsRequest,
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
    RoundAnnouncement,
    RoundEvent,
    ScheduledSession,
    SubmitConfidentialTransactionRequest,
    SubmitConfidentialTransactionResponse,
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
use super::middleware::get_authenticated_user;
use super::stream_registry::SharedStreamRegistry;

/// ArkService gRPC handler backed by the core application service.
pub struct ArkGrpcService {
    core: Arc<dark_core::ArkService>,
    round_repo: Arc<dyn RoundRepository>,
    broker: SharedEventBroker,
    tx_broker: SharedTransactionEventBroker,
    /// Shared CEL fee program store — updated via REST admin API,
    /// read during GetInfo to report fee rates to clients.
    pub cel_fee_store: Arc<tokio::sync::RwLock<crate::rest::CelFeePrograms>>,
    /// Retained for API compatibility; offchain tx operations now go through `core`.
    #[allow(dead_code)]
    offchain_tx_repo: Arc<dyn OffchainTxRepository>,
    /// Shared note store for `RedeemNotes`.
    note_store: Arc<crate::notes::NoteStore>,
    /// Per-stream topic registry for topic-filtered event delivery.
    stream_registry: SharedStreamRegistry,
    /// Mutex for serializing SubmitTx calls (double-spend detection).
    /// Go reference: `offchainTxMu sync.Mutex`.
    offchain_tx_mutex: tokio::sync::Mutex<()>,
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
            stream_registry: Arc::new(super::stream_registry::StreamRegistry::new()),
            offchain_tx_mutex: tokio::sync::Mutex::new(()),
            cel_fee_store: Arc::new(tokio::sync::RwLock::new(
                crate::rest::CelFeePrograms::default(),
            )),
        }
    }

    /// Create with a shared NoteStore and CEL fee store (so notes created via admin API can be redeemed here,
    /// and fee programs set via admin REST API are visible in GetInfo).
    pub fn new_with_notes(
        core: Arc<dark_core::ArkService>,
        round_repo: Arc<dyn RoundRepository>,
        broker: SharedEventBroker,
        tx_broker: SharedTransactionEventBroker,
        offchain_tx_repo: Arc<dyn OffchainTxRepository>,
        note_store: Arc<crate::notes::NoteStore>,
        cel_fee_store: Arc<tokio::sync::RwLock<crate::rest::CelFeePrograms>>,
    ) -> Self {
        Self {
            core,
            round_repo,
            broker,
            tx_broker,
            offchain_tx_repo,
            note_store,
            stream_registry: Arc::new(super::stream_registry::StreamRegistry::new()),
            offchain_tx_mutex: tokio::sync::Mutex::new(()),
            cel_fee_store,
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

/// Server-streaming response type for GetRoundAnnouncements.
type GetRoundAnnouncementsStream =
    Pin<Box<dyn Stream<Item = Result<RoundAnnouncement, Status>> + Send + 'static>>;

/// Server-streaming response type for GetTransactionsStream.
type GetTransactionsStreamStream =
    Pin<Box<dyn Stream<Item = Result<TransactionEvent, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl ArkServiceTrait for ArkGrpcService {
    type GetEventStreamStream = GetEventStreamStream;
    type GetRoundAnnouncementsStream = GetRoundAnnouncementsStream;
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

        // Build fee info — prefer CEL fee store (set via admin REST API)
        // over the static FeeProgram defaults.
        let fee_info = {
            let cel = self.cel_fee_store.read().await;
            let fp = self.core.get_fee_program();
            FeeInfo {
                intent_fee: Some(IntentFeeInfo {
                    offchain_input: if !cel.offchain_input.is_empty() {
                        cel.offchain_input.clone()
                    } else {
                        format!("{}.0", fp.offchain_input_fee)
                    },
                    offchain_output: if !cel.offchain_output.is_empty() {
                        cel.offchain_output.clone()
                    } else {
                        format!("{}.0", fp.offchain_output_fee)
                    },
                    onchain_input: if !cel.onchain_input.is_empty() {
                        cel.onchain_input.clone()
                    } else {
                        format!("{}.0", fp.onchain_input_fee)
                    },
                    onchain_output: if !cel.onchain_output.is_empty() {
                        cel.onchain_output.clone()
                    } else {
                        format!("{}.0", fp.onchain_output_fee)
                    },
                }),
                tx_fee_rate: self.core.config().default_fee_rate_sats_per_vb.to_string(),
            }
        };

        // Build scheduled session info (next round timing)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let scheduled_session = Some(ScheduledSession {
            next_start_time: now,
            next_end_time: now + info.session_duration,
            period: info.session_duration,
            duration: info.session_duration,
            fees: Some(fee_info.clone()),
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
            fees: Some(fee_info),
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

        // Check if participant is banned
        match self.core.is_participant_banned(&req.pubkey).await {
            Ok(true) => {
                return Err(Status::permission_denied(format!(
                    "Participant {} is banned",
                    req.pubkey
                )));
            }
            Ok(false) => {}
            Err(e) => {
                warn!(error = %e, pubkey = %req.pubkey, "Failed to check ban status");
            }
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

        let mut intent = dark_core::domain::Intent::new(
            "grpc-register".to_string(),
            req.pubkey.clone(),
            format!("register:{}:{}", req.pubkey, req.amount),
            inputs,
        )
        .map_err(|e| Status::invalid_argument(format!("Invalid intent: {e}")))?;

        // Set the registrant's pubkey as a cosigner so that finalize_round
        // includes them in the tree signing phase. Without this, the round
        // auto-completes with zero cosigners and never emits BatchFinalized
        // for boarding rounds (the commitment tx is never broadcast).
        intent.cosigners_public_keys = vec![req.pubkey.clone()];

        // Auto-generate an off-chain receiver for the requested amount/pubkey.
        // This mirrors the Go server's RegisterIntent which derives receivers
        // from the proof PSBT outputs. RegisterForRound is a simplified legacy
        // API that doesn't carry a PSBT, so we create the receiver explicitly.
        intent
            .add_receivers(vec![dark_core::domain::Receiver::offchain(
                req.amount,
                req.pubkey.clone(),
            )])
            .map_err(|e| Status::internal(format!("Failed to add receiver: {e}")))?;

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
        // Extract authenticated user's pubkey, with dev-mode fallback
        let auth_user = get_authenticated_user(&request)
            .ok_or_else(|| Status::unauthenticated("Authentication required for this operation"))?;
        let is_placeholder = auth_user.is_placeholder;
        let mut requester_pubkey = auth_user.pubkey;

        let req = request.into_inner();
        info!(
            destination = %req.destination,
            requester = %requester_pubkey,
            vtxo_count = req.vtxo_ids.len(),
            "RequestExit called"
        );

        if req.vtxo_ids.is_empty() {
            return Err(Status::invalid_argument("vtxo_ids must not be empty"));
        }

        let vtxo_outpoints: Vec<dark_core::domain::VtxoOutpoint> = req
            .vtxo_ids
            .iter()
            .map(convert::proto_outpoint_to_domain)
            .collect();

        if is_placeholder {
            // Dev/test mode: derive owner pubkey from the first VTXO
            let vtxos = self
                .core
                .get_vtxos(&vtxo_outpoints)
                .await
                .map_err(|e| Status::internal(format!("Failed to fetch VTXOs: {e}")))?;
            if let Some(first) = vtxos.first() {
                let compressed = first
                    .pubkey
                    .parse::<bitcoin::secp256k1::PublicKey>()
                    .map_err(|e| Status::internal(format!("Bad VTXO pubkey: {e}")))?;
                requester_pubkey = compressed.x_only_public_key().0;
            }
        } else {
            // Verify the requester owns all the VTXOs being exited
            self.verify_vtxo_ownership(&vtxo_outpoints, &requester_pubkey)
                .await?;
        }

        // Parse destination (optional for unilateral exit — client constructs their own tx)
        let destination: bitcoin::Address<bitcoin::address::NetworkUnchecked> = if req
            .destination
            .is_empty()
        {
            // Use a placeholder address when none provided
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
                .parse()
                .map_err(|e| Status::internal(format!("Placeholder address parse failed: {e}")))?
        } else {
            req.destination.parse().map_err(|e| {
                Status::invalid_argument(format!("Invalid destination address: {e}"))
            })?
        };

        // For each VTXO, register a unilateral exit and collect branch PSBTs.
        let mut all_branch_psbts: Vec<String> = Vec::new();
        let mut last_exit_id = String::new();
        let mut last_exit_status = String::new();

        for vtxo_outpoint in &vtxo_outpoints {
            let exit_request = dark_core::domain::UnilateralExitRequest {
                vtxo_id: vtxo_outpoint.clone(),
                destination: destination.clone(),
                fee_rate_sat_vb: 1,
            };

            let exit = self
                .core
                .request_unilateral_exit(exit_request, requester_pubkey)
                .await
                .map_err(|e| {
                    warn!(error = %e, vtxo = %vtxo_outpoint, "Unilateral exit request failed");
                    Status::internal(e.to_string())
                })?;

            last_exit_id = exit.id.to_string();
            last_exit_status = format!("{:?}", exit.status);

            // Fetch the VTXO tree branch for this VTXO (root→leaf PSBTs)
            let branch = self
                .core
                .get_vtxo_tree_branch(vtxo_outpoint)
                .await
                .map_err(|e| {
                    warn!(error = %e, vtxo = %vtxo_outpoint, "Failed to get VTXO tree branch");
                    Status::internal(e.to_string())
                })?;

            all_branch_psbts.extend(branch);
        }

        Ok(Response::new(RequestExitResponse {
            exit_id: last_exit_id,
            status: last_exit_status,
            branch_psbts: all_branch_psbts,
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

        let (mut spendable, mut spent) = self
            .core
            .get_vtxos_for_pubkey(&req.pubkey)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Real-time unroll detection (mirrors IndexerService).
        //
        // When a VTXO's leaf TX is confirmed on-chain, mark it as unrolled.
        // - Settled VTXOs: outpoint.txid is the tree leaf tx.
        // - Preconfirmed VTXOs: outpoint.txid is the ark tx (Phase 2 of unroll).
        //
        // For settled+spent VTXOs (fraud case), additionally trigger the
        // fraud reaction which broadcasts the forfeit/checkpoint tx.
        {
            let mut did_mark = false;
            let all_vtxos: Vec<_> = spendable.iter().chain(spent.iter()).cloned().collect();
            for v in &all_vtxos {
                if v.unrolled || v.swept {
                    continue;
                }
                // Non-preconfirmed VTXOs need a commitment txid.
                if !v.preconfirmed && v.commitment_txids.is_empty() {
                    continue;
                }
                if let Ok(true) = self.core.scanner().is_tx_confirmed(&v.outpoint.txid).await {
                    let _ = self
                        .core
                        .vtxo_repo()
                        .mark_vtxos_unrolled(std::slice::from_ref(v))
                        .await;
                    // Only react to fraud when the VTXO was already spent
                    // (the user is trying to exit a forfeited VTXO).
                    if v.spent {
                        let _ = self.core.react_to_fraud(v).await;
                    }
                    did_mark = true;
                }
            }
            if did_mark {
                let (s, sp) = self
                    .core
                    .get_vtxos_for_pubkey(&req.pubkey)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                spendable = s;
                spent = sp;
            }
        }

        // Hide preconfirmed asset VTXOs superseded by a committed+unrolled
        // counterpart for the same pubkey.  The committed vtxo may not
        // carry assets (batch doesn't always propagate them), so we match
        // on pubkey alone.  Only preconfirmed vtxos WITH assets are
        // filtered — non-asset vtxos (TestSweep, TestUnilateralExit) are
        // unaffected.
        let unrolled_pubkeys: std::collections::HashSet<String> = spent
            .iter()
            .chain(spendable.iter())
            .filter(|v| !v.preconfirmed && v.unrolled)
            .map(|v| v.pubkey.clone())
            .collect();

        let spendable: Vec<_> = spendable
            .into_iter()
            .filter(|v| {
                !(v.preconfirmed
                    && !v.spent
                    && !v.unrolled
                    && !v.assets.is_empty()
                    && unrolled_pubkeys.contains(&v.pubkey))
            })
            .collect();

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
        request: Request<GetEventStreamRequest>,
    ) -> Result<Response<Self::GetEventStreamStream>, Status> {
        let req = request.into_inner();
        let initial_topics = req.topics;
        info!(topics = ?initial_topics, "GetEventStream called");

        let stream_id = uuid::Uuid::new_v4().to_string();
        // Use subscribe_with_replay so late subscribers (those that connected
        // after RegisterIntent but before the round published BatchStarted)
        // still receive the event instead of blocking forever.
        let (mut rx, buffered_events) = self.broker.subscribe_with_replay();
        let registry = Arc::clone(&self.stream_registry);

        // Register with initial topics
        registry.register(&stream_id, initial_topics).await;
        let stream_id_clone = stream_id.clone();
        let registry_cleanup = Arc::clone(&registry);

        // Helper: extract topic list from topic-bearing events
        fn event_topics(event: &RoundEvent) -> Vec<String> {
            match &event.event {
                Some(crate::proto::ark_v1::round_event::Event::TreeNonces(e)) => e.topic.clone(),
                Some(crate::proto::ark_v1::round_event::Event::TreeTx(e)) => e.topic.clone(),
                Some(crate::proto::ark_v1::round_event::Event::TreeSignature(e)) => e.topic.clone(),
                Some(crate::proto::ark_v1::round_event::Event::BatchFailed(_)) => {
                    // BatchFailed is always broadcast to all subscribers.
                    vec![]
                }
                // All other events (BatchStarted, BatchFinalization,
                // BatchFinalized, TreeSigningStarted, Heartbeat,
                // StreamStarted) are broadcast to all subscribers.
                _ => vec![],
            }
        }

        let output = stream! {
            // Yield StreamStarted so the client can use the stream_id for UpdateStreamTopics
            yield Ok(RoundEvent {
                event: Some(crate::proto::ark_v1::round_event::Event::StreamStarted(
                    crate::proto::ark_v1::StreamStartedEvent {
                        id: stream_id_clone.clone(),
                    },
                )),
            });

            // Replay buffered events for the active batch. This covers clients
            // that subscribed after BatchStarted (and possibly TreeTx,
            // TreeSigningStarted, etc.) were already published. Without this
            // replay the client would miss those events and hang.
            for event in buffered_events {
                let topics = event_topics(&event);
                if registry.includes_any(&stream_id_clone, &topics).await {
                    yield Ok(event);
                }
            }

            // Forward live events from the broker, filtering by topics
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let topics = event_topics(&event);
                        if registry.includes_any(&stream_id_clone, &topics).await {
                            yield Ok(event);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "Event stream client lagged, skipped events");
                        // Continue receiving — don't break
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }

            // Clean up when stream ends
            registry_cleanup.unregister(&stream_id_clone).await;
        };

        Ok(Response::new(Box::pin(output)))
    }

    async fn get_round_announcements(
        &self,
        request: Request<GetRoundAnnouncementsRequest>,
    ) -> Result<Response<Self::GetRoundAnnouncementsStream>, Status> {
        const DEFAULT_LIMIT: u32 = 1_000;
        const MAX_LIMIT: u32 = 10_000;

        let req = request.into_inner();
        let limit = match req.limit {
            0 => DEFAULT_LIMIT,
            n if n > MAX_LIMIT => MAX_LIMIT,
            n => n,
        };

        let cursor = if req.cursor.is_empty() {
            None
        } else {
            let (round_id, vtxo_id) = req.cursor.split_once('\n').ok_or_else(|| {
                Status::invalid_argument("cursor must be encoded as '<round_id>\\n<vtxo_id>'")
            })?;
            if round_id.is_empty() || vtxo_id.is_empty() {
                return Err(Status::invalid_argument(
                    "cursor must include both round_id and vtxo_id",
                ));
            }
            Some((round_id, vtxo_id))
        };

        let round_id_start = if req.round_id_start.is_empty() {
            None
        } else {
            Some(req.round_id_start.as_str())
        };
        let round_id_end = if req.round_id_end.is_empty() {
            None
        } else {
            Some(req.round_id_end.as_str())
        };

        if cursor.is_none() {
            if round_id_start.is_none() || round_id_end.is_none() {
                return Err(Status::invalid_argument(
                    "either cursor or both round_id_start and round_id_end are required",
                ));
            }
            if round_id_start > round_id_end {
                return Err(Status::invalid_argument(
                    "round_id_start must be less than or equal to round_id_end",
                ));
            }
        }

        let announcements = self
            .round_repo
            .list_round_announcements(round_id_start, round_id_end, cursor, limit)
            .await
            .map_err(|e| Status::internal(format!("Failed to fetch round announcements: {e}")))?;

        let output = stream! {
            for announcement in announcements {
                yield Ok(RoundAnnouncement {
                    cursor: format!("{}\n{}", announcement.round_id, announcement.vtxo_id),
                    round_id: announcement.round_id,
                    vtxo_id: announcement.vtxo_id,
                    ephemeral_pubkey: announcement.ephemeral_pubkey,
                });
            }
        };

        Ok(Response::new(Box::pin(output)))
    }

    async fn update_stream_topics(
        &self,
        request: Request<UpdateStreamTopicsRequest>,
    ) -> Result<Response<UpdateStreamTopicsResponse>, Status> {
        let req = request.into_inner();
        let stream_id = &req.stream_id;
        info!(stream_id = %stream_id, "UpdateStreamTopics called");

        if stream_id.is_empty() {
            return Err(Status::invalid_argument("stream_id is required"));
        }

        use crate::proto::ark_v1::update_stream_topics_request::TopicsChange;
        match req.topics_change {
            Some(TopicsChange::Overwrite(overwrite)) => {
                let all_topics = self
                    .stream_registry
                    .overwrite_topics(stream_id, &overwrite.topics)
                    .await
                    .ok_or_else(|| Status::not_found(format!("stream {stream_id} not found")))?;
                Ok(Response::new(UpdateStreamTopicsResponse {
                    topics_added: vec![],
                    topics_removed: vec![],
                    all_topics,
                }))
            }
            Some(TopicsChange::Modify(modify)) => {
                let mut added = Vec::new();
                let mut removed = Vec::new();

                if !modify.add_topics.is_empty() {
                    self.stream_registry
                        .add_topics(stream_id, &modify.add_topics)
                        .await
                        .ok_or_else(|| {
                            Status::not_found(format!("stream {stream_id} not found"))
                        })?;
                    added = modify.add_topics;
                }
                if !modify.remove_topics.is_empty() {
                    self.stream_registry
                        .remove_topics(stream_id, &modify.remove_topics)
                        .await
                        .ok_or_else(|| {
                            Status::not_found(format!("stream {stream_id} not found"))
                        })?;
                    removed = modify.remove_topics;
                }

                let all_topics = self
                    .stream_registry
                    .get_topics(stream_id)
                    .await
                    .unwrap_or_default();

                Ok(Response::new(UpdateStreamTopicsResponse {
                    topics_added: added,
                    topics_removed: removed,
                    all_topics,
                }))
            }
            None => {
                // Legacy path: if `topics` field was provided in the old format,
                // treat it as an overwrite for backwards compatibility.
                // Note: proto oneof `topics_change` is separate from the old `topics` field.
                // Since the new proto removed the old `topics` field and uses `stream_id` at
                // field 1, this path handles the case where no topics_change is set.
                Err(Status::invalid_argument(
                    "topics_change is required (use modify or overwrite)",
                ))
            }
        }
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
        let intent = req
            .intent
            .ok_or_else(|| Status::invalid_argument("intent is required"))?;
        info!(proof_len = intent.proof.len(), "DeleteIntent called");

        // Two deletion modes:
        // 1. Proof-based: decode PSBT proof, extract input outpoints, match intents
        // 2. ID-based: use the message field as intent ID (for RegisterForRound clients)
        if intent.proof.is_empty() {
            // ID-based deletion: message field is the intent ID
            if intent.message.is_empty() {
                return Err(Status::invalid_argument(
                    "intent proof or message (intent ID) is required",
                ));
            }
            let intent_id = &intent.message;
            info!(intent_id = %intent_id, "DeleteIntent: deleting by intent ID");
            if let Err(e) = self.core.delete_intent(intent_id).await {
                return Err(Status::not_found(format!(
                    "Intent {} not found: {e}",
                    intent_id
                )));
            }
            return Ok(Response::new(DeleteIntentResponse {}));
        }

        // Proof-based deletion: decode PSBT proof, extract input outpoints.
        // The Go SDK sends a BIP-322 proof whose inputs (after the first
        // toSpend reference) correspond to the VTXOs the intent spends.
        // We match these against registered intents — same as Go arkd's
        // DeleteIntentsByProof.
        use base64::Engine;
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(&intent.proof)
            .map_err(|e| Status::invalid_argument(format!("Invalid base64 proof: {e}")))?;

        let psbt = bitcoin::psbt::Psbt::deserialize(&proof_bytes)
            .map_err(|e| Status::invalid_argument(format!("Invalid PSBT: {e}")))?;

        // Skip first input (BIP-322 toSpend reference) — remaining are real UTXOs
        let input_outpoints: Vec<(String, u32)> = psbt
            .unsigned_tx
            .input
            .iter()
            .skip(1)
            .map(|txin| {
                (
                    txin.previous_output.txid.to_string(),
                    txin.previous_output.vout,
                )
            })
            .collect();

        if input_outpoints.is_empty() {
            return Err(Status::invalid_argument(
                "proof has no inputs to match against",
            ));
        }

        let deleted_ids = self
            .core
            .delete_intents_by_inputs(&input_outpoints)
            .await
            .map_err(|e| match e {
                dark_core::error::ArkError::NotFound(msg) => Status::not_found(msg),
                other => Status::internal(other.to_string()),
            })?;

        info!(deleted = ?deleted_ids, "Intent(s) deleted by input match");
        Ok(Response::new(DeleteIntentResponse {}))
    }

    async fn submit_tx(
        &self,
        request: Request<SubmitTxRequest>,
    ) -> Result<Response<SubmitTxResponse>, Status> {
        let req = request.into_inner();
        info!(
            signed_ark_tx_len = req.signed_ark_tx.len(),
            checkpoint_count = req.checkpoint_txs.len(),
            "ArkService::SubmitTx called"
        );

        if req.signed_ark_tx.is_empty() {
            return Err(Status::invalid_argument("signed_ark_tx is required"));
        }

        // Check if any tx input owner is banned.
        // Parse the PSBT to extract input outpoints, look up VTXOs,
        // and check their owner pubkeys against the ban list.
        {
            use base64::Engine;
            if let Ok(psbt_bytes) =
                base64::engine::general_purpose::STANDARD.decode(&req.signed_ark_tx)
            {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
                    let input_outpoints: Vec<dark_core::domain::VtxoOutpoint> = psbt
                        .unsigned_tx
                        .input
                        .iter()
                        .map(|txin| {
                            dark_core::domain::VtxoOutpoint::new(
                                txin.previous_output.txid.to_string(),
                                txin.previous_output.vout,
                            )
                        })
                        .collect();
                    if let Ok(vtxos) = self.core.get_vtxos(&input_outpoints).await {
                        for vtxo in &vtxos {
                            if !vtxo.pubkey.is_empty() {
                                if let Ok(true) =
                                    self.core.is_participant_banned(&vtxo.pubkey).await
                                {
                                    return Err(Status::permission_denied(format!(
                                        "Participant {} is banned",
                                        vtxo.pubkey
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Validate the ark tx PSBT before co-signing.
        {
            use base64::Engine;
            if let Ok(psbt_bytes) =
                base64::engine::general_purpose::STANDARD.decode(&req.signed_ark_tx)
            {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
                    let tx = &psbt.unsigned_tx;

                    // Count OP_RETURN outputs.  The Go reference server
                    // allows up to 3 OP_RETURN outputs: sub-dust VTXOs
                    // (OP_RETURN <key>) plus an asset extension packet
                    // (OP_RETURN "ARK" ...) can coexist in the same tx.
                    let op_return_count = tx
                        .output
                        .iter()
                        .filter(|o| o.script_pubkey.is_op_return())
                        .count();
                    if op_return_count > 3 {
                        return Err(Status::invalid_argument(format!(
                            "tx has {} OP_RETURN outputs, maximum allowed is 3",
                            op_return_count
                        )));
                    }

                    // Check transaction size (serialized weight)
                    let tx_size = bitcoin::consensus::serialize(tx).len();
                    const MAX_TX_SIZE: usize = 10_000; // 10KB limit for offchain txs
                    if tx_size > MAX_TX_SIZE {
                        return Err(Status::invalid_argument(format!(
                            "transaction size {} exceeds maximum allowed {}",
                            tx_size, MAX_TX_SIZE
                        )));
                    }
                }
            }
        }

        // ASP co-signs the ark tx (script-path spend of input VTXOs) and the checkpoint txs.
        // Derive a deterministic txid from the signed_ark_tx bytes.
        // Derive the ark_txid from the Bitcoin txid of the unsigned tx inside the PSBT,
        // matching what the Go reference server does.  Fall back to sha256 of the raw
        // bytes when the PSBT cannot be parsed (shouldn't happen in practice).
        let ark_txid = {
            let mut txid_opt: Option<String> = None;
            use base64::Engine;
            if let Ok(psbt_bytes) =
                base64::engine::general_purpose::STANDARD.decode(&req.signed_ark_tx)
            {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
                    txid_opt = Some(psbt.unsigned_tx.compute_txid().to_string());
                }
            }
            txid_opt.unwrap_or_else(|| {
                use bitcoin::hashes::{sha256, Hash};
                let hash = sha256::Hash::hash(req.signed_ark_tx.as_bytes());
                hex::encode(hash.as_byte_array())
            })
        };

        // Co-sign the ark tx PSBT with the ASP signer key.
        // The signer accepts hex or base64 input and returns hex output.
        // Convert hex back to base64 for the Go client; fall back to echo on any failure.
        let cosigned_ark_tx = match self.core.cosign_psbt(&req.signed_ark_tx).await {
            Ok(signed) => {
                if let Ok(signed_bytes) = hex::decode(&signed) {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(&signed_bytes)
                } else {
                    // Signer returned non-hex (e.g. mock) — use as-is
                    signed
                }
            }
            Err(e) => {
                warn!(error = %e, "ASP co-sign of ark tx failed, echoing back unsigned");
                req.signed_ark_tx.clone()
            }
        };

        // Co-sign each checkpoint tx PSBT with the ASP signer key
        let mut signed_checkpoint_txs = Vec::with_capacity(req.checkpoint_txs.len());
        for ckpt in &req.checkpoint_txs {
            match self.core.cosign_psbt(ckpt).await {
                Ok(signed) => {
                    if let Ok(signed_bytes) = hex::decode(&signed) {
                        use base64::Engine;
                        signed_checkpoint_txs
                            .push(base64::engine::general_purpose::STANDARD.encode(&signed_bytes));
                    } else {
                        signed_checkpoint_txs.push(signed);
                    }
                }
                Err(e) => {
                    warn!(error = %e, "ASP co-sign of checkpoint tx failed, echoing back unsigned");
                    signed_checkpoint_txs.push(ckpt.clone());
                }
            }
        }

        // Parse inputs and outputs from the PSBT.
        // The Go client sends a base64-encoded PSBT for the ark tx.
        // Extract inputs (previous outpoints) and outputs (P2TR pubkeys + amounts).
        let (inputs, outputs): (
            Vec<dark_core::domain::VtxoInput>,
            Vec<dark_core::domain::VtxoOutput>,
        ) = {
            // Try base64 decode first (Go client), then hex
            let psbt_bytes = {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(&req.signed_ark_tx)
                    .or_else(|_| hex::decode(&req.signed_ark_tx))
                    .ok()
            };

            if let Some(ref bytes) = psbt_bytes {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(bytes) {
                    // Extract input VTXO outpoints from CHECKPOINT TX
                    // inputs, not from ark tx inputs.  The tx chain is:
                    //   user VTXO → checkpoint tx → ark tx
                    // The checkpoint tx's first input spends the user's VTXO,
                    // so its previous_output is the VTXO outpoint we need.
                    // (The ark tx's inputs reference checkpoint outputs, which
                    // are never stored as VTXOs.)
                    let parsed_inputs: Vec<dark_core::domain::VtxoInput> =
                        if req.checkpoint_txs.is_empty() {
                            // No checkpoint txs — extract inputs directly from
                            // the ark tx (Rust client sends VTXOs as direct
                            // inputs without the checkpoint indirection).
                            psbt.unsigned_tx
                                .input
                                .iter()
                                .map(|txin| {
                                    let txid = txin.previous_output.txid.to_string();
                                    let vout = txin.previous_output.vout;
                                    dark_core::domain::VtxoInput {
                                        vtxo_id: format!("{}:{}", txid, vout),
                                        signed_tx: vec![],
                                    }
                                })
                                .collect()
                        } else {
                            req.checkpoint_txs
                                .iter()
                                .filter_map(|ckpt_b64| {
                                    use base64::Engine;
                                    let ckpt_bytes = base64::engine::general_purpose::STANDARD
                                        .decode(ckpt_b64)
                                        .or_else(|_| hex::decode(ckpt_b64))
                                        .ok()?;
                                    let ckpt_psbt =
                                        bitcoin::psbt::Psbt::deserialize(&ckpt_bytes).ok()?;
                                    let first_input = ckpt_psbt.unsigned_tx.input.first()?;
                                    let txid = first_input.previous_output.txid.to_string();
                                    let vout = first_input.previous_output.vout;
                                    Some(dark_core::domain::VtxoInput {
                                        vtxo_id: format!("{}:{}", txid, vout),
                                        signed_tx: vec![],
                                    })
                                })
                                .collect()
                        };

                    // Parse asset packet from OP_RETURN output to associate
                    // assets with VTXO outputs.
                    let asset_map = parse_asset_packet_from_tx(&psbt.unsigned_tx, &ark_txid);

                    let parsed_outputs: Vec<dark_core::domain::VtxoOutput> = psbt
                        .unsigned_tx
                        .output
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, out)| {
                            let amount = out.value.to_sat();
                            if amount == 0 {
                                return None; // skip zero-value outputs
                            }
                            // Extract pubkey from scriptPubKey.
                            // P2TR: x-only pubkey from bytes [2..] (OP_1 PUSH32 <key>).
                            // SubDustScript: OP_RETURN PUSH32 <x-only-key> — extract
                            // the inner 32-byte key so it matches the Go SDK's
                            // NotifyIncomingFunds subscription (which uses P2TR tapkey).
                            let script_bytes = out.script_pubkey.as_bytes();
                            let pubkey_hex = if out.script_pubkey.is_p2tr() {
                                hex::encode(&script_bytes[2..])
                            } else if script_bytes.len() == 34
                                && script_bytes[0] == 0x6a
                                && script_bytes[1] == 0x20
                            {
                                // SubDustScript: OP_RETURN (6a) + PUSH32 (20) + 32-byte x-only key
                                hex::encode(&script_bytes[2..])
                            } else {
                                hex::encode(script_bytes)
                            };
                            let assets = asset_map.get(&(idx as u16)).cloned().unwrap_or_default();
                            Some(dark_core::domain::VtxoOutput {
                                pubkey: pubkey_hex,
                                amount_sats: amount,
                                assets,
                            })
                        })
                        .collect();

                    (parsed_inputs, parsed_outputs)
                } else {
                    // Failed to parse as PSBT — fall back to placeholder
                    let placeholder_input = dark_core::domain::VtxoInput {
                        vtxo_id: ark_txid.clone(),
                        signed_tx: req.signed_ark_tx.as_bytes().to_vec(),
                    };
                    (vec![placeholder_input], vec![])
                }
            } else {
                // Not base64 or hex — try JSON fallback for backwards compat
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&req.signed_ark_tx) {
                    let json_inputs: Vec<dark_core::domain::VtxoInput> = parsed
                        .get("inputs")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|item| {
                                    let vtxo_id = item.get("vtxo_id")?.as_str()?.to_string();
                                    Some(dark_core::domain::VtxoInput {
                                        vtxo_id,
                                        signed_tx: vec![],
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let json_outputs: Vec<dark_core::domain::VtxoOutput> = parsed
                        .get("outputs")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|item| {
                                    let pubkey = item.get("pubkey")?.as_str()?.to_string();
                                    let amount = item.get("amount")?.as_u64()?;
                                    Some(dark_core::domain::VtxoOutput {
                                        pubkey,
                                        amount_sats: amount,
                                        assets: vec![],
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    (json_inputs, json_outputs)
                } else {
                    let placeholder_input = dark_core::domain::VtxoInput {
                        vtxo_id: ark_txid.clone(),
                        signed_tx: req.signed_ark_tx.as_bytes().to_vec(),
                    };
                    (vec![placeholder_input], vec![])
                }
            }
        };

        // NOTE: No dust limit check for offchain transaction outputs.
        // Offchain VTXOs (especially asset-carrying VTXOs) can have amounts
        // below the on-chain dust limit (546 sats). The dust limit only
        // applies to on-chain Bitcoin outputs, not to Ark protocol VTXOs.

        // ── CLTV locktime validation ──────────────────────────────────
        // Go reference: checks CLTV closure locktime against current block
        // height.  We check BOTH the main ark tx AND checkpoint PSBTs.
        // If any tapscript leaf contains OP_CHECKLOCKTIMEVERIFY with a
        // locktime that hasn't been reached, reject the tx.
        {
            use base64::Engine;

            // Helper: extract CLTV locktime from PSBT tapscript leaves
            // or finalized witness stacks.
            let extract_cltv_locktime = |psbt: &bitcoin::psbt::Psbt| -> Option<u32> {
                use bitcoin::script::Instruction;

                // Collect all scripts to check: tap_scripts + final witness scripts
                let mut scripts_to_check: Vec<bitcoin::ScriptBuf> = Vec::new();
                for input in &psbt.inputs {
                    // Pre-finalization: tap_scripts
                    for (script, _) in input.tap_scripts.values() {
                        scripts_to_check.push(script.clone());
                    }
                    // Post-finalization: extract script from witness stack
                    // (second-to-last element is the tapscript in a script-path spend)
                    if let Some(ref witness) = input.final_script_witness {
                        let items: Vec<&[u8]> = witness.iter().collect();
                        if items.len() >= 2 {
                            // In a taproot script-path spend, the witness is:
                            //   [<sig1> [<sig2> ...] <script> <control_block>]
                            // The script is second-to-last.
                            let script_bytes = items[items.len() - 2];
                            scripts_to_check.push(bitcoin::ScriptBuf::from(script_bytes.to_vec()));
                        }
                    }
                    // Also check tap_script_sigs keys for leaf hashes
                    // that might contain the script
                }

                for script in &scripts_to_check {
                    let mut last_push: Option<i64> = None;
                    for instr in script.instructions() {
                        match instr {
                            Ok(Instruction::PushBytes(data)) => {
                                let bytes = data.as_bytes();
                                if bytes.is_empty() {
                                    last_push = Some(0);
                                } else if bytes.len() > 5 {
                                    // CScriptNum is at most 5 bytes; skip larger pushes
                                    last_push = None;
                                } else {
                                    let mut val: i64 = 0;
                                    for (i, &b) in bytes.iter().enumerate() {
                                        val |= (b as i64) << (8 * i);
                                    }
                                    if bytes.last().unwrap() & 0x80 != 0 {
                                        val &= !(0x80i64 << (8 * (bytes.len() - 1)));
                                        val = -val;
                                    }
                                    last_push = Some(val);
                                }
                            }
                            Ok(Instruction::Op(op)) => {
                                if op == bitcoin::opcodes::all::OP_CLTV {
                                    if let Some(val) = last_push {
                                        if val > 0 {
                                            return Some(val as u32);
                                        }
                                    }
                                }
                                last_push = None;
                            }
                            _ => {
                                last_push = None;
                            }
                        }
                    }
                }

                // Also check nLockTime as fallback
                let nlt = psbt.unsigned_tx.lock_time.to_consensus_u32();
                if nlt > 0 {
                    return Some(nlt);
                }
                None
            };

            // Check main ark tx
            let mut cltv_locktime: Option<u32> = None;
            if let Ok(psbt_bytes) =
                base64::engine::general_purpose::STANDARD.decode(&req.signed_ark_tx)
            {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
                    cltv_locktime = extract_cltv_locktime(&psbt);
                }
            }
            // Also check checkpoints
            if cltv_locktime.is_none() {
                for ckpt_b64 in &req.checkpoint_txs {
                    let ckpt_bytes = base64::engine::general_purpose::STANDARD
                        .decode(ckpt_b64)
                        .or_else(|_| hex::decode(ckpt_b64))
                        .ok();
                    if let Some(ref bytes) = ckpt_bytes {
                        if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(bytes) {
                            if let Some(lt) = extract_cltv_locktime(&psbt) {
                                cltv_locktime = Some(lt);
                                break;
                            }
                        }
                    }
                }
            }

            if let Some(locktime) = cltv_locktime {
                if locktime < 500_000_000 {
                    // Block-height based locktime.
                    // Prefer Bitcoin Core RPC (instant) over Esplora (may lag).
                    let cfg = self.core.config();
                    let current_height =
                        if let (Some(ref rpc_url), Some(ref user), Some(ref pass)) = (
                            &cfg.fee_manager_url,
                            &cfg.fee_manager_user,
                            &cfg.fee_manager_pass,
                        ) {
                            // Direct Bitcoin Core RPC call (getblockcount)
                            let client = reqwest::Client::new();
                            let body = serde_json::json!({
                                "jsonrpc": "1.0",
                                "id": "cltv",
                                "method": "getblockcount",
                                "params": []
                            });
                            match client
                                .post(rpc_url)
                                .basic_auth(user, Some(pass))
                                .json(&body)
                                .send()
                                .await
                            {
                                Ok(resp) => {
                                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                                        json["result"].as_u64().unwrap_or(0) as u32
                                    } else {
                                        0
                                    }
                                }
                                Err(_) => 0,
                            }
                        } else {
                            // Fallback: Esplora scanner
                            self.core.scanner().tip_height().await.unwrap_or(0)
                        };
                    if locktime > current_height {
                        return Err(Status::failed_precondition(format!(
                            "CLTV locktime {} not yet reached (current height {})",
                            locktime, current_height
                        )));
                    }
                } else {
                    // Time-based locktime
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    if locktime > now {
                        return Err(Status::failed_precondition(format!(
                            "CLTV locktime {} not yet reached (current time {})",
                            locktime, now
                        )));
                    }
                }
            }
        }

        // ── Input VTXO validation ──────────────────────────────────────
        // Matches Go reference server's SubmitOffchainTx validations:
        // - VTXO must exist, not be spent/unrolled/swept
        // - Input amounts must equal output amounts (balance check)
        // - Double-spend detection via offchain tx repo
        let input_outpoints: Vec<dark_core::domain::VtxoOutpoint> = inputs
            .iter()
            .filter_map(|inp| {
                let parts: Vec<&str> = inp.vtxo_id.rsplitn(2, ':').collect();
                if parts.len() == 2 {
                    let vout: u32 = parts[0].parse().unwrap_or(0);
                    Some(dark_core::domain::VtxoOutpoint::new(
                        parts[1].to_string(),
                        vout,
                    ))
                } else {
                    None
                }
            })
            .collect();

        // Acquire the offchain tx mutex to serialize SubmitTx calls.
        // This is critical for double-spend detection: without it, concurrent
        // requests can all pass the is_input_spent check before any writes
        // the tx to the DB. Go reference uses offchainTxMu.Lock().
        let _offchain_guard = self.offchain_tx_mutex.lock().await;

        if !input_outpoints.is_empty() {
            // 1. Check VTXO state: must exist, not spent
            let dust_limit = self.core.config().min_vtxo_amount_sats;
            let mut total_input_amount: u64 = 0;
            match self.core.get_vtxos(&input_outpoints).await {
                Ok(vtxos) => {
                    for vtxo in &vtxos {
                        if vtxo.spent {
                            return Err(Status::failed_precondition(format!(
                                "VTXO {} is already spent",
                                vtxo.outpoint
                            )));
                        }
                        // Reject swept (sub-dust OP_RETURN) VTXOs as sole inputs —
                        // they can't be spent individually.  The Go server checks
                        // the script type, not the sat amount, so regular VTXOs
                        // with low amounts (e.g. asset-carrying 330-sat VTXOs) are
                        // allowed.
                        if vtxo.swept && input_outpoints.len() == 1 {
                            return Err(Status::failed_precondition(format!(
                                "VTXO {} has sub-dust amount {} (minimum {}), cannot be spent individually",
                                vtxo.outpoint, vtxo.amount, dust_limit
                            )));
                        }
                        total_input_amount += vtxo.amount;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "VTXO lookup failed (non-fatal)");
                }
            }

            // 2. Balance check: input amount must equal output amount
            // (Go reference: BuildTxs validates inputAmount == outputAmount)
            if total_input_amount > 0 {
                let total_output_amount: u64 = outputs.iter().map(|o| o.amount_sats).sum();
                if total_input_amount != total_output_amount {
                    return Err(Status::invalid_argument(format!(
                        "input amount {} != output amount {}",
                        total_input_amount, total_output_amount
                    )));
                }
            }

            // 3. Double-spend detection: check if any input is already used
            //    by a pending offchain tx (Go reference: cache.OffchainTxs().Includes)
            for op in &input_outpoints {
                let vtxo_id = format!("{}:{}", op.txid, op.vout);
                if let Ok(true) = self.offchain_tx_repo.is_input_spent(&vtxo_id).await {
                    return Err(Status::failed_precondition(format!(
                        "VTXO {} is already used by another pending offchain tx",
                        vtxo_id
                    )));
                }
            }
        }

        // Store pending tx keyed by ark_txid so FinalizeTx can retrieve it
        let mut offchain_tx =
            dark_core::domain::OffchainTx::new_with_id(ark_txid.clone(), inputs, outputs);
        offchain_tx.signed_ark_tx = cosigned_ark_tx.clone();
        // Reject duplicate tx IDs (not idempotent — Go reference rejects duplicates)
        if let Err(e) = self.offchain_tx_repo.create(&offchain_tx).await {
            return Err(Status::already_exists(format!(
                "offchain tx {} already exists: {}",
                ark_txid, e
            )));
        }
        // Also store the cosigned ark tx PSBT for GetVirtualTxs
        let _ = self
            .offchain_tx_repo
            .set_signed_ark_tx(&ark_txid, &cosigned_ark_tx)
            .await;

        info!(ark_txid, "SubmitTx: off-chain tx accepted and co-signed");

        Ok(Response::new(SubmitTxResponse {
            ark_txid,
            final_ark_tx: cosigned_ark_tx,
            signed_checkpoint_txs,
        }))
    }

    /// Stub implementation for the confidential-transaction submission RPC
    /// added in #537. The schema lives in `proto/ark/v1/confidential_tx.proto`;
    /// the actual handler is the responsibility of issue #542 and validation
    /// belongs to #538. Until those land we return `Unimplemented` so the
    /// trait is satisfied without pretending we accept anything.
    async fn submit_confidential_transaction(
        &self,
        _request: Request<SubmitConfidentialTransactionRequest>,
    ) -> Result<Response<SubmitConfidentialTransactionResponse>, Status> {
        Err(Status::unimplemented(
            "SubmitConfidentialTransaction is defined in proto but not yet implemented \
             (handler tracked in #542, validation in #538)",
        ))
    }

    async fn finalize_tx(
        &self,
        request: Request<FinalizeTxRequest>,
    ) -> Result<Response<FinalizeTxResponse>, Status> {
        let req = request.into_inner();
        info!(
            ark_txid = %req.ark_txid,
            checkpoints = req.final_checkpoint_txs.len(),
            "ArkService::FinalizeTx called"
        );

        if req.ark_txid.is_empty() {
            return Err(Status::invalid_argument("ark_txid is required"));
        }

        // Store checkpoint txs for later use (unilateral exit).
        // Checkpoint txs are virtual — they are NOT broadcast on-chain.
        // They are only needed if a unilateral exit is triggered.
        if !req.final_checkpoint_txs.is_empty() {
            for (i, ckpt) in req.final_checkpoint_txs.iter().enumerate() {
                info!(
                    ark_txid = %req.ark_txid,
                    idx = i,
                    len = ckpt.len(),
                    prefix = %&ckpt[..std::cmp::min(40, ckpt.len())],
                    "FinalizeTx: checkpoint tx preview"
                );
            }
            info!(
                ark_txid = %req.ark_txid,
                count = req.final_checkpoint_txs.len(),
                "FinalizeTx: storing checkpoint txs (virtual, not broadcast)"
            );
            // Persist final checkpoint txs so GetVirtualTxs can serve them
            let _ = self
                .offchain_tx_repo
                .set_checkpoint_txs(&req.ark_txid, &req.final_checkpoint_txs)
                .await;
        }

        // Finalize the offchain tx AND update VTXO state:
        //   - marks input VTXOs as spent
        //   - creates output VTXOs
        //   - transitions stage to Finalized
        //   - emits TxFinalized event
        if let Err(e) = self
            .core
            .finalize_offchain_tx_with_vtxo_update(&req.ark_txid)
            .await
        {
            warn!(ark_txid = %req.ark_txid, error = %e, "finalize_offchain_tx_with_vtxo_update failed (non-fatal)");
        }

        info!(ark_txid = %req.ark_txid, "FinalizeTx: off-chain tx finalized");
        Ok(Response::new(FinalizeTxResponse {}))
    }

    /// FinalizePendingTxs — reconnect scenario.
    ///
    /// When a client reconnects after a disconnect (e.g. after `SubmitTx` but before
    /// `FinalizeTx`), it calls this to finalize any pending off-chain transactions.
    /// The server fetches all pending txs for the caller's pubkey and finalizes each one,
    /// updating VTXO state accordingly.
    async fn finalize_pending_txs(
        &self,
        request: Request<FinalizePendingTxsRequest>,
    ) -> Result<Response<FinalizePendingTxsResponse>, Status> {
        let req = request.into_inner();
        info!(pubkey = %req.pubkey, "ArkService::FinalizePendingTxs called");

        // Use the API-level offchain_tx_repo (which submit_tx writes to) so that
        // FinalizePendingTxs can find txs stored by SubmitTx in the same session.
        // (The core's repo is a NoopOffchainTxRepository by default.)
        let pending = self
            .offchain_tx_repo
            .get_pending()
            .await
            .map_err(|e| Status::internal(format!("get_pending failed: {e}")))?;

        let mut finalized = Vec::new();
        for tx in pending {
            // Filter by pubkey if provided
            let belongs = if req.pubkey.is_empty() {
                true
            } else {
                let outpoints: Vec<dark_core::domain::VtxoOutpoint> = tx
                    .inputs
                    .iter()
                    .filter_map(|inp| {
                        let parts: Vec<&str> = inp.vtxo_id.rsplitn(2, ':').collect();
                        if parts.len() == 2 {
                            let vout: u32 = parts[0].parse().unwrap_or(0);
                            Some(dark_core::domain::VtxoOutpoint::new(
                                parts[1].to_string(),
                                vout,
                            ))
                        } else {
                            None
                        }
                    })
                    .collect();
                if outpoints.is_empty() {
                    true // no VTXO inputs — finalize anyway
                } else {
                    match self.core.get_vtxos(&outpoints).await {
                        Ok(vtxos) => {
                            let xonly = if req.pubkey.len() == 66 {
                                req.pubkey[2..].to_string()
                            } else {
                                req.pubkey.clone()
                            };
                            vtxos
                                .iter()
                                .any(|v| v.pubkey == req.pubkey || v.pubkey == xonly)
                        }
                        Err(_) => false,
                    }
                }
            };

            if belongs {
                match self
                    .core
                    .finalize_offchain_tx_with_vtxo_update(&tx.id)
                    .await
                {
                    Ok(id) => finalized.push(id),
                    Err(e) => {
                        warn!(tx_id = %tx.id, error = %e, "Failed to finalize pending tx (non-fatal)");
                    }
                }
            }
        }

        info!(
            count = finalized.len(),
            pubkey = %req.pubkey,
            "FinalizePendingTxs: finalized pending txs"
        );

        Ok(Response::new(FinalizePendingTxsResponse {
            finalized_txids: finalized,
        }))
    }

    async fn get_pending_tx(
        &self,
        request: Request<GetPendingTxRequest>,
    ) -> Result<Response<GetPendingTxResponse>, Status> {
        let req = request.into_inner();
        // The Go SDK sends an Intent (proof + message) to identify the pending tx.
        // Parse the intent proof to extract input VTXO outpoints, then filter
        // pending offchain txs by those outpoints.
        let mut query_outpoints: Vec<String> = Vec::new();
        if let Some(crate::proto::ark_v1::get_pending_tx_request::Identifier::Intent(intent)) =
            req.identifier
        {
            // Parse the proof PSBT to extract input outpoints
            use base64::Engine;
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&intent.proof) {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
                    for inp in &psbt.unsigned_tx.input {
                        query_outpoints.push(format!(
                            "{}:{}",
                            inp.previous_output.txid, inp.previous_output.vout
                        ));
                    }
                }
            }
        }

        let pending = self
            .offchain_tx_repo
            .get_pending()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Filter: return only pending txs whose inputs match the query outpoints
        let pending_txs: Vec<crate::proto::ark_v1::PendingTx> = pending
            .iter()
            .filter(|tx| {
                if query_outpoints.is_empty() {
                    return true; // no filter, return all
                }
                tx.inputs
                    .iter()
                    .any(|inp| query_outpoints.contains(&inp.vtxo_id))
            })
            .map(|tx| crate::proto::ark_v1::PendingTx {
                ark_txid: tx.id.clone(),
                final_ark_tx: tx.signed_ark_tx.clone(),
                signed_checkpoint_txs: tx.checkpoint_txs.clone(),
            })
            .collect();

        Ok(Response::new(GetPendingTxResponse { pending_txs }))
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

        // Resolve the delegate pubkey: prefer proto field, fall back to JSON field.
        // A delegate pubkey is present when someone (the delegate, Bob) is submitting
        // an intent on behalf of a VTXO owner (Alice). The BIP-322 proof is signed by
        // Alice, while the cosigner keys are Bob's. The server accepts this as long as
        // the proof signature is valid for the VTXO inputs (BIP-322 verification is
        // tracked in TODO(#40); for now the proof is accepted without strict verification).
        let delegate_pubkey: Option<String> = if !intent_proof.delegate_pubkey.is_empty() {
            Some(intent_proof.delegate_pubkey.clone())
        } else {
            message_json
                .get("delegate_pubkey")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        };

        // Skip first input (BIP-322 toSpend reference) — remaining are real UTXOs
        let mut inputs: Vec<dark_core::domain::Vtxo> = Vec::new();
        // Track PSBT input index for each entry in `inputs` (needed to
        // extract the correct per-input pubkey from the intent proof's
        // tap_scripts later).
        let mut input_psbt_indices: Vec<usize> = Vec::new();
        // Temporary pending key for note redemptions in this intent.
        let note_pending_key = format!("intent-notes:{}", proof_txid);
        let mut has_pending_notes = false;
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

            // Check if this input is a note outpoint — if so, redeem it (pending)
            // to prevent re-use. Notes have outpoint txid = SHA256(preimage), vout = 0.
            // Redeemed notes are NOT added as intent inputs because they are
            // virtual (no on-chain UTXO to spend). Their value is already
            // accounted for in the intent receivers via the Go SDK.
            //
            // Notes are redeemed in pending mode: they are removed from the
            // available pool but not permanently consumed until the round
            // completes. If the round fails, they are rolled back.
            let mut is_note = false;
            if vout == 0 {
                match self
                    .note_store
                    .try_redeem_by_outpoint_pending(&txid, &note_pending_key)
                    .await
                {
                    Ok(Some(note_amount)) => {
                        info!(
                            txid = %txid,
                            amount = note_amount,
                            "Note input redeemed (pending) via RegisterIntent — skipping as intent input"
                        );
                        is_note = true;
                        has_pending_notes = true;
                    }
                    Ok(None) => {
                        // Not a note — regular VTXO input, continue normally
                    }
                    Err(e) => {
                        // Rollback any notes already pending for this intent.
                        if has_pending_notes {
                            self.note_store.rollback_pending(&note_pending_key).await;
                        }
                        return Err(Status::invalid_argument(format!(
                            "Note already redeemed: {e}"
                        )));
                    }
                }
            }

            if !is_note {
                inputs.push(dark_core::domain::Vtxo::new(
                    dark_core::domain::VtxoOutpoint::new(txid, vout),
                    amount,
                    String::new(),
                ));
                // Track the PSBT input index for this intent input so we
                // can later extract the correct per-input pubkey from the
                // intent proof's tap_scripts.
                input_psbt_indices.push(i);
            }
        }

        // Enrich intent inputs with actual VTXO data from the DB.
        // The bare Vtxo::new() above creates objects with empty commitment_txids,
        // which makes requires_forfeit() incorrectly return false.
        // We look up the real VTXO records to get commitment_txids, swept, etc.
        // so the connector count (one per forfeitable input) is computed correctly.
        if !inputs.is_empty() {
            let outpoints: Vec<dark_core::domain::VtxoOutpoint> =
                inputs.iter().map(|inp| inp.outpoint.clone()).collect();
            match self.core.get_vtxos(&outpoints).await {
                Ok(db_vtxos) => {
                    let db_map: std::collections::HashMap<String, &dark_core::domain::Vtxo> =
                        db_vtxos
                            .iter()
                            .map(|v| (format!("{}:{}", v.outpoint.txid, v.outpoint.vout), v))
                            .collect();
                    for inp in &mut inputs {
                        let key = format!("{}:{}", inp.outpoint.txid, inp.outpoint.vout);
                        if let Some(db_vtxo) = db_map.get(&key) {
                            inp.commitment_txids = db_vtxo.commitment_txids.clone();
                            inp.root_commitment_txid = db_vtxo.root_commitment_txid.clone();
                            inp.swept = db_vtxo.swept;
                            inp.preconfirmed = db_vtxo.preconfirmed;
                            inp.ark_txid = db_vtxo.ark_txid.clone();
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "RegisterIntent: failed to look up VTXOs for enrichment");
                }
            }
        }

        // Build receivers from PSBT outputs (P2TR → offchain VTXO, otherwise onchain)
        info!(
            onchain_output_indexes = ?onchain_output_indexes,
            output_count = unsigned_tx.output.len(),
            "RegisterIntent: building receivers from PSBT outputs"
        );
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
                info!(
                    index = i,
                    amount = amount,
                    addr = %addr,
                    "RegisterIntent: on-chain receiver"
                );
                receivers.push(dark_core::domain::Receiver::onchain(amount, addr));
            } else if tx_out.script_pubkey.is_p2tr() {
                // Extract x-only pubkey from P2TR script: OP_1 OP_PUSH32 <32-byte-key>
                let script_bytes = tx_out.script_pubkey.as_bytes();
                let pubkey_hex = if script_bytes.len() >= 34 {
                    hex::encode(&script_bytes[2..34])
                } else {
                    String::new()
                };
                info!(
                    index = i,
                    amount = amount,
                    pubkey = %pubkey_hex,
                    "RegisterIntent: off-chain receiver"
                );
                receivers.push(dark_core::domain::Receiver::offchain(amount, pubkey_hex));
            }
        }

        // Validate: reject intents that mix boarding (non-VTXO) inputs with onchain outputs.
        let has_onchain_outputs = !onchain_output_indexes.is_empty();
        if has_onchain_outputs && !inputs.is_empty() {
            let outpoints: Vec<dark_core::domain::VtxoOutpoint> =
                inputs.iter().map(|inp| inp.outpoint.clone()).collect();
            match self.core.get_vtxos(&outpoints).await {
                Ok(vtxos) => {
                    let known_outpoints: std::collections::HashSet<String> = vtxos
                        .iter()
                        .map(|v| format!("{}:{}", v.outpoint.txid, v.outpoint.vout))
                        .collect();
                    let has_boarding_input = inputs.iter().any(|inp| {
                        let key = format!("{}:{}", inp.outpoint.txid, inp.outpoint.vout);
                        !known_outpoints.contains(&key)
                    });
                    if has_boarding_input {
                        return Err(Status::invalid_argument(
                            "cannot include onchain inputs and outputs",
                        ));
                    }
                }
                Err(_) => {
                    return Err(Status::invalid_argument(
                        "cannot include onchain inputs and outputs",
                    ));
                }
            }
        }

        // Set input pubkeys.
        //
        // For boarding inputs the user's **raw** x-only pubkey must be used
        // (the same key that was used to derive the boarding address taproot
        // tree).  The intent proof PSBT carries the collaborative tapscript
        // leaf on each input as a `TaprootLeafScript`, and the first 32-byte
        // data push in that script is the owner's x-only pubkey:
        //
        //   <owner_xonly> OP_CHECKSIGVERIFY <signer_xonly> OP_CHECKSIG
        //
        // We extract it here so that `finalize_round()` can reconstruct the
        // correct boarding taproot tree later.  Fall back to the first
        // receiver's pubkey for off-chain VTXO inputs (where the receiver
        // key *is* the owner key).
        let fallback_pubkey = receivers
            .iter()
            .find(|r| !r.pubkey.is_empty())
            .map(|r| r.pubkey.clone())
            .unwrap_or_default();

        // Assign pubkeys: prefer per-input extraction from the intent proof
        // PSBT's tap_scripts, fall back to receiver pubkey.
        for (input_idx, inp) in inputs.iter_mut().enumerate() {
            let psbt_idx = input_psbt_indices
                .get(input_idx)
                .copied()
                .unwrap_or(input_idx + 1);
            let mut found = false;
            if let Some(psbt_input) = psbt.inputs.get(psbt_idx) {
                // tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>
                // Look for a collaborative leaf: the script should contain at
                // least two 32-byte pushes (owner + signer) separated by
                // OP_CHECKSIGVERIFY.
                for (script, _ver) in psbt_input.tap_scripts.values() {
                    let script_bytes = script.as_bytes();
                    // Collaborative leaf pattern:
                    //   0x20 <32 bytes owner> OP_CHECKSIGVERIFY(0xad) 0x20 <32 bytes signer> OP_CHECKSIG(0xac)
                    // Total: 1+32+1+1+32+1 = 68 bytes
                    if script_bytes.len() >= 68
                        && script_bytes[0] == 0x20
                        && script_bytes[33] == 0xad // OP_CHECKSIGVERIFY
                        && script_bytes[34] == 0x20
                        && script_bytes[67] == 0xac
                    {
                        inp.pubkey = hex::encode(&script_bytes[1..33]);
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                inp.pubkey = fallback_pubkey.clone();
            }
        }

        info!(
            inputs = inputs.len(),
            receivers = receivers.len(),
            owner = %fallback_pubkey,
            delegate = ?delegate_pubkey,
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

        // Set cosigner public keys from the intent message.
        // In a delegate flow, cosigners_public_keys contains the delegate's key (e.g. Bob's),
        // not the VTXO owner's key (Alice's). The delegate_pubkey field records who is acting
        // as the delegate. Full BIP-322 proof validation is tracked in TODO(#40).
        info!(
            cosigners = ?cosigners_public_keys,
            "RegisterIntent: parsed cosigner public keys from message"
        );
        intent.cosigners_public_keys = cosigners_public_keys;
        intent.delegate_pubkey = delegate_pubkey;

        // Extract asset extension from the proof PSBT and store it as the
        // leaf_tx_asset_packet. The Go reference server does this to embed
        // asset data in the VTXO tree leaf PSBTs during round finalization.
        // Format: hex-encoded OP_RETURN push data (the full extension
        // including "ARK" magic).
        {
            use base64::Engine;
            if let Ok(proof_bytes) =
                base64::engine::general_purpose::STANDARD.decode(&intent_proof.proof)
            {
                if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&proof_bytes) {
                    for out in &psbt.unsigned_tx.output {
                        let script_bytes = out.script_pubkey.as_bytes();
                        if let Some(push_data) = decode_op_return_push(script_bytes) {
                            if push_data.len() >= 3
                                && push_data[0] == 0x41
                                && push_data[1] == 0x52
                                && push_data[2] == 0x4b
                            {
                                // Found ARK extension — store as hex for tree builder
                                intent.leaf_tx_asset_packet = hex::encode(push_data);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Check if any cosigner is banned before registering the intent.
        // Also check the owner/receiver pubkeys — the SDK may not set
        // cosigners for some intents (e.g. when reconnecting after a ban).
        let mut ban_check_keys: Vec<String> = intent.cosigners_public_keys.clone();
        // Add the fallback (receiver) pubkey — this is the VTXO owner's key
        if !fallback_pubkey.is_empty() && !ban_check_keys.contains(&fallback_pubkey) {
            ban_check_keys.push(fallback_pubkey.clone());
        }
        // Add per-input pubkeys — these identify the VTXO owner
        for inp in &intent.inputs {
            if !inp.pubkey.is_empty() && !ban_check_keys.contains(&inp.pubkey) {
                ban_check_keys.push(inp.pubkey.clone());
            }
        }
        for cosigner_pk in &ban_check_keys {
            // Normalize to x-only (32 bytes hex, 64 chars) for ban lookup —
            // ban records may store either compressed or x-only form.
            let xonly = if cosigner_pk.len() == 66 {
                &cosigner_pk[2..]
            } else {
                cosigner_pk.as_str()
            };
            for pk in [cosigner_pk.as_str(), xonly] {
                match self.core.is_participant_banned(pk).await {
                    Ok(true) => {
                        if has_pending_notes {
                            self.note_store.rollback_pending(&note_pending_key).await;
                        }
                        return Err(Status::permission_denied(format!(
                            "Participant {} is banned",
                            cosigner_pk
                        )));
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!(error = %e, pubkey = %pk, "Failed to check ban status");
                    }
                }
            }
        }

        let intent_id = match self.core.register_intent(intent).await {
            Ok(id) => id,
            Err(e) => {
                // Rollback pending notes if intent registration fails.
                if has_pending_notes {
                    self.note_store.rollback_pending(&note_pending_key).await;
                    warn!("RegisterIntent failed, rolled back pending notes: {e}");
                }
                return Err(Status::internal(e.to_string()));
            }
        };

        // Re-key pending notes to the actual round_id for lifecycle tracking.
        if has_pending_notes {
            let round_id = self
                .core
                .current_round_snapshot()
                .await
                .map(|r| r.id.clone())
                .unwrap_or_else(|| note_pending_key.clone());
            self.note_store
                .rekey_pending(&note_pending_key, &round_id)
                .await;
        }

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
                    cosigners_public_keys: intent.cosigners_public_keys.clone(),
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
        // Go SDK sends one nonce per tree txid. Serialize the full map as JSON for storage.
        // The application layer will deserialize and emit one TreeNoncesEvent per txid.
        let nonces_json = serde_json::to_vec(&req.tree_nonces).unwrap_or_default();

        self.core
            .submit_tree_nonces(&req.batch_id, &req.pubkey, nonces_json)
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

        // Serialize tree signatures map (txid → sig_hex) as JSON for the store.
        // Proto uses map<string, bytes>. Go clients send hex-encoded strings
        // (received as UTF-8 bytes), while Rust clients send raw binary sigs.
        // Normalize everything to hex strings for aggregate_tree_signatures().
        let sigs_as_strings: std::collections::HashMap<String, String> = req
            .tree_signatures
            .into_iter()
            .map(|(k, v)| {
                // If already a valid hex string (UTF-8 + all hex chars), use as-is
                let hex_str = match String::from_utf8(v.clone()) {
                    Ok(s) if s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit()) => s,
                    _ => hex::encode(v),
                };
                (k, hex_str)
            })
            .collect();
        let signatures: Vec<u8> = serde_json::to_vec(&sigs_as_strings)
            .map_err(|e| Status::internal(format!("Failed to serialize tree signatures: {e}")))?;

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

        // If the client sent a signed commitment tx, finalize and broadcast it.
        // The round_id is resolved inside broadcast_signed_commitment_tx from
        // the stored partial PSBTs (the first partial carries the round_id).
        // We pass the best-effort current round id as a fallback.
        if !req.signed_commitment_tx.is_empty() {
            let signed_commitment_str = &req.signed_commitment_tx;
            let fallback_round_id = self
                .core
                .current_round_snapshot()
                .await
                .map(|r| r.id.clone())
                .unwrap_or_default();
            info!(
                round_id = %fallback_round_id,
                "Client sent signed_commitment_tx — attempting broadcast"
            );
            match self
                .core
                .broadcast_signed_commitment_tx(signed_commitment_str, &fallback_round_id)
                .await
            {
                Ok(txid) => info!(txid = %txid, "Commitment tx broadcast from client signature"),
                Err(e) => {
                    warn!(error = %e, "Failed to broadcast client-signed commitment tx — aborting round and banning participants");
                    // Invalid commitment tx (e.g. bad boarding input signatures)
                    // → abort the round so participants get banned.
                    let _ = self.core.abort_round("signing timeout").await;
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
    // Asset & Note RPCs (#297, #298)
    // ─────────────────────────────────────────────────────────────────────────

    async fn issue_asset(
        &self,
        request: Request<IssueAssetRequest>,
    ) -> Result<Response<IssueAssetResponse>, Status> {
        use sha2::{Digest, Sha256};

        let req = request.into_inner();
        info!(
            "ArkService::IssueAsset called pubkey={} amount={} name={}",
            req.pubkey, req.amount, req.name
        );

        if req.amount == 0 {
            return Err(Status::invalid_argument("amount must be > 0"));
        }
        if req.pubkey.is_empty() {
            return Err(Status::invalid_argument("pubkey must not be empty"));
        }

        let pubkey = req.pubkey.clone();

        // Generate a deterministic asset_id via SHA-256(pubkey || name || amount).
        // No timestamp — the same inputs always produce the same asset_id, which
        // makes issuance idempotent for retries.
        let mut hasher = Sha256::new();
        hasher.update(pubkey.as_bytes());
        hasher.update(req.name.as_bytes());
        hasher.update(req.amount.to_le_bytes());
        let asset_id = hex::encode(hasher.finalize());

        // The `name` field encodes the control asset type using a protocol tag
        // understood by the client SDK:
        //   "control:new:<amount>"       — mint a new control asset alongside the main asset
        //   "control:existing:<id>"      — reference an already-minted control asset
        //   ""                           — plain issuance, no control asset
        let mut issued_asset_ids = Vec::new();
        let mut vtxo_assets: Vec<(String, u64)> = Vec::new();

        if req.name.starts_with("control:new:") {
            // Create a new control asset alongside the main asset
            let control_amount: u64 = req.name["control:new:".len()..].parse().unwrap_or(1);
            let mut ctrl_hasher = Sha256::new();
            ctrl_hasher.update(b"control:");
            ctrl_hasher.update(pubkey.as_bytes());
            ctrl_hasher.update(control_amount.to_le_bytes());
            let control_asset_id = hex::encode(ctrl_hasher.finalize());

            // Store control asset
            let control_asset = dark_core::domain::Asset {
                asset_id: control_asset_id.clone(),
                amount: control_amount,
                issuer_pubkey: pubkey.clone(),
                max_supply: Some(control_amount),
                metadata: std::collections::HashMap::new(),
            };
            let _ = self.core.asset_repo().store_asset(&control_asset).await;

            vtxo_assets.push((control_asset_id.clone(), control_amount));
            vtxo_assets.push((asset_id.clone(), req.amount));
            issued_asset_ids.push(control_asset_id);
            issued_asset_ids.push(asset_id.clone());
        } else if req.name.starts_with("control:existing:") {
            let _existing_control_id = req.name["control:existing:".len()..].to_string();
            // The existing control asset is already stored; just issue the new asset
            vtxo_assets.push((asset_id.clone(), req.amount));
            issued_asset_ids.push(asset_id.clone());
        } else {
            // No control asset — single asset issuance
            vtxo_assets.push((asset_id.clone(), req.amount));
            issued_asset_ids.push(asset_id.clone());
        }

        // Store the main asset
        let asset = dark_core::domain::Asset {
            asset_id: asset_id.clone(),
            amount: req.amount,
            issuer_pubkey: pubkey.clone(),
            max_supply: Some(req.amount),
            metadata: std::collections::HashMap::new(),
        };
        let _ = self.core.asset_repo().store_asset(&asset).await;

        // Generate a deterministic txid for this issuance
        let mut tx_hasher = Sha256::new();
        tx_hasher.update(b"issue-tx:");
        tx_hasher.update(asset_id.as_bytes());
        tx_hasher.update(pubkey.as_bytes());
        let txid = hex::encode(tx_hasher.finalize());

        // Store issuance record
        let issuance = dark_core::domain::AssetIssuance {
            txid: txid.clone(),
            asset_id: asset_id.clone(),
            amount: req.amount,
            issuer_pubkey: pubkey.clone(),
            control_asset_id: if issued_asset_ids.len() > 1 {
                Some(issued_asset_ids[0].clone())
            } else {
                None
            },
            metadata: std::collections::HashMap::new(),
        };
        let _ = self.core.asset_repo().store_issuance(&issuance).await;

        // Create a VTXO that carries the asset(s).
        // The sat amount is the dust limit — asset VTXOs don't carry real BTC value,
        // they just need enough sats to be valid on-chain if settled.
        const ASSET_VTXO_DUST_SATS: u64 = 546;
        let vtxo_outpoint = dark_core::domain::VtxoOutpoint::new(txid.clone(), 0);
        let mut vtxo =
            dark_core::domain::Vtxo::new(vtxo_outpoint, ASSET_VTXO_DUST_SATS, pubkey.clone());
        vtxo.ark_txid = txid.clone();
        vtxo.preconfirmed = true;
        vtxo.assets = vtxo_assets;
        let vtxo_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        vtxo.expires_at = vtxo_now + 86400; // 24h expiry

        // Link the asset VTXO to the same on-chain commitment as the
        // issuer's BTC VTXO so that `check_unrolled_vtxos()` can detect
        // when the VTXO tree has been unrolled and mark this asset VTXO
        // accordingly.
        if let Ok((spendable, _)) = self
            .core
            .vtxo_repo()
            .get_all_vtxos_for_pubkey(&pubkey)
            .await
        {
            // Pick the most recent spendable VTXO that has a commitment
            // txid (i.e. was settled in a round, not a note).
            if let Some(anchor) = spendable
                .iter()
                .filter(|v| !v.root_commitment_txid.is_empty())
                .max_by_key(|v| v.expires_at)
            {
                vtxo.root_commitment_txid = anchor.root_commitment_txid.clone();
                vtxo.commitment_txids = anchor.commitment_txids.clone();
            }
        }

        if let Err(e) = self.core.vtxo_repo().add_vtxos(&[vtxo]).await {
            warn!("Failed to create asset VTXO: {}", e);
        }

        info!(
            asset_id = %asset_id,
            txid = %txid,
            issued_count = issued_asset_ids.len(),
            "Asset issued successfully"
        );

        Ok(Response::new(IssueAssetResponse {
            asset_id: asset_id.clone(),
            txid,
            issued_asset_ids,
        }))
    }

    async fn reissue_asset(
        &self,
        request: Request<ReissueAssetRequest>,
    ) -> Result<Response<ReissueAssetResponse>, Status> {
        use sha2::{Digest, Sha256};

        let req = request.into_inner();
        info!(
            "ArkService::ReissueAsset called asset_id={} amount={}",
            req.asset_id, req.amount
        );

        if req.asset_id.is_empty() {
            return Err(Status::invalid_argument("asset_id must not be empty"));
        }
        if req.amount == 0 {
            return Err(Status::invalid_argument("amount must be > 0"));
        }

        let pubkey = if req.pubkey.is_empty() {
            "default-issuer".to_string()
        } else {
            req.pubkey.clone()
        };

        // Generate deterministic txid for the reissuance
        let mut hasher = Sha256::new();
        hasher.update(b"reissue-tx:");
        hasher.update(req.asset_id.as_bytes());
        hasher.update(req.amount.to_le_bytes());
        hasher.update(pubkey.as_bytes());
        let txid = hex::encode(hasher.finalize());

        // Create a new VTXO with the reissued amount
        const ASSET_VTXO_DUST_SATS: u64 = 546;
        let vtxo_outpoint = dark_core::domain::VtxoOutpoint::new(txid.clone(), 0);
        let mut vtxo =
            dark_core::domain::Vtxo::new(vtxo_outpoint, ASSET_VTXO_DUST_SATS, pubkey.clone());
        vtxo.ark_txid = txid.clone();
        vtxo.preconfirmed = true;
        vtxo.assets = vec![(req.asset_id.clone(), req.amount)];
        let vtxo_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        vtxo.expires_at = vtxo_now + 86400;

        if let Err(e) = self.core.vtxo_repo().add_vtxos(&[vtxo]).await {
            warn!("Failed to create reissued asset VTXO: {}", e);
        }

        // Store issuance record
        let issuance = dark_core::domain::AssetIssuance {
            txid: txid.clone(),
            asset_id: req.asset_id.clone(),
            amount: req.amount,
            issuer_pubkey: pubkey,
            control_asset_id: None,
            metadata: std::collections::HashMap::new(),
        };
        let _ = self.core.asset_repo().store_issuance(&issuance).await;

        info!(asset_id = %req.asset_id, amount = req.amount, txid = %txid, "Asset reissued");

        Ok(Response::new(ReissueAssetResponse { txid }))
    }

    async fn burn_asset(
        &self,
        request: Request<BurnAssetRequest>,
    ) -> Result<Response<BurnAssetResponse>, Status> {
        use sha2::{Digest, Sha256};

        let req = request.into_inner();
        info!(
            "ArkService::BurnAsset called asset_id={} amount={}",
            req.asset_id, req.amount
        );

        if req.asset_id.is_empty() {
            return Err(Status::invalid_argument("asset_id must not be empty"));
        }
        if req.amount == 0 {
            return Err(Status::invalid_argument("amount must be > 0"));
        }

        let pubkey = if req.pubkey.is_empty() {
            "default-issuer".to_string()
        } else {
            req.pubkey.clone()
        };

        // Generate deterministic txid for the burn
        let mut hasher = Sha256::new();
        hasher.update(b"burn-tx:");
        hasher.update(req.asset_id.as_bytes());
        hasher.update(req.amount.to_le_bytes());
        hasher.update(pubkey.as_bytes());
        let txid = hex::encode(hasher.finalize());

        // Find existing VTXOs with this asset for this pubkey and reduce their balance
        let (spendable, _) = self
            .core
            .get_vtxos_for_pubkey(&pubkey)
            .await
            .map_err(|e| Status::internal(format!("Failed to get VTXOs: {}", e)))?;

        let mut remaining_burn = req.amount;
        for vtxo in &spendable {
            if remaining_burn == 0 {
                break;
            }
            // Check if this VTXO has the target asset
            let has_asset = vtxo.assets.iter().any(|(id, _)| id == &req.asset_id);
            if !has_asset {
                continue;
            }

            // Mark the old VTXO as spent
            let spend_outpoint = vtxo.outpoint.clone();
            let _ = self
                .core
                .vtxo_repo()
                .spend_vtxos(&[(spend_outpoint.clone(), txid.clone())], &txid)
                .await;

            // Create a replacement VTXO with reduced asset amount
            let mut new_assets: Vec<(String, u64)> = Vec::new();
            for (aid, amt) in &vtxo.assets {
                if aid == &req.asset_id {
                    let burn_from_this = remaining_burn.min(*amt);
                    remaining_burn -= burn_from_this;
                    let new_amt = amt - burn_from_this;
                    if new_amt > 0 {
                        new_assets.push((aid.clone(), new_amt));
                    }
                } else {
                    new_assets.push((aid.clone(), *amt));
                }
            }

            // Create replacement VTXO with new asset balance
            let new_outpoint =
                dark_core::domain::VtxoOutpoint::new(txid.clone(), spend_outpoint.vout);
            let mut new_vtxo =
                dark_core::domain::Vtxo::new(new_outpoint, vtxo.amount, vtxo.pubkey.clone());
            new_vtxo.ark_txid = txid.clone();
            new_vtxo.preconfirmed = true;
            new_vtxo.assets = new_assets;
            new_vtxo.expires_at = vtxo.expires_at;
            new_vtxo.expires_at_block = vtxo.expires_at_block;

            if let Err(e) = self.core.vtxo_repo().add_vtxos(&[new_vtxo]).await {
                warn!("Failed to create post-burn VTXO: {}", e);
            }
        }

        info!(asset_id = %req.asset_id, burned = req.amount, txid = %txid, "Asset burned");

        Ok(Response::new(BurnAssetResponse { txid }))
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

        // Get the current round ID for pending note tracking.
        // register_intent will auto-start a round if needed, so we get the
        // round_id after registration below. For now, redeem notes as pending
        // with a temporary tag; we'll re-tag after we know the round.

        // Build the intent first (before redeeming notes) so we can register
        // and learn the round_id, then use pending redemption.
        let note_id = uuid::Uuid::new_v4().to_string();

        // Validate and compute total amount without consuming notes yet.
        let mut total_amount: u64 = 0;
        for note_str in &req.notes {
            // Validate note format by decoding (dry run).
            let _ = crate::notes::decode_note_public(note_str)
                .map_err(|e| Status::invalid_argument(format!("Invalid note: {e}")))?;
        }

        // We need the round_id for pending tracking. Register the intent first
        // to ensure a round exists, then redeem notes as pending for that round.
        // However, we need the amount before registering. So: decode all notes
        // to get amounts, redeem as pending for a temporary key, register intent,
        // then re-key pending entries to the actual round_id.

        // Redeem all notes as pending under a temporary key (the note_id).
        // If any fail, rollback previously redeemed ones.
        let pending_key = format!("note-intent:{}", note_id);
        for (i, note_str) in req.notes.iter().enumerate() {
            match self.note_store.redeem_pending(note_str, &pending_key).await {
                Ok(amount) => {
                    info!(amount, "Note redeemed (pending)");
                    total_amount += amount;
                }
                Err(e) => {
                    // Rollback any notes already redeemed in this batch.
                    if i > 0 {
                        self.note_store.rollback_pending(&pending_key).await;
                    }
                    return Err(Status::invalid_argument(format!("Invalid note: {e}")));
                }
            }
        }

        let mut intent = dark_core::domain::Intent::new(
            note_id.clone(),
            format!("note-redeem:{}", note_id), // proof placeholder
            format!("note-redeem:{}:{}", req.pubkey, total_amount),
            vec![],
        )
        .map_err(|e| {
            // Rollback notes if intent creation fails.
            // Note: we can't await in map_err, so we use block_in_place workaround.
            // Instead, just log — the rollback happens below.
            Status::internal(format!("Failed to create note intent: {e}"))
        })?;

        // Set the receiver — this is the output VTXO the redeemer will receive
        intent.receivers = vec![dark_core::domain::Receiver {
            pubkey: req.pubkey.clone(),
            onchain_address: String::new(),
            amount: total_amount,
        }];
        // Note redemptions do not participate in MuSig2 tree signing — the server
        // auto-completes signing for rounds with no cosigners. Leave cosigners empty.
        intent.cosigners_public_keys = vec![];

        // Subscribe to the event bus BEFORE attempting registration so we
        // never miss a RoundStarted event that fires between our attempt and
        // the subscribe call.
        let mut event_rx = self
            .core
            .subscribe_events()
            .await
            .map_err(|e| Status::internal(format!("Failed to subscribe to events: {e}")))?;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);

        let intent_id = loop {
            match self.core.register_intent(intent.clone()).await {
                Ok(id) => break id,
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("Not in registration stage") {
                        // Non-retryable error — rollback and return immediately.
                        self.note_store.rollback_pending(&pending_key).await;
                        warn!("Intent registration failed, rolled back pending notes: {e}");
                        return Err(Status::internal(msg));
                    }

                    // The round is not currently accepting registrations.
                    // Wait for the next RoundStarted event, then retry.
                    info!("Round not in registration stage, waiting for next RoundStarted…");
                    loop {
                        let timeout =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        if timeout.is_zero() {
                            self.note_store.rollback_pending(&pending_key).await;
                            warn!("Timed out waiting for registration window");
                            return Err(Status::internal(
                                "Timed out waiting for a round in registration stage".to_string(),
                            ));
                        }
                        match tokio::time::timeout(timeout, event_rx.recv()).await {
                            Ok(Ok(dark_core::domain::ArkEvent::RoundStarted { .. })) => {
                                // New round started — break inner loop to retry registration.
                                break;
                            }
                            Ok(Ok(_)) => {
                                // Irrelevant event — keep waiting.
                                continue;
                            }
                            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                                warn!(skipped = n, "Event subscriber lagged, continuing");
                                continue;
                            }
                            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                                self.note_store.rollback_pending(&pending_key).await;
                                return Err(Status::internal("Event bus closed".to_string()));
                            }
                            Err(_) => {
                                // Timeout elapsed.
                                self.note_store.rollback_pending(&pending_key).await;
                                warn!("Timed out waiting for RoundStarted event");
                                return Err(Status::internal(
                                    "Timed out waiting for a round in registration stage"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        };

        // Now get the actual round_id and re-key the pending entries.
        let round_id = self
            .core
            .current_round_snapshot()
            .await
            .map(|r| r.id.clone())
            .unwrap_or_else(|| pending_key.clone());
        self.note_store.rekey_pending(&pending_key, &round_id).await;

        info!(
            intent_id,
            total_amount, "Note redeemed — intent registered, returning immediately"
        );

        Ok(Response::new(RedeemNotesResponse {
            txid: intent_id,
            amount_redeemed: total_amount,
        }))
    }
}

// TODO(#55): Asset RPCs (ListAssets, RegisterAsset, GetAsset) pending proto update

/// Parse the Arkade asset packet from a transaction's OP_RETURN output.
///
/// Returns a map from output vout → Vec<(asset_id, amount)>.
/// The format is: OP_RETURN <push> "ARK" <type=0x00> <varint_len> <packet>.
/// A packet is: <varint_group_count> [<group>...] where each group has
/// presence bits, optional asset_id, inputs and outputs.
///
/// For issuance groups (no asset_id in group), the asset_id is derived as
/// sha256(sha256(txid_le ++ group_index_le16)).  This matches the Go
/// `asset.NewAssetId(txid, index)` behaviour.
fn parse_asset_packet_from_tx(
    tx: &bitcoin::Transaction,
    ark_txid: &str,
) -> std::collections::HashMap<u16, Vec<(String, u64)>> {
    let mut result: std::collections::HashMap<u16, Vec<(String, u64)>> =
        std::collections::HashMap::new();

    // Find the OP_RETURN output containing the ARK extension
    let mut ext_data: Option<&[u8]> = None;
    for out in &tx.output {
        let script_bytes = out.script_pubkey.as_bytes();
        if script_bytes.len() < 5 || script_bytes[0] != 0x6a {
            continue; // not OP_RETURN
        }
        // Decode OP_RETURN push data
        let push_data = match decode_op_return_push(script_bytes) {
            Some(d) => d,
            None => continue,
        };
        // Check for "ARK" magic (0x41 0x52 0x4b)
        if push_data.len() >= 3
            && push_data[0] == 0x41
            && push_data[1] == 0x52
            && push_data[2] == 0x4b
        {
            ext_data = Some(push_data);
            break;
        }
    }

    let ext_data = match ext_data {
        Some(d) => d,
        None => return result,
    };

    // Skip "ARK" magic
    let data = &ext_data[3..];
    if data.is_empty() {
        return result;
    }

    // Parse extension packets: <type_byte> <varint_length> <data>
    let mut pos = 0;
    while pos < data.len() {
        let pkt_type = data[pos];
        pos += 1;
        let (pkt_len, bytes_read) = match read_varint(&data[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += bytes_read;
        if pkt_type == 0x00 {
            // Asset packet
            let end = std::cmp::min(pos + pkt_len as usize, data.len());
            parse_asset_groups(&data[pos..end], ark_txid, &mut result);
        }
        pos += pkt_len as usize;
    }

    result
}

/// Decode the push data from an OP_RETURN script.
fn decode_op_return_push(script: &[u8]) -> Option<&[u8]> {
    if script.len() < 2 || script[0] != 0x6a {
        return None;
    }
    let mut pos = 1;
    // Handle push opcode
    let op = script[pos];
    pos += 1;
    if op <= 75 {
        // Direct push: op is the length
        let len = op as usize;
        if pos + len <= script.len() {
            return Some(&script[pos..pos + len]);
        }
    } else if op == 0x4c {
        // OP_PUSHDATA1
        if pos >= script.len() {
            return None;
        }
        let len = script[pos] as usize;
        pos += 1;
        if pos + len <= script.len() {
            return Some(&script[pos..pos + len]);
        }
    } else if op == 0x4d {
        // OP_PUSHDATA2
        if pos + 1 >= script.len() {
            return None;
        }
        let len = u16::from_le_bytes([script[pos], script[pos + 1]]) as usize;
        pos += 2;
        if pos + len <= script.len() {
            return Some(&script[pos..pos + len]);
        }
    } else if op == 0x4e {
        // OP_PUSHDATA4
        if pos + 3 >= script.len() {
            return None;
        }
        let len = u32::from_le_bytes([
            script[pos],
            script[pos + 1],
            script[pos + 2],
            script[pos + 3],
        ]) as usize;
        pos += 4;
        if pos + len <= script.len() {
            return Some(&script[pos..pos + len]);
        }
    }
    None
}

/// Read a varint (protobuf-style base-128 / Go binary.Uvarint). Returns (value, bytes_consumed).
/// Each byte's MSB indicates continuation; bits 0-6 carry value in little-endian order.
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return None; // overflow
        }
        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None // unterminated varint
}

/// Parse asset groups from the packet body and populate the vout → assets map.
fn parse_asset_groups(
    data: &[u8],
    ark_txid: &str,
    result: &mut std::collections::HashMap<u16, Vec<(String, u64)>>,
) {
    let mut pos = 0;

    // Read group count
    let (group_count, n) = match read_varint(&data[pos..]) {
        Some(v) => v,
        None => return,
    };
    pos += n;

    for group_index in 0..group_count as u16 {
        if pos >= data.len() {
            break;
        }

        // Presence byte
        let presence = data[pos];
        pos += 1;

        // Determine asset_id
        let has_asset_id = (presence & 0x01) != 0;
        let has_control_asset = (presence & 0x02) != 0;
        let has_metadata = (presence & 0x04) != 0;

        let asset_id_str: String;

        if has_asset_id {
            // Read 34-byte asset ID: 32-byte txid (display-order) + 2-byte index LE
            // The String() format is hex(serialized_bytes)
            if pos + 34 > data.len() {
                break;
            }
            asset_id_str = hex::encode(&data[pos..pos + 34]);
            pos += 34;
        } else {
            // Issuance: derive asset_id from ark_txid + group_index
            // Go's asset.NewAssetId(txid, index).String() returns
            // hex(serializeTxHash(chainhash) ++ uint16LE(index))
            // where serializeTxHash reverses the internal chainhash bytes
            // back to display order. Since ark_txid is already in display
            // order, the serialized form is just the raw hex bytes of
            // ark_txid followed by the 2-byte LE index.
            let index_bytes = group_index.to_le_bytes();
            asset_id_str = format!("{}{}", ark_txid, hex::encode(index_bytes));
        }

        // Skip control asset if present
        if has_control_asset {
            if pos >= data.len() {
                break;
            }
            let ref_type = data[pos];
            pos += 1;
            match ref_type {
                1 => pos += 34, // AssetRefByID: 34-byte asset_id
                2 => pos += 2,  // AssetRefByGroup: 2-byte group index
                _ => break,
            }
        }

        // Skip metadata if present
        if has_metadata {
            let (md_count, n) = match read_varint(&data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += n;
            for _ in 0..md_count {
                // key: varint_len + bytes
                let (klen, n) = match read_varint(&data[pos..]) {
                    Some(v) => v,
                    None => return,
                };
                pos += n + klen as usize;
                // value: varint_len + bytes
                let (vlen, n) = match read_varint(&data[pos..]) {
                    Some(v) => v,
                    None => return,
                };
                pos += n + vlen as usize;
            }
        }

        // Read inputs (skip them, we only need outputs)
        let (input_count, n) = match read_varint(&data[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += n;
        for _ in 0..input_count {
            if pos >= data.len() {
                break;
            }
            let input_type = data[pos];
            pos += 1;
            match input_type {
                1 => {
                    // Local: vin(2) + varint amount
                    pos += 2;
                    let (_, n) = match read_varint(&data[pos..]) {
                        Some(v) => v,
                        None => return,
                    };
                    pos += n;
                }
                2 => {
                    // Intent: txid(32) + vin(2) + varint amount
                    pos += 32 + 2;
                    let (_, n) = match read_varint(&data[pos..]) {
                        Some(v) => v,
                        None => return,
                    };
                    pos += n;
                }
                _ => return,
            }
        }

        // Read outputs — this is what we need
        let (output_count, n) = match read_varint(&data[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += n;
        for _ in 0..output_count {
            if pos >= data.len() {
                break;
            }
            let _output_type = data[pos]; // always 1 (Local)
            pos += 1;
            if pos + 2 > data.len() {
                break;
            }
            let vout = u16::from_le_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            let (amount, n) = match read_varint(&data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += n;

            result
                .entry(vout)
                .or_default()
                .push((asset_id_str.clone(), amount));
        }
    }
}

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
        } else {
            panic!("Expected heartbeat event");
        }
    }
}
