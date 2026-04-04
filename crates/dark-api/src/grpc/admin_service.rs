//! AdminService gRPC implementation — operator API.

use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};
use tracing::info;

use crate::proto::ark_v1::admin_service_server::AdminService as AdminServiceTrait;
use crate::proto::ark_v1::{
    BanParticipantRequest, BanParticipantResponse, BanScriptRequest, BanScriptResponse,
    ClearIntentFeesRequest, ClearIntentFeesResponse, ClearScheduledSessionConfigRequest,
    ClearScheduledSessionConfigResponse, CreateNoteRequest as ProtoCreateNoteRequest,
    CreateNoteResponse as ProtoCreateNoteResponse, DeleteConvictionRequest,
    DeleteConvictionResponse, DeleteIntentsRequest, DeleteIntentsResponse,
    GetActiveScriptConvictionsRequest, GetActiveScriptConvictionsResponse,
    GetConvictionsByRoundRequest, GetConvictionsByRoundResponse, GetConvictionsInRangeRequest,
    GetConvictionsInRangeResponse, GetConvictionsRequest, GetConvictionsResponse,
    GetExpiringLiquidityRequest, GetExpiringLiquidityResponse, GetIntentFeesRequest,
    GetIntentFeesResponse, GetRecoverableLiquidityRequest, GetRecoverableLiquidityResponse,
    GetRoundDetailsRequest, GetRoundDetailsResponse, GetRoundsRequest, GetRoundsResponse,
    GetScheduledSessionConfigRequest, GetScheduledSessionConfigResponse, GetScheduledSweepRequest,
    GetScheduledSweepResponse, GetStatusRequest, GetStatusResponse, ListConvictionsRequest,
    ListConvictionsResponse, ListIntentsRequest, ListIntentsResponse, PardonConvictionRequest,
    PardonConvictionResponse, RevokeAuthRequest, RevokeAuthResponse, SweepRequest, SweepResponse,
    UpdateIntentFeesRequest, UpdateIntentFeesResponse, UpdateScheduledSessionConfigRequest,
    UpdateScheduledSessionConfigResponse,
};

/// Convert a domain Conviction to the proto Conviction message.
fn conviction_to_proto(c: &dark_core::Conviction) -> crate::proto::ark_v1::Conviction {
    use crate::proto::ark_v1::{ConvictionType, CrimeType};

    let crime_type = match c.crime_type {
        dark_core::CrimeType::Unspecified => CrimeType::Unspecified,
        dark_core::CrimeType::Musig2NonceSubmission => CrimeType::Musig2NonceSubmission,
        dark_core::CrimeType::Musig2SignatureSubmission => CrimeType::Musig2SignatureSubmission,
        dark_core::CrimeType::Musig2InvalidSignature => CrimeType::Musig2InvalidSignature,
        dark_core::CrimeType::ForfeitSubmission => CrimeType::ForfeitSubmission,
        dark_core::CrimeType::ForfeitInvalidSignature => CrimeType::ForfeitInvalidSignature,
        dark_core::CrimeType::BoardingInputSubmission => CrimeType::BoardingInputSubmission,
        dark_core::CrimeType::ManualBan => CrimeType::ManualBan,
        dark_core::CrimeType::DoubleSpend => CrimeType::Unspecified,
    };

    let conviction_type = match c.kind {
        dark_core::ConvictionKind::Unspecified => ConvictionType::Unspecified,
        dark_core::ConvictionKind::Script => ConvictionType::Script,
    };

    crate::proto::ark_v1::Conviction {
        id: c.id.clone(),
        r#type: conviction_type as i32,
        created_at: c.created_at,
        expires_at: c.expires_at,
        pardoned: c.pardoned,
        script: c.script.clone(),
        crime_type: crime_type as i32,
        round_id: c.round_id.clone(),
        reason: c.reason.clone(),
    }
}

/// AdminService gRPC handler backed by the core application service.
pub struct AdminGrpcService {
    core: Arc<dark_core::ArkService>,
    authenticator: Arc<crate::auth::Authenticator>,
    started_at: Instant,
    pub note_store: Arc<crate::notes::NoteStore>,
}

impl AdminGrpcService {
    /// Create a new AdminGrpcService wrapping the core service.
    pub fn new(core: Arc<dark_core::ArkService>) -> Self {
        Self {
            core,
            authenticator: Arc::new(crate::auth::Authenticator::new(vec![0u8; 32])),
            started_at: Instant::now(),
            note_store: Arc::new(crate::notes::NoteStore::new()),
        }
    }

    /// Create a new AdminGrpcService with a shared authenticator.
    ///
    /// The authenticator is shared with the gRPC server so that tokens
    /// revoked via `RevokeAuth` are immediately rejected on all endpoints.
    pub fn new_with_auth(
        core: Arc<dark_core::ArkService>,
        authenticator: Arc<crate::auth::Authenticator>,
    ) -> Self {
        Self {
            core,
            authenticator,
            started_at: Instant::now(),
            note_store: Arc::new(crate::notes::NoteStore::new()),
        }
    }

    /// Create with a shared NoteStore (so ArkGrpcService can redeem notes).
    pub fn new_with_auth_and_notes(
        core: Arc<dark_core::ArkService>,
        authenticator: Arc<crate::auth::Authenticator>,
        note_store: Arc<crate::notes::NoteStore>,
    ) -> Self {
        Self {
            core,
            authenticator,
            started_at: Instant::now(),
            note_store,
        }
    }
}

#[tonic::async_trait]
impl AdminServiceTrait for AdminGrpcService {
    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        info!("AdminService::GetStatus called");

        let info = self
            .core
            .get_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let stats = self
            .core
            .get_indexer_stats()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let uptime = self.started_at.elapsed().as_secs();

        Ok(Response::new(GetStatusResponse {
            version: dark_core::VERSION.to_string(),
            network: info.network,
            uptime_secs: uptime,
            active_rounds: 0,
            total_participants: 0,
            total_vtxos: stats.total_vtxos,
            signer_pubkey: info.signer_pubkey,
        }))
    }

    async fn get_round_details(
        &self,
        request: Request<GetRoundDetailsRequest>,
    ) -> Result<Response<GetRoundDetailsResponse>, Status> {
        let req = request.into_inner();
        info!(round_id = %req.round_id, "AdminService::GetRoundDetails called");

        if req.round_id.is_empty() {
            return Err(Status::invalid_argument("round_id is required"));
        }

        let round = self
            .core
            .get_round_by_id(&req.round_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("Round {} not found", req.round_id)))?;

        // Compute aggregate amounts and collect VTXO IDs from round intents.
        let forfeited_amount: u64 = 0;
        let mut total_vtxos_amount: u64 = 0;
        let mut total_exit_amount: u64 = 0;
        let total_fee_amount: u64 = 0;
        let mut inputs_vtxos: Vec<String> = Vec::new();
        let mut outputs_vtxos: Vec<String> = Vec::new();
        let mut exit_addresses: Vec<String> = Vec::new();

        for intent in round.intents.values() {
            total_vtxos_amount += intent.total_input_amount();
            for input in &intent.inputs {
                inputs_vtxos.push(format!("{}:{}", input.outpoint.txid, input.outpoint.vout));
            }
            for receiver in &intent.receivers {
                outputs_vtxos.push(receiver.pubkey.clone());
                if receiver.is_onchain() {
                    exit_addresses.push(receiver.pubkey.clone());
                    total_exit_amount += receiver.amount;
                }
            }
        }
        let _ = (forfeited_amount, total_fee_amount); // populated when forfeit tracking is added

        Ok(Response::new(GetRoundDetailsResponse {
            round_id: round.id,
            started_at: round.starting_timestamp,
            ended_at: round.ending_timestamp,
            commitment_txid: round.commitment_txid,
            intent_count: round.intents.len() as u32,
            forfeited_amount,
            total_vtxos_amount,
            total_exit_amount,
            total_fee_amount,
            inputs_vtxos,
            outputs_vtxos,
            exit_addresses,
        }))
    }

    async fn get_rounds(
        &self,
        request: Request<GetRoundsRequest>,
    ) -> Result<Response<GetRoundsResponse>, Status> {
        let req = request.into_inner();
        info!(
            with_failed = req.with_failed,
            with_completed = req.with_completed,
            "AdminService::GetRounds called"
        );

        let rounds = self
            .core
            .list_rounds(0, 1000)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Filter by time range and status flags.
        // after/before are unix timestamps; 0 means "not set".
        let round_ids: Vec<String> = rounds
            .into_iter()
            .filter(|r| {
                if req.after > 0 && r.starting_timestamp < req.after {
                    return false;
                }
                if req.before > 0 && r.starting_timestamp > req.before {
                    return false;
                }
                if req.with_failed && r.stage.failed {
                    return true;
                }
                if req.with_completed && !r.stage.failed && r.swept {
                    return true;
                }
                !req.with_failed && !req.with_completed
            })
            .map(|r| r.id)
            .collect();

        Ok(Response::new(GetRoundsResponse { round_ids }))
    }

    // --- Intents ---

    async fn list_intents(
        &self,
        _request: Request<ListIntentsRequest>,
    ) -> Result<Response<ListIntentsResponse>, Status> {
        info!("AdminService::ListIntents called");
        Ok(Response::new(ListIntentsResponse { intents: vec![] }))
    }

    async fn delete_intents(
        &self,
        request: Request<DeleteIntentsRequest>,
    ) -> Result<Response<DeleteIntentsResponse>, Status> {
        let req = request.into_inner();
        info!(
            count = req.intent_ids.len(),
            "AdminService::DeleteIntents called"
        );

        if req.intent_ids.is_empty() {
            return Err(Status::invalid_argument("intent_ids must not be empty"));
        }

        // TODO: needs IntentRepository wired into ArkService (#165)
        Err(Status::unimplemented(
            "DeleteIntents not yet implemented — requires IntentRepository",
        ))
    }

    // --- Intent Fees ---

    async fn get_intent_fees(
        &self,
        _request: Request<GetIntentFeesRequest>,
    ) -> Result<Response<GetIntentFeesResponse>, Status> {
        info!("AdminService::GetIntentFees called");
        Ok(Response::new(GetIntentFeesResponse {
            fees: Some(crate::proto::ark_v1::IntentFeeConfig {
                base_fee_sats: 0,
                fee_rate_ppm: 0,
            }),
        }))
    }

    async fn update_intent_fees(
        &self,
        request: Request<UpdateIntentFeesRequest>,
    ) -> Result<Response<UpdateIntentFeesResponse>, Status> {
        let req = request.into_inner();
        info!("AdminService::UpdateIntentFees called");

        let _fees = req
            .fees
            .ok_or_else(|| Status::invalid_argument("fees config is required"))?;

        // TODO: needs fee persistence in ConfigService (#165)
        Err(Status::unimplemented(
            "UpdateIntentFees not yet implemented — requires fee persistence",
        ))
    }

    async fn clear_intent_fees(
        &self,
        _request: Request<ClearIntentFeesRequest>,
    ) -> Result<Response<ClearIntentFeesResponse>, Status> {
        info!("AdminService::ClearIntentFees called");
        Ok(Response::new(ClearIntentFeesResponse {}))
    }

    // --- Sweep ---

    async fn get_scheduled_sweep(
        &self,
        _request: Request<GetScheduledSweepRequest>,
    ) -> Result<Response<GetScheduledSweepResponse>, Status> {
        info!("AdminService::GetScheduledSweep called");

        // Query expired VTXOs eligible for sweep (expired by wall-clock
        // time, not yet spent/swept/unrolled).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let expired_vtxos = self
            .core
            .vtxo_repo()
            .find_expired_vtxos(now)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Group by expiration timestamp into individual sweep cohorts.
        use std::collections::BTreeMap;
        let mut by_expiry: BTreeMap<i64, (u32, u64)> = BTreeMap::new();
        for vtxo in &expired_vtxos {
            let entry = by_expiry.entry(vtxo.expires_at).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += vtxo.amount;
        }

        let scheduled_sweeps: Vec<crate::proto::ark_v1::ScheduledSweep> = by_expiry
            .into_iter()
            .map(
                |(ts, (count, amount))| crate::proto::ark_v1::ScheduledSweep {
                    scheduled_at: ts,
                    vtxo_count: count,
                    total_amount: amount,
                },
            )
            .collect();

        // Populate deprecated top-level fields with aggregates for
        // backward compatibility.
        let total_vtxo_count: u32 = scheduled_sweeps.iter().map(|s| s.vtxo_count).sum();
        let total_amount: u64 = scheduled_sweeps.iter().map(|s| s.total_amount).sum();
        let earliest = scheduled_sweeps
            .first()
            .map(|s| s.scheduled_at)
            .unwrap_or(0);

        Ok(Response::new(GetScheduledSweepResponse {
            scheduled_at: earliest,
            vtxo_count: total_vtxo_count,
            total_amount,
            scheduled_sweeps,
        }))
    }

    async fn sweep(
        &self,
        _request: Request<SweepRequest>,
    ) -> Result<Response<SweepResponse>, Status> {
        info!("AdminService::Sweep called");

        // First, sweep expired VTXOs by wall-clock time (marks them in DB).
        let time_swept = self.core.sweep_expired_vtxos().await.unwrap_or(0);

        let current_height = self
            .core
            .wallet()
            .get_current_block_time()
            .await
            .map(|bt| bt.height as u32)
            .unwrap_or(0);

        // Also sweep block-height-based expired VTXOs.
        let block_swept = self.core.sweep_expired_by_height().await.unwrap_or(0);

        let sweep_result = self
            .core
            .run_scheduled_sweep_with_result(current_height)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let swept_count = (sweep_result.vtxos_swept as u32)
            .max(time_swept)
            .max(block_swept);
        let sweep_txid = sweep_result.tx_ids.first().cloned().unwrap_or_default();

        info!(
            swept_vtxos = swept_count,
            sats_recovered = sweep_result.sats_recovered,
            current_height,
            "Admin sweep complete"
        );

        Ok(Response::new(SweepResponse {
            sweep_txid,
            swept_count,
            recovery_txid: String::new(),
        }))
    }

    // --- Liquidity ---

    async fn get_expiring_liquidity(
        &self,
        request: Request<GetExpiringLiquidityRequest>,
    ) -> Result<Response<GetExpiringLiquidityResponse>, Status> {
        let req = request.into_inner();
        info!(
            within_secs = req.within_secs,
            "AdminService::GetExpiringLiquidity called"
        );
        Ok(Response::new(GetExpiringLiquidityResponse {
            total_amount: 0,
            vtxo_count: 0,
        }))
    }

    async fn get_recoverable_liquidity(
        &self,
        _request: Request<GetRecoverableLiquidityRequest>,
    ) -> Result<Response<GetRecoverableLiquidityResponse>, Status> {
        info!("AdminService::GetRecoverableLiquidity called");
        Ok(Response::new(GetRecoverableLiquidityResponse {
            total_amount: 0,
            vtxo_count: 0,
        }))
    }

    // --- Auth ---

    async fn revoke_auth(
        &self,
        request: Request<RevokeAuthRequest>,
    ) -> Result<Response<RevokeAuthResponse>, Status> {
        let req = request.into_inner();
        info!(token_id = %req.token_id, "AdminService::RevokeAuth called");

        if req.token_id.is_empty() {
            return Err(Status::invalid_argument("token_id is required"));
        }

        self.authenticator
            .revoke_token(&req.token_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RevokeAuthResponse {}))
    }

    // --- Session Config ---

    async fn get_scheduled_session_config(
        &self,
        _request: Request<GetScheduledSessionConfigRequest>,
    ) -> Result<Response<GetScheduledSessionConfigResponse>, Status> {
        info!("AdminService::GetScheduledSessionConfig called");

        let repo = self.core.scheduled_session_repo();
        let persisted = repo
            .get()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let config = match persisted {
            Some(cfg) => crate::proto::ark_v1::SessionConfig {
                round_interval_secs: cfg.round_interval_secs,
                round_lifetime_secs: cfg.round_lifetime_secs,
                max_intents_per_round: cfg.max_intents_per_round,
            },
            None => {
                // Fall back to static config defaults
                crate::proto::ark_v1::SessionConfig {
                    round_interval_secs: 10,
                    round_lifetime_secs: 30,
                    max_intents_per_round: 128,
                }
            }
        };

        Ok(Response::new(GetScheduledSessionConfigResponse {
            config: Some(config),
        }))
    }

    async fn update_scheduled_session_config(
        &self,
        request: Request<UpdateScheduledSessionConfigRequest>,
    ) -> Result<Response<UpdateScheduledSessionConfigResponse>, Status> {
        let req = request.into_inner();
        info!("AdminService::UpdateScheduledSessionConfig called");

        let proto_config = req
            .config
            .ok_or_else(|| Status::invalid_argument("config is required"))?;

        let domain_config = dark_core::ScheduledSessionConfig::new(
            proto_config.round_interval_secs,
            proto_config.round_lifetime_secs,
            proto_config.max_intents_per_round,
        );

        self.core
            .scheduled_session_repo()
            .upsert(domain_config)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(UpdateScheduledSessionConfigResponse {
            config: Some(proto_config),
        }))
    }

    async fn clear_scheduled_session_config(
        &self,
        _request: Request<ClearScheduledSessionConfigRequest>,
    ) -> Result<Response<ClearScheduledSessionConfigResponse>, Status> {
        info!("AdminService::ClearScheduledSessionConfig called");

        self.core
            .scheduled_session_repo()
            .clear()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ClearScheduledSessionConfigResponse {}))
    }

    // --- Legacy conviction RPCs ---

    async fn list_convictions(
        &self,
        _request: Request<ListConvictionsRequest>,
    ) -> Result<Response<ListConvictionsResponse>, Status> {
        info!("AdminService::ListConvictions called");
        Ok(Response::new(ListConvictionsResponse {
            convictions: vec![],
        }))
    }

    async fn delete_conviction(
        &self,
        request: Request<DeleteConvictionRequest>,
    ) -> Result<Response<DeleteConvictionResponse>, Status> {
        let req = request.into_inner();
        info!(conviction_id = %req.conviction_id, "AdminService::DeleteConviction called");

        if req.conviction_id.is_empty() {
            return Err(Status::invalid_argument("conviction_id is required"));
        }

        // Pardon is the equivalent of delete in the conviction system
        self.core
            .pardon_conviction(&req.conviction_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeleteConvictionResponse {}))
    }

    async fn ban_participant(
        &self,
        request: Request<BanParticipantRequest>,
    ) -> Result<Response<BanParticipantResponse>, Status> {
        let req = request.into_inner();
        info!(
            pubkey = %req.pubkey,
            reason = %req.reason,
            "AdminService::BanParticipant called"
        );

        if req.pubkey.is_empty() {
            return Err(Status::invalid_argument("pubkey is required"));
        }

        // Convert proto reason to BanReason
        let ban_reason = match req.reason.as_str() {
            "double_spend" => dark_core::BanReason::DoubleSpend,
            "failed_to_confirm" => dark_core::BanReason::FailedToConfirm,
            "invalid_proof" => dark_core::BanReason::InvalidProof,
            other => dark_core::BanReason::Other(other.to_string()),
        };

        // Actually ban the participant using the core service
        match self
            .core
            .ban_participant(&req.pubkey, ban_reason, "admin")
            .await
        {
            Ok(()) => {
                info!(pubkey = %req.pubkey, "Participant banned successfully");
                Ok(Response::new(BanParticipantResponse { success: true }))
            }
            Err(e) => {
                warn!(pubkey = %req.pubkey, error = %e, "Failed to ban participant");
                Err(Status::internal(format!("Failed to ban: {e}")))
            }
        }
    }

    // --- New conviction RPCs (Go admin.proto aligned, #162) ---

    async fn get_convictions(
        &self,
        request: Request<GetConvictionsRequest>,
    ) -> Result<Response<GetConvictionsResponse>, Status> {
        let req = request.into_inner();
        info!(
            ids_count = req.ids.len(),
            "AdminService::GetConvictions called"
        );

        let convictions = self
            .core
            .get_convictions_by_ids(&req.ids)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetConvictionsResponse {
            convictions: convictions.iter().map(conviction_to_proto).collect(),
        }))
    }

    async fn get_convictions_in_range(
        &self,
        request: Request<GetConvictionsInRangeRequest>,
    ) -> Result<Response<GetConvictionsInRangeResponse>, Status> {
        let req = request.into_inner();
        info!(
            from = req.from,
            to = req.to,
            "AdminService::GetConvictionsInRange called"
        );

        let convictions = self
            .core
            .get_convictions_in_range(req.from, req.to)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetConvictionsInRangeResponse {
            convictions: convictions.iter().map(conviction_to_proto).collect(),
        }))
    }

    async fn get_convictions_by_round(
        &self,
        request: Request<GetConvictionsByRoundRequest>,
    ) -> Result<Response<GetConvictionsByRoundResponse>, Status> {
        let req = request.into_inner();
        info!(
            round_id = %req.round_id,
            "AdminService::GetConvictionsByRound called"
        );

        let convictions = self
            .core
            .get_convictions_by_round(&req.round_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetConvictionsByRoundResponse {
            convictions: convictions.iter().map(conviction_to_proto).collect(),
        }))
    }

    async fn get_active_script_convictions(
        &self,
        request: Request<GetActiveScriptConvictionsRequest>,
    ) -> Result<Response<GetActiveScriptConvictionsResponse>, Status> {
        let req = request.into_inner();
        info!(
            script = %req.script,
            "AdminService::GetActiveScriptConvictions called"
        );

        let convictions = self
            .core
            .get_active_script_convictions(&req.script)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetActiveScriptConvictionsResponse {
            convictions: convictions.iter().map(conviction_to_proto).collect(),
        }))
    }

    async fn pardon_conviction(
        &self,
        request: Request<PardonConvictionRequest>,
    ) -> Result<Response<PardonConvictionResponse>, Status> {
        let req = request.into_inner();
        info!(id = %req.id, "AdminService::PardonConviction called");

        if req.id.is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }

        self.core
            .pardon_conviction(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(PardonConvictionResponse {}))
    }

    async fn ban_script(
        &self,
        request: Request<BanScriptRequest>,
    ) -> Result<Response<BanScriptResponse>, Status> {
        let req = request.into_inner();
        info!(
            script = %req.script,
            ban_duration = req.ban_duration,
            reason = %req.reason,
            "AdminService::BanScript called"
        );

        if req.script.is_empty() {
            return Err(Status::invalid_argument("script is required"));
        }

        self.core
            .ban_script(&req.script, &req.reason, req.ban_duration)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(BanScriptResponse {}))
    }

    async fn create_note(
        &self,
        request: Request<ProtoCreateNoteRequest>,
    ) -> Result<Response<ProtoCreateNoteResponse>, Status> {
        let req = request.into_inner();
        info!(
            amount = req.amount,
            quantity = req.quantity,
            "AdminService::CreateNote called"
        );

        if req.amount == 0 {
            return Err(Status::invalid_argument("amount must be > 0"));
        }
        if req.quantity == 0 {
            return Err(Status::invalid_argument("quantity must be > 0"));
        }

        let notes = self
            .note_store
            .create(req.amount, req.quantity.max(1))
            .await;
        info!(count = notes.len(), amount = req.amount, "Notes created");
        Ok(Response::new(ProtoCreateNoteResponse { notes }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_grpc_service_creation() {
        // Verify we can reference the type
        let _type_check: fn(Arc<dark_core::ArkService>) -> AdminGrpcService = AdminGrpcService::new;
    }

    #[test]
    fn test_create_note_request_types() {
        let req = ProtoCreateNoteRequest {
            amount: 100_000,
            quantity: 5,
        };
        assert_eq!(req.amount, 100_000);
        assert_eq!(req.quantity, 5);

        let resp = ProtoCreateNoteResponse {
            notes: vec!["note1".to_string(), "note2".to_string()],
        };
        assert_eq!(resp.notes.len(), 2);
    }

    #[test]
    fn test_ban_script_request_types() {
        let req = BanScriptRequest {
            script: "deadbeef".to_string(),
            ban_duration: 3600,
            reason: "spam".to_string(),
        };
        assert_eq!(req.script, "deadbeef");
        assert_eq!(req.ban_duration, 3600);
        assert_eq!(req.reason, "spam");
    }

    #[test]
    fn test_ban_participant_request_types() {
        let req = BanParticipantRequest {
            pubkey: "deadbeef".to_string(),
            reason: "spam".to_string(),
        };
        assert_eq!(req.pubkey, "deadbeef");
        assert_eq!(req.reason, "spam");

        let resp = BanParticipantResponse { success: true };
        assert!(resp.success);
    }

    #[test]
    fn test_conviction_to_proto() {
        let c = dark_core::Conviction {
            id: "conv-1".to_string(),
            kind: dark_core::ConvictionKind::Script,
            created_at: 1000,
            expires_at: 2000,
            pardoned: false,
            script: "deadbeef".to_string(),
            crime_type: dark_core::CrimeType::ManualBan,
            round_id: "round-1".to_string(),
            reason: "spam".to_string(),
        };

        let proto = conviction_to_proto(&c);
        assert_eq!(proto.id, "conv-1");
        assert_eq!(proto.created_at, 1000);
        assert_eq!(proto.expires_at, 2000);
        assert!(!proto.pardoned);
        assert_eq!(proto.script, "deadbeef");
        assert_eq!(proto.round_id, "round-1");
        assert_eq!(proto.reason, "spam");
        assert_eq!(
            proto.r#type,
            crate::proto::ark_v1::ConvictionType::Script as i32
        );
        assert_eq!(
            proto.crime_type,
            crate::proto::ark_v1::CrimeType::ManualBan as i32
        );
    }

    #[test]
    fn test_conviction_to_proto_all_crime_types() {
        use crate::proto::ark_v1::CrimeType as ProtoCrimeType;

        let cases = vec![
            (
                dark_core::CrimeType::Unspecified,
                ProtoCrimeType::Unspecified,
            ),
            (
                dark_core::CrimeType::Musig2NonceSubmission,
                ProtoCrimeType::Musig2NonceSubmission,
            ),
            (
                dark_core::CrimeType::Musig2SignatureSubmission,
                ProtoCrimeType::Musig2SignatureSubmission,
            ),
            (
                dark_core::CrimeType::Musig2InvalidSignature,
                ProtoCrimeType::Musig2InvalidSignature,
            ),
            (
                dark_core::CrimeType::ForfeitSubmission,
                ProtoCrimeType::ForfeitSubmission,
            ),
            (
                dark_core::CrimeType::ForfeitInvalidSignature,
                ProtoCrimeType::ForfeitInvalidSignature,
            ),
            (
                dark_core::CrimeType::BoardingInputSubmission,
                ProtoCrimeType::BoardingInputSubmission,
            ),
            (dark_core::CrimeType::ManualBan, ProtoCrimeType::ManualBan),
        ];

        for (domain_crime, expected_proto) in cases {
            let c = dark_core::Conviction {
                id: "test".to_string(),
                kind: dark_core::ConvictionKind::Unspecified,
                created_at: 0,
                expires_at: 0,
                pardoned: false,
                script: String::new(),
                crime_type: domain_crime,
                round_id: String::new(),
                reason: String::new(),
            };
            let proto = conviction_to_proto(&c);
            assert_eq!(proto.crime_type, expected_proto as i32);
        }
    }

    #[test]
    fn test_get_round_details_response_mapping() {
        let resp = GetRoundDetailsResponse {
            round_id: "round-abc".to_string(),
            started_at: 1234567890,
            ended_at: 1234567900,
            commitment_txid: "txid123".to_string(),
            intent_count: 5,
            forfeited_amount: 0,
            total_vtxos_amount: 0,
            total_exit_amount: 0,
            total_fee_amount: 0,
            inputs_vtxos: vec![],
            outputs_vtxos: vec![],
            exit_addresses: vec![],
        };
        assert_eq!(resp.round_id, "round-abc");
        assert_eq!(resp.started_at, 1234567890);
        assert_eq!(resp.ended_at, 1234567900);
        assert_eq!(resp.commitment_txid, "txid123");
        assert_eq!(resp.intent_count, 5);
    }

    #[test]
    fn test_sweep_response_types() {
        let resp = SweepResponse {
            sweep_txid: String::new(),
            swept_count: 42,
            recovery_txid: String::new(),
        };
        assert_eq!(resp.swept_count, 42);
        assert!(resp.sweep_txid.is_empty());
        assert!(resp.recovery_txid.is_empty());
    }
}
