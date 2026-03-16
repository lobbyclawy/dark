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

/// AdminService gRPC handler backed by the core application service.
pub struct AdminGrpcService {
    core: Arc<arkd_core::ArkService>,
    started_at: Instant,
}

impl AdminGrpcService {
    /// Create a new AdminGrpcService wrapping the core service.
    pub fn new(core: Arc<arkd_core::ArkService>) -> Self {
        Self {
            core,
            started_at: Instant::now(),
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

        let uptime = self.started_at.elapsed().as_secs();

        Ok(Response::new(GetStatusResponse {
            version: arkd_core::VERSION.to_string(),
            network: info.network,
            uptime_secs: uptime,
            active_rounds: 0,
            total_participants: 0,
            total_vtxos: 0,
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

        // Round details require RoundRepository — not yet wired through ArkService
        Err(Status::not_found(format!(
            "Round {} not found",
            req.round_id
        )))
    }

    async fn get_rounds(
        &self,
        _request: Request<GetRoundsRequest>,
    ) -> Result<Response<GetRoundsResponse>, Status> {
        info!("AdminService::GetRounds called");

        // Returns empty until RoundRepository is wired
        Ok(Response::new(GetRoundsResponse { round_ids: vec![] }))
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
        Ok(Response::new(GetScheduledSweepResponse {
            scheduled_at: 0,
            vtxo_count: 0,
            total_amount: 0,
        }))
    }

    async fn sweep(
        &self,
        _request: Request<SweepRequest>,
    ) -> Result<Response<SweepResponse>, Status> {
        info!("AdminService::Sweep called");
        Err(Status::unimplemented(
            "Sweep not yet implemented — requires SweepService integration",
        ))
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

        Err(Status::unimplemented(
            "RevokeAuth not yet implemented — requires AuthService integration",
        ))
    }

    // --- Session Config ---

    async fn get_scheduled_session_config(
        &self,
        _request: Request<GetScheduledSessionConfigRequest>,
    ) -> Result<Response<GetScheduledSessionConfigResponse>, Status> {
        info!("AdminService::GetScheduledSessionConfig called");
        Ok(Response::new(GetScheduledSessionConfigResponse {
            config: Some(crate::proto::ark_v1::SessionConfig {
                round_interval_secs: 10,
                round_lifetime_secs: 30,
                max_intents_per_round: 128,
            }),
        }))
    }

    async fn update_scheduled_session_config(
        &self,
        request: Request<UpdateScheduledSessionConfigRequest>,
    ) -> Result<Response<UpdateScheduledSessionConfigResponse>, Status> {
        let req = request.into_inner();
        info!("AdminService::UpdateScheduledSessionConfig called");

        let _config = req
            .config
            .ok_or_else(|| Status::invalid_argument("config is required"))?;

        Err(Status::unimplemented(
            "UpdateScheduledSessionConfig not yet implemented — requires config persistence",
        ))
    }

    async fn clear_scheduled_session_config(
        &self,
        _request: Request<ClearScheduledSessionConfigRequest>,
    ) -> Result<Response<ClearScheduledSessionConfigResponse>, Status> {
        info!("AdminService::ClearScheduledSessionConfig called");
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

        Err(Status::unimplemented(
            "DeleteConviction not yet implemented — requires ConvictionRepository",
        ))
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

        Ok(Response::new(BanParticipantResponse { success: true }))
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
        Err(Status::unimplemented("TODO: #162"))
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
        Err(Status::unimplemented("TODO: #162"))
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
        Err(Status::unimplemented("TODO: #162"))
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
        Err(Status::unimplemented("TODO: #162"))
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

        Err(Status::unimplemented("TODO: #162"))
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

        Err(Status::unimplemented("TODO: #162"))
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

        Err(Status::unimplemented("TODO: #162"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_grpc_service_creation() {
        // Verify we can reference the type
        let _type_check: fn(Arc<arkd_core::ArkService>) -> AdminGrpcService = AdminGrpcService::new;
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
}
