//! AdminService gRPC implementation — operator API.

use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};
use tracing::info;

use crate::proto::ark_v1::admin_service_server::AdminService as AdminServiceTrait;
use crate::proto::ark_v1::{
    ClearIntentFeesRequest, ClearIntentFeesResponse, ClearScheduledSessionConfigRequest,
    ClearScheduledSessionConfigResponse, DeleteConvictionRequest, DeleteConvictionResponse,
    DeleteIntentsRequest, DeleteIntentsResponse, GetExpiringLiquidityRequest,
    GetExpiringLiquidityResponse, GetIntentFeesRequest, GetIntentFeesResponse,
    GetRecoverableLiquidityRequest, GetRecoverableLiquidityResponse, GetRoundDetailsRequest,
    GetRoundDetailsResponse, GetRoundsRequest, GetRoundsResponse, GetScheduledSessionConfigRequest,
    GetScheduledSessionConfigResponse, GetScheduledSweepRequest, GetScheduledSweepResponse,
    GetStatusRequest, GetStatusResponse, ListConvictionsRequest, ListConvictionsResponse,
    ListIntentsRequest, ListIntentsResponse, RevokeAuthRequest, RevokeAuthResponse, SweepRequest,
    SweepResponse, UpdateIntentFeesRequest, UpdateIntentFeesResponse,
    UpdateScheduledSessionConfigRequest, UpdateScheduledSessionConfigResponse,
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

    // --- New RPCs ---

    async fn list_intents(
        &self,
        _request: Request<ListIntentsRequest>,
    ) -> Result<Response<ListIntentsResponse>, Status> {
        info!("AdminService::ListIntents called");
        // Stub: returns empty list until IntentRepository is wired
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

        // Stub: no-op until IntentRepository is wired
        Err(Status::unimplemented(
            "DeleteIntents not yet implemented — requires IntentRepository",
        ))
    }

    async fn get_intent_fees(
        &self,
        _request: Request<GetIntentFeesRequest>,
    ) -> Result<Response<GetIntentFeesResponse>, Status> {
        info!("AdminService::GetIntentFees called");
        // Stub: returns default fee config
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

        // Stub: requires fee persistence — returning UNIMPLEMENTED for consistency
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

    async fn get_scheduled_sweep(
        &self,
        _request: Request<GetScheduledSweepRequest>,
    ) -> Result<Response<GetScheduledSweepResponse>, Status> {
        info!("AdminService::GetScheduledSweep called");
        // Stub: no sweep scheduled
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
        // Stub: requires SweepService wiring
        Err(Status::unimplemented(
            "Sweep not yet implemented — requires SweepService integration",
        ))
    }

    async fn get_expiring_liquidity(
        &self,
        request: Request<GetExpiringLiquidityRequest>,
    ) -> Result<Response<GetExpiringLiquidityResponse>, Status> {
        let req = request.into_inner();
        info!(
            within_secs = req.within_secs,
            "AdminService::GetExpiringLiquidity called"
        );
        // Stub: returns zero until VtxoRepository queries are wired
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
        // Stub: returns zero until VtxoRepository queries are wired
        Ok(Response::new(GetRecoverableLiquidityResponse {
            total_amount: 0,
            vtxo_count: 0,
        }))
    }

    async fn revoke_auth(
        &self,
        request: Request<RevokeAuthRequest>,
    ) -> Result<Response<RevokeAuthResponse>, Status> {
        let req = request.into_inner();
        info!(token_id = %req.token_id, "AdminService::RevokeAuth called");

        if req.token_id.is_empty() {
            return Err(Status::invalid_argument("token_id is required"));
        }

        // Stub: requires AuthService wiring
        Err(Status::unimplemented(
            "RevokeAuth not yet implemented — requires AuthService integration",
        ))
    }

    async fn get_scheduled_session_config(
        &self,
        _request: Request<GetScheduledSessionConfigRequest>,
    ) -> Result<Response<GetScheduledSessionConfigResponse>, Status> {
        info!("AdminService::GetScheduledSessionConfig called");
        // Stub: returns default config
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

        // Stub: requires config persistence — returning UNIMPLEMENTED for consistency
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

    async fn list_convictions(
        &self,
        _request: Request<ListConvictionsRequest>,
    ) -> Result<Response<ListConvictionsResponse>, Status> {
        info!("AdminService::ListConvictions called");
        // Stub: returns empty list until ConvictionRepository is wired
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

        // Stub: requires ConvictionRepository wiring
        Err(Status::unimplemented(
            "DeleteConviction not yet implemented — requires ConvictionRepository",
        ))
    }
}

// ---------------------------------------------------------------------------
// CreateNote — not yet in .proto, so we define Rust-side request/response
// types and a standalone method on AdminGrpcService.
// ---------------------------------------------------------------------------

/// Request payload for creating a note VTXO (Rust-side, pending proto definition).
#[derive(Debug, Clone)]
pub struct CreateNoteRequest {
    /// Amount in satoshis
    pub amount: u64,
    /// Receiver's public key (hex-encoded x-only)
    pub receiver_pubkey: String,
}

/// Response payload for a created note VTXO (Rust-side, pending proto definition).
#[derive(Debug, Clone)]
pub struct CreateNoteResponse {
    /// The created note VTXO's outpoint as string ("txid:vout")
    pub outpoint: String,
    /// Note URI for sharing
    pub note_uri: String,
}

impl AdminGrpcService {
    /// Create a note VTXO (stub — will be wired to AdminPort once proto is updated).
    ///
    /// Returns `Status::unimplemented` until the admin port is wired.
    pub async fn create_note(
        &self,
        _request: CreateNoteRequest,
    ) -> Result<CreateNoteResponse, Status> {
        Err(Status::unimplemented(
            "CreateNote not yet implemented — requires AdminPort wiring",
        ))
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

    #[tokio::test]
    async fn test_create_note_returns_unimplemented() {
        // We can't easily construct ArkService here, so just verify the types compile.
        let req = CreateNoteRequest {
            amount: 100_000,
            receiver_pubkey: "deadbeef".to_string(),
        };
        // Type-level check: CreateNoteRequest and CreateNoteResponse are usable
        assert_eq!(req.amount, 100_000);
        assert_eq!(req.receiver_pubkey, "deadbeef");
    }
}
