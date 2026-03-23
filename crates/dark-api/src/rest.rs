//! REST/JSON gateway for the admin API.
//!
//! Provides axum HTTP handlers that translate JSON REST requests into calls
//! to the underlying gRPC service implementations. This enables Go e2e tests
//! and other HTTP clients to interact with dark without a gRPC client.
//!
//! ## Endpoints
//!
//! ### Wallet
//! - `GET  /v1/admin/wallet/seed`    → `WalletService::GenSeed`
//! - `POST /v1/admin/wallet/create`  → `WalletService::Create`
//! - `POST /v1/admin/wallet/restore` → `WalletService::Restore`
//! - `POST /v1/admin/wallet/unlock`  → `WalletService::Unlock`
//! - `GET  /v1/admin/wallet/status`  → `WalletService::GetStatus`
//! - `GET  /v1/admin/wallet/balance` → `WalletService::GetBalance`
//! - `GET  /v1/admin/wallet/address` → `WalletService::DeriveAddress`
//!
//! ### Admin
//! - `POST /v1/admin/note`              → `AdminService::CreateNote`
//! - `GET  /v1/admin/intentFees`        → `AdminService::GetIntentFees`
//! - `POST /v1/admin/intentFees`        → `AdminService::UpdateIntentFees`
//! - `POST /v1/admin/intentFees/clear`  → `AdminService::ClearIntentFees`
//! - `GET  /v1/admin/sweeps`            → `AdminService::GetScheduledSweep`
//! - `POST /v1/admin/sweep`             → `AdminService::Sweep`
//! - `POST /v1/admin/fees`              → stub (returns `{}`)

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tonic::Request;
use tracing::info;

use crate::grpc::admin_service::AdminGrpcService;
use crate::grpc::wallet_service::WalletGrpcService;
use crate::proto::ark_v1::admin_service_server::AdminService as AdminServiceTrait;
use crate::proto::ark_v1::wallet_service_server::WalletService as WalletServiceTrait;

// ── Shared state ─────────────────────────────────────────────────────────

/// Shared state for REST handlers, holding references to the gRPC service
/// implementations so REST calls can delegate directly.
#[derive(Clone)]
pub struct RestState {
    pub wallet_svc: Arc<WalletGrpcService>,
    pub admin_svc: Arc<AdminGrpcService>,
}

// ── Error handling ───────────────────────────────────────────────────────

/// Convert a tonic `Status` into an axum HTTP response with a JSON body.
fn status_to_response(status: tonic::Status) -> Response {
    let http_code = match status.code() {
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };

    let body = serde_json::json!({
        "error": status.message(),
        "code": status.code() as i32,
    });

    (http_code, Json(body)).into_response()
}

// ── Router ───────────────────────────────────────────────────────────────

/// Build the REST router for admin endpoints.
pub fn build_rest_router(state: RestState) -> Router {
    Router::new()
        // Wallet endpoints
        .route("/v1/admin/wallet/seed", get(wallet_gen_seed))
        .route("/v1/admin/wallet/create", post(wallet_create))
        .route("/v1/admin/wallet/restore", post(wallet_restore))
        .route("/v1/admin/wallet/unlock", post(wallet_unlock))
        .route("/v1/admin/wallet/status", get(wallet_status))
        .route("/v1/admin/wallet/balance", get(wallet_balance))
        .route("/v1/admin/wallet/address", get(wallet_address))
        // Admin endpoints
        .route("/v1/admin/note", post(admin_create_note))
        .route(
            "/v1/admin/intentFees",
            get(admin_get_intent_fees).post(admin_update_intent_fees),
        )
        .route("/v1/admin/intentFees/clear", post(admin_clear_intent_fees))
        .route("/v1/admin/sweeps", get(admin_get_scheduled_sweeps))
        .route("/v1/admin/sweep", post(admin_sweep))
        .route("/v1/admin/fees", post(admin_set_fee_programs))
        .with_state(state)
}

// ── Wallet handlers ──────────────────────────────────────────────────────

/// GET /v1/admin/wallet/seed
async fn wallet_gen_seed(State(state): State<RestState>) -> Response {
    info!("REST: GET /v1/admin/wallet/seed");

    match state
        .wallet_svc
        .gen_seed(Request::new(crate::proto::ark_v1::GenSeedRequest {}))
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            Json(GenSeedResponse {
                seed: inner.seed_phrase,
            })
            .into_response()
        }
        Err(status) => status_to_response(status),
    }
}

#[derive(Serialize)]
struct GenSeedResponse {
    /// Field named "seed" to match the test client's `body["seed"]` lookup.
    seed: String,
}

/// POST /v1/admin/wallet/create
async fn wallet_create(
    State(state): State<RestState>,
    Json(body): Json<WalletCreateRequest>,
) -> Response {
    info!("REST: POST /v1/admin/wallet/create");

    let req = crate::proto::ark_v1::CreateRequest {
        seed_phrase: body.seed.unwrap_or_default(),
        password: body.password.unwrap_or_default(),
    };

    match state.wallet_svc.create(Request::new(req)).await {
        Ok(_) => Json(serde_json::json!({})).into_response(),
        Err(status) => status_to_response(status),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletCreateRequest {
    seed: Option<String>,
    #[serde(alias = "seedPhrase", alias = "seed_phrase")]
    _seed_phrase: Option<String>,
    password: Option<String>,
}

/// POST /v1/admin/wallet/restore
async fn wallet_restore(
    State(state): State<RestState>,
    Json(body): Json<WalletRestoreRequest>,
) -> Response {
    info!("REST: POST /v1/admin/wallet/restore");

    let req = crate::proto::ark_v1::RestoreRequest {
        seed_phrase: body.seed.unwrap_or_default(),
        password: body.password.unwrap_or_default(),
        gap_limit: body.gap_limit.unwrap_or(0),
    };

    match state.wallet_svc.restore(Request::new(req)).await {
        Ok(_) => Json(serde_json::json!({})).into_response(),
        Err(status) => status_to_response(status),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletRestoreRequest {
    seed: Option<String>,
    password: Option<String>,
    gap_limit: Option<u64>,
}

/// POST /v1/admin/wallet/unlock
async fn wallet_unlock(
    State(state): State<RestState>,
    Json(body): Json<WalletUnlockRequest>,
) -> Response {
    info!("REST: POST /v1/admin/wallet/unlock");

    let req = crate::proto::ark_v1::UnlockRequest {
        password: body.password.unwrap_or_default(),
    };

    match state.wallet_svc.unlock(Request::new(req)).await {
        Ok(_) => Json(serde_json::json!({})).into_response(),
        Err(status) => status_to_response(status),
    }
}

#[derive(Deserialize)]
struct WalletUnlockRequest {
    password: Option<String>,
}

/// GET /v1/admin/wallet/status
async fn wallet_status(State(state): State<RestState>) -> Response {
    info!("REST: GET /v1/admin/wallet/status");

    match state
        .wallet_svc
        .get_status(Request::new(
            crate::proto::ark_v1::GetWalletStatusRequest {},
        ))
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            Json(serde_json::json!({
                "initialized": inner.initialized,
                "unlocked": inner.unlocked,
                "synced": inner.synced,
            }))
            .into_response()
        }
        Err(status) => status_to_response(status),
    }
}

/// GET /v1/admin/wallet/balance
async fn wallet_balance(State(state): State<RestState>) -> Response {
    info!("REST: GET /v1/admin/wallet/balance");

    match state
        .wallet_svc
        .get_balance(Request::new(crate::proto::ark_v1::GetBalanceRequest {}))
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            Json(BalanceResponse {
                main_account: inner.main_account.map(|b| BalanceAccount {
                    available: b.available,
                    locked: b.locked,
                }),
                connectors_account: inner.connectors_account.map(|b| BalanceAccount {
                    available: b.available,
                    locked: b.locked,
                }),
            })
            .into_response()
        }
        Err(status) => status_to_response(status),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BalanceResponse {
    main_account: Option<BalanceAccount>,
    connectors_account: Option<BalanceAccount>,
}

#[derive(Serialize)]
struct BalanceAccount {
    available: String,
    locked: String,
}

/// GET /v1/admin/wallet/address
async fn wallet_address(State(state): State<RestState>) -> Response {
    info!("REST: GET /v1/admin/wallet/address");

    match state
        .wallet_svc
        .derive_address(Request::new(crate::proto::ark_v1::DeriveAddressRequest {}))
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            Json(serde_json::json!({
                "address": inner.address,
                "derivationPath": inner.derivation_path,
            }))
            .into_response()
        }
        Err(status) => status_to_response(status),
    }
}

// ── Admin handlers ───────────────────────────────────────────────────────

/// POST /v1/admin/note
async fn admin_create_note(
    State(state): State<RestState>,
    Json(body): Json<CreateNoteRequest>,
) -> Response {
    info!("REST: POST /v1/admin/note");

    let amount = body
        .amount
        .as_ref()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let quantity = body.quantity.unwrap_or(1);

    let req = crate::proto::ark_v1::CreateNoteRequest { amount, quantity };

    match state.admin_svc.create_note(Request::new(req)).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            Json(serde_json::json!({
                "notes": inner.notes,
            }))
            .into_response()
        }
        Err(status) => status_to_response(status),
    }
}

#[derive(Deserialize)]
struct CreateNoteRequest {
    amount: Option<String>,
    quantity: Option<u32>,
}

/// GET /v1/admin/intentFees
async fn admin_get_intent_fees(State(state): State<RestState>) -> Response {
    info!("REST: GET /v1/admin/intentFees");

    match state
        .admin_svc
        .get_intent_fees(Request::new(crate::proto::ark_v1::GetIntentFeesRequest {}))
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            let fees = inner.fees.map(|f| {
                serde_json::json!({
                    "baseFeeSats": f.base_fee_sats.to_string(),
                    "feeRatePpm": f.fee_rate_ppm.to_string(),
                })
            });
            Json(serde_json::json!({ "fees": fees })).into_response()
        }
        Err(status) => status_to_response(status),
    }
}

/// POST /v1/admin/intentFees
async fn admin_update_intent_fees(
    State(state): State<RestState>,
    Json(body): Json<UpdateIntentFeesRequest>,
) -> Response {
    info!("REST: POST /v1/admin/intentFees");

    let fees = body.fees.map(|f| crate::proto::ark_v1::IntentFeeConfig {
        base_fee_sats: f
            .base_fee_sats
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        fee_rate_ppm: f
            .fee_rate_ppm
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    });

    let req = crate::proto::ark_v1::UpdateIntentFeesRequest { fees };

    match state.admin_svc.update_intent_fees(Request::new(req)).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            let fees = inner.fees.map(|f| {
                serde_json::json!({
                    "baseFeeSats": f.base_fee_sats.to_string(),
                    "feeRatePpm": f.fee_rate_ppm.to_string(),
                })
            });
            Json(serde_json::json!({ "fees": fees })).into_response()
        }
        Err(status) => status_to_response(status),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateIntentFeesRequest {
    fees: Option<IntentFeeConfigRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntentFeeConfigRequest {
    base_fee_sats: Option<String>,
    fee_rate_ppm: Option<String>,
}

/// POST /v1/admin/intentFees/clear
async fn admin_clear_intent_fees(State(state): State<RestState>) -> Response {
    info!("REST: POST /v1/admin/intentFees/clear");

    match state
        .admin_svc
        .clear_intent_fees(Request::new(
            crate::proto::ark_v1::ClearIntentFeesRequest {},
        ))
        .await
    {
        Ok(_) => Json(serde_json::json!({})).into_response(),
        Err(status) => status_to_response(status),
    }
}

// ── Sweep & Fee handlers ────────────────────────────────────────────────

/// GET /v1/admin/sweeps
async fn admin_get_scheduled_sweeps(State(state): State<RestState>) -> Response {
    info!("REST: GET /v1/admin/sweeps");

    match state
        .admin_svc
        .get_scheduled_sweep(Request::new(
            crate::proto::ark_v1::GetScheduledSweepRequest {},
        ))
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            let sweeps: Vec<serde_json::Value> = inner
                .scheduled_sweeps
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "scheduledAt": s.scheduled_at,
                        "vtxoCount": s.vtxo_count,
                        "totalAmount": s.total_amount,
                    })
                })
                .collect();
            Json(serde_json::json!({
                "scheduledAt": inner.scheduled_at,
                "vtxoCount": inner.vtxo_count,
                "totalAmount": inner.total_amount,
                "scheduledSweeps": sweeps,
            }))
            .into_response()
        }
        Err(status) => status_to_response(status),
    }
}

/// POST /v1/admin/sweep
async fn admin_sweep(
    State(state): State<RestState>,
    Json(_body): Json<SweepRequestBody>,
) -> Response {
    info!("REST: POST /v1/admin/sweep");

    match state
        .admin_svc
        .sweep(Request::new(crate::proto::ark_v1::SweepRequest {}))
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            Json(serde_json::json!({
                "txid": inner.sweep_txid,
                "hex": "",
                "sweepTxid": inner.sweep_txid,
                "sweptCount": inner.swept_count,
                "recoveryTxid": inner.recovery_txid,
            }))
            .into_response()
        }
        Err(status) => status_to_response(status),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SweepRequestBody {
    #[serde(default)]
    _connectors: bool,
    #[serde(default)]
    _commitment_txids: Vec<String>,
}

/// POST /v1/admin/fees
async fn admin_set_fee_programs(
    State(_state): State<RestState>,
    Json(_body): Json<serde_json::Value>,
) -> Response {
    info!("REST: POST /v1/admin/fees");
    // Fee programs endpoint — stub returning empty JSON for now.
    Json(serde_json::json!({})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_to_response_maps_codes() {
        let s = tonic::Status::invalid_argument("bad input");
        let resp = status_to_response(s);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let s = tonic::Status::not_found("missing");
        let resp = status_to_response(s);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let s = tonic::Status::internal("oops");
        let resp = status_to_response(s);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_deserialize_create_request() {
        // Go-style JSON with "seed" field
        let json = r#"{"seed":"abandon abandon","password":"secret"}"#;
        let req: WalletCreateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.seed.as_deref(), Some("abandon abandon"));
        assert_eq!(req.password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_deserialize_unlock_request() {
        let json = r#"{"password":"secret"}"#;
        let req: WalletUnlockRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_deserialize_create_note_request() {
        let json = r#"{"amount":"100000"}"#;
        let req: CreateNoteRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.amount.as_deref(), Some("100000"));
        assert!(req.quantity.is_none());
    }

    #[test]
    fn test_deserialize_update_intent_fees() {
        let json = r#"{"fees":{"baseFeeSats":"100","feeRatePpm":"1000"}}"#;
        let req: UpdateIntentFeesRequest = serde_json::from_str(json).unwrap();
        let fees = req.fees.unwrap();
        assert_eq!(fees.base_fee_sats.as_deref(), Some("100"));
        assert_eq!(fees.fee_rate_ppm.as_deref(), Some("1000"));
    }
}
