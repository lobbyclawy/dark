//! `/v1/txs` — async off-chain Ark transactions.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use dark_api::proto::ark_v1::{get_pending_tx_request::Identifier, GetPendingTxRequest, Intent};

use crate::dto::{
    FinalizeTxRequestDto, PendingTxResponseDto, SubmitTxRequestDto, SubmitTxResponseDto,
};
use crate::error::{ApiError, ApiResult, ProblemDetails};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/txs", post(submit_tx))
        .route("/txs/query", post(query_pending_txs))
        .route("/txs/{id}", get(get_tx))
        .route("/txs/{id}/finalize", post(finalize_tx))
}

#[utoipa::path(
    post,
    path = "/txs",
    tag = "txs",
    summary = "Submit a signed Ark virtual tx",
    request_body = SubmitTxRequestDto,
    responses(
        (status = 200, description = "Accepted", body = SubmitTxResponseDto),
        (status = 400, description = "Bad request", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn submit_tx(
    State(state): State<AppState>,
    Json(req): Json<SubmitTxRequestDto>,
) -> ApiResult<Json<SubmitTxResponseDto>> {
    if req.signed_ark_tx.is_empty() {
        return Err(ApiError::BadRequest(
            "signed_ark_tx must not be empty".into(),
        ));
    }
    let mut ark = state.ark().await;
    let ark_txid = ark.submit_tx(&req.signed_ark_tx).await?;
    Ok(Json(SubmitTxResponseDto { ark_txid }))
}

#[utoipa::path(
    post,
    path = "/txs/{id}/finalize",
    tag = "txs",
    params(("id" = String, Path, description = "Ark txid")),
    request_body = FinalizeTxRequestDto,
    responses(
        (status = 204, description = "Finalized"),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn finalize_tx(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(_req): Json<FinalizeTxRequestDto>,
) -> ApiResult<axum::http::StatusCode> {
    let mut ark = state.ark().await;
    ark.finalize_tx(&id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/txs/{id}",
    tag = "txs",
    summary = "Look up a pending Ark tx by id (best-effort)",
    description = "Calls `ArkService.GetPendingTx` with an empty Intent filter \
                   and returns the first pending tx whose `ark_txid` matches. \
                   For authenticated queries use `POST /v1/txs/query`.",
    params(("id" = String, Path, description = "Ark txid")),
    responses(
        (status = 200, description = "Pending tx status", body = PendingTxResponseDto),
        (status = 404, description = "Not pending", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn get_tx(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<PendingTxResponseDto>> {
    let mut client = state.ark_raw().await;
    let resp = client
        .get_pending_tx(GetPendingTxRequest {
            identifier: Some(Identifier::Intent(Intent {
                proof: String::new(),
                message: String::new(),
                delegate_pubkey: String::new(),
            })),
        })
        .await
        .map_err(|e| ApiError::Upstream(format!("GetPendingTx: {e}")))?
        .into_inner();

    let hit = resp.pending_txs.into_iter().find(|p| p.ark_txid == id);
    match hit {
        Some(pt) => Ok(Json(PendingTxResponseDto {
            ark_txid: pt.ark_txid,
            status: "pending".to_string(),
        })),
        None => Err(ApiError::NotFound(format!("no pending tx with id {id}"))),
    }
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct IntentFilterDto {
    pub proof: String,
    pub message: String,
    #[serde(default)]
    pub delegate_pubkey: String,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct PendingTxsResponse {
    pub pending_txs: Vec<PendingTxResponseDto>,
}

#[utoipa::path(
    post,
    path = "/txs/query",
    tag = "txs",
    summary = "List pending Ark txs matching an intent filter",
    request_body = IntentFilterDto,
    responses(
        (status = 200, description = "Matching pending txs", body = PendingTxsResponse),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn query_pending_txs(
    State(state): State<AppState>,
    Json(req): Json<IntentFilterDto>,
) -> ApiResult<Json<PendingTxsResponse>> {
    let mut client = state.ark_raw().await;
    let resp = client
        .get_pending_tx(GetPendingTxRequest {
            identifier: Some(Identifier::Intent(Intent {
                proof: req.proof,
                message: req.message,
                delegate_pubkey: req.delegate_pubkey,
            })),
        })
        .await
        .map_err(|e| ApiError::Upstream(format!("GetPendingTx: {e}")))?
        .into_inner();

    Ok(Json(PendingTxsResponse {
        pending_txs: resp
            .pending_txs
            .into_iter()
            .map(|p| PendingTxResponseDto {
                ark_txid: p.ark_txid,
                status: "pending".to_string(),
            })
            .collect(),
    }))
}
