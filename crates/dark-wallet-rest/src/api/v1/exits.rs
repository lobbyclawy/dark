//! `/v1/exits` — unilateral / collaborative exit back to on-chain.

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};

use crate::dto::{RequestExitRequestDto, RequestExitResponseDto};
use crate::error::{ApiError, ApiResult, ProblemDetails};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/exits", post(request_exit))
}

#[utoipa::path(
    post,
    path = "/exits",
    tag = "exits",
    summary = "Request a collaborative on-chain exit",
    description = "Spends the given VTXOs into an on-chain address via the next commitment \
                   transaction. Returns a placeholder `exit_id` that becomes the final commitment \
                   txid once the round settles.",
    request_body = RequestExitRequestDto,
    responses(
        (status = 200, description = "Exit accepted", body = RequestExitResponseDto),
        (status = 400, description = "Invalid request", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn request_exit(
    State(state): State<AppState>,
    Json(req): Json<RequestExitRequestDto>,
) -> ApiResult<Json<RequestExitResponseDto>> {
    if req.onchain_address.is_empty() {
        return Err(ApiError::BadRequest(
            "onchain_address must not be empty".into(),
        ));
    }
    if req.amount == 0 {
        return Err(ApiError::BadRequest("amount must be > 0".into()));
    }
    if req.vtxo_ids.is_empty() {
        return Err(ApiError::BadRequest("vtxo_ids must not be empty".into()));
    }

    let mut ark = state.ark().await;
    let exit_id = ark
        .collaborative_exit(&req.onchain_address, req.amount, req.vtxo_ids)
        .await?;
    Ok(Json(RequestExitResponseDto { exit_id }))
}
