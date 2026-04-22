//! `GET /v1/info` — server info (mirrors `ark.v1.ArkService.GetInfo`).

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use crate::dto::ServerInfoDto;
use crate::error::{ApiError, ApiResult, ProblemDetails};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/info", get(get_info))
}

#[utoipa::path(
    get,
    path = "/info",
    tag = "info",
    summary = "Server info",
    description = "Returns server identity, network, session parameters, and VTXO limits. \
                   Equivalent to `ark.v1.ArkService.GetInfo` over gRPC.",
    responses(
        (status = 200, description = "Server info", body = ServerInfoDto),
        (status = 502, description = "Upstream dark server error", body = ProblemDetails),
    )
)]
pub async fn get_info(State(state): State<AppState>) -> ApiResult<Json<ServerInfoDto>> {
    let mut ark = state.ark().await;
    let info = ark
        .get_info()
        .await
        .map_err(|e| ApiError::Upstream(e.to_string()))?;
    Ok(Json(ServerInfoDto::from(info)))
}
