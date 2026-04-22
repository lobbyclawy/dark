//! `/v1/rounds` — round history and VTXO trees.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use utoipa::IntoParams;

use dark_api::proto::ark_v1::{
    GetCommitmentTxRequest, GetVtxoTreeRequest, IndexerOutpoint, IndexerPageRequest,
};

use crate::dto::{
    BatchInfoDto, CommitmentTxResponse, IndexerNodeDto, ListRoundsResponse, PageInfo, RoundInfoDto,
    RoundSummaryDto, VtxoTreeResponse,
};
use crate::error::{ApiError, ApiResult, ProblemDetails};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/rounds", get(list_rounds))
        .route("/rounds/{id}", get(get_round))
        .route("/rounds/{id}/tree", get(get_tree))
        .route("/rounds/{id}/commitment-tx", get(get_commitment_tx))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListRoundsQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[utoipa::path(
    get,
    path = "/rounds",
    tag = "rounds",
    summary = "List recent rounds",
    params(ListRoundsQuery),
    responses(
        (status = 200, description = "Paginated round summaries", body = ListRoundsResponse),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn list_rounds(
    State(state): State<AppState>,
    Query(q): Query<ListRoundsQuery>,
) -> ApiResult<Json<ListRoundsResponse>> {
    let mut ark = state.ark().await;
    let rounds = ark.list_rounds(q.limit, q.offset).await?;
    Ok(Json(ListRoundsResponse {
        rounds: rounds.into_iter().map(RoundSummaryDto::from).collect(),
    }))
}

#[utoipa::path(
    get,
    path = "/rounds/{id}",
    tag = "rounds",
    summary = "Get a round by id",
    params(("id" = String, Path, description = "Round id")),
    responses(
        (status = 200, description = "Round details", body = RoundInfoDto),
        (status = 404, description = "Round not found", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn get_round(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<RoundInfoDto>> {
    let mut ark = state.ark().await;
    let round = ark.get_round(&id).await?;
    Ok(Json(round.into()))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TreeQuery {
    /// `txid:vout` batch outpoint. If absent, the round's commitment tx is used
    /// as the batch outpoint (`{commitment_txid}:0`).
    pub batch_outpoint: Option<String>,
    pub page_index: Option<i32>,
    pub page_size: Option<i32>,
}

#[utoipa::path(
    get,
    path = "/rounds/{id}/tree",
    tag = "rounds",
    summary = "VTXO tree for a round",
    params(
        ("id" = String, Path, description = "Round id (commitment txid)"),
        TreeQuery,
    ),
    responses(
        (status = 200, description = "VTXO tree nodes", body = VtxoTreeResponse),
        (status = 400, description = "Invalid outpoint", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn get_tree(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<TreeQuery>,
) -> ApiResult<Json<VtxoTreeResponse>> {
    let outpoint = batch_outpoint(&id, q.batch_outpoint.as_deref())?;
    let mut indexer = state.indexer().await;
    let resp = indexer
        .get_vtxo_tree(tonic::Request::new(GetVtxoTreeRequest {
            batch_outpoint: Some(outpoint),
            page: page_req(q.page_index, q.page_size),
        }))
        .await
        .map_err(|e| ApiError::Upstream(format!("GetVtxoTree: {e}")))?
        .into_inner();

    let tree = resp
        .vtxo_tree
        .into_iter()
        .map(|n| IndexerNodeDto {
            txid: n.txid,
            children: n
                .children
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        })
        .collect();

    Ok(Json(VtxoTreeResponse {
        vtxo_tree: tree,
        page: resp.page.map(|p| PageInfo {
            current: p.current,
            next: p.next,
            total: p.total,
        }),
    }))
}

#[utoipa::path(
    get,
    path = "/rounds/{id}/commitment-tx",
    tag = "rounds",
    summary = "Commitment transaction metadata",
    params(("id" = String, Path, description = "Commitment txid")),
    responses(
        (status = 200, description = "Commitment tx metadata", body = CommitmentTxResponse),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn get_commitment_tx(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<CommitmentTxResponse>> {
    let mut indexer = state.indexer().await;
    let resp = indexer
        .get_commitment_tx(tonic::Request::new(GetCommitmentTxRequest { txid: id }))
        .await
        .map_err(|e| ApiError::Upstream(format!("GetCommitmentTx: {e}")))?
        .into_inner();

    let batches: HashMap<String, BatchInfoDto> = resp
        .batches
        .into_iter()
        .map(|(k, b)| {
            (
                k.to_string(),
                BatchInfoDto {
                    total_output_amount: b.total_output_amount,
                    total_output_vtxos: b.total_output_vtxos,
                    expires_at: b.expires_at,
                    swept: b.swept,
                },
            )
        })
        .collect();

    Ok(Json(CommitmentTxResponse {
        started_at: resp.started_at,
        ended_at: resp.ended_at,
        total_input_amount: resp.total_input_amount,
        total_input_vtxos: resp.total_input_vtxos,
        total_output_amount: resp.total_output_amount,
        total_output_vtxos: resp.total_output_vtxos,
        batches,
    }))
}

fn batch_outpoint(round_id: &str, override_outpoint: Option<&str>) -> ApiResult<IndexerOutpoint> {
    match override_outpoint {
        Some(s) => parse_indexer_outpoint(s),
        None => Ok(IndexerOutpoint {
            txid: round_id.to_string(),
            vout: 0,
        }),
    }
}

fn parse_indexer_outpoint(s: &str) -> ApiResult<IndexerOutpoint> {
    let (txid, vout) = s
        .split_once(':')
        .ok_or_else(|| ApiError::BadRequest("batch_outpoint must be txid:vout".into()))?;
    let vout: u32 = vout
        .parse()
        .map_err(|_| ApiError::BadRequest("vout must be a u32".into()))?;
    Ok(IndexerOutpoint {
        txid: txid.to_string(),
        vout,
    })
}

fn page_req(index: Option<i32>, size: Option<i32>) -> Option<IndexerPageRequest> {
    match (index, size) {
        (None, None) => None,
        _ => Some(IndexerPageRequest {
            index: index.unwrap_or(0),
            size: size.unwrap_or(50),
        }),
    }
}
