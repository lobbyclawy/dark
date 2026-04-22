//! `/v1/vtxos` — VTXO inspection.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use utoipa::IntoParams;

use dark_api::proto::ark_v1::{GetVtxoChainRequest, IndexerChainedTxType, IndexerOutpoint};

use crate::dto::{ListVtxosResponse, PageInfo, VtxoChainEntryDto, VtxoChainResponse, VtxoDto};
use crate::error::{ApiError, ApiResult, ProblemDetails};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vtxos", get(list_vtxos))
        .route("/vtxos/{outpoint}/chain", get(vtxo_chain))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListVtxosQuery {
    /// Hex-encoded x-only pubkey (or compressed 33-byte pubkey) of the owner.
    pub pubkey: String,
}

#[utoipa::path(
    get,
    path = "/vtxos",
    tag = "vtxos",
    summary = "List VTXOs owned by a pubkey",
    params(ListVtxosQuery),
    responses(
        (status = 200, description = "VTXOs for the pubkey", body = ListVtxosResponse),
        (status = 400, description = "Invalid pubkey", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn list_vtxos(
    State(state): State<AppState>,
    Query(q): Query<ListVtxosQuery>,
) -> ApiResult<Json<ListVtxosResponse>> {
    let mut ark = state.ark().await;
    let vtxos = ark.list_vtxos(&q.pubkey).await?;
    Ok(Json(ListVtxosResponse {
        vtxos: vtxos.into_iter().map(VtxoDto::from).collect(),
    }))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageQuery {
    pub page_index: Option<i32>,
    pub page_size: Option<i32>,
}

#[utoipa::path(
    get,
    path = "/vtxos/{outpoint}/chain",
    tag = "vtxos",
    summary = "Chain of virtual txs leading to a VTXO",
    description = "`outpoint` is `txid:vout`. Returns the chain of VTXOs that were \
                   spent to arrive at this one.",
    params(
        ("outpoint" = String, Path, description = "`txid:vout`"),
        PageQuery
    ),
    responses(
        (status = 200, description = "Virtual tx chain", body = VtxoChainResponse),
        (status = 400, description = "Invalid outpoint", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn vtxo_chain(
    State(state): State<AppState>,
    Path(outpoint): Path<String>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<VtxoChainResponse>> {
    let (txid, vout) = parse_outpoint(&outpoint)?;

    let mut indexer = state.indexer().await;
    let req = tonic::Request::new(GetVtxoChainRequest {
        outpoint: Some(IndexerOutpoint { txid, vout }),
        page: page_request(&page),
    });
    let resp = indexer
        .get_vtxo_chain(req)
        .await
        .map_err(|e| ApiError::Upstream(format!("GetVtxoChain: {e}")))?
        .into_inner();

    let chain = resp
        .chain
        .into_iter()
        .map(|c| VtxoChainEntryDto {
            txid: c.txid,
            expires_at: c.expires_at,
            chained_type: chained_type_name(c.r#type),
            spends: c.spends,
        })
        .collect();

    Ok(Json(VtxoChainResponse {
        chain,
        page: resp.page.map(|p| PageInfo {
            current: p.current,
            next: p.next,
            total: p.total,
        }),
    }))
}

fn parse_outpoint(s: &str) -> Result<(String, u32), ApiError> {
    let (txid, vout) = s
        .split_once(':')
        .ok_or_else(|| ApiError::BadRequest("outpoint must be txid:vout".into()))?;
    let vout: u32 = vout
        .parse()
        .map_err(|_| ApiError::BadRequest("vout must be a u32".into()))?;
    Ok((txid.to_string(), vout))
}

fn page_request(q: &PageQuery) -> Option<dark_api::proto::ark_v1::IndexerPageRequest> {
    match (q.page_index, q.page_size) {
        (None, None) => None,
        (idx, size) => Some(dark_api::proto::ark_v1::IndexerPageRequest {
            index: idx.unwrap_or(0),
            size: size.unwrap_or(50),
        }),
    }
}

fn chained_type_name(t: i32) -> String {
    match IndexerChainedTxType::try_from(t) {
        Ok(IndexerChainedTxType::Unspecified) => "unspecified",
        Ok(IndexerChainedTxType::Commitment) => "commitment",
        Ok(IndexerChainedTxType::Ark) => "ark",
        Ok(IndexerChainedTxType::Tree) => "tree",
        Ok(IndexerChainedTxType::Checkpoint) => "checkpoint",
        Err(_) => "unknown",
    }
    .to_string()
}
