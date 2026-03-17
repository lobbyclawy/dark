//! IndexerService gRPC implementation — read-only querying API.
//!
//! Provides 13 RPCs for querying commitment transactions, VTXOs,
//! virtual transactions, assets, and script subscriptions.
//! `GetVtxos` is wired to the core indexer; the remaining RPCs
//! return `Status::unimplemented` until the extended indexer backend
//! is built (tracked in the relevant follow-up issues).

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::info;

use crate::proto::ark_v1::indexer_service_server::IndexerService as IndexerServiceTrait;
use crate::proto::ark_v1::{
    GetAssetRequest, GetAssetResponse, GetBatchSweepTransactionsRequest,
    GetBatchSweepTransactionsResponse, GetCommitmentTxRequest, GetCommitmentTxResponse,
    GetConnectorsRequest, GetConnectorsResponse, GetForfeitTxsRequest, GetForfeitTxsResponse,
    GetSubscriptionRequest, GetSubscriptionResponse, GetVirtualTxsRequest, GetVirtualTxsResponse,
    GetVtxoChainRequest, GetVtxoChainResponse, GetVtxoTreeLeavesRequest, GetVtxoTreeLeavesResponse,
    GetVtxoTreeRequest, GetVtxoTreeResponse, IndexerOutpoint, IndexerPageResponse,
    IndexerServiceGetVtxosRequest, IndexerServiceGetVtxosResponse, IndexerVtxo,
    SubscribeForScriptsRequest, SubscribeForScriptsResponse, UnsubscribeForScriptsRequest,
    UnsubscribeForScriptsResponse,
};

/// Server-streaming response type for GetSubscription.
type GetSubscriptionStream =
    tokio_stream::wrappers::ReceiverStream<Result<GetSubscriptionResponse, Status>>;

/// Convert a core domain `Vtxo` to the proto `IndexerVtxo` message.
fn vtxo_to_proto(v: &arkd_core::Vtxo) -> IndexerVtxo {
    IndexerVtxo {
        outpoint: Some(IndexerOutpoint {
            txid: v.outpoint.txid.clone(),
            vout: v.outpoint.vout,
        }),
        created_at: v.created_at,
        expires_at: v.expires_at,
        amount: v.amount,
        script: v.pubkey.clone(),
        is_preconfirmed: v.preconfirmed,
        is_swept: v.swept,
        is_unrolled: v.unrolled,
        is_spent: v.spent,
        spent_by: v.spent_by.clone(),
        commitment_txids: v.commitment_txids.clone(),
        settled_by: v.settled_by.clone(),
        ark_txid: v.ark_txid.clone(),
        assets: vec![],
    }
}

/// IndexerService gRPC handler backed by the core application service.
///
/// Provides read-only RPCs for querying VTXOs, commitment transactions,
/// virtual transactions, connectors, assets, batch sweeps, and script
/// subscriptions. Mirrors the Go arkd IndexerService proto definition.
pub struct IndexerGrpcService {
    core: Arc<arkd_core::ArkService>,
}

impl IndexerGrpcService {
    /// Create a new IndexerGrpcService wrapping the core service.
    pub fn new(core: Arc<arkd_core::ArkService>) -> Self {
        Self { core }
    }
}

#[tonic::async_trait]
impl IndexerServiceTrait for IndexerGrpcService {
    type GetSubscriptionStream = GetSubscriptionStream;

    async fn get_commitment_tx(
        &self,
        request: Request<GetCommitmentTxRequest>,
    ) -> Result<Response<GetCommitmentTxResponse>, Status> {
        let req = request.into_inner();
        info!(txid = %req.txid, "IndexerService::GetCommitmentTx called");
        Err(Status::unimplemented(
            "GetCommitmentTx not yet implemented — requires commitment-tx indexer",
        ))
    }

    async fn get_forfeit_txs(
        &self,
        request: Request<GetForfeitTxsRequest>,
    ) -> Result<Response<GetForfeitTxsResponse>, Status> {
        let req = request.into_inner();
        info!(txid = %req.txid, "IndexerService::GetForfeitTxs called");
        Err(Status::unimplemented(
            "GetForfeitTxs not yet implemented — requires forfeit-tx indexer",
        ))
    }

    async fn get_connectors(
        &self,
        request: Request<GetConnectorsRequest>,
    ) -> Result<Response<GetConnectorsResponse>, Status> {
        let req = request.into_inner();
        info!(txid = %req.txid, "IndexerService::GetConnectors called");
        Err(Status::unimplemented(
            "GetConnectors not yet implemented — requires connector-tree indexer",
        ))
    }

    async fn get_vtxo_tree(
        &self,
        _request: Request<GetVtxoTreeRequest>,
    ) -> Result<Response<GetVtxoTreeResponse>, Status> {
        info!("IndexerService::GetVtxoTree called");
        Err(Status::unimplemented(
            "GetVtxoTree not yet implemented — requires VTXO-tree indexer",
        ))
    }

    async fn get_vtxo_tree_leaves(
        &self,
        _request: Request<GetVtxoTreeLeavesRequest>,
    ) -> Result<Response<GetVtxoTreeLeavesResponse>, Status> {
        info!("IndexerService::GetVtxoTreeLeaves called");
        Err(Status::unimplemented(
            "GetVtxoTreeLeaves not yet implemented — requires VTXO-tree indexer",
        ))
    }

    /// List VTXOs filtered by scripts (owner pubkeys) or outpoints.
    ///
    /// Scripts are treated as owner pubkeys; the first non-empty script is
    /// used to filter the indexer. When no scripts are provided all VTXOs
    /// are returned (subject to `spendable_only` / `spent_only` flags).
    async fn get_vtxos(
        &self,
        request: Request<IndexerServiceGetVtxosRequest>,
    ) -> Result<Response<IndexerServiceGetVtxosResponse>, Status> {
        let req = request.into_inner();
        info!(
            scripts = req.scripts.len(),
            outpoints = req.outpoints.len(),
            "IndexerService::GetVtxos called"
        );

        // Use the first script as the pubkey filter (scripts == owner pubkeys in ARK).
        let pubkey_filter = req.scripts.first().map(|s| s.as_str());

        let vtxos = self
            .core
            .list_vtxos(pubkey_filter)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Apply client-requested filters.
        let filtered: Vec<IndexerVtxo> = vtxos
            .iter()
            .filter(|v| {
                if req.spendable_only {
                    return !v.spent && !v.swept;
                }
                if req.spent_only {
                    return v.spent;
                }
                if req.pending_only {
                    return v.preconfirmed;
                }
                true
            })
            .filter(|v| {
                // Outpoint filter: skip VTXOs not in the requested set.
                if req.outpoints.is_empty() {
                    return true;
                }
                let key = format!("{}:{}", v.outpoint.txid, v.outpoint.vout);
                req.outpoints.contains(&key)
            })
            .map(vtxo_to_proto)
            .collect();

        let total = filtered.len() as i32;

        Ok(Response::new(IndexerServiceGetVtxosResponse {
            vtxos: filtered,
            page: Some(IndexerPageResponse {
                current: 0,
                next: -1,
                total,
            }),
        }))
    }

    async fn get_vtxo_chain(
        &self,
        _request: Request<GetVtxoChainRequest>,
    ) -> Result<Response<GetVtxoChainResponse>, Status> {
        info!("IndexerService::GetVtxoChain called");
        Err(Status::unimplemented(
            "GetVtxoChain not yet implemented — requires chain-traversal indexer",
        ))
    }

    async fn get_virtual_txs(
        &self,
        request: Request<GetVirtualTxsRequest>,
    ) -> Result<Response<GetVirtualTxsResponse>, Status> {
        let req = request.into_inner();
        info!(
            txids = req.txids.len(),
            "IndexerService::GetVirtualTxs called"
        );
        Err(Status::unimplemented(
            "GetVirtualTxs not yet implemented — requires virtual-tx store",
        ))
    }

    async fn get_asset(
        &self,
        request: Request<GetAssetRequest>,
    ) -> Result<Response<GetAssetResponse>, Status> {
        let req = request.into_inner();
        info!(asset_id = %req.asset_id, "IndexerService::GetAsset called");
        Err(Status::unimplemented(
            "GetAsset not yet implemented — requires asset registry",
        ))
    }

    async fn get_batch_sweep_transactions(
        &self,
        _request: Request<GetBatchSweepTransactionsRequest>,
    ) -> Result<Response<GetBatchSweepTransactionsResponse>, Status> {
        info!("IndexerService::GetBatchSweepTransactions called");
        Err(Status::unimplemented(
            "GetBatchSweepTransactions not yet implemented — requires sweep-tx indexer",
        ))
    }

    async fn subscribe_for_scripts(
        &self,
        request: Request<SubscribeForScriptsRequest>,
    ) -> Result<Response<SubscribeForScriptsResponse>, Status> {
        let req = request.into_inner();
        info!(
            scripts = req.scripts.len(),
            subscription_id = %req.subscription_id,
            "IndexerService::SubscribeForScripts called"
        );
        Err(Status::unimplemented(
            "SubscribeForScripts not yet implemented — requires script subscription store",
        ))
    }

    async fn unsubscribe_for_scripts(
        &self,
        request: Request<UnsubscribeForScriptsRequest>,
    ) -> Result<Response<UnsubscribeForScriptsResponse>, Status> {
        let req = request.into_inner();
        info!(
            subscription_id = %req.subscription_id,
            "IndexerService::UnsubscribeForScripts called"
        );
        Err(Status::unimplemented(
            "UnsubscribeForScripts not yet implemented — requires script subscription store",
        ))
    }

    async fn get_subscription(
        &self,
        request: Request<GetSubscriptionRequest>,
    ) -> Result<Response<Self::GetSubscriptionStream>, Status> {
        let req = request.into_inner();
        info!(
            subscription_id = %req.subscription_id,
            "IndexerService::GetSubscription called"
        );
        Err(Status::unimplemented(
            "GetSubscription not yet implemented — requires event subscription store",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtxo_to_proto_mapping() {
        let v = arkd_core::Vtxo {
            outpoint: arkd_core::VtxoOutpoint {
                txid: "abc123".to_string(),
                vout: 0,
            },
            amount: 100_000,
            pubkey: "deadbeef".to_string(),
            commitment_txids: vec!["txid1".to_string()],
            root_commitment_txid: "txid1".to_string(),
            settled_by: "settle_txid".to_string(),
            spent_by: String::new(),
            ark_txid: String::new(),
            spent: false,
            unrolled: false,
            swept: false,
            preconfirmed: false,
            expires_at: 9999,
            created_at: 1000,
        };

        let proto = vtxo_to_proto(&v);
        assert_eq!(proto.amount, 100_000);
        assert_eq!(proto.script, "deadbeef");
        assert!(!proto.is_spent);
        assert!(!proto.is_swept);
        assert!(!proto.is_preconfirmed);
        assert_eq!(proto.expires_at, 9999);
        assert_eq!(proto.created_at, 1000);
        assert_eq!(proto.commitment_txids, vec!["txid1"]);
        assert_eq!(proto.settled_by, "settle_txid");
        let op = proto.outpoint.unwrap();
        assert_eq!(op.txid, "abc123");
        assert_eq!(op.vout, 0);
    }

    #[test]
    fn test_vtxo_to_proto_spent_flags() {
        let v = arkd_core::Vtxo {
            outpoint: arkd_core::VtxoOutpoint {
                txid: "def".to_string(),
                vout: 1,
            },
            amount: 50_000,
            pubkey: "pk".to_string(),
            commitment_txids: vec![],
            root_commitment_txid: String::new(),
            settled_by: String::new(),
            spent_by: "spend_tx".to_string(),
            ark_txid: String::new(),
            spent: true,
            unrolled: false,
            swept: true,
            preconfirmed: false,
            expires_at: 0,
            created_at: 0,
        };

        let proto = vtxo_to_proto(&v);
        assert!(proto.is_spent);
        assert!(proto.is_swept);
        assert_eq!(proto.spent_by, "spend_tx");
    }
}
