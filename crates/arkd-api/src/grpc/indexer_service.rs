//! IndexerService gRPC implementation — read-only querying API.
//!
//! Provides 13 RPCs for querying commitment transactions, VTXOs,
//! virtual transactions, assets, and script subscriptions.
//! All methods currently return `Status::unimplemented` — real
//! implementations will follow as the indexer backend is built.

use std::pin::Pin;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::info;

use crate::proto::ark_v1::indexer_service_server::IndexerService as IndexerServiceTrait;
use crate::proto::ark_v1::{
    GetAssetRequest, GetAssetResponse, GetBatchSweepTransactionsRequest,
    GetBatchSweepTransactionsResponse, GetCommitmentTxRequest, GetCommitmentTxResponse,
    GetConnectorsRequest, GetConnectorsResponse, GetForfeitTxsRequest, GetForfeitTxsResponse,
    GetSubscriptionRequest, GetSubscriptionResponse, GetVirtualTxsRequest, GetVirtualTxsResponse,
    GetVtxoChainRequest, GetVtxoChainResponse, GetVtxoTreeLeavesRequest, GetVtxoTreeLeavesResponse,
    GetVtxoTreeRequest, GetVtxoTreeResponse, IndexerGetVtxosRequest, IndexerGetVtxosResponse,
    SubscribeForScriptsRequest, SubscribeForScriptsResponse, UnsubscribeForScriptsRequest,
    UnsubscribeForScriptsResponse,
};

/// Server-streaming response type for GetSubscription.
type GetSubscriptionStream =
    Pin<Box<dyn Stream<Item = Result<GetSubscriptionResponse, Status>> + Send + 'static>>;

/// IndexerService gRPC handler.
///
/// Provides read-only RPCs for querying commitment transactions, VTXOs,
/// virtual transactions, connectors, assets, batch sweeps, and script
/// subscriptions. Mirrors the Go arkd IndexerService proto definition.
pub struct IndexerGrpcService;

impl IndexerGrpcService {
    /// Create a new IndexerGrpcService.
    pub fn new() -> Self {
        Self
    }
}

impl Default for IndexerGrpcService {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl IndexerServiceTrait for IndexerGrpcService {
    type GetSubscriptionStream = GetSubscriptionStream;

    async fn get_commitment_tx(
        &self,
        _request: Request<GetCommitmentTxRequest>,
    ) -> Result<Response<GetCommitmentTxResponse>, Status> {
        info!("IndexerService::GetCommitmentTx called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_forfeit_txs(
        &self,
        _request: Request<GetForfeitTxsRequest>,
    ) -> Result<Response<GetForfeitTxsResponse>, Status> {
        info!("IndexerService::GetForfeitTxs called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_connectors(
        &self,
        _request: Request<GetConnectorsRequest>,
    ) -> Result<Response<GetConnectorsResponse>, Status> {
        info!("IndexerService::GetConnectors called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_vtxo_tree(
        &self,
        _request: Request<GetVtxoTreeRequest>,
    ) -> Result<Response<GetVtxoTreeResponse>, Status> {
        info!("IndexerService::GetVtxoTree called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_vtxo_tree_leaves(
        &self,
        _request: Request<GetVtxoTreeLeavesRequest>,
    ) -> Result<Response<GetVtxoTreeLeavesResponse>, Status> {
        info!("IndexerService::GetVtxoTreeLeaves called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_vtxos(
        &self,
        _request: Request<IndexerGetVtxosRequest>,
    ) -> Result<Response<IndexerGetVtxosResponse>, Status> {
        info!("IndexerService::GetVtxos called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_vtxo_chain(
        &self,
        _request: Request<GetVtxoChainRequest>,
    ) -> Result<Response<GetVtxoChainResponse>, Status> {
        info!("IndexerService::GetVtxoChain called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_virtual_txs(
        &self,
        _request: Request<GetVirtualTxsRequest>,
    ) -> Result<Response<GetVirtualTxsResponse>, Status> {
        info!("IndexerService::GetVirtualTxs called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_asset(
        &self,
        _request: Request<GetAssetRequest>,
    ) -> Result<Response<GetAssetResponse>, Status> {
        info!("IndexerService::GetAsset called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_batch_sweep_transactions(
        &self,
        _request: Request<GetBatchSweepTransactionsRequest>,
    ) -> Result<Response<GetBatchSweepTransactionsResponse>, Status> {
        info!("IndexerService::GetBatchSweepTransactions called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn subscribe_for_scripts(
        &self,
        _request: Request<SubscribeForScriptsRequest>,
    ) -> Result<Response<SubscribeForScriptsResponse>, Status> {
        info!("IndexerService::SubscribeForScripts called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn unsubscribe_for_scripts(
        &self,
        _request: Request<UnsubscribeForScriptsRequest>,
    ) -> Result<Response<UnsubscribeForScriptsResponse>, Status> {
        info!("IndexerService::UnsubscribeForScripts called");
        Err(Status::unimplemented("TODO: #160"))
    }

    async fn get_subscription(
        &self,
        _request: Request<GetSubscriptionRequest>,
    ) -> Result<Response<Self::GetSubscriptionStream>, Status> {
        info!("IndexerService::GetSubscription called");
        Err(Status::unimplemented("TODO: #160"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> IndexerGrpcService {
        IndexerGrpcService::new()
    }

    #[tokio::test]
    async fn test_all_rpcs_return_unimplemented() {
        let svc = service();

        let err = svc
            .get_commitment_tx(Request::new(GetCommitmentTxRequest { txid: "abc".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_forfeit_txs(Request::new(GetForfeitTxsRequest {
                txid: "abc".into(),
                page: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_connectors(Request::new(GetConnectorsRequest {
                txid: "abc".into(),
                page: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_vtxo_tree(Request::new(GetVtxoTreeRequest {
                batch_outpoint: None,
                page: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_vtxo_tree_leaves(Request::new(GetVtxoTreeLeavesRequest {
                batch_outpoint: None,
                page: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_vtxos(Request::new(IndexerGetVtxosRequest {
                scripts: vec![],
                outpoints: vec![],
                spendable_only: false,
                spent_only: false,
                recoverable_only: false,
                page: None,
                pending_only: false,
                after: 0,
                before: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_vtxo_chain(Request::new(GetVtxoChainRequest {
                outpoint: None,
                page: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_virtual_txs(Request::new(GetVirtualTxsRequest {
                txids: vec![],
                page: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_asset(Request::new(GetAssetRequest {
                asset_id: "abc".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_batch_sweep_transactions(Request::new(GetBatchSweepTransactionsRequest {
                batch_outpoint: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .subscribe_for_scripts(Request::new(SubscribeForScriptsRequest {
                scripts: vec![],
                subscription_id: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .unsubscribe_for_scripts(Request::new(UnsubscribeForScriptsRequest {
                subscription_id: String::new(),
                scripts: vec![],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = svc
            .get_subscription(Request::new(GetSubscriptionRequest {
                subscription_id: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }
}
