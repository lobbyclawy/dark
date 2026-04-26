//! Integration test: drive [`StealthScanner`] against a real in-process
//! tonic gRPC server.
//!
//! The fake server implements only `get_round_announcements`; every other
//! `ArkService` method panics. That is sufficient because the scanner only
//! ever calls one RPC, and keeping the rest as `unimplemented!()` makes
//! coverage gaps loud rather than silent.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use tokio::net::TcpListener;
use tokio::sync::Mutex as TokioMutex;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use dark_api::proto::ark_v1::ark_service_server::{ArkService, ArkServiceServer};
use dark_api::proto::ark_v1::{
    BurnAssetRequest, BurnAssetResponse, ConfirmRegistrationRequest, ConfirmRegistrationResponse,
    DeleteIntentRequest, DeleteIntentResponse, EstimateIntentFeeRequest, EstimateIntentFeeResponse,
    FinalizePendingTxsRequest, FinalizePendingTxsResponse, FinalizeTxRequest, FinalizeTxResponse,
    GetEventStreamRequest, GetInfoRequest, GetInfoResponse, GetIntentRequest, GetIntentResponse,
    GetPendingTxRequest, GetPendingTxResponse, GetRoundAnnouncementsRequest, GetRoundRequest,
    GetRoundResponse, GetTransactionsStreamRequest, GetVtxosRequest, GetVtxosResponse,
    IssueAssetRequest, IssueAssetResponse, ListRoundsRequest, ListRoundsResponse,
    RedeemNotesRequest, RedeemNotesResponse, RegisterForRoundRequest, RegisterForRoundResponse,
    RegisterIntentRequest, RegisterIntentResponse, ReissueAssetRequest, ReissueAssetResponse,
    RequestExitRequest, RequestExitResponse, RoundAnnouncement as ProtoRoundAnnouncement,
    RoundEvent, SubmitConfidentialTransactionRequest, SubmitConfidentialTransactionResponse,
    SubmitSignedForfeitTxsRequest, SubmitSignedForfeitTxsResponse, SubmitTreeNoncesRequest,
    SubmitTreeNoncesResponse, SubmitTreeSignaturesRequest, SubmitTreeSignaturesResponse,
    SubmitTxRequest, SubmitTxResponse, TransactionEvent, UpdateStreamTopicsRequest,
    UpdateStreamTopicsResponse,
};

use dark_client::client::ArkClient;
use dark_client::stealth_scan::{
    ArkClientSource, ScannerConfig, StealthScanner, CHECKPOINT_METADATA_KEY,
};
use dark_client::store::InMemoryStore;

/// Stub gRPC service: only `get_round_announcements` is real; every other
/// method panics so any unintended RPC surfaces immediately.
struct AnnouncementOnlyService {
    announcements: Vec<ProtoRoundAnnouncement>,
}

type AnnouncementStream =
    Pin<Box<dyn Stream<Item = Result<ProtoRoundAnnouncement, Status>> + Send + 'static>>;
type EventStream = Pin<Box<dyn Stream<Item = Result<RoundEvent, Status>> + Send + 'static>>;
type TxStream = Pin<Box<dyn Stream<Item = Result<TransactionEvent, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl ArkService for AnnouncementOnlyService {
    type GetRoundAnnouncementsStream = AnnouncementStream;
    type GetEventStreamStream = EventStream;
    type GetTransactionsStreamStream = TxStream;

    async fn get_round_announcements(
        &self,
        request: Request<GetRoundAnnouncementsRequest>,
    ) -> Result<Response<Self::GetRoundAnnouncementsStream>, Status> {
        let req = request.into_inner();
        // Honour the cursor so repeated polls don't re-emit the same items
        // — mirrors the real server's exclusive-cursor semantics.
        let cursor = req
            .cursor
            .split_once('\n')
            .map(|(r, v)| (r.to_string(), v.to_string()));
        let filtered: Vec<ProtoRoundAnnouncement> = self
            .announcements
            .iter()
            .filter(|ann| match &cursor {
                Some((r, v)) => {
                    (ann.round_id.as_str(), ann.vtxo_id.as_str()) > (r.as_str(), v.as_str())
                }
                None => true,
            })
            .cloned()
            .collect();
        let output = stream! {
            for ann in filtered {
                yield Ok(ann);
            }
        };
        Ok(Response::new(Box::pin(output)))
    }

    async fn get_event_stream(
        &self,
        _request: Request<GetEventStreamRequest>,
    ) -> Result<Response<Self::GetEventStreamStream>, Status> {
        unimplemented!("get_event_stream is not stubbed");
    }

    async fn get_transactions_stream(
        &self,
        _request: Request<GetTransactionsStreamRequest>,
    ) -> Result<Response<Self::GetTransactionsStreamStream>, Status> {
        unimplemented!("get_transactions_stream is not stubbed");
    }

    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        unimplemented!("get_info is not stubbed");
    }

    async fn register_intent(
        &self,
        _request: Request<RegisterIntentRequest>,
    ) -> Result<Response<RegisterIntentResponse>, Status> {
        unimplemented!("register_intent is not stubbed");
    }

    async fn confirm_registration(
        &self,
        _request: Request<ConfirmRegistrationRequest>,
    ) -> Result<Response<ConfirmRegistrationResponse>, Status> {
        unimplemented!("confirm_registration is not stubbed");
    }

    async fn get_intent(
        &self,
        _request: Request<GetIntentRequest>,
    ) -> Result<Response<GetIntentResponse>, Status> {
        unimplemented!("get_intent is not stubbed");
    }

    async fn submit_tree_nonces(
        &self,
        _request: Request<SubmitTreeNoncesRequest>,
    ) -> Result<Response<SubmitTreeNoncesResponse>, Status> {
        unimplemented!("submit_tree_nonces is not stubbed");
    }

    async fn submit_tree_signatures(
        &self,
        _request: Request<SubmitTreeSignaturesRequest>,
    ) -> Result<Response<SubmitTreeSignaturesResponse>, Status> {
        unimplemented!("submit_tree_signatures is not stubbed");
    }

    async fn submit_signed_forfeit_txs(
        &self,
        _request: Request<SubmitSignedForfeitTxsRequest>,
    ) -> Result<Response<SubmitSignedForfeitTxsResponse>, Status> {
        unimplemented!("submit_signed_forfeit_txs is not stubbed");
    }

    async fn register_for_round(
        &self,
        _request: Request<RegisterForRoundRequest>,
    ) -> Result<Response<RegisterForRoundResponse>, Status> {
        unimplemented!("register_for_round is not stubbed");
    }

    async fn request_exit(
        &self,
        _request: Request<RequestExitRequest>,
    ) -> Result<Response<RequestExitResponse>, Status> {
        unimplemented!("request_exit is not stubbed");
    }

    async fn get_vtxos(
        &self,
        _request: Request<GetVtxosRequest>,
    ) -> Result<Response<GetVtxosResponse>, Status> {
        unimplemented!("get_vtxos is not stubbed");
    }

    async fn list_rounds(
        &self,
        _request: Request<ListRoundsRequest>,
    ) -> Result<Response<ListRoundsResponse>, Status> {
        unimplemented!("list_rounds is not stubbed");
    }

    async fn get_round(
        &self,
        _request: Request<GetRoundRequest>,
    ) -> Result<Response<GetRoundResponse>, Status> {
        unimplemented!("get_round is not stubbed");
    }

    async fn update_stream_topics(
        &self,
        _request: Request<UpdateStreamTopicsRequest>,
    ) -> Result<Response<UpdateStreamTopicsResponse>, Status> {
        unimplemented!("update_stream_topics is not stubbed");
    }

    async fn estimate_intent_fee(
        &self,
        _request: Request<EstimateIntentFeeRequest>,
    ) -> Result<Response<EstimateIntentFeeResponse>, Status> {
        unimplemented!("estimate_intent_fee is not stubbed");
    }

    async fn delete_intent(
        &self,
        _request: Request<DeleteIntentRequest>,
    ) -> Result<Response<DeleteIntentResponse>, Status> {
        unimplemented!("delete_intent is not stubbed");
    }

    async fn submit_tx(
        &self,
        _request: Request<SubmitTxRequest>,
    ) -> Result<Response<SubmitTxResponse>, Status> {
        unimplemented!("submit_tx is not stubbed");
    }

    async fn submit_confidential_transaction(
        &self,
        _request: Request<SubmitConfidentialTransactionRequest>,
    ) -> Result<Response<SubmitConfidentialTransactionResponse>, Status> {
        unimplemented!("submit_confidential_transaction is not stubbed");
    }

    async fn finalize_tx(
        &self,
        _request: Request<FinalizeTxRequest>,
    ) -> Result<Response<FinalizeTxResponse>, Status> {
        unimplemented!("finalize_tx is not stubbed");
    }

    async fn get_pending_tx(
        &self,
        _request: Request<GetPendingTxRequest>,
    ) -> Result<Response<GetPendingTxResponse>, Status> {
        unimplemented!("get_pending_tx is not stubbed");
    }

    async fn finalize_pending_txs(
        &self,
        _request: Request<FinalizePendingTxsRequest>,
    ) -> Result<Response<FinalizePendingTxsResponse>, Status> {
        unimplemented!("finalize_pending_txs is not stubbed");
    }

    async fn issue_asset(
        &self,
        _request: Request<IssueAssetRequest>,
    ) -> Result<Response<IssueAssetResponse>, Status> {
        unimplemented!("issue_asset is not stubbed");
    }

    async fn reissue_asset(
        &self,
        _request: Request<ReissueAssetRequest>,
    ) -> Result<Response<ReissueAssetResponse>, Status> {
        unimplemented!("reissue_asset is not stubbed");
    }

    async fn burn_asset(
        &self,
        _request: Request<BurnAssetRequest>,
    ) -> Result<Response<BurnAssetResponse>, Status> {
        unimplemented!("burn_asset is not stubbed");
    }

    async fn redeem_notes(
        &self,
        _request: Request<RedeemNotesRequest>,
    ) -> Result<Response<RedeemNotesResponse>, Status> {
        unimplemented!("redeem_notes is not stubbed");
    }
}

async fn spawn_fake_server(announcements: Vec<ProtoRoundAnnouncement>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = ArkServiceServer::new(AnnouncementOnlyService { announcements });

    tokio::spawn(async move {
        Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Brief breathing room for the listener to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

fn make_keys() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let scan_priv = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let spend_priv = SecretKey::from_slice(&[11u8; 32]).unwrap();
    let spend_pk = PublicKey::from_secret_key(&secp, &spend_priv);
    (scan_priv, spend_pk)
}

#[tokio::test]
async fn scanner_discovers_match_through_real_grpc_server() {
    let (scan_priv, spend_pk) = make_keys();
    let pk_hex = hex::encode(spend_pk.serialize());

    let canned = vec![
        ProtoRoundAnnouncement {
            cursor: "round-001\ntx:0".into(),
            round_id: "round-001".into(),
            vtxo_id: "tx:0".into(),
            ephemeral_pubkey: "decoy".into(),
        },
        ProtoRoundAnnouncement {
            cursor: "round-001\ntx:1".into(),
            round_id: "round-001".into(),
            vtxo_id: "tx:1".into(),
            ephemeral_pubkey: pk_hex,
        },
    ];

    let server_url = spawn_fake_server(canned).await;

    let mut client = ArkClient::new(server_url);
    client.connect().await.expect("client must connect");

    let store = InMemoryStore::new();
    let source = Arc::new(ArkClientSource::new(Arc::new(TokioMutex::new(client))));

    let scanner = StealthScanner::with_config(
        scan_priv,
        spend_pk,
        source,
        store.clone(),
        ScannerConfig {
            poll_interval: Duration::from_millis(20),
            page_limit: 100,
        },
    );
    let metrics = scanner.metrics();
    let cancel = scanner.cancellation_token();
    let handle = scanner.start();

    for _ in 0..200 {
        if metrics.matches_found() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    cancel.cancel();
    handle.await.expect("scanner task panicked");

    assert_eq!(metrics.matches_found(), 1, "scanner must find the match");
    assert!(
        store.get_vtxo("tx:1").is_some(),
        "matched VTXO must be persisted"
    );
    let cp = store
        .get_metadata(CHECKPOINT_METADATA_KEY)
        .expect("checkpoint must be persisted");
    assert!(cp.starts_with("round-001\n"));
}
