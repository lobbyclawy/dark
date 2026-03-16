//! Integration tests for gRPC services.
//!
//! These tests spin up a real tonic server, connect a client, and exercise
//! each RPC endpoint.

use std::sync::Arc;

use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};

use arkd_api::proto::ark_v1::admin_service_client::AdminServiceClient;
use arkd_api::proto::ark_v1::admin_service_server::AdminServiceServer;
use arkd_api::proto::ark_v1::ark_service_client::ArkServiceClient;
use arkd_api::proto::ark_v1::ark_service_server::ArkServiceServer;
use arkd_api::proto::ark_v1::{
    DeleteIntentRequest, EstimateIntentFeeRequest, FinalizeTxRequest, GetEventStreamRequest,
    GetInfoRequest, GetPendingTxRequest, GetRoundRequest, GetStatusRequest, GetVtxosRequest,
    ListRoundsRequest, Outpoint, Output, RegisterForRoundRequest, RequestExitRequest,
    SignedVtxoInput, SubmitTxRequest, UpdateStreamTopicsRequest,
};

use arkd_api::grpc::admin_service::AdminGrpcService;
use arkd_api::grpc::ark_service::ArkGrpcService;

// ─── Mock infrastructure ────────────────────────────────────────────

use arkd_core::domain::{Vtxo, VtxoOutpoint};
use arkd_core::error::ArkResult;
use arkd_core::ports::*;
use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

struct MockWallet;
#[async_trait]
impl WalletService for MockWallet {
    async fn status(&self) -> ArkResult<WalletStatus> {
        Ok(WalletStatus {
            initialized: true,
            unlocked: true,
            synced: true,
        })
    }
    async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap())
    }
    async fn derive_connector_address(&self) -> ArkResult<String> {
        Ok("tb1q_connector".to_string())
    }
    async fn sign_transaction(&self, partial_tx: &str, _extract_raw: bool) -> ArkResult<String> {
        Ok(partial_tx.to_string())
    }
    async fn select_utxos(
        &self,
        _amount: u64,
        _confirmed_only: bool,
    ) -> ArkResult<(Vec<TxInput>, u64)> {
        Ok((vec![], 0))
    }
    async fn broadcast_transaction(&self, _txs: Vec<String>) -> ArkResult<String> {
        Ok("txid".to_string())
    }
    async fn fee_rate(&self) -> ArkResult<u64> {
        Ok(1)
    }
    async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
        Ok(BlockTimestamp {
            height: 100,
            timestamp: 1_700_000_000,
        })
    }
    async fn get_dust_amount(&self) -> ArkResult<u64> {
        Ok(546)
    }
    async fn get_outpoint_status(&self, _outpoint: &VtxoOutpoint) -> ArkResult<bool> {
        Ok(false)
    }
}

struct MockSigner;
#[async_trait]
impl SignerService for MockSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap())
    }
    async fn sign_transaction(&self, partial_tx: &str, _extract_raw: bool) -> ArkResult<String> {
        Ok(partial_tx.to_string())
    }
}

struct MockVtxoRepo;
#[async_trait]
impl VtxoRepository for MockVtxoRepo {
    async fn add_vtxos(&self, _vtxos: &[Vtxo]) -> ArkResult<()> {
        Ok(())
    }
    async fn get_vtxos(&self, _outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
        Ok(vec![])
    }
    async fn get_all_vtxos_for_pubkey(&self, _pubkey: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
        Ok((vec![], vec![]))
    }
    async fn spend_vtxos(
        &self,
        _spent: &[(VtxoOutpoint, String)],
        _ark_txid: &str,
    ) -> ArkResult<()> {
        Ok(())
    }
}

struct MockTxBuilder;
#[async_trait]
impl arkd_core::ports::TxBuilder for MockTxBuilder {
    async fn build_commitment_tx(
        &self,
        _signer_pubkey: &XOnlyPublicKey,
        _intents: &[arkd_core::domain::Intent],
        _boarding_inputs: &[arkd_core::ports::BoardingInput],
    ) -> ArkResult<arkd_core::ports::CommitmentTxResult> {
        Ok(arkd_core::ports::CommitmentTxResult {
            commitment_tx: String::new(),
            vtxo_tree: vec![],
            connector_address: String::new(),
            connectors: vec![],
        })
    }
    async fn verify_forfeit_txs(
        &self,
        _vtxos: &[Vtxo],
        _connectors: &arkd_core::domain::FlatTxTree,
        _txs: &[String],
    ) -> ArkResult<Vec<arkd_core::ports::ValidForfeitTx>> {
        Ok(vec![])
    }
    async fn build_sweep_tx(
        &self,
        _inputs: &[arkd_core::ports::SweepInput],
    ) -> ArkResult<(String, String)> {
        Ok((String::new(), String::new()))
    }
    async fn get_sweepable_batch_outputs(
        &self,
        _vtxo_tree: &Vec<arkd_core::domain::TxTreeNode>,
    ) -> ArkResult<Option<arkd_core::ports::SweepableOutput>> {
        Ok(None)
    }
    async fn finalize_and_extract(&self, _psbt_hex: &str) -> ArkResult<String> {
        Ok(String::new())
    }
    async fn verify_vtxo_tapscript_sigs(
        &self,
        _tx: &str,
        _must_include_signer: bool,
    ) -> ArkResult<bool> {
        Ok(true)
    }
    async fn verify_boarding_tapscript_sigs(
        &self,
        _signed_tx: &str,
        _commitment_tx: &str,
    ) -> ArkResult<std::collections::HashMap<u32, arkd_core::ports::SignedBoardingInput>> {
        Ok(std::collections::HashMap::new())
    }
}

struct MockCache;
#[async_trait]
impl CacheService for MockCache {
    async fn set(&self, _key: &str, _value: &[u8], _ttl: Option<u64>) -> ArkResult<()> {
        Ok(())
    }
    async fn get(&self, _key: &str) -> ArkResult<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn delete(&self, _key: &str) -> ArkResult<bool> {
        Ok(false)
    }
}

struct MockEvents;
#[async_trait]
impl EventPublisher for MockEvents {
    async fn publish_event(&self, _event: ArkEvent) -> ArkResult<()> {
        Ok(())
    }
    async fn subscribe(&self) -> ArkResult<tokio::sync::broadcast::Receiver<ArkEvent>> {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        drop(tx);
        Ok(rx)
    }
}

// --- Mock OffchainTxRepository ---
use std::collections::HashMap;
use std::sync::Mutex;

struct MockOffchainTxRepo {
    store: Mutex<HashMap<String, arkd_core::domain::OffchainTx>>,
}
impl MockOffchainTxRepo {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}
#[async_trait]
impl arkd_core::ports::OffchainTxRepository for MockOffchainTxRepo {
    async fn create(&self, tx: &arkd_core::domain::OffchainTx) -> ArkResult<()> {
        self.store.lock().unwrap().insert(tx.id.clone(), tx.clone());
        Ok(())
    }
    async fn get(&self, id: &str) -> ArkResult<Option<arkd_core::domain::OffchainTx>> {
        Ok(self.store.lock().unwrap().get(id).cloned())
    }
    async fn get_pending(&self) -> ArkResult<Vec<arkd_core::domain::OffchainTx>> {
        Ok(self.store.lock().unwrap().values().cloned().collect())
    }
    async fn update_stage(
        &self,
        id: &str,
        stage: &arkd_core::domain::OffchainTxStage,
    ) -> ArkResult<()> {
        if let Some(tx) = self.store.lock().unwrap().get_mut(id) {
            tx.stage = stage.clone();
        }
        Ok(())
    }
}

struct MockRoundRepo;
#[async_trait]
impl arkd_core::ports::RoundRepository for MockRoundRepo {
    async fn add_or_update_round(&self, _round: &arkd_core::domain::Round) -> ArkResult<()> {
        Ok(())
    }
    async fn get_round_with_id(&self, _id: &str) -> ArkResult<Option<arkd_core::domain::Round>> {
        Ok(None)
    }
    async fn get_round_stats(
        &self,
        _txid: &str,
    ) -> ArkResult<Option<arkd_core::domain::RoundStats>> {
        Ok(None)
    }
    async fn confirm_intent(&self, _round_id: &str, _intent_id: &str) -> ArkResult<()> {
        Ok(())
    }
    async fn get_pending_confirmations(&self, _round_id: &str) -> ArkResult<Vec<String>> {
        Ok(Vec::new())
    }
}

/// Build a test ArkService with mock dependencies.
fn build_test_core() -> Arc<arkd_core::ArkService> {
    Arc::new(arkd_core::ArkService::new(
        Arc::new(MockWallet),
        Arc::new(MockSigner),
        Arc::new(MockVtxoRepo),
        Arc::new(MockTxBuilder),
        Arc::new(MockCache),
        Arc::new(MockEvents),
        arkd_core::ArkConfig::default(),
    ))
}

/// Start a test ArkService gRPC server and return a connected client.
async fn start_ark_server() -> ArkServiceClient<Channel> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let core = build_test_core();
    let round_repo: Arc<dyn arkd_core::ports::RoundRepository> = Arc::new(MockRoundRepo);
    let broker = Arc::new(arkd_api::EventBroker::new(64));
    let offchain_tx_repo: Arc<dyn arkd_core::ports::OffchainTxRepository> =
        Arc::new(MockOffchainTxRepo::new());
    let svc = ArkServiceServer::new(ArkGrpcService::new(
        core,
        round_repo,
        broker,
        offchain_tx_repo,
    ));

    tokio::spawn(async move {
        Server::builder()
            .add_service(svc)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Give server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();

    ArkServiceClient::new(channel)
}

/// Start a test AdminService gRPC server and return a connected client.
async fn start_admin_server() -> AdminServiceClient<Channel> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let core = build_test_core();
    let svc = AdminServiceServer::new(AdminGrpcService::new(core));

    tokio::spawn(async move {
        Server::builder()
            .add_service(svc)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();

    AdminServiceClient::new(channel)
}

// ─── ArkService Tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_get_info() {
    let mut client = start_ark_server().await;
    let resp = client.get_info(GetInfoRequest {}).await.unwrap();
    let info = resp.into_inner();
    assert!(!info.version.is_empty());
    assert!(!info.signer_pubkey.is_empty());
    assert!(!info.network.is_empty());
    assert!(info.dust > 0);
}

#[tokio::test]
async fn test_get_info_new_fields() {
    let mut client = start_ark_server().await;
    let resp = client.get_info(GetInfoRequest {}).await.unwrap();
    let info = resp.into_inner();

    // forfeit_address must be non-empty (derived from forfeit pubkey)
    assert!(!info.forfeit_address.is_empty(), "forfeit_address is empty");
    // For regtest, the address should start with "bcrt1"
    assert!(
        info.forfeit_address.starts_with("bcrt1"),
        "forfeit_address should be a regtest bech32m address, got: {}",
        info.forfeit_address
    );

    // checkpoint_tapscript must be non-empty
    assert!(
        !info.checkpoint_tapscript.is_empty(),
        "checkpoint_tapscript is empty"
    );

    // UTXO amount bounds (from ArkConfig defaults)
    assert!(
        info.utxo_min_amount > 0,
        "utxo_min_amount should be > 0, got: {}",
        info.utxo_min_amount
    );
    assert!(
        info.utxo_max_amount > info.utxo_min_amount,
        "utxo_max_amount ({}) should be > utxo_min_amount ({})",
        info.utxo_max_amount,
        info.utxo_min_amount
    );

    // Exit delays
    assert!(
        info.public_unilateral_exit_delay > 0,
        "public_unilateral_exit_delay should be > 0"
    );
    assert!(
        info.boarding_exit_delay > 0,
        "boarding_exit_delay should be > 0"
    );

    // Max tx weight
    assert!(
        info.max_tx_weight > 0,
        "max_tx_weight should be > 0, got: {}",
        info.max_tx_weight
    );

    // Service status should have 3 subsystems
    assert_eq!(
        info.service_status.len(),
        3,
        "service_status should have 3 entries, got: {}",
        info.service_status.len()
    );
    for name in &["database", "wallet", "bitcoin_rpc"] {
        let status = info
            .service_status
            .get(*name)
            .unwrap_or_else(|| panic!("service_status missing '{name}'"));
        assert!(status.available, "'{name}' should be available");
        assert_eq!(status.name, *name, "status.name mismatch for '{name}'");
        assert!(!status.details.is_empty(), "'{name}' details is empty");
    }
}

#[tokio::test]
async fn test_get_info_default_values_are_sensible() {
    let mut client = start_ark_server().await;
    let resp = client.get_info(GetInfoRequest {}).await.unwrap();
    let info = resp.into_inner();

    // Default utxo_min_amount should be 1000 sats
    assert_eq!(info.utxo_min_amount, 1000);
    // Default utxo_max_amount should be 1 BTC (100_000_000 sats)
    assert_eq!(info.utxo_max_amount, 100_000_000);
    // Default boarding_exit_delay should be 512 blocks
    assert_eq!(info.boarding_exit_delay, 512);
    // Default public_unilateral_exit_delay should be 512 blocks
    assert_eq!(info.public_unilateral_exit_delay, 512);
    // Default max_tx_weight should be 400_000
    assert_eq!(info.max_tx_weight, 400_000);
}

#[tokio::test]
async fn test_register_for_round_validation() {
    let mut client = start_ark_server().await;

    // Empty pubkey should fail
    let result = client
        .register_for_round(RegisterForRoundRequest {
            pubkey: String::new(),
            amount: 1000,
            inputs: vec![],
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);

    // Zero amount should fail
    let result = client
        .register_for_round(RegisterForRoundRequest {
            pubkey: "pubkey123".to_string(),
            amount: 0,
            inputs: vec![],
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_request_exit_validation() {
    let mut client = start_ark_server().await;

    // Without authentication, should get Unauthenticated error
    // (auth is required for exit requests since they modify user funds)
    let result = client
        .request_exit(RequestExitRequest {
            vtxo_ids: vec![Outpoint {
                txid: "abc".to_string(),
                vout: 0,
            }],
            destination: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        })
        .await;
    assert!(result.is_err());
    // Note: Without auth interceptor in test server, this falls through to
    // require_authenticated_user which returns Unauthenticated
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_get_vtxos() {
    let mut client = start_ark_server().await;

    let resp = client
        .get_vtxos(GetVtxosRequest {
            pubkey: "some_pubkey".to_string(),
        })
        .await
        .unwrap();
    let vtxos = resp.into_inner();
    assert!(vtxos.spendable.is_empty());
    assert!(vtxos.spent.is_empty());
}

#[tokio::test]
async fn test_get_vtxos_validation() {
    let mut client = start_ark_server().await;

    let result = client
        .get_vtxos(GetVtxosRequest {
            pubkey: String::new(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_list_rounds() {
    let mut client = start_ark_server().await;

    let resp = client
        .list_rounds(ListRoundsRequest {
            after: 0,
            before: 0,
            limit: 10,
            offset: 0,
        })
        .await
        .unwrap();
    assert!(resp.into_inner().rounds.is_empty());
}

#[tokio::test]
async fn test_get_round_not_found() {
    let mut client = start_ark_server().await;

    let result = client
        .get_round(GetRoundRequest {
            round_id: "nonexistent".to_string(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_get_round_validation() {
    let mut client = start_ark_server().await;

    let result = client
        .get_round(GetRoundRequest {
            round_id: String::new(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

// ─── AdminService Tests ─────────────────────────────────────────────

#[tokio::test]
async fn test_admin_get_status() {
    let mut client = start_admin_server().await;

    let resp = client.get_status(GetStatusRequest {}).await.unwrap();
    let status = resp.into_inner();
    assert!(!status.version.is_empty());
    assert!(!status.network.is_empty());
    assert!(!status.signer_pubkey.is_empty());
}

#[tokio::test]
async fn test_admin_get_rounds() {
    let mut client = start_admin_server().await;

    let resp = client
        .get_rounds(arkd_api::proto::ark_v1::GetRoundsRequest {
            after: 0,
            before: 0,
        })
        .await
        .unwrap();
    assert!(resp.into_inner().round_ids.is_empty());
}

#[tokio::test]
async fn test_admin_get_round_details_not_found() {
    let mut client = start_admin_server().await;

    let result = client
        .get_round_details(arkd_api::proto::ark_v1::GetRoundDetailsRequest {
            round_id: "nonexistent".to_string(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_admin_get_round_details_validation() {
    let mut client = start_admin_server().await;

    let result = client
        .get_round_details(arkd_api::proto::ark_v1::GetRoundDetailsRequest {
            round_id: String::new(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_admin_create_note_returns_unimplemented() {
    let mut client = start_admin_server().await;

    let result = client
        .create_note(arkd_api::proto::ark_v1::CreateNoteRequest {
            amount: 50_000,
            quantity: 1,
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn test_admin_create_note_validation() {
    let mut client = start_admin_server().await;

    // Missing amount
    let result = client
        .create_note(arkd_api::proto::ark_v1::CreateNoteRequest {
            amount: 0,
            quantity: 1,
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);

    // Missing quantity
    let result = client
        .create_note(arkd_api::proto::ark_v1::CreateNoteRequest {
            amount: 50_000,
            quantity: 0,
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_admin_ban_participant_success() {
    let mut client = start_admin_server().await;

    let resp = client
        .ban_participant(arkd_api::proto::ark_v1::BanParticipantRequest {
            pubkey: "deadbeef".to_string(),
            reason: "spam".to_string(),
        })
        .await
        .unwrap();
    assert!(resp.into_inner().success);
}

#[tokio::test]
async fn test_admin_ban_participant_validation() {
    let mut client = start_admin_server().await;

    let result = client
        .ban_participant(arkd_api::proto::ark_v1::BanParticipantRequest {
            pubkey: String::new(),
            reason: "test".to_string(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

// ─── Event stream tests ─────────────────────────────────────────────

#[tokio::test]
async fn test_event_stream_initial_heartbeat() {
    use tokio_stream::StreamExt;

    let mut client = start_ark_server().await;

    let response = client
        .get_event_stream(GetEventStreamRequest {})
        .await
        .expect("get_event_stream should succeed");

    let mut stream = response.into_inner();
    let first = stream.next().await.expect("stream should yield an item");
    let event = first.expect("first item should be Ok");

    match event.event {
        Some(arkd_api::proto::ark_v1::round_event::Event::Heartbeat(hb)) => {
            assert!(hb.timestamp > 0, "heartbeat timestamp should be positive");
        }
        other => panic!("Expected heartbeat event, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_update_stream_topics_noop() {
    let mut client = start_ark_server().await;

    let response = client
        .update_stream_topics(UpdateStreamTopicsRequest {
            topics: vec![],
            update_mode: None,
        })
        .await;

    assert!(response.is_ok(), "update_stream_topics should succeed");
}

// ─── EstimateIntentFee Tests ────────────────────────────────────────

#[tokio::test]
async fn test_estimate_intent_fee_basic() {
    let mut client = start_ark_server().await;

    let resp = client
        .estimate_intent_fee(EstimateIntentFeeRequest {
            input_vtxo_ids: vec!["vtxo1".to_string(), "vtxo2".to_string()],
            outputs: vec![
                Output {
                    amount: 50_000,
                    destination: Some(
                        arkd_api::proto::ark_v1::output::Destination::OnchainAddress(
                            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
                        ),
                    ),
                },
                Output {
                    amount: 30_000,
                    destination: Some(
                        arkd_api::proto::ark_v1::output::Destination::OnchainAddress(
                            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
                        ),
                    ),
                },
            ],
        })
        .await
        .unwrap();

    let fee = resp.into_inner();
    // fee = (2 * 68 + 2 * 43 + 10) * 1 = (136 + 86 + 10) = 232
    assert!(fee.fee_sats > 0, "fee_sats should be > 0");
    assert_eq!(fee.fee_sats, 232);
    assert_eq!(fee.fee_rate_sats_per_vb, 1);
}

#[tokio::test]
async fn test_estimate_intent_fee_more_inputs() {
    let mut client = start_ark_server().await;

    // 2-input fee
    let resp2 = client
        .estimate_intent_fee(EstimateIntentFeeRequest {
            input_vtxo_ids: vec!["vtxo1".to_string(), "vtxo2".to_string()],
            outputs: vec![Output {
                amount: 50_000,
                destination: Some(
                    arkd_api::proto::ark_v1::output::Destination::OnchainAddress(
                        "tb1qtest".to_string(),
                    ),
                ),
            }],
        })
        .await
        .unwrap()
        .into_inner();

    // 5-input fee
    let resp5 = client
        .estimate_intent_fee(EstimateIntentFeeRequest {
            input_vtxo_ids: vec![
                "v1".to_string(),
                "v2".to_string(),
                "v3".to_string(),
                "v4".to_string(),
                "v5".to_string(),
            ],
            outputs: vec![Output {
                amount: 50_000,
                destination: Some(
                    arkd_api::proto::ark_v1::output::Destination::OnchainAddress(
                        "tb1qtest".to_string(),
                    ),
                ),
            }],
        })
        .await
        .unwrap()
        .into_inner();

    assert!(
        resp5.fee_sats > resp2.fee_sats,
        "5-input fee ({}) should be > 2-input fee ({})",
        resp5.fee_sats,
        resp2.fee_sats
    );
}

// ─── DeleteIntent Tests ─────────────────────────────────────────────

#[tokio::test]
async fn test_delete_intent_empty_id() {
    let mut client = start_ark_server().await;

    let result = client
        .delete_intent(DeleteIntentRequest {
            intent_id: String::new(),
            proof: vec![1, 2, 3],
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_delete_intent_empty_proof() {
    let mut client = start_ark_server().await;

    let result = client
        .delete_intent(DeleteIntentRequest {
            intent_id: "some-intent-id".to_string(),
            proof: vec![],
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_delete_intent_not_found() {
    let mut client = start_ark_server().await;

    let result = client
        .delete_intent(DeleteIntentRequest {
            intent_id: "nonexistent-intent".to_string(),
            proof: vec![1, 2, 3, 4],
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
}

// --- Offchain transaction tests ---

#[tokio::test]
async fn test_submit_tx_empty_inputs() {
    let mut client = start_ark_server().await;
    let resp = client
        .submit_tx(SubmitTxRequest {
            inputs: vec![],
            outputs: vec![],
        })
        .await;
    assert_eq!(resp.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_submit_tx_basic() {
    let mut client = start_ark_server().await;
    let resp = client
        .submit_tx(SubmitTxRequest {
            inputs: vec![SignedVtxoInput {
                vtxo_id: "vtxo-1".to_string(),
                signed_tx: vec![0u8; 32],
            }],
            outputs: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!resp.tx_id.is_empty());
}

#[tokio::test]
async fn test_finalize_tx_not_found() {
    let mut client = start_ark_server().await;
    let resp = client
        .finalize_tx(FinalizeTxRequest {
            tx_id: "nonexistent-id".to_string(),
            checkpoint_txs: vec![],
        })
        .await;
    assert_eq!(resp.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_get_pending_tx_not_found() {
    let mut client = start_ark_server().await;
    let resp = client
        .get_pending_tx(GetPendingTxRequest {
            tx_id: "nonexistent-id".to_string(),
        })
        .await;
    assert_eq!(resp.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_offchain_tx_submit_and_get() {
    let mut client = start_ark_server().await;
    let submit = client
        .submit_tx(SubmitTxRequest {
            inputs: vec![SignedVtxoInput {
                vtxo_id: "vtxo-abc".to_string(),
                signed_tx: vec![1u8; 32],
            }],
            outputs: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    let tx_id = submit.tx_id;
    assert!(!tx_id.is_empty());

    let get = client
        .get_pending_tx(GetPendingTxRequest {
            tx_id: tx_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(get.tx_id, tx_id);
    assert!(!get.stage.is_empty());
}

// ─── TLS Configuration Tests ────────────────────────────────────────

#[test]
fn test_tls_config_fields_default_none() {
    let config = arkd_api::ServerConfig::default();
    assert!(!config.tls_enabled);
    assert!(config.tls_cert_path.is_none());
    assert!(config.tls_key_path.is_none());
}

#[test]
fn test_tls_config_none_uses_plaintext() {
    // ServerConfig with TLS disabled should work fine (plaintext)
    let config = arkd_api::ServerConfig {
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        ..Default::default()
    };
    assert!(!config.tls_enabled);
    // Server creation should succeed with plaintext config
    // (actual server start tested via start_ark_server above)
}
