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
    GetInfoRequest, GetRoundRequest, GetStatusRequest, GetVtxosRequest, ListRoundsRequest,
    Outpoint, RegisterForRoundRequest, RequestExitRequest,
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
    let svc = ArkServiceServer::new(ArkGrpcService::new(core, round_repo));

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
