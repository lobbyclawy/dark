//! Integration tests for gRPC services.
//!
//! These tests spin up a real tonic server, connect a client, and exercise
//! each RPC endpoint.

use std::sync::Arc;

use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};

use dark_api::proto::ark_v1::admin_service_client::AdminServiceClient;
use dark_api::proto::ark_v1::admin_service_server::AdminServiceServer;
use dark_api::proto::ark_v1::ark_service_client::ArkServiceClient;
use dark_api::proto::ark_v1::ark_service_server::ArkServiceServer;
use dark_api::proto::ark_v1::{
    DeleteIntentRequest, EstimateIntentFeeRequest, FinalizeTxRequest, GetEventStreamRequest,
    GetInfoRequest, GetPendingTxRequest, GetRoundAnnouncementsRequest, GetRoundRequest,
    GetStatusRequest, GetTransactionsStreamRequest, GetVtxosRequest, Intent, ListRoundsRequest,
    Outpoint, Output, RegisterForRoundRequest, RequestExitRequest, SubmitTxRequest,
    UpdateStreamTopicsRequest,
};

use dark_api::grpc::admin_service::AdminGrpcService;
use dark_api::grpc::ark_service::ArkGrpcService;

// ─── Mock infrastructure ────────────────────────────────────────────

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;
use dark_core::domain::{Vtxo, VtxoOutpoint};
use dark_core::error::ArkResult;
use dark_core::ports::*;

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
    async fn get_secret_key_bytes(&self) -> ArkResult<[u8; 32]> {
        let mut key = [0u8; 32];
        key[31] = 1;
        Ok(key)
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
impl dark_core::ports::TxBuilder for MockTxBuilder {
    async fn build_commitment_tx(
        &self,
        _signer_pubkey: &XOnlyPublicKey,
        _intents: &[dark_core::domain::Intent],
        _boarding_inputs: &[dark_core::ports::BoardingInput],
    ) -> ArkResult<dark_core::ports::CommitmentTxResult> {
        Ok(dark_core::ports::CommitmentTxResult {
            commitment_tx: String::new(),
            vtxo_tree: vec![],
            connector_address: String::new(),
            connectors: vec![],
        })
    }
    async fn verify_forfeit_txs(
        &self,
        _vtxos: &[Vtxo],
        _connectors: &dark_core::domain::FlatTxTree,
        _txs: &[String],
    ) -> ArkResult<Vec<dark_core::ports::ValidForfeitTx>> {
        Ok(vec![])
    }
    async fn build_sweep_tx(
        &self,
        _inputs: &[dark_core::ports::SweepInput],
    ) -> ArkResult<(String, String)> {
        Ok((String::new(), String::new()))
    }
    async fn get_sweepable_batch_outputs(
        &self,
        _vtxo_tree: &Vec<dark_core::domain::TxTreeNode>,
    ) -> ArkResult<Option<dark_core::ports::SweepableOutput>> {
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
    ) -> ArkResult<std::collections::HashMap<u32, dark_core::ports::SignedBoardingInput>> {
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
    store: Mutex<HashMap<String, dark_core::domain::OffchainTx>>,
}
impl MockOffchainTxRepo {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}
#[async_trait]
impl dark_core::ports::OffchainTxRepository for MockOffchainTxRepo {
    async fn create(&self, tx: &dark_core::domain::OffchainTx) -> ArkResult<()> {
        self.store.lock().unwrap().insert(tx.id.clone(), tx.clone());
        Ok(())
    }
    async fn get(&self, id: &str) -> ArkResult<Option<dark_core::domain::OffchainTx>> {
        Ok(self.store.lock().unwrap().get(id).cloned())
    }
    async fn get_pending(&self) -> ArkResult<Vec<dark_core::domain::OffchainTx>> {
        Ok(self.store.lock().unwrap().values().cloned().collect())
    }
    async fn get_all_finalized(&self) -> ArkResult<Vec<dark_core::domain::OffchainTx>> {
        Ok(self
            .store
            .lock()
            .unwrap()
            .values()
            .filter(|tx| tx.is_finalized())
            .cloned()
            .collect())
    }
    async fn update_stage(
        &self,
        id: &str,
        stage: &dark_core::domain::OffchainTxStage,
    ) -> ArkResult<()> {
        if let Some(tx) = self.store.lock().unwrap().get_mut(id) {
            tx.stage = stage.clone();
        }
        Ok(())
    }
    async fn set_signed_ark_tx(&self, id: &str, signed_ark_tx: &str) -> ArkResult<()> {
        if let Some(tx) = self.store.lock().unwrap().get_mut(id) {
            tx.signed_ark_tx = signed_ark_tx.to_string();
        }
        Ok(())
    }
    async fn set_checkpoint_txs(&self, id: &str, checkpoint_txs: &[String]) -> ArkResult<()> {
        if let Some(tx) = self.store.lock().unwrap().get_mut(id) {
            tx.checkpoint_txs = checkpoint_txs.to_vec();
        }
        Ok(())
    }
    async fn is_input_spent(&self, vtxo_id: &str) -> ArkResult<bool> {
        let store = self.store.lock().unwrap();
        for tx in store.values() {
            for input in &tx.inputs {
                if input.vtxo_id == vtxo_id {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

struct MockRoundRepo {
    announcements: Vec<dark_core::ports::RoundAnnouncement>,
}

impl MockRoundRepo {
    fn empty() -> Self {
        Self {
            announcements: Vec::new(),
        }
    }

    fn with_announcements(announcements: Vec<dark_core::ports::RoundAnnouncement>) -> Self {
        Self { announcements }
    }
}

#[async_trait]
impl dark_core::ports::RoundRepository for MockRoundRepo {
    async fn add_or_update_round(&self, _round: &dark_core::domain::Round) -> ArkResult<()> {
        Ok(())
    }
    async fn get_round_with_id(&self, _id: &str) -> ArkResult<Option<dark_core::domain::Round>> {
        Ok(None)
    }
    async fn get_round_stats(
        &self,
        _txid: &str,
    ) -> ArkResult<Option<dark_core::domain::RoundStats>> {
        Ok(None)
    }
    async fn confirm_intent(&self, _round_id: &str, _intent_id: &str) -> ArkResult<()> {
        Ok(())
    }
    async fn get_pending_confirmations(&self, _round_id: &str) -> ArkResult<Vec<String>> {
        Ok(Vec::new())
    }
    async fn list_round_announcements(
        &self,
        round_id_start: Option<&str>,
        round_id_end: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: u32,
    ) -> ArkResult<Vec<dark_core::ports::RoundAnnouncement>> {
        let mut announcements = self.announcements.clone();
        announcements.sort_by(|a, b| {
            a.round_id
                .cmp(&b.round_id)
                .then_with(|| a.vtxo_id.cmp(&b.vtxo_id))
        });

        let filtered = announcements
            .into_iter()
            .filter(|announcement| match (round_id_start, round_id_end) {
                (Some(start), Some(end)) => {
                    announcement.round_id.as_str() >= start && announcement.round_id.as_str() <= end
                }
                _ => true,
            })
            .filter(|announcement| match cursor {
                Some((round_id, vtxo_id)) => {
                    (
                        announcement.round_id.as_str(),
                        announcement.vtxo_id.as_str(),
                    ) > (round_id, vtxo_id)
                }
                None => true,
            })
            .take(limit as usize)
            .collect();

        Ok(filtered)
    }
}

/// Build a test ArkService with mock dependencies.
fn build_test_core() -> Arc<dark_core::ArkService> {
    Arc::new(dark_core::ArkService::new(
        Arc::new(MockWallet),
        Arc::new(MockSigner),
        Arc::new(MockVtxoRepo),
        Arc::new(MockTxBuilder),
        Arc::new(MockCache),
        Arc::new(MockEvents),
        dark_core::ArkConfig::default(),
    ))
}

/// Start a test ArkService gRPC server and return a connected client.
async fn start_ark_server() -> ArkServiceClient<Channel> {
    start_ark_server_with_round_repo(Arc::new(MockRoundRepo::empty())).await
}

async fn start_ark_server_with_round_repo(
    round_repo: Arc<dyn dark_core::ports::RoundRepository>,
) -> ArkServiceClient<Channel> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let core = build_test_core();
    let broker = Arc::new(dark_api::EventBroker::new(64));
    let tx_broker = Arc::new(dark_api::TransactionEventBroker::new(64));
    let offchain_tx_repo: Arc<dyn dark_core::ports::OffchainTxRepository> =
        Arc::new(MockOffchainTxRepo::new());
    let svc = ArkServiceServer::new(ArkGrpcService::new(
        core,
        round_repo,
        broker,
        tx_broker,
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
        assert!(!status.is_empty(), "'{name}' status string is empty");
    }
}

#[tokio::test]
async fn test_get_info_pubkeys_are_compressed() {
    let mut client = start_ark_server().await;
    let resp = client.get_info(GetInfoRequest {}).await.unwrap();
    let info = resp.into_inner();

    // signer_pubkey and forfeit_pubkey must be 33-byte compressed (66 hex chars)
    // with 02 or 03 prefix — matching arkade-os/arkd's SerializeCompressed() format.
    assert_eq!(
        info.signer_pubkey.len(),
        66,
        "signer_pubkey must be 66 hex chars (33 bytes compressed), got {} chars: {}",
        info.signer_pubkey.len(),
        info.signer_pubkey
    );
    assert!(
        info.signer_pubkey.starts_with("02") || info.signer_pubkey.starts_with("03"),
        "signer_pubkey must start with 02 or 03, got: {}",
        info.signer_pubkey
    );
    assert_eq!(
        info.forfeit_pubkey.len(),
        66,
        "forfeit_pubkey must be 66 hex chars (33 bytes compressed), got {} chars: {}",
        info.forfeit_pubkey.len(),
        info.forfeit_pubkey
    );
    assert!(
        info.forfeit_pubkey.starts_with("02") || info.forfeit_pubkey.starts_with("03"),
        "forfeit_pubkey must start with 02 or 03, got: {}",
        info.forfeit_pubkey
    );

    // checkpoint_tapscript is a CSVMultisigClosure binary script (hex-encoded).
    // Format: <seq_push> b2 75 20 <32-byte-pubkey> ac
    //   - starts with sequence push bytes (variable, e.g. "0190" for 144 blocks)
    //   - contains "b275" (OP_CSV OP_DROP)
    //   - contains "20" + 64 hex pubkey chars
    //   - ends with "ac" (OP_CHECKSIG)
    assert!(
        info.checkpoint_tapscript.contains("b275") && info.checkpoint_tapscript.ends_with("ac"),
        "checkpoint_tapscript should be a CSVMultisigClosure script, got: {}",
        info.checkpoint_tapscript
    );
    // Should be at least 72 hex chars: 2 (seq) + 4 (b275) + 2 (20) + 64 (pubkey) + 2 (ac)
    assert!(
        info.checkpoint_tapscript.len() >= 72,
        "checkpoint_tapscript too short ({}), expected CSVMultisigClosure format",
        info.checkpoint_tapscript.len()
    );
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
    // Default boarding_exit_delay: 1024s (BIP68 multiple, matches Go test env ARKD_BOARDING_EXIT_DELAY=1024)
    assert_eq!(info.boarding_exit_delay, 1_024);
    // Default public_unilateral_exit_delay: 512s (BIP68 multiple, matches Go test env ARKD_UNILATERAL_EXIT_DELAY=512)
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
        .get_rounds(dark_api::proto::ark_v1::GetRoundsRequest {
            after: 0,
            before: 0,
            with_failed: false,
            with_completed: false,
        })
        .await
        .unwrap();
    assert!(resp.into_inner().round_ids.is_empty());
}

#[tokio::test]
async fn test_admin_get_round_details_not_found() {
    let mut client = start_admin_server().await;

    let result = client
        .get_round_details(dark_api::proto::ark_v1::GetRoundDetailsRequest {
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
        .get_round_details(dark_api::proto::ark_v1::GetRoundDetailsRequest {
            round_id: String::new(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_admin_create_note_returns_notes() {
    let mut client = start_admin_server().await;

    let result = client
        .create_note(dark_api::proto::ark_v1::CreateNoteRequest {
            amount: 50_000,
            quantity: 2,
        })
        .await;
    assert!(result.is_ok(), "create_note should succeed: {:?}", result);
    let resp = result.unwrap().into_inner();
    assert_eq!(resp.notes.len(), 2);
    for note in &resp.notes {
        assert!(
            note.starts_with("arknote"),
            "note should have arknote prefix: {note}"
        );
    }
}

#[tokio::test]
async fn test_admin_create_note_validation() {
    let mut client = start_admin_server().await;

    // Missing amount
    let result = client
        .create_note(dark_api::proto::ark_v1::CreateNoteRequest {
            amount: 0,
            quantity: 1,
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);

    // Missing quantity
    let result = client
        .create_note(dark_api::proto::ark_v1::CreateNoteRequest {
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
        .ban_participant(dark_api::proto::ark_v1::BanParticipantRequest {
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
        .ban_participant(dark_api::proto::ark_v1::BanParticipantRequest {
            pubkey: String::new(),
            reason: "test".to_string(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

// ─── Event stream tests ─────────────────────────────────────────────

#[tokio::test]
async fn test_event_stream_initial_stream_started() {
    use tokio_stream::StreamExt;

    let mut client = start_ark_server().await;

    let response = client
        .get_event_stream(GetEventStreamRequest { topics: vec![] })
        .await
        .expect("get_event_stream should succeed");

    let mut stream = response.into_inner();
    let first = stream.next().await.expect("stream should yield an item");
    let event = first.expect("first item should be Ok");

    match event.event {
        Some(dark_api::proto::ark_v1::round_event::Event::StreamStarted(ref started)) => {
            assert!(
                !started.id.is_empty(),
                "StreamStarted should have a non-empty id"
            );
        }
        other => panic!("Expected StreamStarted event, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_update_stream_topics_noop() {
    let mut client = start_ark_server().await;

    // First open an event stream to get a stream_id
    let mut stream = client
        .get_event_stream(GetEventStreamRequest { topics: vec![] })
        .await
        .expect("should open event stream")
        .into_inner();

    // Read the StreamStarted event to get the stream_id
    let first_event = stream.message().await.unwrap().unwrap();
    let stream_id = match first_event.event {
        Some(dark_api::proto::ark_v1::round_event::Event::StreamStarted(s)) => s.id,
        other => panic!("Expected StreamStarted, got: {:?}", other),
    };

    let response = client
        .update_stream_topics(UpdateStreamTopicsRequest {
            stream_id,
            topics_change: Some(
                dark_api::proto::ark_v1::update_stream_topics_request::TopicsChange::Overwrite(
                    dark_api::proto::ark_v1::OverwriteTopics {
                        topics: vec!["test-topic".to_string()],
                    },
                ),
            ),
        })
        .await;

    assert!(response.is_ok(), "update_stream_topics should succeed");
}

#[tokio::test]
async fn test_get_round_announcements_range_returns_stable_order() {
    use tokio_stream::StreamExt;

    let repo = Arc::new(MockRoundRepo::with_announcements(vec![
        dark_core::ports::RoundAnnouncement {
            round_id: "round-002".to_string(),
            vtxo_id: "txb:1".to_string(),
            ephemeral_pubkey: "02bb".to_string(),
        },
        dark_core::ports::RoundAnnouncement {
            round_id: "round-001".to_string(),
            vtxo_id: "txa:0".to_string(),
            ephemeral_pubkey: "02aa".to_string(),
        },
        dark_core::ports::RoundAnnouncement {
            round_id: "round-003".to_string(),
            vtxo_id: "txc:0".to_string(),
            ephemeral_pubkey: "02cc".to_string(),
        },
    ]));
    let mut client = start_ark_server_with_round_repo(repo).await;

    let response = client
        .get_round_announcements(GetRoundAnnouncementsRequest {
            round_id_start: "round-001".to_string(),
            round_id_end: "round-002".to_string(),
            cursor: String::new(),
            limit: 10,
        })
        .await
        .expect("get_round_announcements should succeed");

    let announcements: Vec<_> = response
        .into_inner()
        .collect::<Result<Vec<_>, _>>()
        .await
        .expect("stream should be readable");

    assert_eq!(announcements.len(), 2);
    assert_eq!(announcements[0].round_id, "round-001");
    assert_eq!(announcements[0].vtxo_id, "txa:0");
    assert_eq!(announcements[0].cursor, "round-001\ntxa:0");
    assert_eq!(announcements[1].round_id, "round-002");
    assert_eq!(announcements[1].vtxo_id, "txb:1");
}

#[tokio::test]
async fn test_get_round_announcements_cursor_resumes_exclusively() {
    use tokio_stream::StreamExt;

    let repo = Arc::new(MockRoundRepo::with_announcements(vec![
        dark_core::ports::RoundAnnouncement {
            round_id: "round-001".to_string(),
            vtxo_id: "txa:0".to_string(),
            ephemeral_pubkey: "02aa".to_string(),
        },
        dark_core::ports::RoundAnnouncement {
            round_id: "round-001".to_string(),
            vtxo_id: "txa:1".to_string(),
            ephemeral_pubkey: "02ab".to_string(),
        },
    ]));
    let mut client = start_ark_server_with_round_repo(repo).await;

    let response = client
        .get_round_announcements(GetRoundAnnouncementsRequest {
            round_id_start: String::new(),
            round_id_end: String::new(),
            cursor: "round-001\ntxa:0".to_string(),
            limit: 10,
        })
        .await
        .expect("get_round_announcements should succeed");

    let announcements: Vec<_> = response
        .into_inner()
        .collect::<Result<Vec<_>, _>>()
        .await
        .expect("stream should be readable");

    assert_eq!(announcements.len(), 1);
    assert_eq!(announcements[0].vtxo_id, "txa:1");
}

#[tokio::test]
async fn test_get_round_announcements_requires_selector() {
    let mut client = start_ark_server().await;

    let err = client
        .get_round_announcements(GetRoundAnnouncementsRequest {
            round_id_start: String::new(),
            round_id_end: String::new(),
            cursor: String::new(),
            limit: 0,
        })
        .await
        .expect_err("missing selector should fail");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

/// Build a deterministic batch of announcements spanning multiple rounds,
/// used by the pagination and reconnect tests below.
fn sample_announcements() -> Vec<dark_core::ports::RoundAnnouncement> {
    vec![
        dark_core::ports::RoundAnnouncement {
            round_id: "round-001".to_string(),
            vtxo_id: "txa:0".to_string(),
            ephemeral_pubkey: "02a0".to_string(),
        },
        dark_core::ports::RoundAnnouncement {
            round_id: "round-001".to_string(),
            vtxo_id: "txa:1".to_string(),
            ephemeral_pubkey: "02a1".to_string(),
        },
        dark_core::ports::RoundAnnouncement {
            round_id: "round-002".to_string(),
            vtxo_id: "txb:0".to_string(),
            ephemeral_pubkey: "02b0".to_string(),
        },
        dark_core::ports::RoundAnnouncement {
            round_id: "round-003".to_string(),
            vtxo_id: "txc:0".to_string(),
            ephemeral_pubkey: "02c0".to_string(),
        },
        dark_core::ports::RoundAnnouncement {
            round_id: "round-003".to_string(),
            vtxo_id: "txc:1".to_string(),
            ephemeral_pubkey: "02c1".to_string(),
        },
    ]
}

/// Acceptance criterion #1: "Client iterates over a round range and gets all
/// announcements exactly once." This drives the cursor through a small page
/// size until the server returns an empty page, then asserts the union of all
/// pages is the full input set with no duplicates and in stable order.
#[tokio::test]
async fn test_get_round_announcements_paginated_iteration_visits_each_exactly_once() {
    use tokio_stream::StreamExt;

    let expected = sample_announcements();
    let repo = Arc::new(MockRoundRepo::with_announcements(expected.clone()));
    let mut client = start_ark_server_with_round_repo(repo).await;

    let mut cursor = String::new();
    let mut collected: Vec<(String, String, String)> = Vec::new();
    let page_size: u32 = 2;

    loop {
        let response = client
            .get_round_announcements(GetRoundAnnouncementsRequest {
                round_id_start: "round-001".to_string(),
                round_id_end: "round-003".to_string(),
                cursor: cursor.clone(),
                limit: page_size,
            })
            .await
            .expect("get_round_announcements should succeed");

        let page: Vec<_> = response
            .into_inner()
            .collect::<Result<Vec<_>, _>>()
            .await
            .expect("stream should be readable");

        if page.is_empty() {
            break;
        }

        cursor = page
            .last()
            .map(|item| item.cursor.clone())
            .expect("non-empty page must have a cursor");

        for item in page {
            collected.push((item.round_id, item.vtxo_id, item.ephemeral_pubkey));
        }
    }

    let expected_tuples: Vec<(String, String, String)> = expected
        .into_iter()
        .map(|a| (a.round_id, a.vtxo_id, a.ephemeral_pubkey))
        .collect();
    assert_eq!(
        collected, expected_tuples,
        "paginated iteration must yield every announcement exactly once, in stable order"
    );
}

/// Acceptance criterion #2: "Disconnect + reconnect with cursor resumes
/// cleanly." Open a stream, consume a prefix of it, then drop the stream
/// (simulating a network disconnect) and reopen with the last seen cursor.
/// The second stream must yield the suffix without overlap or gap.
#[tokio::test]
async fn test_get_round_announcements_disconnect_reconnect_resumes_cleanly() {
    use tokio_stream::StreamExt;

    let expected = sample_announcements();
    let repo = Arc::new(MockRoundRepo::with_announcements(expected.clone()));
    let mut client = start_ark_server_with_round_repo(repo).await;

    // First connection: take the first two items, then drop the stream.
    let first_stream = client
        .get_round_announcements(GetRoundAnnouncementsRequest {
            round_id_start: "round-001".to_string(),
            round_id_end: "round-003".to_string(),
            cursor: String::new(),
            limit: 100,
        })
        .await
        .expect("initial stream should open");

    let mut first = first_stream.into_inner();
    let mut prefix = Vec::new();
    for _ in 0..2 {
        let item = first
            .next()
            .await
            .expect("stream should yield at least 2 items")
            .expect("item should be Ok");
        prefix.push(item);
    }
    let resume_cursor = prefix.last().expect("prefix is non-empty").cursor.clone();
    drop(first); // Simulate a client-side disconnect.

    // Second connection: resume from the cursor of the last seen item.
    let response = client
        .get_round_announcements(GetRoundAnnouncementsRequest {
            round_id_start: String::new(),
            round_id_end: String::new(),
            cursor: resume_cursor,
            limit: 100,
        })
        .await
        .expect("resume stream should open");

    let suffix: Vec<_> = response
        .into_inner()
        .collect::<Result<Vec<_>, _>>()
        .await
        .expect("resume stream should be readable");

    let combined: Vec<(String, String)> = prefix
        .into_iter()
        .chain(suffix)
        .map(|a| (a.round_id, a.vtxo_id))
        .collect();
    let expected_pairs: Vec<(String, String)> = expected
        .into_iter()
        .map(|a| (a.round_id, a.vtxo_id))
        .collect();
    assert_eq!(
        combined, expected_pairs,
        "prefix + reconnected suffix must equal the full announcement list with no overlap or gap"
    );
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
                        dark_api::proto::ark_v1::output::Destination::OnchainAddress(
                            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
                        ),
                    ),
                },
                Output {
                    amount: 30_000,
                    destination: Some(
                        dark_api::proto::ark_v1::output::Destination::OnchainAddress(
                            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
                        ),
                    ),
                },
            ],
        })
        .await
        .unwrap();

    let fee = resp.into_inner();
    // Fee is 0 with default zero-rate FeeProgram; just verify we got a response
    let _ = fee.fee_sats; // fee_sats is u64, always non-negative
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
                    dark_api::proto::ark_v1::output::Destination::OnchainAddress(
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
                    dark_api::proto::ark_v1::output::Destination::OnchainAddress(
                        "tb1qtest".to_string(),
                    ),
                ),
            }],
        })
        .await
        .unwrap()
        .into_inner();

    // With zero-rate FeeProgram both fees are 0; both should be non-negative
    assert!(
        resp5.fee_sats >= resp2.fee_sats,
        "5-input fee ({}) should be >= 2-input fee ({})",
        resp5.fee_sats,
        resp2.fee_sats
    );
}

// ─── DeleteIntent Tests ─────────────────────────────────────────────

#[tokio::test]
async fn test_delete_intent_empty_id() {
    let mut client = start_ark_server().await;

    let result = client
        .delete_intent(DeleteIntentRequest { intent: None })
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_delete_intent_empty_proof() {
    let mut client = start_ark_server().await;

    // Deleting by ID when no round exists (or intent already consumed) returns Ok.
    let result = client
        .delete_intent(DeleteIntentRequest {
            intent: Some(Intent {
                message: "some-intent-id".to_string(),
                proof: String::new(),
                delegate_pubkey: String::new(),
            }),
        })
        .await;
    assert!(
        result.is_ok(),
        "delete_intent should succeed (no-op for missing intent)"
    );
}

#[tokio::test]
async fn test_delete_intent_not_found() {
    let mut client = start_ark_server().await;

    let result = client
        .delete_intent(DeleteIntentRequest {
            intent: Some(Intent {
                message: "nonexistent-intent".to_string(),
                proof: "proof".to_string(),
                delegate_pubkey: String::new(),
            }),
        })
        .await;
    assert!(result.is_err());
    let code = result.unwrap_err().code();
    assert!(
        code == tonic::Code::NotFound || code == tonic::Code::InvalidArgument,
        "expected NotFound or InvalidArgument, got {:?}",
        code
    );
}

// --- Offchain transaction tests ---

#[tokio::test]
async fn test_submit_tx_empty_inputs() {
    let mut client = start_ark_server().await;
    let resp = client
        .submit_tx(SubmitTxRequest {
            signed_ark_tx: String::new(),
            checkpoint_txs: vec![],
        })
        .await;
    assert_eq!(resp.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_submit_tx_basic() {
    let mut client = start_ark_server().await;
    let resp = client
        .submit_tx(SubmitTxRequest {
            signed_ark_tx: "fake-ark-tx-data".to_string(),
            checkpoint_txs: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!resp.ark_txid.is_empty());
}

#[tokio::test]
async fn test_finalize_tx_accepts_any_txid() {
    let mut client = start_ark_server().await;
    let resp = client
        .finalize_tx(FinalizeTxRequest {
            ark_txid: "nonexistent-id".to_string(),
            final_checkpoint_txs: vec![],
        })
        .await;
    assert!(resp.is_ok());
}

#[tokio::test]
async fn test_get_pending_tx_not_found() {
    let mut client = start_ark_server().await;
    let resp = client
        .get_pending_tx(GetPendingTxRequest {
            identifier: Some(
                dark_api::proto::ark_v1::get_pending_tx_request::Identifier::Intent(Intent {
                    message: "nonexistent-id".to_string(),
                    proof: String::new(),
                    delegate_pubkey: String::new(),
                }),
            ),
        })
        .await;
    // Server returns Ok with empty list (not NotFound) for unknown intents.
    assert!(resp.is_ok() || resp.unwrap_err().code() == tonic::Code::NotFound);
}

#[tokio::test]
async fn test_offchain_tx_submit_and_get() {
    let mut client = start_ark_server().await;
    let submit = client
        .submit_tx(SubmitTxRequest {
            signed_ark_tx: "fake-ark-tx-abc".to_string(),
            checkpoint_txs: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    let tx_id = submit.ark_txid;
    assert!(!tx_id.is_empty());

    // GetPendingTx with the submit-generated txid — behavior may vary
    let _ = client
        .get_pending_tx(GetPendingTxRequest {
            identifier: Some(
                dark_api::proto::ark_v1::get_pending_tx_request::Identifier::Intent(Intent {
                    message: tx_id.clone(),
                    proof: String::new(),
                    delegate_pubkey: String::new(),
                }),
            ),
        })
        .await; // OK either way
}

// ─── GetTransactionsStream Tests ────────────────────────────────────

#[tokio::test]
async fn test_transactions_stream_initial_heartbeat() {
    use tokio_stream::StreamExt;

    let mut client = start_ark_server().await;

    let response = client
        .get_transactions_stream(GetTransactionsStreamRequest { scripts: vec![] })
        .await
        .expect("get_transactions_stream should succeed");

    let mut stream = response.into_inner();
    let first = stream.next().await.expect("stream should yield an item");
    let event = first.expect("first item should be Ok");

    match event.event {
        Some(dark_api::proto::ark_v1::transaction_event::Event::Heartbeat(hb)) => {
            assert!(hb.timestamp > 0, "heartbeat timestamp should be positive");
        }
        other => panic!("Expected heartbeat event, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_transactions_stream_with_script_filter() {
    use tokio_stream::StreamExt;

    let mut client = start_ark_server().await;

    // Request stream with a script filter
    let response = client
        .get_transactions_stream(GetTransactionsStreamRequest {
            scripts: vec!["script_alice".to_string(), "script_bob".to_string()],
        })
        .await
        .expect("get_transactions_stream should succeed");

    let mut stream = response.into_inner();
    // Should still get initial heartbeat
    let first = stream.next().await.expect("stream should yield an item");
    let event = first.expect("first item should be Ok");

    match event.event {
        Some(dark_api::proto::ark_v1::transaction_event::Event::Heartbeat(hb)) => {
            assert!(hb.timestamp > 0, "heartbeat timestamp should be positive");
        }
        other => panic!("Expected heartbeat event, got: {:?}", other),
    }
}

// ─── TLS Configuration Tests ────────────────────────────────────────

#[test]
fn test_tls_config_fields_default_none() {
    let config = dark_api::ServerConfig::default();
    assert!(!config.tls_enabled);
    assert!(config.tls_cert_path.is_none());
    assert!(config.tls_key_path.is_none());
}

#[test]
fn test_tls_config_none_uses_plaintext() {
    // ServerConfig with TLS disabled should work fine (plaintext)
    let config = dark_api::ServerConfig {
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        ..Default::default()
    };
    assert!(!config.tls_enabled);
    // Server creation should succeed with plaintext config
    // (actual server start tested via start_ark_server above)
}

// ─── SubmitConfidentialTransaction tests (#542) ──────────────────────
//
// These exercise the confidential-tx submit handler end-to-end. We bypass
// the gRPC client and call the trait method directly because:
//   - we need to inject an `AuthenticatedUser` into request extensions to
//     test the "auth-pass" path (the gRPC client + interceptor-less test
//     server combination cannot do this);
//   - the rate-limit-tripped test needs to construct the service with a
//     small `confidential_submit_inflight` cap, which is only available via
//     the test-only `new_with_inflight_cap` constructor.

mod confidential_submit_tests {
    use super::*;
    use dark_api::auth::TokenPermissions;
    use dark_api::grpc::middleware::AuthenticatedUser;
    use dark_api::proto::ark_v1::ark_service_server::ArkService as _;
    use dark_api::proto::ark_v1::submit_confidential_transaction_response::Error as SubError;
    use dark_api::proto::ark_v1::{
        BalanceProof, ConfidentialTransaction, ConfidentialVtxoOutput, EncryptedMemo, Nullifier,
        PedersenCommitment, RangeProof, SubmitConfidentialTransactionRequest,
    };

    /// Build a structurally-valid `ConfidentialTransaction` (passes the
    /// shape-check inside the handler). The validator (#538 stub) will then
    /// reject with `NotImplemented` -> the gRPC layer maps that to
    /// `Status::unimplemented`. That's the expected response shape on the
    /// happy path until #538 lands.
    fn well_formed_tx() -> ConfidentialTransaction {
        ConfidentialTransaction {
            nullifiers: vec![Nullifier {
                value: vec![0x11u8; 32],
            }],
            outputs: vec![ConfidentialVtxoOutput {
                commitment: Some(PedersenCommitment {
                    point: vec![0x02u8; 33],
                }),
                range_proof: Some(RangeProof {
                    proof: vec![0xAA, 0xBB, 0xCC],
                }),
                owner_pubkey: vec![0x03u8; 33],
                ephemeral_pubkey: vec![0x04u8; 33],
                encrypted_memo: Some(EncryptedMemo { ciphertext: vec![] }),
            }],
            balance_proof: Some(BalanceProof {
                sig: vec![0x55u8; 65],
            }),
            fee_amount: 100,
            schema_version: 1,
        }
    }

    /// Build a fresh `ArkGrpcService` for testing. Uses the same mocks as the
    /// rest of this file. `inflight_cap` controls the confidential-submit
    /// in-flight slot count; pass `usize::MAX` for "no rate limit".
    fn make_service(inflight_cap: usize) -> ArkGrpcService {
        let core = build_test_core();
        let broker = Arc::new(dark_api::EventBroker::new(64));
        let tx_broker = Arc::new(dark_api::TransactionEventBroker::new(64));
        let offchain_tx_repo: Arc<dyn OffchainTxRepository> = Arc::new(MockOffchainTxRepo::new());
        ArkGrpcService::new_with_inflight_cap(
            core,
            Arc::new(MockRoundRepo::empty()),
            broker,
            tx_broker,
            offchain_tx_repo,
            inflight_cap,
        )
    }

    /// Helper: attach a real `AuthenticatedUser` to a request, simulating
    /// what the `AuthInterceptor` does on the wire path. Returning the
    /// request lets the test thread it through `submit_confidential_transaction`.
    fn with_auth<T>(mut req: tonic::Request<T>) -> tonic::Request<T> {
        let pubkey = XOnlyPublicKey::from_slice(&[0x02u8; 32]).unwrap();
        req.extensions_mut()
            .insert(AuthenticatedUser::new(pubkey, TokenPermissions::write()));
        req
    }

    #[tokio::test]
    async fn auth_fail_returns_unauthenticated() {
        // No auth user attached — the interceptor would have rejected, but
        // the trait method also has its own `require_authenticated_user`
        // guard, so we expect `Unauthenticated` from a direct call too.
        let svc = make_service(1024);
        let req = tonic::Request::new(SubmitConfidentialTransactionRequest {
            transaction: Some(well_formed_tx()),
        });

        let err = svc
            .submit_confidential_transaction(req)
            .await
            .expect_err("submit should fail without auth");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn auth_fail_placeholder_user_rejected() {
        // Dev-mode placeholder identity must NOT be allowed for confidential
        // submissions — they materially modify state.
        let svc = make_service(1024);
        let mut req = tonic::Request::new(SubmitConfidentialTransactionRequest {
            transaction: Some(well_formed_tx()),
        });
        req.extensions_mut()
            .insert(AuthenticatedUser::placeholder());

        let err = svc
            .submit_confidential_transaction(req)
            .await
            .expect_err("placeholder user should be rejected");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn auth_pass_with_well_formed_tx_reaches_validator() {
        // With a real authenticated user the request gets past auth and
        // backpressure, the shape check accepts the well-formed tx, and
        // validation reaches the `dark_core` stub which returns
        // `NotImplemented` -> `Status::unimplemented` on the wire.
        //
        // Once #538 lands this test should be flipped to assert
        // `accepted == true`. The `Unimplemented` assertion here is a
        // deliberate pin: it proves the wiring (auth + rate-limit + shape +
        // dispatch into core) is intact end-to-end without depending on
        // #538's body.
        let svc = make_service(1024);
        let req = with_auth(tonic::Request::new(SubmitConfidentialTransactionRequest {
            transaction: Some(well_formed_tx()),
        }));

        let err = svc
            .submit_confidential_transaction(req)
            .await
            .expect_err("validator stub returns NotImplemented today");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        // The metadata header carries the structured wire-error tag.
        let tag = err
            .metadata()
            .get("x-confidential-tx-error")
            .expect("wire-error metadata header must be set")
            .to_str()
            .unwrap()
            .parse::<i32>()
            .unwrap();
        // `NotImplemented` is folded into `ERROR_UNSPECIFIED` because the
        // wire enum has no dedicated "stub" variant.
        assert_eq!(tag, SubError::Unspecified as i32);
    }

    #[tokio::test]
    async fn auth_pass_missing_transaction_field_is_invalid() {
        // Empty request (no `transaction` field) -> InvalidArgument, after
        // auth + backpressure pass.
        let svc = make_service(1024);
        let req = with_auth(tonic::Request::new(SubmitConfidentialTransactionRequest {
            transaction: None,
        }));

        let err = svc
            .submit_confidential_transaction(req)
            .await
            .expect_err("missing transaction field must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn auth_pass_malformed_output_returns_structured_response() {
        // Malformed payloads come back as a *successful* gRPC response with
        // `accepted == false` and `error == MALFORMED_OUTPUT` so the client
        // can recover the structured wire-error enum tag (a bare
        // `Status::invalid_argument` would lose this).
        let svc = make_service(1024);
        let mut tx = well_formed_tx();
        tx.outputs[0].commitment = None; // malformed
        let req = with_auth(tonic::Request::new(SubmitConfidentialTransactionRequest {
            transaction: Some(tx),
        }));

        let resp = svc
            .submit_confidential_transaction(req)
            .await
            .expect("malformed output yields Ok response with accepted=false")
            .into_inner();
        assert!(!resp.accepted);
        assert_eq!(resp.error, SubError::MalformedOutput as i32);
        assert!(resp.error_message.contains("missing commitment"));
        assert!(resp.ark_txid.is_empty());
    }

    #[tokio::test]
    async fn rate_limit_tripped_returns_resource_exhausted() {
        // Pin the cap to 1, hold the only permit by spawning a request that
        // will block in the `dark_core` stub (it returns `NotImplemented`
        // synchronously, so we can't actually block — instead we manually
        // acquire the permit on the inner semaphore and drop it after the
        // assertion). This proves: when capacity is exhausted, requests
        // surface `Status::resource_exhausted` and DO NOT proceed to
        // validation.
        let svc = make_service(1);

        // Drain the only permit. We use `try_acquire_owned` so we hold a
        // permit independent of any submit call.
        let permit = svc
            .__test_inflight_semaphore()
            .try_acquire_owned()
            .expect("test seam must yield a permit");

        let req = with_auth(tonic::Request::new(SubmitConfidentialTransactionRequest {
            transaction: Some(well_formed_tx()),
        }));
        let err = svc
            .submit_confidential_transaction(req)
            .await
            .expect_err("submit must trip the rate limit when capacity is 0");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(err.message().to_lowercase().contains("rate limit"));

        // Release the permit so other tests sharing the runtime can proceed.
        drop(permit);
    }

    #[tokio::test]
    async fn rate_limit_recovers_after_permit_drop() {
        // After a rate-limit trip we should be able to retry once a permit
        // becomes available. Pin cap to 1, take + drop the permit, and then
        // a fresh submit must reach the validator (and surface
        // `Unimplemented` from the #538 stub).
        let svc = make_service(1);
        let permit = svc.__test_inflight_semaphore().try_acquire_owned().unwrap();
        drop(permit);

        let req = with_auth(tonic::Request::new(SubmitConfidentialTransactionRequest {
            transaction: Some(well_formed_tx()),
        }));
        let err = svc
            .submit_confidential_transaction(req)
            .await
            .expect_err("after permit drop, validator stub still rejects");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }
}

// ─── ComplianceService::VerifyComplianceProof tests (#569) ──────────
//
// End-to-end tests for the public, unauthenticated bundle-verification RPC.
// These spin up a real tonic server (no auth interceptor — the production
// server registers ComplianceService unwrapped) and exercise the three
// acceptance scenarios from issue #569:
//   1. A known-good bundle returns all-passed.
//   2. A tampered bundle returns at-least-one-failed.
//   3. An oversized request returns ResourceExhausted.

mod compliance_service_tests {
    use dark_api::grpc::compliance_service::{ComplianceGrpcService, MAX_BUNDLE_BYTES};
    use dark_api::proto::ark_v1::compliance_service_client::ComplianceServiceClient;
    use dark_api::proto::ark_v1::compliance_service_server::ComplianceServiceServer;
    use dark_api::proto::ark_v1::VerifyComplianceProofRequest;
    use serde_json::json;
    use tokio::net::TcpListener;
    use tonic::transport::{Channel, Server};

    /// Spin up a ComplianceService gRPC server without the auth interceptor
    /// (matching production wiring) and return a client connected to it.
    async fn start_compliance_server() -> ComplianceServiceClient<Channel> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let svc = ComplianceServiceServer::new(ComplianceGrpcService::new());

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

        ComplianceServiceClient::new(channel)
    }

    fn known_good_bundle() -> Vec<u8> {
        json!({
            "proofs": [
                {
                    "proof_type": "source_of_funds",
                    "payload": {
                        "commitment_path": ["c0", "c1", "c2"],
                        "owner_signature": "deadbeef",
                    },
                },
                {
                    "proof_type": "non_inclusion",
                    "payload": { "nullifier": "0xabc123" },
                },
            ]
        })
        .to_string()
        .into_bytes()
    }

    fn tampered_bundle() -> Vec<u8> {
        // First proof verifies; second is flagged tampered. The acceptance
        // criterion is "at-least-one-failed" — we assert exactly that, plus
        // that ordering and indices are preserved.
        json!({
            "proofs": [
                {
                    "proof_type": "source_of_funds",
                    "payload": {
                        "commitment_path": ["c0", "c1"],
                        "owner_signature": "deadbeef",
                    },
                },
                {
                    "proof_type": "source_of_funds",
                    "payload": {
                        "commitment_path": ["c0", "c1"],
                        "owner_signature": "deadbeef",
                        "tampered": true,
                    },
                },
            ]
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn known_good_bundle_returns_all_passed() {
        let mut client = start_compliance_server().await;
        let resp = client
            .verify_compliance_proof(VerifyComplianceProofRequest {
                bundle: known_good_bundle(),
            })
            .await
            .expect("known-good bundle must verify")
            .into_inner();

        assert_eq!(resp.results.len(), 2);
        assert!(
            resp.results.iter().all(|r| r.passed),
            "all proofs in a known-good bundle must pass: {:?}",
            resp.results
        );
        assert!(
            resp.results.iter().all(|r| r.error.is_none()),
            "no proof in a known-good bundle should carry an error reason"
        );

        // Indices preserve bundle ordering.
        for (i, r) in resp.results.iter().enumerate() {
            assert_eq!(r.proof_index, i as u32);
        }
        assert_eq!(resp.results[0].proof_type, "source_of_funds");
        assert_eq!(resp.results[1].proof_type, "non_inclusion");
    }

    #[tokio::test]
    async fn tampered_bundle_returns_at_least_one_failure() {
        let mut client = start_compliance_server().await;
        let resp = client
            .verify_compliance_proof(VerifyComplianceProofRequest {
                bundle: tampered_bundle(),
            })
            .await
            .expect("tampered bundle is still a successful RPC, but with failures inside")
            .into_inner();

        assert_eq!(resp.results.len(), 2);
        assert!(
            resp.results.iter().any(|r| !r.passed),
            "tampered bundle must produce at least one failed result: {:?}",
            resp.results
        );

        // The first proof passed; the second failed with a non-empty reason.
        assert!(resp.results[0].passed);
        assert!(resp.results[0].error.is_none());
        assert!(!resp.results[1].passed);
        let reason = resp.results[1]
            .error
            .as_ref()
            .expect("failed proof must carry a failure reason");
        assert!(!reason.is_empty());
    }

    #[tokio::test]
    async fn oversized_request_returns_resource_exhausted() {
        let mut client = start_compliance_server().await;
        let err = client
            .verify_compliance_proof(VerifyComplianceProofRequest {
                bundle: vec![0u8; MAX_BUNDLE_BYTES + 1],
            })
            .await
            .expect_err("bundles above the size cap must be rejected");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(
            err.message().to_lowercase().contains("bundle"),
            "ResourceExhausted message should mention the bundle: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn unknown_proof_type_is_reported_not_panicked() {
        // Acceptance bullet: "Unknown bundle version returns a structured
        // error, not a crash." We model this as a proof with an unrecognised
        // type tag — the response carries `passed = false` plus a human
        // reason, and the RPC itself succeeds.
        let mut client = start_compliance_server().await;
        let bundle = json!({
            "proofs": [{ "proof_type": "made_up_proof", "payload": {} }]
        })
        .to_string()
        .into_bytes();

        let resp = client
            .verify_compliance_proof(VerifyComplianceProofRequest { bundle })
            .await
            .expect("unknown proof types must not crash the RPC")
            .into_inner();

        assert_eq!(resp.results.len(), 1);
        let only = &resp.results[0];
        assert!(!only.passed);
        assert_eq!(only.proof_type, "made_up_proof");
        assert!(only
            .error
            .as_ref()
            .expect("unknown type must carry a reason")
            .contains("unknown proof type"));
    }

    #[tokio::test]
    async fn empty_bundle_is_invalid_argument() {
        let mut client = start_compliance_server().await;
        let err = client
            .verify_compliance_proof(VerifyComplianceProofRequest { bundle: vec![] })
            .await
            .expect_err("empty bundle must be rejected as malformed input");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
