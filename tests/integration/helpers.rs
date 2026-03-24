//! Shared test helpers for integration tests.
//!
//! Provides in-memory mock implementations of ports for testing
//! `ArkService` without external dependencies.

use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;
use dark_core::domain::{Intent, Receiver, Vtxo, VtxoOutpoint};
use dark_core::error::ArkResult;
use dark_core::ports::*;
use dark_core::{ArkConfig, ArkService};
use secp256k1::{rand::rngs::OsRng, Secp256k1};
use std::str::FromStr;
use tokio::sync::RwLock;

// ─── Mock Wallet ────────────────────────────────────────────────────

/// Mock wallet service for testing
pub struct MockWallet {
    pub block_height: u64,
}

impl MockWallet {
    pub fn new() -> Self {
        Self {
            block_height: 800_000,
        }
    }

    #[allow(dead_code)]
    pub fn with_block_height(height: u64) -> Self {
        Self {
            block_height: height,
        }
    }
}

impl Default for MockWallet {
    fn default() -> Self {
        Self::new()
    }
}

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

    async fn sign_transaction(&self, ptx: &str, _extract: bool) -> ArkResult<String> {
        Ok(ptx.to_string())
    }

    async fn select_utxos(&self, _amount: u64, _confirmed: bool) -> ArkResult<(Vec<TxInput>, u64)> {
        Ok((vec![], 0))
    }

    async fn broadcast_transaction(&self, _txs: Vec<String>) -> ArkResult<String> {
        Ok("txid_broadcast".to_string())
    }

    async fn fee_rate(&self) -> ArkResult<u64> {
        Ok(1)
    }

    async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
        Ok(BlockTimestamp {
            height: self.block_height,
            timestamp: 1_700_000_000,
        })
    }

    async fn get_dust_amount(&self) -> ArkResult<u64> {
        Ok(546)
    }

    async fn get_outpoint_status(&self, _op: &VtxoOutpoint) -> ArkResult<bool> {
        Ok(false)
    }
}

// ─── Mock Signer ────────────────────────────────────────────────────

/// Mock signer service for testing
pub struct MockSigner;

#[async_trait]
impl SignerService for MockSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap())
    }

    async fn sign_transaction(&self, ptx: &str, _extract: bool) -> ArkResult<String> {
        Ok(ptx.to_string())
    }
}

// ─── In-Memory VTXO Repository ──────────────────────────────────────

/// In-memory VTXO repository for integration tests
pub struct InMemoryVtxoRepo {
    vtxos: RwLock<Vec<Vtxo>>,
}

impl InMemoryVtxoRepo {
    pub fn new() -> Self {
        Self {
            vtxos: RwLock::new(Vec::new()),
        }
    }

    /// Seed the repository with VTXOs (for test setup)
    pub async fn seed_vtxos(&self, vtxos: Vec<Vtxo>) {
        let mut store = self.vtxos.write().await;
        store.extend(vtxos);
    }
}

impl Default for InMemoryVtxoRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VtxoRepository for InMemoryVtxoRepo {
    async fn add_vtxos(&self, vtxos: &[Vtxo]) -> ArkResult<()> {
        let mut store = self.vtxos.write().await;
        for v in vtxos {
            // Upsert by outpoint
            if let Some(pos) = store.iter().position(|s| s.outpoint == v.outpoint) {
                store[pos] = v.clone();
            } else {
                store.push(v.clone());
            }
        }
        Ok(())
    }

    async fn get_vtxos(&self, outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
        let store = self.vtxos.read().await;
        Ok(store
            .iter()
            .filter(|v| outpoints.contains(&v.outpoint))
            .cloned()
            .collect())
    }

    async fn get_all_vtxos_for_pubkey(&self, pubkey: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
        let store = self.vtxos.read().await;
        let mut spendable = Vec::new();
        let mut spent = Vec::new();
        for v in store.iter().filter(|v| v.pubkey == pubkey) {
            if v.spent || v.swept {
                spent.push(v.clone());
            } else {
                spendable.push(v.clone());
            }
        }
        Ok((spendable, spent))
    }

    async fn spend_vtxos(&self, spent: &[(VtxoOutpoint, String)], ark_txid: &str) -> ArkResult<()> {
        let mut store = self.vtxos.write().await;
        for (op, spent_by) in spent {
            if let Some(v) = store.iter_mut().find(|v| v.outpoint == *op) {
                v.spent = true;
                v.spent_by = spent_by.clone();
                v.ark_txid = ark_txid.to_string();
            }
        }
        Ok(())
    }
}

// ─── Mock Transaction Builder ───────────────────────────────────────

/// Mock transaction builder for testing
pub struct MockTxBuilder;

#[async_trait]
impl TxBuilder for MockTxBuilder {
    async fn build_commitment_tx(
        &self,
        _signer: &XOnlyPublicKey,
        _intents: &[Intent],
        _boarding: &[BoardingInput],
    ) -> ArkResult<CommitmentTxResult> {
        Ok(CommitmentTxResult {
            commitment_tx: "commitment_tx_hex".to_string(),
            vtxo_tree: vec![],
            connector_address: "tb1q_connector".to_string(),
            connectors: vec![],
        })
    }

    async fn verify_forfeit_txs(
        &self,
        _vtxos: &[Vtxo],
        _connectors: &dark_core::domain::FlatTxTree,
        _txs: &[String],
    ) -> ArkResult<Vec<ValidForfeitTx>> {
        Ok(vec![])
    }

    async fn build_sweep_tx(
        &self,
        _inputs: &[dark_core::ports::SweepInput],
    ) -> ArkResult<(String, String)> {
        Ok(("mock_txid".into(), "mock_sweep_hex".into()))
    }

    async fn get_sweepable_batch_outputs(
        &self,
        _vtxo_tree: &dark_core::domain::FlatTxTree,
    ) -> ArkResult<Option<dark_core::ports::SweepableOutput>> {
        Ok(None)
    }

    async fn finalize_and_extract(&self, _tx: &str) -> ArkResult<String> {
        Ok("mock_raw_tx".into())
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

// ─── Mock Cache ─────────────────────────────────────────────────────

/// Mock cache service for testing
pub struct MockCache;

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

// ─── Mock Event Publisher ───────────────────────────────────────────

/// Mock event publisher for testing
pub struct MockEvents;

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

// ─── Service Builder ────────────────────────────────────────────────

/// Build an `ArkService` with the given VTXO repository and default mocks
pub fn build_service(vtxo_repo: Arc<InMemoryVtxoRepo>) -> ArkService {
    ArkService::new(
        Arc::new(MockWallet::new()),
        Arc::new(MockSigner),
        vtxo_repo,
        Arc::new(MockTxBuilder),
        Arc::new(MockCache),
        Arc::new(MockEvents),
        ArkConfig::default(),
    )
}

/// Build an `ArkService` with a custom wallet
#[allow(dead_code)]
pub fn build_service_with_wallet(
    vtxo_repo: Arc<InMemoryVtxoRepo>,
    wallet: Arc<MockWallet>,
) -> ArkService {
    ArkService::new(
        wallet,
        Arc::new(MockSigner),
        vtxo_repo,
        Arc::new(MockTxBuilder),
        Arc::new(MockCache),
        Arc::new(MockEvents),
        ArkConfig::default(),
    )
}

// ─── Test Fixtures ──────────────────────────────────────────────────

/// Generate a random XOnlyPublicKey for testing
pub fn test_xonly_pubkey() -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let (_, pk) = secp.generate_keypair(&mut OsRng);
    XOnlyPublicKey::from(pk)
}

/// Generate a test Bitcoin address (regtest)
pub fn test_address() -> bitcoin::Address<bitcoin::address::NetworkUnchecked> {
    bitcoin::Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap()
}

/// Create a test intent with the given ID and receivers
pub fn make_intent(id: &str, receivers: Vec<Receiver>) -> Intent {
    Intent {
        id: id.to_string(),
        inputs: vec![],
        receivers,
        proof: "proof".to_string(),
        message: "msg".to_string(),
        txid: "txid".to_string(),
        leaf_tx_asset_packet: String::new(),
        cosigners_public_keys: Vec::new(),
        delegate_pubkey: None,
    }
}

/// Create a test VTXO with the given parameters
pub fn make_vtxo(txid: &str, vout: u32, pubkey: &str, amount: u64) -> Vtxo {
    Vtxo::new(
        VtxoOutpoint::new(txid.to_string(), vout),
        amount,
        pubkey.to_string(),
    )
}
