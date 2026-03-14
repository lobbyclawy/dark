use std::sync::Arc;

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("arkd=info".parse()?)
                .add_directive("arkd_api=info".parse()?)
                .add_directive("arkd_core=info".parse()?),
        )
        .init();

    info!("Starting arkd-rs v{}", env!("CARGO_PKG_VERSION"));

    // --- Database ---
    let db = arkd_db::Database::connect_in_memory()
        .await
        .map_err(|e| anyhow::anyhow!("DB init failed: {e}"))?;
    info!("Database ready (SQLite in-memory)");

    let sqlite_pool = db
        .sqlite_pool()
        .map_err(|e| anyhow::anyhow!("Failed to get SQLite pool: {e}"))?
        .clone();

    let round_repo = Arc::new(arkd_db::repos::SqliteRoundRepository::new(
        sqlite_pool.clone(),
    ));
    let offchain_tx_repo = Arc::new(arkd_db::repos::SqliteOffchainTxRepository::new(sqlite_pool));

    // --- Core service (with stub impls for now) ---
    let core = Arc::new(arkd_core::ArkService::new(
        Arc::new(StubWallet),
        Arc::new(StubSigner),
        Arc::new(StubVtxoRepo),
        Arc::new(StubTxBuilder),
        Arc::new(StubCache),
        Arc::new(StubEvents),
        arkd_core::ArkConfig::default(),
    ));

    // --- API server ---
    let config = arkd_api::ServerConfig::default();
    info!(grpc = %config.grpc_addr, "Starting gRPC server");

    let server = arkd_api::Server::new(
        config,
        core,
        round_repo as Arc<dyn arkd_core::ports::RoundRepository>,
        offchain_tx_repo as Arc<dyn arkd_core::ports::OffchainTxRepository>,
        None,
    )?;

    server
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))?;

    Ok(())
}

// ─── Stub implementations ───────────────────────────────────────────
// These mirror the mock impls from grpc_integration.rs.
// They will be replaced by real implementations as features are wired.

use arkd_core::domain::{Vtxo, VtxoOutpoint};
use arkd_core::error::ArkResult;
use arkd_core::ports::*;
use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

struct StubWallet;
#[async_trait]
impl WalletService for StubWallet {
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

struct StubSigner;
#[async_trait]
impl SignerService for StubSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap())
    }
    async fn sign_transaction(&self, partial_tx: &str, _extract_raw: bool) -> ArkResult<String> {
        Ok(partial_tx.to_string())
    }
}

struct StubVtxoRepo;
#[async_trait]
impl VtxoRepository for StubVtxoRepo {
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

struct StubTxBuilder;
#[async_trait]
impl arkd_core::ports::TxBuilder for StubTxBuilder {
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

struct StubCache;
#[async_trait]
impl CacheService for StubCache {
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

struct StubEvents;
#[async_trait]
impl EventPublisher for StubEvents {
    async fn publish_event(&self, _event: ArkEvent) -> ArkResult<()> {
        Ok(())
    }
    async fn subscribe(&self) -> ArkResult<tokio::sync::broadcast::Receiver<ArkEvent>> {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        drop(tx);
        Ok(rx)
    }
}
