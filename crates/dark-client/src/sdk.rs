//! High-level Ark client SDK.
//!
//! Wraps the gRPC transport (`ArkClient`), wallet (`SingleKeyWallet`),
//! block explorer (`EsploraExplorer`), and local state store (`InMemoryStore`)
//! into a single ergonomic interface.
//!
//! Mirrors Go's `client-lib` top-level `ArkClient` which composes
//! wallet + explorer + indexer + store.

use bitcoin::Network;

use crate::client::ArkClient;
use crate::error::{ClientError, ClientResult};
use crate::explorer::EsploraExplorer;
use crate::store::{ClientConfig, InMemoryStore};
use crate::types::{Balance, BatchTxRes, BoardingAddress, OffchainAddress, Vtxo};
use crate::wallet::SingleKeyWallet;

/// High-level Ark SDK client that orchestrates wallet, transport, explorer,
/// and store into a cohesive API.
pub struct ArkSdk {
    /// The gRPC transport client.
    transport: ArkClient,
    /// The local wallet (keypair).
    wallet: SingleKeyWallet,
    /// The block explorer client.
    explorer: EsploraExplorer,
    /// Local state store.
    store: InMemoryStore,
    /// Whether `init()` has been called successfully.
    initialized: bool,
}

impl ArkSdk {
    /// Create a new SDK instance with all components.
    ///
    /// Does **not** connect to the server — call [`init`](Self::init) to connect
    /// and sync server metadata.
    pub fn new(
        server_url: impl Into<String>,
        wallet: SingleKeyWallet,
        esplora_url: impl Into<String>,
    ) -> Self {
        Self {
            transport: ArkClient::new(server_url),
            wallet,
            explorer: EsploraExplorer::new(esplora_url),
            store: InMemoryStore::new(),
            initialized: false,
        }
    }

    /// Create a new SDK with a freshly generated wallet.
    pub fn generate(
        server_url: impl Into<String>,
        esplora_url: impl Into<String>,
        network: Network,
    ) -> Self {
        Self::new(server_url, SingleKeyWallet::generate(network), esplora_url)
    }

    /// Create with a custom store (e.g. pre-loaded from disk).
    pub fn with_store(
        server_url: impl Into<String>,
        wallet: SingleKeyWallet,
        esplora_url: impl Into<String>,
        store: InMemoryStore,
    ) -> Self {
        Self {
            transport: ArkClient::new(server_url),
            wallet,
            explorer: EsploraExplorer::new(esplora_url),
            store,
            initialized: false,
        }
    }

    // ── Accessors ──────────────────────────────────────────────────

    /// Get a reference to the underlying transport client.
    pub fn transport(&self) -> &ArkClient {
        &self.transport
    }

    /// Get a mutable reference to the transport client.
    pub fn transport_mut(&mut self) -> &mut ArkClient {
        &mut self.transport
    }

    /// Get a reference to the wallet.
    pub fn wallet(&self) -> &SingleKeyWallet {
        &self.wallet
    }

    /// Get a reference to the explorer.
    pub fn explorer(&self) -> &EsploraExplorer {
        &self.explorer
    }

    /// Get a reference to the store.
    pub fn store(&self) -> &InMemoryStore {
        &self.store
    }

    /// Whether the SDK has been initialized (connected + synced).
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ── Lifecycle ──────────────────────────────────────────────────

    /// Initialize the SDK: connect to the server, fetch server info,
    /// and store the configuration locally.
    pub async fn init(&mut self) -> ClientResult<()> {
        // Connect gRPC transport
        self.transport.connect().await?;

        // Fetch server info and store config
        let info = self.transport.get_info().await?;
        self.store.set_config(ClientConfig {
            server_url: self.transport.server_url().to_string(),
            network: info.network.clone(),
            server_pubkey: info.pubkey.clone(),
            session_duration: info.session_duration,
            unilateral_exit_delay: info.unilateral_exit_delay,
            dust: info.dust,
        });

        self.initialized = true;
        Ok(())
    }

    fn require_init(&self) -> ClientResult<()> {
        if !self.initialized {
            return Err(ClientError::Wallet(
                "SDK not initialized — call init() first".into(),
            ));
        }
        Ok(())
    }

    // ── High-level operations ──────────────────────────────────────

    /// Get receive addresses (onchain, offchain, boarding) for this wallet.
    pub async fn receive(&mut self) -> ClientResult<(String, OffchainAddress, BoardingAddress)> {
        self.require_init()?;
        let pubkey = self.wallet.pubkey_hex();
        self.transport.receive(&pubkey).await
    }

    /// Send satoshis off-chain to `to_address`.
    ///
    /// **Note:** This is currently a stub — full implementation requires
    /// VTXO input selection and wallet-based PSBT signing.
    pub async fn send_offchain(
        &mut self,
        to_address: &str,
        amount: u64,
    ) -> ClientResult<crate::client::OffchainTxResult> {
        self.require_init()?;
        let pubkey = self.wallet.pubkey_hex();
        self.transport
            .send_offchain(&pubkey, to_address, amount)
            .await
    }

    /// Settle VTXOs in the next batch round (registration-only, no MuSig2 signing).
    pub async fn settle(&mut self, amount: u64) -> ClientResult<BatchTxRes> {
        self.require_init()?;
        let pubkey = self.wallet.pubkey_hex();
        self.transport.settle(&pubkey, amount).await
    }

    /// Full settlement with MuSig2 signing via the batch protocol.
    ///
    /// Runs the complete batch protocol: register intent, subscribe to events,
    /// MuSig2 tree signing, forfeit submission, and returns the real
    /// commitment txid from the finalized batch.
    pub async fn settle_full(&mut self, amount: u64) -> ClientResult<BatchTxRes> {
        self.require_init()?;
        let pubkey = self.wallet.pubkey_hex();
        let secret_key = *self.wallet.secret_key();
        self.transport
            .settle_with_key(&pubkey, amount, &secret_key)
            .await
    }

    /// List VTXOs for this wallet's pubkey and cache them in the store.
    pub async fn list_vtxos(&mut self) -> ClientResult<Vec<Vtxo>> {
        self.require_init()?;
        let pubkey = self.wallet.pubkey_hex();
        let vtxos = self.transport.list_vtxos(&pubkey).await?;
        // Cache in local store
        self.store.upsert_vtxos(vtxos.clone());
        Ok(vtxos)
    }

    /// Get the combined balance for this wallet's pubkey.
    pub async fn balance(&mut self) -> ClientResult<Balance> {
        self.require_init()?;
        let pubkey = self.wallet.pubkey_hex();
        self.transport.get_balance(&pubkey).await
    }

    /// Redeem bearer notes and receive VTXOs.
    pub async fn redeem_notes(&mut self, notes: Vec<String>) -> ClientResult<String> {
        self.require_init()?;
        self.transport.redeem_notes(notes).await
    }

    /// Collaborative exit: move funds from off-chain VTXOs to an on-chain address.
    pub async fn collaborative_exit(
        &mut self,
        onchain_address: &str,
        amount: u64,
    ) -> ClientResult<String> {
        self.require_init()?;
        // Select spendable VTXOs from the store
        let spendable = self.store.list_spendable_vtxos();
        let vtxo_ids: Vec<String> = spendable.iter().map(|v| v.id.clone()).collect();

        if vtxo_ids.is_empty() {
            return Err(ClientError::Wallet(
                "No spendable VTXOs available for exit".into(),
            ));
        }

        self.transport
            .collaborative_exit(onchain_address, amount, vtxo_ids)
            .await
    }

    /// Get UTXOs for an address via the block explorer.
    pub async fn get_onchain_utxos(
        &self,
        address: &str,
    ) -> ClientResult<Vec<crate::explorer::Utxo>> {
        self.explorer.get_utxos(address).await
    }

    /// Get the current block tip height via the explorer.
    pub async fn get_tip_height(&self) -> ClientResult<u64> {
        self.explorer.get_tip_height().await
    }

    /// Broadcast a raw transaction via the explorer.
    pub async fn broadcast_tx(&self, tx_hex: &str) -> ClientResult<String> {
        self.explorer.broadcast_tx(tx_hex).await
    }

    /// Export the store state as JSON for file-based persistence.
    pub fn export_state(&self) -> ClientResult<String> {
        self.store
            .to_json()
            .map_err(|e| ClientError::Serialization(format!("Failed to export state: {e}")))
    }

    /// Import store state from a JSON string.
    pub fn import_state(&mut self, json: &str) -> ClientResult<()> {
        let restored = InMemoryStore::from_json(json)
            .map_err(|e| ClientError::Serialization(format!("Failed to import state: {e}")))?;
        self.store = restored;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_new() {
        let sdk = ArkSdk::generate(
            "http://localhost:50051",
            "http://localhost:3000",
            Network::Regtest,
        );
        assert!(!sdk.is_initialized());
        assert!(!sdk.wallet().pubkey_hex().is_empty());
    }

    #[test]
    fn test_sdk_with_store() {
        let store = InMemoryStore::new();
        store.set_metadata("test", "value");

        let wallet = SingleKeyWallet::generate(Network::Regtest);
        let sdk = ArkSdk::with_store(
            "http://localhost:50051",
            wallet,
            "http://localhost:3000",
            store,
        );

        assert_eq!(sdk.store().get_metadata("test").unwrap(), "value");
    }

    #[tokio::test]
    async fn test_sdk_requires_init() {
        let mut sdk = ArkSdk::generate(
            "http://localhost:50051",
            "http://localhost:3000",
            Network::Regtest,
        );

        // All high-level ops should fail before init
        assert!(sdk.balance().await.is_err());
        assert!(sdk.list_vtxos().await.is_err());
        assert!(sdk.receive().await.is_err());
        assert!(sdk.settle(1000).await.is_err());
        assert!(sdk.redeem_notes(vec![]).await.is_err());
    }

    #[test]
    fn test_sdk_export_import_state() {
        let sdk = ArkSdk::generate(
            "http://localhost:50051",
            "http://localhost:3000",
            Network::Regtest,
        );
        sdk.store().set_metadata("hello", "world");

        let json = sdk.export_state().unwrap();
        assert!(json.contains("hello"));

        let mut sdk2 = ArkSdk::generate(
            "http://localhost:50051",
            "http://localhost:3000",
            Network::Regtest,
        );
        sdk2.import_state(&json).unwrap();
        assert_eq!(sdk2.store().get_metadata("hello").unwrap(), "world");
    }
}
