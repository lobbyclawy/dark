//! gRPC WalletService implementation backed by dark-wallet and AES-256 seed encryption.

use std::path::PathBuf;
use std::sync::Arc;

use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
use bdk_wallet::keys::GeneratableKey;
use bdk_wallet::miniscript::Tap;
use bitcoin::Network;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::info;

use dark_wallet::{WalletConfig, WalletManager};

use crate::encryption;
use crate::proto::wallet_service_server::WalletService;
use crate::proto::*;

/// Wallet states.
enum WalletState {
    /// No seed on disk yet.
    Uninitialized,
    /// Seed encrypted on disk but wallet locked.
    Locked,
    /// Wallet is unlocked and ready.
    Unlocked {
        manager: Arc<WalletManager>,
        #[allow(dead_code)]
        mnemonic: String,
    },
}

/// gRPC wallet service implementation.
pub struct WalletGrpcService {
    state: Arc<RwLock<WalletState>>,
    data_dir: PathBuf,
    network: Network,
    esplora_url: String,
}

impl WalletGrpcService {
    pub fn new(data_dir: PathBuf, network: Network, esplora_url: String) -> Self {
        // Check if encrypted seed exists on disk.
        let seed_path = data_dir.join("seed.enc");
        let initial_state = if seed_path.exists() {
            WalletState::Locked
        } else {
            WalletState::Uninitialized
        };

        Self {
            state: Arc::new(RwLock::new(initial_state)),
            data_dir,
            network,
            esplora_url,
        }
    }

    fn seed_path(&self) -> PathBuf {
        self.data_dir.join("seed.enc")
    }

    fn db_path(&self) -> String {
        self.data_dir
            .join("wallet.db")
            .to_string_lossy()
            .to_string()
    }

    /// Build a WalletConfig from the current settings and a mnemonic.
    fn build_config(&self, mnemonic: &str) -> WalletConfig {
        WalletConfig {
            network: self.network,
            esplora_url: Some(self.esplora_url.clone()),
            database_path: self.db_path(),
            external_descriptor: None,
            internal_descriptor: None,
            mnemonic: Some(mnemonic.to_string()),
            gap_limit: 20,
            min_confirmations: 1,
            stop_gap: 50,
            parallel_requests: 5,
        }
    }

    /// Get a reference to the unlocked wallet manager, or return FAILED_PRECONDITION.
    async fn require_unlocked(&self) -> Result<Arc<WalletManager>, Status> {
        let state = self.state.read().await;
        match &*state {
            WalletState::Unlocked { manager, .. } => Ok(Arc::clone(manager)),
            WalletState::Locked => Err(Status::failed_precondition("wallet is locked")),
            WalletState::Uninitialized => {
                Err(Status::failed_precondition("wallet is not initialized"))
            }
        }
    }
}

#[tonic::async_trait]
impl WalletService for WalletGrpcService {
    async fn gen_seed(
        &self,
        _request: Request<GenSeedRequest>,
    ) -> Result<Response<GenSeedResponse>, Status> {
        use bdk_wallet::keys::GeneratedKey;
        let generated: GeneratedKey<Mnemonic, Tap> =
            Mnemonic::generate((WordCount::Words24, Language::English))
                .map_err(|e| Status::internal(format!("failed to generate mnemonic: {e:?}")))?;
        let mnemonic = generated.into_key();
        Ok(Response::new(GenSeedResponse {
            seed_phrase: mnemonic.to_string(),
        }))
    }

    async fn create(
        &self,
        request: Request<CreateRequest>,
    ) -> Result<Response<CreateResponse>, Status> {
        let req = request.into_inner();
        if req.seed_phrase.is_empty() {
            return Err(Status::invalid_argument("seed_phrase is required"));
        }
        if req.password.is_empty() {
            return Err(Status::invalid_argument("password is required"));
        }

        let mut state = self.state.write().await;
        if matches!(&*state, WalletState::Locked | WalletState::Unlocked { .. }) {
            return Err(Status::already_exists("wallet already initialized"));
        }

        // Ensure data directory exists.
        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| Status::internal(format!("failed to create data dir: {e}")))?;

        // Encrypt and save seed.
        let encrypted = encryption::encrypt_seed(&req.seed_phrase, &req.password)
            .map_err(|e| Status::internal(format!("encryption failed: {e}")))?;
        encryption::save_encrypted_seed(&self.seed_path(), &encrypted)
            .map_err(|e| Status::internal(format!("failed to save seed: {e}")))?;

        // Initialize wallet.
        let config = self.build_config(&req.seed_phrase);
        let manager = WalletManager::new(config)
            .await
            .map_err(|e| Status::internal(format!("wallet init failed: {e}")))?;

        info!("Wallet created and unlocked");
        *state = WalletState::Unlocked {
            manager: Arc::new(manager),
            mnemonic: req.seed_phrase,
        };

        Ok(Response::new(CreateResponse {}))
    }

    async fn restore(
        &self,
        request: Request<RestoreRequest>,
    ) -> Result<Response<RestoreResponse>, Status> {
        let req = request.into_inner();
        if req.seed_phrase.is_empty() {
            return Err(Status::invalid_argument("seed_phrase is required"));
        }
        if req.password.is_empty() {
            return Err(Status::invalid_argument("password is required"));
        }

        let mut state = self.state.write().await;
        if matches!(&*state, WalletState::Locked | WalletState::Unlocked { .. }) {
            return Err(Status::already_exists("wallet already initialized"));
        }

        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| Status::internal(format!("failed to create data dir: {e}")))?;

        let encrypted = encryption::encrypt_seed(&req.seed_phrase, &req.password)
            .map_err(|e| Status::internal(format!("encryption failed: {e}")))?;
        encryption::save_encrypted_seed(&self.seed_path(), &encrypted)
            .map_err(|e| Status::internal(format!("failed to save seed: {e}")))?;

        let config = self.build_config(&req.seed_phrase);
        let manager = WalletManager::new(config)
            .await
            .map_err(|e| Status::internal(format!("wallet init failed: {e}")))?;

        // Sync to discover existing UTXOs.
        manager
            .sync()
            .await
            .map_err(|e| Status::internal(format!("wallet sync failed: {e}")))?;

        info!("Wallet restored and synced");
        *state = WalletState::Unlocked {
            manager: Arc::new(manager),
            mnemonic: req.seed_phrase,
        };

        Ok(Response::new(RestoreResponse {}))
    }

    async fn unlock(
        &self,
        request: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        let req = request.into_inner();
        if req.password.is_empty() {
            return Err(Status::invalid_argument("password is required"));
        }

        let mut state = self.state.write().await;
        match &*state {
            WalletState::Uninitialized => {
                return Err(Status::failed_precondition("wallet not initialized"));
            }
            WalletState::Unlocked { .. } => {
                return Err(Status::already_exists("wallet already unlocked"));
            }
            WalletState::Locked => {}
        }

        // Decrypt seed from disk.
        let encrypted = encryption::load_encrypted_seed(&self.seed_path())
            .map_err(|e| Status::internal(format!("failed to load seed: {e}")))?;
        let mnemonic = encryption::decrypt_seed(&encrypted, &req.password)
            .map_err(|_| Status::unauthenticated("wrong password"))?;

        let config = self.build_config(&mnemonic);
        let manager = WalletManager::new(config)
            .await
            .map_err(|e| Status::internal(format!("wallet init failed: {e}")))?;

        info!("Wallet unlocked");
        *state = WalletState::Unlocked {
            manager: Arc::new(manager),
            mnemonic,
        };

        Ok(Response::new(UnlockResponse {}))
    }

    async fn lock(&self, _request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        let mut state = self.state.write().await;
        match &*state {
            WalletState::Uninitialized => {
                return Err(Status::failed_precondition("wallet not initialized"));
            }
            WalletState::Locked => {
                return Err(Status::failed_precondition("wallet already locked"));
            }
            WalletState::Unlocked { .. } => {}
        }

        info!("Wallet locked");
        *state = WalletState::Locked;
        Ok(Response::new(LockResponse {}))
    }

    async fn get_status(
        &self,
        _request: Request<GetWalletStatusRequest>,
    ) -> Result<Response<GetWalletStatusResponse>, Status> {
        let state = self.state.read().await;
        let (initialized, unlocked, synced) = match &*state {
            WalletState::Uninitialized => (false, false, false),
            WalletState::Locked => (true, false, false),
            WalletState::Unlocked { .. } => (true, true, true),
        };

        Ok(Response::new(GetWalletStatusResponse {
            initialized,
            unlocked,
            synced,
        }))
    }

    async fn derive_address(
        &self,
        _request: Request<DeriveAddressRequest>,
    ) -> Result<Response<DeriveAddressResponse>, Status> {
        let manager = self.require_unlocked().await?;
        let address = manager
            .get_new_address()
            .await
            .map_err(|e| Status::internal(format!("address derivation failed: {e}")))?;

        Ok(Response::new(DeriveAddressResponse {
            address: address.to_string(),
            derivation_path: String::new(),
        }))
    }

    async fn get_balance(
        &self,
        _request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>, Status> {
        let manager = self.require_unlocked().await?;
        let balance = manager
            .get_balance()
            .await
            .map_err(|e| Status::internal(format!("balance query failed: {e}")))?;

        Ok(Response::new(GetBalanceResponse {
            main_account: Some(Balance {
                locked: balance.immature.to_sat().to_string(),
                available: balance.confirmed.to_sat().to_string(),
            }),
            connectors_account: Some(Balance {
                locked: "0".to_string(),
                available: "0".to_string(),
            }),
        }))
    }

    async fn withdraw(
        &self,
        _request: Request<WithdrawRequest>,
    ) -> Result<Response<WithdrawResponse>, Status> {
        // Withdraw is not yet implemented — the underlying WalletManager
        // doesn't expose a high-level "send to address" API.
        Err(Status::unimplemented(
            "withdraw not yet implemented in standalone wallet",
        ))
    }
}
