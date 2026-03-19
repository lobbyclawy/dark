//! WalletService gRPC implementation — operator wallet management API.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::info;

use arkd_core::ports::WalletService;

use crate::proto::ark_v1::wallet_service_server::WalletService as WalletServiceTrait;
use crate::proto::ark_v1::{
    Balance, CreateRequest, CreateResponse, DeriveAddressRequest, DeriveAddressResponse,
    GenSeedRequest, GenSeedResponse, GetBalanceRequest, GetBalanceResponse, GetWalletStatusRequest,
    GetWalletStatusResponse, LockRequest, LockResponse, RestoreRequest, RestoreResponse,
    UnlockRequest, UnlockResponse, WithdrawRequest, WithdrawResponse,
};

/// WalletService gRPC handler backed by a [`WalletService`] port.
///
/// Provides operators with wallet management RPCs (seed generation,
/// create/restore, lock/unlock, balance queries, and withdrawals),
/// wired to the real BDK wallet implementation.
pub struct WalletGrpcService {
    wallet: Arc<dyn WalletService>,
}

impl WalletGrpcService {
    /// Create a new WalletGrpcService backed by the given wallet port.
    pub fn new(wallet: Arc<dyn WalletService>) -> Self {
        Self { wallet }
    }
}

/// Map an `ArkError` into a gRPC `Status`.
fn ark_err_to_status(e: arkd_core::error::ArkError) -> Status {
    Status::internal(e.to_string())
}

#[tonic::async_trait]
impl WalletServiceTrait for WalletGrpcService {
    async fn gen_seed(
        &self,
        _request: Request<GenSeedRequest>,
    ) -> Result<Response<GenSeedResponse>, Status> {
        info!("WalletService::GenSeed called");

        let seed_phrase = self.wallet.gen_seed().await.map_err(ark_err_to_status)?;
        Ok(Response::new(GenSeedResponse { seed_phrase }))
    }

    async fn create(
        &self,
        request: Request<CreateRequest>,
    ) -> Result<Response<CreateResponse>, Status> {
        let req = request.into_inner();
        info!("WalletService::Create called");

        if req.seed_phrase.is_empty() {
            return Err(Status::invalid_argument("seed_phrase is required"));
        }
        if req.password.is_empty() {
            return Err(Status::invalid_argument("password is required"));
        }

        self.wallet
            .create_wallet(&req.seed_phrase, &req.password)
            .await
            .map_err(ark_err_to_status)?;

        Ok(Response::new(CreateResponse {}))
    }

    async fn restore(
        &self,
        request: Request<RestoreRequest>,
    ) -> Result<Response<RestoreResponse>, Status> {
        let req = request.into_inner();
        info!(gap_limit = req.gap_limit, "WalletService::Restore called");

        if req.seed_phrase.is_empty() {
            return Err(Status::invalid_argument("seed_phrase is required"));
        }

        let password = if req.password.is_empty() {
            ""
        } else {
            &req.password
        };

        self.wallet
            .restore_wallet(&req.seed_phrase, password)
            .await
            .map_err(ark_err_to_status)?;

        Ok(Response::new(RestoreResponse {}))
    }

    async fn unlock(
        &self,
        request: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        let req = request.into_inner();
        info!("WalletService::Unlock called");

        if req.password.is_empty() {
            return Err(Status::invalid_argument("password is required"));
        }

        self.wallet
            .unlock(&req.password)
            .await
            .map_err(ark_err_to_status)?;

        Ok(Response::new(UnlockResponse {}))
    }

    async fn lock(&self, _request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        info!("WalletService::Lock called");

        self.wallet.lock().await.map_err(ark_err_to_status)?;

        Ok(Response::new(LockResponse {}))
    }

    async fn get_status(
        &self,
        _request: Request<GetWalletStatusRequest>,
    ) -> Result<Response<GetWalletStatusResponse>, Status> {
        info!("WalletService::GetStatus called");

        let status = self.wallet.status().await.map_err(ark_err_to_status)?;

        Ok(Response::new(GetWalletStatusResponse {
            initialized: status.initialized,
            unlocked: status.unlocked,
            synced: status.synced,
        }))
    }

    async fn derive_address(
        &self,
        _request: Request<DeriveAddressRequest>,
    ) -> Result<Response<DeriveAddressResponse>, Status> {
        info!("WalletService::DeriveAddress called");

        let derived = self
            .wallet
            .derive_address()
            .await
            .map_err(ark_err_to_status)?;

        Ok(Response::new(DeriveAddressResponse {
            address: derived.address,
            derivation_path: derived.derivation_path,
        }))
    }

    async fn get_balance(
        &self,
        _request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>, Status> {
        info!("WalletService::GetBalance called");

        let balance = self.wallet.get_balance().await.map_err(ark_err_to_status)?;

        Ok(Response::new(GetBalanceResponse {
            main_account: Some(Balance {
                available: balance.confirmed.to_string(),
                locked: balance.locked.to_string(),
            }),
            connectors_account: None,
        }))
    }

    async fn withdraw(
        &self,
        request: Request<WithdrawRequest>,
    ) -> Result<Response<WithdrawResponse>, Status> {
        let req = request.into_inner();
        info!(address = %req.address, amount = req.amount_sats, all = req.all, "WalletService::Withdraw called");

        if req.address.is_empty() {
            return Err(Status::invalid_argument("address is required"));
        }
        if !req.all && req.amount_sats == 0 {
            return Err(Status::invalid_argument(
                "amount_sats must be > 0 (or set all=true)",
            ));
        }

        let txid = self
            .wallet
            .withdraw(&req.address, req.amount_sats)
            .await
            .map_err(ark_err_to_status)?;

        Ok(Response::new(WithdrawResponse { txid }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkd_core::error::ArkResult;
    use arkd_core::ports::{DerivedAddress, WalletBalance};

    /// Mock wallet that implements enough for gRPC handler tests.
    struct MockWallet;

    #[async_trait::async_trait]
    impl WalletService for MockWallet {
        async fn status(&self) -> ArkResult<arkd_core::ports::WalletStatus> {
            Ok(arkd_core::ports::WalletStatus {
                initialized: true,
                unlocked: true,
                synced: true,
            })
        }
        async fn get_forfeit_pubkey(&self) -> ArkResult<bitcoin::XOnlyPublicKey> {
            unimplemented!()
        }
        async fn derive_connector_address(&self) -> ArkResult<String> {
            Ok("bcrt1pconnector".into())
        }
        async fn sign_transaction(&self, _: &str, _: bool) -> ArkResult<String> {
            unimplemented!()
        }
        async fn select_utxos(
            &self,
            _: u64,
            _: bool,
        ) -> ArkResult<(Vec<arkd_core::ports::TxInput>, u64)> {
            unimplemented!()
        }
        async fn broadcast_transaction(&self, _: Vec<String>) -> ArkResult<String> {
            unimplemented!()
        }
        async fn fee_rate(&self) -> ArkResult<u64> {
            Ok(1)
        }
        async fn get_current_block_time(&self) -> ArkResult<arkd_core::ports::BlockTimestamp> {
            unimplemented!()
        }
        async fn get_dust_amount(&self) -> ArkResult<u64> {
            Ok(546)
        }
        async fn get_outpoint_status(&self, _: &arkd_core::VtxoOutpoint) -> ArkResult<bool> {
            Ok(false)
        }

        // Operator wallet methods
        async fn gen_seed(&self) -> ArkResult<String> {
            Ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into())
        }
        async fn create_wallet(&self, _mnemonic: &str, _password: &str) -> ArkResult<()> {
            Ok(())
        }
        async fn restore_wallet(&self, _mnemonic: &str, _password: &str) -> ArkResult<()> {
            Ok(())
        }
        async fn unlock(&self, _password: &str) -> ArkResult<()> {
            Ok(())
        }
        async fn lock(&self) -> ArkResult<()> {
            Ok(())
        }
        async fn derive_address(&self) -> ArkResult<DerivedAddress> {
            Ok(DerivedAddress {
                address: "bcrt1ptest123".into(),
                derivation_path: "m/86\'/{1}\'/0\'/0/0".into(),
            })
        }
        async fn get_balance(&self) -> ArkResult<WalletBalance> {
            Ok(WalletBalance {
                confirmed: 100_000,
                unconfirmed: 5_000,
                locked: 0,
            })
        }
        async fn withdraw(&self, _address: &str, _amount: u64) -> ArkResult<String> {
            Ok("aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233".into())
        }
    }

    fn service() -> WalletGrpcService {
        WalletGrpcService::new(Arc::new(MockWallet))
    }

    #[tokio::test]
    async fn test_gen_seed_returns_mnemonic() {
        let resp = service()
            .gen_seed(Request::new(GenSeedRequest {}))
            .await
            .unwrap();
        let phrase = &resp.get_ref().seed_phrase;
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[tokio::test]
    async fn test_get_balance_returns_values() {
        let resp = service()
            .get_balance(Request::new(GetBalanceRequest {}))
            .await
            .unwrap();
        let bal = resp.get_ref();
        let main = bal.main_account.as_ref().unwrap();
        assert_eq!(main.available, "100000");
        assert_eq!(main.locked, "0");
    }

    #[tokio::test]
    async fn test_derive_address_returns_address() {
        let resp = service()
            .derive_address(Request::new(DeriveAddressRequest {}))
            .await
            .unwrap();
        let addr = resp.get_ref();
        assert!(addr.address.starts_with("bcrt1"));
        assert!(!addr.derivation_path.is_empty());
    }

    #[tokio::test]
    async fn test_create_validates_input() {
        let err = service()
            .create(Request::new(CreateRequest {
                seed_phrase: String::new(),
                password: "secret".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = service()
            .create(Request::new(CreateRequest {
                seed_phrase: "abandon ".repeat(12).trim().to_string(),
                password: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_create_succeeds_with_valid_input() {
        let resp = service()
            .create(Request::new(CreateRequest {
                seed_phrase: "abandon ".repeat(12).trim().to_string(),
                password: "secret".to_string(),
            }))
            .await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn test_withdraw_validates_input() {
        let err = service()
            .withdraw(Request::new(WithdrawRequest {
                address: String::new(),
                amount_sats: 1000,
                all: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = service()
            .withdraw(Request::new(WithdrawRequest {
                address: "bcrt1qfoo".to_string(),
                amount_sats: 0,
                all: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_withdraw_all_allows_zero_amount() {
        let resp = service()
            .withdraw(Request::new(WithdrawRequest {
                address: "bcrt1qfoo".to_string(),
                amount_sats: 0,
                all: true,
            }))
            .await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn test_get_status_returns_wallet_status() {
        let resp = service()
            .get_status(Request::new(GetWalletStatusRequest {}))
            .await
            .unwrap();
        let status = resp.get_ref();
        // MockWallet returns initialized=true, unlocked=true, synced=true
        assert!(status.initialized);
        assert!(status.unlocked);
        assert!(status.synced);
    }

    #[tokio::test]
    async fn test_restore_validates_seed() {
        let err = service()
            .restore(Request::new(RestoreRequest {
                seed_phrase: String::new(),
                password: "secret".to_string(),
                gap_limit: 20,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_withdraw_succeeds_with_valid_input() {
        let resp = service()
            .withdraw(Request::new(WithdrawRequest {
                address: "bcrt1qfoo".to_string(),
                amount_sats: 50_000,
                all: false,
            }))
            .await
            .unwrap();
        assert!(!resp.get_ref().txid.is_empty());
    }

    #[tokio::test]
    async fn test_unlock_validates_password() {
        let err = service()
            .unlock(Request::new(UnlockRequest {
                password: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_lock_succeeds() {
        let resp = service().lock(Request::new(LockRequest {})).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn test_restore_validates_input() {
        let err = service()
            .restore(Request::new(RestoreRequest {
                seed_phrase: String::new(),
                password: String::new(),
                gap_limit: 20,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
