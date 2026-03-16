//! WalletService gRPC implementation — operator wallet management API.

use tonic::{Request, Response, Status};
use tracing::info;

use crate::proto::ark_v1::wallet_service_server::WalletService as WalletServiceTrait;
use crate::proto::ark_v1::{
    Balance, CreateRequest, CreateResponse, DeriveAddressRequest, DeriveAddressResponse,
    GenSeedRequest, GenSeedResponse, GetBalanceRequest, GetBalanceResponse, GetWalletStatusRequest,
    GetWalletStatusResponse, LockRequest, LockResponse, RestoreRequest, RestoreResponse,
    UnlockRequest, UnlockResponse, WithdrawRequest, WithdrawResponse,
};

/// WalletService gRPC handler.
///
/// Provides operators with wallet management RPCs (seed generation,
/// create/restore, lock/unlock, balance queries, and withdrawals).
///
/// Current implementation returns stub responses — real BDK wallet
/// integration will follow.
pub struct WalletGrpcService;

impl WalletGrpcService {
    /// Create a new WalletGrpcService.
    pub fn new() -> Self {
        Self
    }
}

impl Default for WalletGrpcService {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl WalletServiceTrait for WalletGrpcService {
    async fn gen_seed(
        &self,
        _request: Request<GenSeedRequest>,
    ) -> Result<Response<GenSeedResponse>, Status> {
        info!("WalletService::GenSeed called");

        // Stub: return a placeholder 12-word mnemonic.
        // Real implementation will use BIP-39 via BDK.
        Ok(Response::new(GenSeedResponse {
            seed_phrase: "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about"
                .to_string(),
        }))
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

        // Stub: wallet creation not yet wired to BDK.
        Err(Status::unimplemented(
            "Create is not yet implemented — BDK wallet integration pending",
        ))
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

        // Stub: wallet restore not yet wired to BDK.
        Err(Status::unimplemented(
            "Restore is not yet implemented — BDK wallet integration pending",
        ))
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

        // Stub: unlock not yet wired to BDK.
        Err(Status::unimplemented(
            "Unlock is not yet implemented — BDK wallet integration pending",
        ))
    }

    async fn lock(&self, _request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        info!("WalletService::Lock called");

        // Stub: lock not yet wired to BDK.
        Err(Status::unimplemented(
            "Lock is not yet implemented — BDK wallet integration pending",
        ))
    }

    async fn get_status(
        &self,
        _request: Request<GetWalletStatusRequest>,
    ) -> Result<Response<GetWalletStatusResponse>, Status> {
        info!("WalletService::GetStatus called");

        // Stub: wallet is not initialized/unlocked/synced until BDK wiring.
        Ok(Response::new(GetWalletStatusResponse {
            initialized: false,
            unlocked: false,
            synced: false,
        }))
    }

    async fn derive_address(
        &self,
        _request: Request<DeriveAddressRequest>,
    ) -> Result<Response<DeriveAddressResponse>, Status> {
        info!("WalletService::DeriveAddress called");

        // Stub: return a placeholder regtest address.
        Ok(Response::new(DeriveAddressResponse {
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            derivation_path: "m/84'/1'/0'/0/0".to_string(),
        }))
    }

    async fn get_balance(
        &self,
        _request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>, Status> {
        info!("WalletService::GetBalance called");

        // Stub: return zero balances using Go-parity Balance sub-messages.
        Ok(Response::new(GetBalanceResponse {
            main_account: Some(Balance {
                locked: "0".to_string(),
                available: "0".to_string(),
            }),
            connectors_account: Some(Balance {
                locked: "0".to_string(),
                available: "0".to_string(),
            }),
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

        // Stub: withdrawal not yet wired to BDK.
        Err(Status::unimplemented(
            "Withdraw is not yet implemented — BDK wallet integration pending",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> WalletGrpcService {
        WalletGrpcService::new()
    }

    #[tokio::test]
    async fn test_gen_seed_returns_mnemonic() {
        let resp = service()
            .gen_seed(Request::new(GenSeedRequest {}))
            .await
            .unwrap();
        let phrase = &resp.get_ref().seed_phrase;
        // BIP-39 12-word mnemonic has 12 words.
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[tokio::test]
    async fn test_get_balance_returns_zero() {
        let resp = service()
            .get_balance(Request::new(GetBalanceRequest {}))
            .await
            .unwrap();
        let bal = resp.get_ref();
        assert!(bal.main_account.is_some());
        assert!(bal.connectors_account.is_some());
        let main = bal.main_account.as_ref().unwrap();
        assert_eq!(main.locked, "0");
        assert_eq!(main.available, "0");
    }

    #[tokio::test]
    async fn test_derive_address_returns_stub() {
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
        // Empty seed phrase should fail.
        let err = service()
            .create(Request::new(CreateRequest {
                seed_phrase: String::new(),
                password: "secret".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // Empty password should fail.
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
    async fn test_withdraw_validates_input() {
        // Empty address should fail.
        let err = service()
            .withdraw(Request::new(WithdrawRequest {
                address: String::new(),
                amount_sats: 1000,
                all: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // Zero amount with all=false should fail.
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
        // all=true with zero amount should NOT fail on validation (but will be unimplemented).
        let err = service()
            .withdraw(Request::new(WithdrawRequest {
                address: "bcrt1qfoo".to_string(),
                amount_sats: 0,
                all: true,
            }))
            .await
            .unwrap_err();
        // Should be unimplemented, not invalid argument.
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn test_get_status_returns_not_initialized() {
        let resp = service()
            .get_status(Request::new(GetWalletStatusRequest {}))
            .await
            .unwrap();
        let status = resp.get_ref();
        assert!(!status.initialized);
        assert!(!status.unlocked);
        assert!(!status.synced);
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
}
