//! Simple flat-rate fee manager implementation.

use arkd_core::error::ArkResult;
use arkd_core::ports::FeeManagerService;
use async_trait::async_trait;

/// Simple fee manager with a flat fee rate and minimum fee.
///
/// Calculates fees based on estimated transaction sizes:
/// - Boarding: ~150 vbytes
/// - Transfer: ~100 vbytes
/// - Round: ~(vtxo_count * 50 + 200) vbytes
///
/// Fees are capped at 1% of the transaction amount (for boarding/transfer).
pub struct SimpleFeeManager {
    fee_rate_sats_per_vbyte: u64,
    min_fee_sats: u64,
}

impl SimpleFeeManager {
    /// Create a new SimpleFeeManager with the given fee rate and minimum fee.
    pub fn new(fee_rate_sats_per_vbyte: u64, min_fee_sats: u64) -> Self {
        Self {
            fee_rate_sats_per_vbyte,
            min_fee_sats,
        }
    }

    /// Default configuration for mainnet (5 sat/vbyte, 546 sat minimum).
    pub fn default_mainnet() -> Self {
        Self::new(5, 546)
    }

    /// Default configuration for testnet (1 sat/vbyte, 100 sat minimum).
    pub fn default_testnet() -> Self {
        Self::new(1, 100)
    }
}

#[async_trait]
impl FeeManagerService for SimpleFeeManager {
    async fn boarding_fee(&self, amount_sats: u64) -> ArkResult<u64> {
        // ~150 vbytes for a boarding transaction
        Ok((150 * self.fee_rate_sats_per_vbyte)
            .max(self.min_fee_sats)
            .min(amount_sats / 100))
    }

    async fn transfer_fee(&self, amount_sats: u64) -> ArkResult<u64> {
        // ~100 vbytes for a transfer transaction
        Ok((100 * self.fee_rate_sats_per_vbyte)
            .max(self.min_fee_sats)
            .min(amount_sats / 100))
    }

    async fn round_fee(&self, vtxo_count: u32) -> ArkResult<u64> {
        // ~(vtxo_count * 50 + 200) vbytes for a round transaction
        Ok(((vtxo_count as u64 * 50 + 200) * self.fee_rate_sats_per_vbyte).max(self.min_fee_sats))
    }

    async fn current_fee_rate(&self) -> ArkResult<u64> {
        Ok(self.fee_rate_sats_per_vbyte)
    }
}
