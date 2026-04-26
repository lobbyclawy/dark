//! Simple flat-rate fee manager implementation.

use async_trait::async_trait;
use dark_core::error::ArkResult;
use dark_core::ports::FeeManagerService;

use crate::confidential::confidential_vbytes;

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

    async fn minimum_fee_confidential(&self, inputs: usize, outputs: usize) -> ArkResult<u64> {
        // Static path (ADR-0004): flat fee rate × confidential-tx vbytes,
        // floored at the deployment-configured minimum.
        let vbytes = confidential_vbytes(inputs as u64, outputs as u64);
        Ok((vbytes * self.fee_rate_sats_per_vbyte).max(self.min_fee_sats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::confidential_vbytes;

    #[tokio::test]
    async fn simple_minimum_fee_confidential_uses_flat_rate() {
        let fm = SimpleFeeManager::new(2, 0);
        // 1 input, 1 output -> 1620 vbytes -> 3240 sats at 2 sat/vB
        let fee = fm.minimum_fee_confidential(1, 1).await.unwrap();
        let vbytes = confidential_vbytes(1, 1);
        assert_eq!(fee, vbytes * 2);
    }

    #[tokio::test]
    async fn simple_minimum_fee_confidential_clamps_to_min() {
        let fm = SimpleFeeManager::new(0, 1_000);
        let fee = fm.minimum_fee_confidential(1, 1).await.unwrap();
        // rate = 0, so vbytes * 0 = 0; clamped to min 1_000
        assert_eq!(fee, 1_000);
    }

    #[tokio::test]
    async fn simple_minimum_fee_confidential_scales_with_outputs() {
        let fm = SimpleFeeManager::new(1, 0);
        let f1 = fm.minimum_fee_confidential(1, 1).await.unwrap();
        let f2 = fm.minimum_fee_confidential(1, 2).await.unwrap();
        // Each extra output adds ~1500 vbytes at 1 sat/vB
        assert_eq!(f2 - f1, 1500);
    }
}
