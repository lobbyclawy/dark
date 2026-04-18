//! Weight-based fee manager implementation.
//!
//! Computes intent fees using standard Bitcoin transaction weight units,
//! mirroring Go dark's `FeeManager.ComputeIntentFees`.
//!
//! Weight constants (P2TR / Taproot):
//! - Transaction overhead: 10.5 vbytes
//! - P2TR input: 57.5 vbytes
//! - P2TR output: 43 vbytes

use async_trait::async_trait;
use dark_core::domain::Vtxo;
use dark_core::error::ArkResult;
use dark_core::ports::{BoardingInput, FeeManagerService};

/// Transaction overhead in milli-vbytes (10.5 vbytes = 10_500 mvB).
const TX_OVERHEAD_MVB: u64 = 10_500;
/// P2TR input weight in milli-vbytes (57.5 vbytes = 57_500 mvB).
const P2TR_INPUT_MVB: u64 = 57_500;
/// P2TR output weight in milli-vbytes (43 vbytes = 43_000 mvB).
const P2TR_OUTPUT_MVB: u64 = 43_000;

/// Weight-based fee manager that estimates transaction fees from input/output
/// counts and a configurable fee rate.
///
/// # Fee calculation
///
/// ```text
/// vbytes = 10.5 + (num_inputs × 57.5) + (num_outputs × 43)
/// fee    = ceil(vbytes × fee_rate)
/// ```
pub struct WeightBasedFeeManager {
    /// Fee rate in sats per vbyte.
    fee_rate_sats_per_vbyte: u64,
    /// Minimum fee in satoshis.
    min_fee_sats: u64,
}

impl WeightBasedFeeManager {
    /// Create a new weight-based fee manager.
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

    /// Estimate the fee in satoshis for a transaction with the given
    /// number of inputs and outputs.
    ///
    /// Uses milli-vbyte arithmetic internally to avoid floating-point,
    /// then rounds up to the nearest satoshi.
    pub fn estimate_fee(&self, num_inputs: u64, num_outputs: u64) -> u64 {
        let weight_mvb =
            TX_OVERHEAD_MVB + num_inputs * P2TR_INPUT_MVB + num_outputs * P2TR_OUTPUT_MVB;
        // fee = ceil(weight_mvb * fee_rate / 1000)
        let fee = (weight_mvb * self.fee_rate_sats_per_vbyte).div_ceil(1000);
        fee.max(self.min_fee_sats)
    }
}

#[async_trait]
impl FeeManagerService for WeightBasedFeeManager {
    async fn boarding_fee(&self, amount_sats: u64) -> ArkResult<u64> {
        // 1 boarding input, 1 output
        let fee = self.estimate_fee(1, 1);
        // Cap at 1% of amount
        Ok(fee.min(amount_sats / 100))
    }

    async fn transfer_fee(&self, amount_sats: u64) -> ArkResult<u64> {
        // 1 VTXO input, 1 output
        let fee = self.estimate_fee(1, 1);
        Ok(fee.min(amount_sats / 100))
    }

    async fn round_fee(&self, vtxo_count: u32) -> ArkResult<u64> {
        // vtxo_count inputs, 1 shared output
        let fee = self.estimate_fee(vtxo_count as u64, 1);
        Ok(fee)
    }

    async fn current_fee_rate(&self) -> ArkResult<u64> {
        Ok(self.fee_rate_sats_per_vbyte)
    }

    async fn compute_intent_fees(
        &self,
        boarding_inputs: &[BoardingInput],
        vtxo_inputs: &[Vtxo],
        onchain_outputs: usize,
        offchain_outputs: usize,
    ) -> ArkResult<u64> {
        let num_inputs = boarding_inputs.len() as u64 + vtxo_inputs.len() as u64;
        let num_outputs = onchain_outputs as u64 + offchain_outputs as u64;
        Ok(self.estimate_fee(num_inputs, num_outputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dark_core::domain::VtxoOutpoint;

    fn make_boarding_inputs(count: usize) -> Vec<BoardingInput> {
        (0..count)
            .map(|i| BoardingInput {
                outpoint: VtxoOutpoint {
                    txid: format!("{:064x}", i),
                    vout: 0,
                },
                amount: 100_000,
            })
            .collect()
    }

    fn make_vtxo_inputs(count: usize) -> Vec<Vtxo> {
        (0..count)
            .map(|i| Vtxo {
                outpoint: VtxoOutpoint {
                    txid: format!("{:064x}", i),
                    vout: 0,
                },
                amount: 50_000,
                pubkey: "deadbeef".to_string(),
                commitment_txids: vec![],
                root_commitment_txid: String::new(),
                settled_by: String::new(),
                spent_by: String::new(),
                ark_txid: String::new(),
                spent: false,
                unrolled: false,
                swept: false,
                preconfirmed: false,
                expires_at: 0,
                expires_at_block: 0,
                created_at: 0,
                assets: vec![],
            })
            .collect()
    }

    #[tokio::test]
    async fn test_zero_inputs_returns_base_fee() {
        let fm = WeightBasedFeeManager::new(1, 0);
        let fee = fm.compute_intent_fees(&[], &[], 0, 0).await.unwrap();
        // Only tx overhead: ceil(10.5 * 1) = 11 sats
        assert_eq!(fee, 11);
    }

    #[tokio::test]
    async fn test_fee_scales_with_input_count() {
        let fm = WeightBasedFeeManager::new(1, 0);
        let fee_1 = fm
            .compute_intent_fees(&make_boarding_inputs(1), &[], 1, 0)
            .await
            .unwrap();
        let fee_5 = fm
            .compute_intent_fees(&make_boarding_inputs(5), &[], 1, 0)
            .await
            .unwrap();
        let fee_10 = fm
            .compute_intent_fees(&make_boarding_inputs(10), &[], 1, 0)
            .await
            .unwrap();

        assert!(fee_5 > fee_1, "5 inputs should cost more than 1");
        assert!(fee_10 > fee_5, "10 inputs should cost more than 5");
        // Each additional input adds 57.5 vbytes = ~58 sats at 1 sat/vbyte
        let diff = fee_5 - fee_1;
        assert!(
            (4 * 57..=4 * 58).contains(&diff),
            "4 extra inputs should add ~230 sats, got {}",
            diff
        );
    }

    #[tokio::test]
    async fn test_fee_rate_applied_correctly() {
        let fm_1 = WeightBasedFeeManager::new(1, 0);
        let fm_10 = WeightBasedFeeManager::new(10, 0);

        let fee_1 = fm_1
            .compute_intent_fees(&make_boarding_inputs(2), &[], 2, 0)
            .await
            .unwrap();
        let fee_10 = fm_10
            .compute_intent_fees(&make_boarding_inputs(2), &[], 2, 0)
            .await
            .unwrap();

        // fee_10 should be exactly 10× fee_1 (or very close due to ceiling)
        assert!(
            fee_10 >= fee_1 * 9 && fee_10 <= fee_1 * 11,
            "10x fee rate should give ~10x fee: {} vs {}",
            fee_10,
            fee_1
        );
    }

    #[tokio::test]
    async fn test_weight_based_fee_manager_reasonable_range() {
        let fm = WeightBasedFeeManager::new(1, 0);
        // 10 inputs, 2 outputs at 1 sat/vbyte
        // Expected: 10.5 + 10*57.5 + 2*43 = 10.5 + 575 + 86 = 671.5 -> 672 sats
        let fee = fm
            .compute_intent_fees(&make_boarding_inputs(5), &make_vtxo_inputs(5), 1, 1)
            .await
            .unwrap();
        assert!(
            fee < 10_000,
            "Fee for 10 inputs at 1 sat/vbyte should be < 10000, got {}",
            fee
        );
        assert!(fee > 0, "Fee should be positive");
    }

    #[tokio::test]
    async fn test_mixed_boarding_and_vtxo_inputs() {
        let fm = WeightBasedFeeManager::new(2, 0);
        // 3 boarding + 2 vtxo = 5 inputs, 3 outputs (1 onchain + 2 offchain)
        let fee = fm
            .compute_intent_fees(&make_boarding_inputs(3), &make_vtxo_inputs(2), 1, 2)
            .await
            .unwrap();
        // Expected: ceil((10_500 + 5*57_500 + 3*43_000) * 2 / 1000)
        //         = ceil((10_500 + 287_500 + 129_000) * 2 / 1000)
        //         = ceil(427_000 * 2 / 1000) = ceil(854) = 854
        assert_eq!(fee, 854);
    }

    #[tokio::test]
    async fn test_min_fee_applied() {
        let fm = WeightBasedFeeManager::new(1, 1000);
        // Zero inputs/outputs -> overhead only = 11 sats, but min is 1000
        let fee = fm.compute_intent_fees(&[], &[], 0, 0).await.unwrap();
        assert_eq!(fee, 1000);
    }

    #[test]
    fn test_estimate_fee_unit() {
        let fm = WeightBasedFeeManager::new(1, 0);
        // 1 input, 1 output: 10.5 + 57.5 + 43 = 111 vbytes -> 111 sats
        assert_eq!(fm.estimate_fee(1, 1), 111);

        // 0 inputs, 0 outputs: overhead only = ceil(10.5) = 11
        assert_eq!(fm.estimate_fee(0, 0), 11);

        // 2 inputs, 3 outputs: 10.5 + 115 + 129 = 254.5 -> 255
        assert_eq!(fm.estimate_fee(2, 3), 255);
    }

    #[test]
    fn test_default_mainnet_config() {
        let fm = WeightBasedFeeManager::default_mainnet();
        // 1 input, 1 output at 5 sat/vbyte: ceil(111 * 5) = 555
        assert_eq!(fm.estimate_fee(1, 1), 555);
        // min_fee is 546, and 555 > 546 so no clamping
        assert_eq!(fm.estimate_fee(1, 1), 555);
    }

    #[test]
    fn test_default_testnet_config() {
        let fm = WeightBasedFeeManager::default_testnet();
        // 1 input, 1 output at 1 sat/vbyte = 111 sats, min is 100
        assert_eq!(fm.estimate_fee(1, 1), 111);
        // Overhead only = 11 sats, but min is 100
        assert_eq!(fm.estimate_fee(0, 0), 100);
    }

    #[test]
    fn test_min_fee_clamps_low_estimates() {
        let fm = WeightBasedFeeManager::new(1, 500);
        // overhead only = 11 sats, clamped to 500
        assert_eq!(fm.estimate_fee(0, 0), 500);
        // 1 input, 1 output = 111, still below 500
        assert_eq!(fm.estimate_fee(1, 1), 500);
        // many inputs to exceed min
        // 10 inputs, 1 output: 10.5 + 575 + 43 = 628.5 -> 629 > 500
        assert_eq!(fm.estimate_fee(10, 1), 629);
    }

    #[tokio::test]
    async fn test_boarding_fee_capped_at_one_percent() {
        let fm = WeightBasedFeeManager::new(5, 0);
        // 1 input, 1 output at 5 sat/vbyte = 555 sats
        // For 10_000 sats, 1% = 100, so fee = min(555, 100) = 100
        let fee = fm.boarding_fee(10_000).await.unwrap();
        assert_eq!(fee, 100);

        // For 1_000_000 sats, 1% = 10_000, fee = min(555, 10_000) = 555
        let fee = fm.boarding_fee(1_000_000).await.unwrap();
        assert_eq!(fee, 555);
    }

    #[tokio::test]
    async fn test_transfer_fee_capped_at_one_percent() {
        let fm = WeightBasedFeeManager::new(5, 0);
        let fee = fm.transfer_fee(5_000).await.unwrap();
        // 1% of 5_000 = 50, base fee = 555, so capped at 50
        assert_eq!(fee, 50);
    }

    #[tokio::test]
    async fn test_round_fee_scales_with_vtxo_count() {
        let fm = WeightBasedFeeManager::new(1, 0);
        let fee1 = fm.round_fee(1).await.unwrap();
        let fee10 = fm.round_fee(10).await.unwrap();
        assert!(fee10 > fee1);
        // 10 inputs, 1 output vs 1 input, 1 output: diff = 9 * 57.5 = 517.5
        let diff = fee10 - fee1;
        assert!((517..=518).contains(&diff));
    }

    #[tokio::test]
    async fn test_current_fee_rate_returns_configured() {
        let fm = WeightBasedFeeManager::new(42, 0);
        assert_eq!(fm.current_fee_rate().await.unwrap(), 42);
    }

    #[test]
    fn test_estimate_fee_high_fee_rate() {
        let fm = WeightBasedFeeManager::new(100, 0);
        // 1 input, 1 output: ceil(111_000 * 100 / 1000) = 11_100
        assert_eq!(fm.estimate_fee(1, 1), 11_100);
    }
}
