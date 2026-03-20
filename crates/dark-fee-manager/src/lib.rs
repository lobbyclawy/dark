//! Fee manager implementations for Ark protocol
//!
//! Provides multiple fee estimation backends:
//! - [`BitcoinCoreFeeManager`]: Queries a local Bitcoin Core node via RPC
//! - [`MempoolSpaceFeeManager`]: Uses the mempool.space API (no local node required)
//! - [`StaticFeeManager`]: Fixed fee rate (useful for testing)
//! - [`SimpleFeeManager`]: Flat-rate fee calculator for transaction types
//! - [`WeightBasedFeeManager`]: Weight-based fee computation

pub mod bitcoin_core;
pub mod mempool_space;
pub mod simple;
pub mod static_fee;
pub mod weight;

pub use bitcoin_core::BitcoinCoreFeeManager;
pub use mempool_space::{MempoolNetwork, MempoolSpaceFeeManager, RecommendedFees};
pub use simple::SimpleFeeManager;
pub use static_fee::StaticFeeManager;
pub use weight::WeightBasedFeeManager;

/// Convert BTC/kB fee rate to sat/vbyte.
///
/// Bitcoin Core returns fee rates in BTC/kB (1000 bytes).
/// 1 BTC = 100_000_000 sats, so BTC/kB * 100_000_000 / 1000 = BTC/kB * 100_000
pub fn btc_per_kb_to_sat_per_vbyte(btc_per_kb: f64) -> u64 {
    (btc_per_kb * 100_000.0).round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use dark_core::ports::FeeManagerService;

    #[test]
    fn test_btc_per_kb_to_sat_per_vbyte_conversion() {
        // 0.00001 BTC/kB = 1 sat/vbyte
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.00001), 1);
        // 0.0001 BTC/kB = 10 sat/vbyte
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.0001), 10);
        // 0.001 BTC/kB = 100 sat/vbyte
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.001), 100);
        // 0.00002 BTC/kB = 2 sat/vbyte
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.00002), 2);
        // Zero
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.0), 0);
    }

    #[tokio::test]
    async fn test_simple_fee_manager_boarding_fee() {
        let fm = SimpleFeeManager::new(5, 546);
        // 150 * 5 = 750, max(750, 546) = 750, min(750, 100_000/100=1000) = 750
        assert_eq!(fm.boarding_fee(100_000).await.unwrap(), 750);
        // For small amount: 150 * 5 = 750, max(750, 546) = 750, min(750, 1000/100=10) = 10
        assert_eq!(fm.boarding_fee(1_000).await.unwrap(), 10);
    }

    #[tokio::test]
    async fn test_simple_fee_manager_transfer_fee() {
        let fm = SimpleFeeManager::new(5, 546);
        // 100 * 5 = 500, max(500, 546) = 546, min(546, 100_000/100=1000) = 546
        assert_eq!(fm.transfer_fee(100_000).await.unwrap(), 546);
        // For large amount: 100 * 5 = 500, max(500, 546) = 546, min(546, 1_000_000/100=10_000) = 546
        assert_eq!(fm.transfer_fee(1_000_000).await.unwrap(), 546);
    }

    #[tokio::test]
    async fn test_simple_fee_manager_round_fee() {
        let fm = SimpleFeeManager::new(5, 546);
        // (10 * 50 + 200) * 5 = 700 * 5 = 3500, max(3500, 546) = 3500
        assert_eq!(fm.round_fee(10).await.unwrap(), 3500);
        // (0 * 50 + 200) * 5 = 1000, max(1000, 546) = 1000
        assert_eq!(fm.round_fee(0).await.unwrap(), 1000);
    }

    #[tokio::test]
    async fn test_default_mainnet_fee_rate() {
        let fm = SimpleFeeManager::default_mainnet();
        assert_eq!(fm.current_fee_rate().await.unwrap(), 5);
    }
}
