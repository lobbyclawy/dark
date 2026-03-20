//! mempool.space API fee manager — provides fee estimation without a local Bitcoin node.
//!
//! Uses the [mempool.space recommended fees API](https://mempool.space/docs/api/rest#get-recommended-fees)
//! to fetch current fee estimates. Supports mainnet, testnet, and signet networks.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::debug;

use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::{FeeManager, FeeStrategy};

/// Default cache TTL: 60 seconds
const DEFAULT_CACHE_TTL_SECS: u64 = 60;

/// Bitcoin network for mempool.space API endpoint selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolNetwork {
    /// Mainnet (mempool.space/api/)
    Mainnet,
    /// Testnet (mempool.space/testnet/api/)
    Testnet,
    /// Signet (mempool.space/signet/api/)
    Signet,
}

impl MempoolNetwork {
    /// Returns the base API URL for this network.
    fn api_url(&self) -> &'static str {
        match self {
            MempoolNetwork::Mainnet => "https://mempool.space/api/v1/fees/recommended",
            MempoolNetwork::Testnet => "https://mempool.space/testnet/api/v1/fees/recommended",
            MempoolNetwork::Signet => "https://mempool.space/signet/api/v1/fees/recommended",
        }
    }
}

impl std::fmt::Display for MempoolNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolNetwork::Mainnet => write!(f, "mainnet"),
            MempoolNetwork::Testnet => write!(f, "testnet"),
            MempoolNetwork::Signet => write!(f, "signet"),
        }
    }
}

/// Cached fee estimates from mempool.space.
#[derive(Debug, Clone)]
struct CacheEntry {
    fees: RecommendedFees,
    fetched_at: Instant,
}

/// mempool.space recommended fees response.
///
/// See: <https://mempool.space/docs/api/rest#get-recommended-fees>
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedFees {
    /// Fastest fee (next block, ~10 min)
    pub fastest_fee: u64,
    /// Half hour fee (~30 min, 3 blocks)
    pub half_hour_fee: u64,
    /// Hour fee (~60 min, 6 blocks)
    pub hour_fee: u64,
    /// Economy fee (slower, more economical)
    pub economy_fee: u64,
    /// Minimum relay fee
    pub minimum_fee: u64,
}

/// Fee manager that queries the mempool.space API.
///
/// This is ideal for light deployments without a local Bitcoin Core node.
/// Caches results with a configurable TTL to avoid excessive API calls.
///
/// # Example
///
/// ```rust,no_run
/// use arkd_fee_manager::mempool_space::{MempoolSpaceFeeManager, MempoolNetwork};
/// use arkd_core::ports::{FeeManager, FeeStrategy};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let fm = MempoolSpaceFeeManager::new(MempoolNetwork::Mainnet);
///
/// // Get conservative fee estimate (6 blocks / 1 hour)
/// let fee_rate = fm.estimate_fee_rate(FeeStrategy::Conservative).await?;
/// println!("Conservative fee rate: {} sat/vB", fee_rate);
///
/// // Get economical fee estimate (next block)
/// let fast_fee = fm.estimate_fee_rate(FeeStrategy::Economical).await?;
/// println!("Fast fee rate: {} sat/vB", fast_fee);
/// # Ok(())
/// # }
/// ```
pub struct MempoolSpaceFeeManager {
    network: MempoolNetwork,
    client: reqwest::Client,
    cache: RwLock<Option<CacheEntry>>,
    cache_ttl: Duration,
    /// Custom API base URL (overrides network default)
    custom_url: Option<String>,
}

impl MempoolSpaceFeeManager {
    /// Create a new mempool.space fee manager for the given network.
    pub fn new(network: MempoolNetwork) -> Self {
        Self {
            network,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("arkd-rs/0.1.0")
                .build()
                .unwrap_or_default(),
            cache: RwLock::new(None),
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
            custom_url: None,
        }
    }

    /// Create a mainnet fee manager.
    pub fn mainnet() -> Self {
        Self::new(MempoolNetwork::Mainnet)
    }

    /// Create a testnet fee manager.
    pub fn testnet() -> Self {
        Self::new(MempoolNetwork::Testnet)
    }

    /// Create a signet fee manager.
    pub fn signet() -> Self {
        Self::new(MempoolNetwork::Signet)
    }

    /// Set a custom cache TTL.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Set a custom API URL (e.g., for self-hosted mempool.space instance).
    pub fn with_custom_url(mut self, url: impl Into<String>) -> Self {
        self.custom_url = Some(url.into());
        self
    }

    /// Get the API URL to use.
    fn api_url(&self) -> &str {
        self.custom_url
            .as_deref()
            .unwrap_or_else(|| self.network.api_url())
    }

    /// Fetch fresh fee estimates from the API.
    async fn fetch_fees(&self) -> ArkResult<RecommendedFees> {
        let url = self.api_url();
        debug!("Fetching fee estimates from {}", url);

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("mempool.space request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ArkError::Internal(format!(
                "mempool.space returned status {}: {}",
                status, body
            )));
        }

        let fees: RecommendedFees = response.json().await.map_err(|e| {
            ArkError::Internal(format!("Failed to parse mempool.space response: {e}"))
        })?;

        debug!(
            "mempool.space fees for {}: fastest={}, half_hour={}, hour={}, economy={}, minimum={}",
            self.network,
            fees.fastest_fee,
            fees.half_hour_fee,
            fees.hour_fee,
            fees.economy_fee,
            fees.minimum_fee
        );

        Ok(fees)
    }

    /// Get fee estimates, using cache if available and fresh.
    async fn get_or_fetch(&self) -> ArkResult<RecommendedFees> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.as_ref() {
                if entry.fetched_at.elapsed() < self.cache_ttl {
                    debug!(
                        "Using cached mempool.space fees (age: {:?})",
                        entry.fetched_at.elapsed()
                    );
                    return Ok(entry.fees.clone());
                }
            }
        }

        // Fetch fresh estimates
        let fees = self.fetch_fees().await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            *cache = Some(CacheEntry {
                fees: fees.clone(),
                fetched_at: Instant::now(),
            });
        }

        Ok(fees)
    }

    /// Get the raw recommended fees (useful for custom strategies).
    pub async fn get_recommended_fees(&self) -> ArkResult<RecommendedFees> {
        self.get_or_fetch().await
    }
}

#[async_trait]
impl FeeManager for MempoolSpaceFeeManager {
    async fn estimate_fee_rate(&self, strategy: FeeStrategy) -> ArkResult<u64> {
        match strategy {
            FeeStrategy::Conservative => {
                // Conservative maps to hour_fee (6 blocks / ~1 hour)
                let fees = self.get_or_fetch().await?;
                Ok(fees.hour_fee.max(1)) // Ensure minimum of 1 sat/vB
            }
            FeeStrategy::Economical => {
                // Economical maps to fastest_fee (next block)
                let fees = self.get_or_fetch().await?;
                Ok(fees.fastest_fee.max(1))
            }
            FeeStrategy::Custom(rate) => Ok(rate),
        }
    }

    async fn invalidate_cache(&self) -> ArkResult<()> {
        let mut cache = self.cache.write().await;
        *cache = None;
        debug!("mempool.space fee cache invalidated");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_api_urls() {
        assert_eq!(
            MempoolNetwork::Mainnet.api_url(),
            "https://mempool.space/api/v1/fees/recommended"
        );
        assert_eq!(
            MempoolNetwork::Testnet.api_url(),
            "https://mempool.space/testnet/api/v1/fees/recommended"
        );
        assert_eq!(
            MempoolNetwork::Signet.api_url(),
            "https://mempool.space/signet/api/v1/fees/recommended"
        );
    }

    #[test]
    fn test_network_display() {
        assert_eq!(format!("{}", MempoolNetwork::Mainnet), "mainnet");
        assert_eq!(format!("{}", MempoolNetwork::Testnet), "testnet");
        assert_eq!(format!("{}", MempoolNetwork::Signet), "signet");
    }

    #[test]
    fn test_custom_url_override() {
        let fm = MempoolSpaceFeeManager::new(MempoolNetwork::Mainnet)
            .with_custom_url("https://my-mempool.example.com/api/v1/fees/recommended");
        assert_eq!(
            fm.api_url(),
            "https://my-mempool.example.com/api/v1/fees/recommended"
        );
    }

    #[test]
    fn test_parse_recommended_fees() {
        let json = r#"{
            "fastestFee": 25,
            "halfHourFee": 20,
            "hourFee": 15,
            "economyFee": 10,
            "minimumFee": 5
        }"#;

        let fees: RecommendedFees = serde_json::from_str(json).unwrap();
        assert_eq!(fees.fastest_fee, 25);
        assert_eq!(fees.half_hour_fee, 20);
        assert_eq!(fees.hour_fee, 15);
        assert_eq!(fees.economy_fee, 10);
        assert_eq!(fees.minimum_fee, 5);
    }

    #[tokio::test]
    async fn test_custom_fee_strategy() {
        let fm = MempoolSpaceFeeManager::mainnet();
        let rate = fm.estimate_fee_rate(FeeStrategy::Custom(42)).await.unwrap();
        assert_eq!(rate, 42);
    }

    // Integration test that actually calls the API (disabled by default)
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_live_api_mainnet() {
        let fm = MempoolSpaceFeeManager::mainnet();
        let fees = fm.get_recommended_fees().await.unwrap();

        // Sanity checks
        assert!(fees.fastest_fee >= fees.minimum_fee);
        assert!(fees.half_hour_fee >= fees.minimum_fee);
        assert!(fees.hour_fee >= fees.minimum_fee);
        assert!(fees.economy_fee >= fees.minimum_fee);
        assert!(fees.minimum_fee >= 1);
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_live_fee_strategies() {
        let fm = MempoolSpaceFeeManager::mainnet();

        let conservative = fm
            .estimate_fee_rate(FeeStrategy::Conservative)
            .await
            .unwrap();
        let economical = fm.estimate_fee_rate(FeeStrategy::Economical).await.unwrap();

        // Economical (faster) should be >= conservative (slower)
        assert!(economical >= conservative);
        assert!(conservative >= 1);
    }
}
