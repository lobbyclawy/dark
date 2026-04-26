//! Bitcoin Core RPC fee manager — calls `estimatesmartfee` for dynamic fee estimation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::{FeeManager, FeeManagerService, FeeStrategy};

use crate::btc_per_kb_to_sat_per_vbyte;
use crate::confidential::minimum_fee_for_rate;

/// Default cache TTL: 60 seconds
const DEFAULT_CACHE_TTL_SECS: u64 = 60;

/// Confirmation target for conservative strategy (6 blocks ≈ 1 hour)
const CONSERVATIVE_CONF_TARGET: u32 = 6;

/// Confirmation target for economical strategy (1 block ≈ 10 min)
const ECONOMICAL_CONF_TARGET: u32 = 1;

/// Cached fee estimate entry
#[derive(Debug, Clone)]
struct CacheEntry {
    rate: u64,
    fetched_at: Instant,
    conf_target: u32,
}

/// Fee manager that queries a Bitcoin Core node via JSON-RPC.
///
/// Caches results per confirmation target with a configurable TTL.
pub struct BitcoinCoreFeeManager {
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    client: reqwest::Client,
    /// Cache: keyed by confirmation target
    cache: RwLock<Vec<CacheEntry>>,
    cache_ttl: Duration,
}

impl BitcoinCoreFeeManager {
    /// Create a new Bitcoin Core fee manager.
    pub fn new(rpc_url: String, rpc_user: String, rpc_pass: String) -> Self {
        Self {
            rpc_url,
            rpc_user,
            rpc_pass,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            cache: RwLock::new(Vec::new()),
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        }
    }

    /// Create with a custom cache TTL.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Build the Basic auth header value.
    fn auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.rpc_user, self.rpc_pass);
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        format!("Basic {}", encoded)
    }

    /// Call `estimatesmartfee` on Bitcoin Core.
    async fn rpc_estimate(&self, conf_target: u32) -> ArkResult<u64> {
        let request = RpcRequest {
            jsonrpc: "1.0",
            id: "dark-fee",
            method: "estimatesmartfee",
            params: vec![serde_json::Value::Number(conf_target.into())],
        };

        let response = self
            .client
            .post(&self.rpc_url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Bitcoin Core RPC request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Bitcoin Core RPC returned status {}",
                response.status()
            )));
        }

        let rpc_response: RpcResponse = response
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse RPC response: {e}")))?;

        if let Some(err) = rpc_response.error {
            return Err(ArkError::Internal(format!(
                "Bitcoin Core RPC error: {}",
                err.message
            )));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| ArkError::Internal("Bitcoin Core RPC returned no result".to_string()))?;

        if let Some(errors) = &result.errors {
            if !errors.is_empty() {
                warn!(
                    "estimatesmartfee warnings for conf_target={}: {:?}",
                    conf_target, errors
                );
            }
        }

        let feerate = result.feerate.ok_or_else(|| {
            ArkError::Internal(
                "estimatesmartfee returned no feerate (insufficient data)".to_string(),
            )
        })?;

        let sat_per_vbyte = btc_per_kb_to_sat_per_vbyte(feerate);
        // Ensure minimum of 1 sat/vbyte
        Ok(sat_per_vbyte.max(1))
    }

    /// Get fee rate, using cache if available.
    async fn get_or_fetch(&self, conf_target: u32) -> ArkResult<u64> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.iter().find(|e| e.conf_target == conf_target) {
                if entry.fetched_at.elapsed() < self.cache_ttl {
                    debug!(
                        "Using cached fee rate {} sat/vB for conf_target={}",
                        entry.rate, conf_target
                    );
                    return Ok(entry.rate);
                }
            }
        }

        // Fetch fresh estimate
        let rate = self.rpc_estimate(conf_target).await?;
        debug!(
            "Fetched fee rate {} sat/vB for conf_target={}",
            rate, conf_target
        );

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.retain(|e| e.conf_target != conf_target);
            cache.push(CacheEntry {
                rate,
                fetched_at: Instant::now(),
                conf_target,
            });
        }

        Ok(rate)
    }
}

#[async_trait]
impl FeeManager for BitcoinCoreFeeManager {
    async fn estimate_fee_rate(&self, strategy: FeeStrategy) -> ArkResult<u64> {
        match strategy {
            FeeStrategy::Conservative => self.get_or_fetch(CONSERVATIVE_CONF_TARGET).await,
            FeeStrategy::Economical => self.get_or_fetch(ECONOMICAL_CONF_TARGET).await,
            FeeStrategy::Custom(rate) => Ok(rate),
        }
    }

    async fn invalidate_cache(&self) -> ArkResult<()> {
        let mut cache = self.cache.write().await;
        cache.clear();
        debug!("Fee manager cache invalidated");
        Ok(())
    }
}

/// `FeeManagerService` impl for the Bitcoin Core RPC path.
///
/// Per ADR-0004 §"Constraints on #543" the RPC backend "applies unchanged"
/// — we lower its `sat/vbyte` rate into a `u64` minimum fee using the
/// shared confidential-tx weight table in [`crate::confidential`]. The RPC
/// only ever sees the operator's own node; no confidential metadata
/// crosses the boundary.
///
/// Boarding/transfer/round surfaces fall back to `current_fee_rate`-times-
/// confidential-vbytes for parity with the transparent
/// `WeightBasedFeeManager`. Callers using this manager for *transparent*
/// rounds should compose with `WeightBasedFeeManager` directly.
#[async_trait]
impl FeeManagerService for BitcoinCoreFeeManager {
    async fn boarding_fee(&self, _amount_sats: u64) -> ArkResult<u64> {
        // The RPC backend exposes only fee rates; transparent boarding
        // fee scoring is owned by `WeightBasedFeeManager`. The
        // `FeeManagerService` impl exists primarily for the confidential
        // path; transparent surfaces fall back to a per-input/output
        // approximation at the current rate.
        let rate = self.estimate_fee_rate(FeeStrategy::Conservative).await?;
        Ok(rate.saturating_mul(150))
    }

    async fn transfer_fee(&self, _amount_sats: u64) -> ArkResult<u64> {
        let rate = self.estimate_fee_rate(FeeStrategy::Conservative).await?;
        Ok(rate.saturating_mul(100))
    }

    async fn round_fee(&self, vtxo_count: u32) -> ArkResult<u64> {
        let rate = self.estimate_fee_rate(FeeStrategy::Conservative).await?;
        Ok(rate.saturating_mul(vtxo_count as u64 * 50 + 200))
    }

    async fn current_fee_rate(&self) -> ArkResult<u64> {
        self.estimate_fee_rate(FeeStrategy::Conservative).await
    }

    async fn minimum_fee_confidential(&self, inputs: usize, outputs: usize) -> ArkResult<u64> {
        // RPC path (ADR-0004): rate from estimatesmartfee × confidential-tx
        // vbytes. Counts only — no amounts plumbed into the RPC.
        minimum_fee_for_rate(self, FeeStrategy::Conservative, inputs, outputs, 0).await
    }
}

/// JSON-RPC request
#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: Vec<serde_json::Value>,
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<EstimateSmartFeeResult>,
    error: Option<RpcError>,
}

/// estimatesmartfee result
#[derive(Debug, Deserialize)]
struct EstimateSmartFeeResult {
    feerate: Option<f64>,
    errors: Option<Vec<String>>,
    #[allow(dead_code)]
    blocks: Option<u32>,
}

/// JSON-RPC error
#[derive(Debug, Deserialize)]
struct RpcError {
    #[allow(dead_code)]
    code: i32,
    message: String,
}
