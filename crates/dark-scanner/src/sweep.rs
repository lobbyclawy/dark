//! Esplora-based sweep service for reclaiming expired VTXO outputs.
//!
//! Implements [`SweepService`] by querying an Esplora HTTP API to identify
//! VTXO outputs that have passed their CSV timelock and are eligible for
//! sweeping back to the ASP wallet.

use async_trait::async_trait;
use tracing::{debug, info, warn};

use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::{SweepResult, SweepService};

/// An output identified as sweepable (past its CSV timelock).
#[derive(Debug, Clone)]
pub struct SweepableVtxoOutput {
    /// Transaction ID containing the output.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// CSV delay (in blocks) that has elapsed.
    pub csv_delay: u32,
    /// Current chain height when identified.
    pub identified_at_height: u32,
}

/// Esplora outspend response.
#[derive(Debug, serde::Deserialize)]
struct OutspendResponse {
    spent: bool,
}

/// Esplora block status for a transaction.
#[derive(Debug, serde::Deserialize)]
struct TxStatus {
    confirmed: bool,
    #[serde(default)]
    block_height: Option<u32>,
}

/// Minimal Esplora transaction response.
#[derive(Debug, serde::Deserialize)]
struct EsploraTxResponse {
    #[allow(dead_code)]
    txid: String,
    status: TxStatus,
}

/// Esplora-based sweep service that identifies expired VTXO outputs.
///
/// Queries the Esplora API to:
/// 1. Get the current chain tip height
/// 2. Check transaction confirmation status and block height
/// 3. Determine if outputs have passed their CSV timelock
/// 4. Log sweepable outputs for future transaction building
///
/// # Note
/// Full sweep transaction building requires `TxBuilder` wiring which is
/// deferred to a follow-up. This implementation identifies and logs
/// sweepable outputs but does not yet build or broadcast sweep transactions.
pub struct EsploraSweepService {
    base_url: String,
    client: reqwest::Client,
    /// Optional VTXO repository for querying expired VTXOs.
    vtxo_repo: Option<Arc<dyn dark_core::ports::VtxoRepository>>,
    /// Optional wallet service for broadcasting sweep transactions.
    wallet: Option<Arc<dyn dark_core::ports::WalletService>>,
    /// Optional tx builder for constructing sweep transactions.
    tx_builder: Option<Arc<dyn dark_core::ports::TxBuilder>>,
    /// Optional round repository for looking up connector trees.
    round_repo: Option<Arc<dyn dark_core::ports::RoundRepository>>,
}

use std::sync::Arc;

impl EsploraSweepService {
    /// Create a new Esplora-based sweep service.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            vtxo_repo: None,
            wallet: None,
            tx_builder: None,
            round_repo: None,
        }
    }

    /// Wire in the dependencies needed for actual sweep transaction building.
    pub fn with_deps(
        mut self,
        vtxo_repo: Arc<dyn dark_core::ports::VtxoRepository>,
        wallet: Arc<dyn dark_core::ports::WalletService>,
        tx_builder: Arc<dyn dark_core::ports::TxBuilder>,
    ) -> Self {
        self.vtxo_repo = Some(vtxo_repo);
        self.wallet = Some(wallet);
        self.tx_builder = Some(tx_builder);
        self
    }

    /// Wire in a round repository for connector sweep support.
    pub fn with_round_repo(
        mut self,
        round_repo: Arc<dyn dark_core::ports::RoundRepository>,
    ) -> Self {
        self.round_repo = Some(round_repo);
        self
    }

    /// Get the current chain tip height from Esplora.
    async fn tip_height(&self) -> ArkResult<u32> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        let resp =
            self.client.get(&url).send().await.map_err(|e| {
                ArkError::Internal(format!("Esplora tip height request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let text = resp
            .text()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to read tip height: {e}")))?;

        text.trim()
            .parse()
            .map_err(|e| ArkError::Internal(format!("Failed to parse tip height '{}': {e}", text)))
    }

    /// Check if a specific output is unspent on-chain.
    async fn is_output_unspent(&self, txid: &str, vout: u32) -> ArkResult<bool> {
        let url = format!("{}/tx/{}/outspend/{}", self.base_url, txid, vout);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora outspend request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(true); // tx not found means output is unspent
        }

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let outspend: OutspendResponse = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse outspend: {e}")))?;

        Ok(!outspend.spent)
    }

    /// Get the confirmation block height of a transaction.
    async fn get_tx_block_height(&self, txid: &str) -> ArkResult<Option<u32>> {
        let url = format!("{}/tx/{}", self.base_url, txid);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora tx request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let tx: EsploraTxResponse = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse tx response: {e}")))?;

        if tx.status.confirmed {
            Ok(tx.status.block_height)
        } else {
            Ok(None)
        }
    }

    /// Check if a VTXO output has passed its CSV timelock and is sweepable.
    ///
    /// Returns `Some(SweepableVtxoOutput)` if the output is:
    /// 1. Confirmed on-chain
    /// 2. Unspent
    /// 3. Past its CSV delay relative to confirmation height
    pub async fn check_sweepable(
        &self,
        txid: &str,
        vout: u32,
        amount: u64,
        csv_delay: u32,
    ) -> ArkResult<Option<SweepableVtxoOutput>> {
        // Check if the output is still unspent
        if !self.is_output_unspent(txid, vout).await? {
            debug!(txid = %txid, vout, "Output already spent, not sweepable");
            return Ok(None);
        }

        // Get the confirmation height of the transaction
        let confirm_height = match self.get_tx_block_height(txid).await? {
            Some(h) => h,
            None => {
                debug!(txid = %txid, "Transaction not confirmed, not sweepable");
                return Ok(None);
            }
        };

        // Get current tip to check if CSV has elapsed
        let current_height = self.tip_height().await?;
        let blocks_since_confirm = current_height.saturating_sub(confirm_height);

        if blocks_since_confirm < csv_delay {
            debug!(
                txid = %txid,
                vout,
                blocks_since_confirm,
                csv_delay,
                "CSV timelock not yet elapsed"
            );
            return Ok(None);
        }

        info!(
            txid = %txid,
            vout,
            amount,
            csv_delay,
            blocks_since_confirm,
            "Found sweepable VTXO output"
        );

        Ok(Some(SweepableVtxoOutput {
            txid: txid.to_string(),
            vout,
            amount,
            csv_delay,
            identified_at_height: current_height,
        }))
    }
}

#[async_trait]
impl SweepService for EsploraSweepService {
    async fn sweep_expired_vtxos(&self, current_height: u32) -> ArkResult<SweepResult> {
        info!(
            current_height,
            "EsploraSweepService: checking for expired VTXOs to sweep"
        );

        let (vtxo_repo, wallet, tx_builder) = match (
            &self.vtxo_repo,
            &self.wallet,
            &self.tx_builder,
        ) {
            (Some(r), Some(w), Some(t)) => (r, w, t),
            _ => {
                warn!("EsploraSweepService: missing deps (vtxo_repo/wallet/tx_builder) — skipping sweep");
                return Ok(SweepResult::default());
            }
        };

        // Find expired VTXOs using the efficient DB query (filters by timestamp + swept/spent)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let expired = vtxo_repo.find_expired_vtxos(now).await.unwrap_or_default();

        if expired.is_empty() {
            debug!("EsploraSweepService: no expired VTXOs to sweep");
            return Ok(SweepResult::default());
        }

        info!(
            count = expired.len(),
            "EsploraSweepService: found expired VTXOs"
        );

        // Build sweep inputs
        let sweep_inputs: Vec<dark_core::ports::SweepInput> = expired
            .iter()
            .map(|v| dark_core::ports::SweepInput {
                txid: v.outpoint.txid.clone(),
                vout: v.outpoint.vout,
                amount: v.amount,
                tapscripts: vec![],
            })
            .collect();

        // Build sweep tx
        let (sweep_tx_hex, sweep_txid) = match tx_builder.build_sweep_tx(&sweep_inputs).await {
            Ok(result) => result,
            Err(e) => {
                warn!(error = %e, "EsploraSweepService: failed to build sweep tx");
                return Ok(SweepResult::default());
            }
        };

        // Broadcast
        match wallet.broadcast_transaction(vec![sweep_tx_hex]).await {
            Ok(txid) => {
                let sats: u64 = expired.iter().map(|v| v.amount).sum();
                info!(txid = %txid, vtxos = expired.len(), sats, "EsploraSweepService: sweep tx broadcast");
                // Mark VTXOs as swept in the repository
                if let Err(e) = vtxo_repo.mark_vtxos_swept(&expired).await {
                    warn!(
                        error = %e,
                        txid = %txid,
                        "EsploraSweepService: failed to mark VTXOs as swept after broadcast"
                    );
                }
                Ok(SweepResult {
                    vtxos_swept: expired.len(),
                    sats_recovered: sats,
                    tx_ids: vec![sweep_txid],
                })
            }
            Err(e) => {
                warn!(error = %e, "EsploraSweepService: broadcast failed");
                Ok(SweepResult::default())
            }
        }
    }

    async fn sweep_connectors(&self, round_id: &str) -> ArkResult<SweepResult> {
        info!(
            round_id = %round_id,
            "EsploraSweepService: checking connectors for sweep"
        );

        let (wallet, tx_builder, round_repo) = match (
            &self.wallet,
            &self.tx_builder,
            &self.round_repo,
        ) {
            (Some(w), Some(t), Some(r)) => (w, t, r),
            _ => {
                warn!(
                    round_id = %round_id,
                    "EsploraSweepService: missing deps (wallet/tx_builder/round_repo) — skipping connector sweep"
                );
                return Ok(SweepResult::default());
            }
        };

        // Load the round from the repository to get its connector tree
        let round = match round_repo.get_round_with_id(round_id).await? {
            Some(r) => r,
            None => {
                debug!(
                    round_id = %round_id,
                    "Round not found in repository — skipping connector sweep"
                );
                return Ok(SweepResult::default());
            }
        };

        if round.connectors.is_empty() {
            debug!(round_id = %round_id, "No connectors in round");
            return Ok(SweepResult::default());
        }

        // Get sweepable outputs from the connector tree via TxBuilder
        let sweepable = match tx_builder
            .get_sweepable_batch_outputs(&round.connectors)
            .await?
        {
            Some(s) => s,
            None => {
                debug!(
                    round_id = %round_id,
                    "No sweepable connector outputs found"
                );
                return Ok(SweepResult::default());
            }
        };

        // Check if the connector tx is confirmed and get its block height
        let confirm_height = match self.get_tx_block_height(&sweepable.txid).await? {
            Some(h) => h,
            None => {
                debug!(
                    round_id = %round_id,
                    txid = %sweepable.txid,
                    "Connector tx not confirmed — skipping sweep"
                );
                return Ok(SweepResult::default());
            }
        };

        let current_height = self.tip_height().await?;

        // Verify the CSV timelock has elapsed
        let blocks_since_confirm = current_height.saturating_sub(confirm_height);
        if blocks_since_confirm < sweepable.csv_delay {
            debug!(
                round_id = %round_id,
                blocks_since_confirm,
                csv_delay = sweepable.csv_delay,
                "Connector CSV timelock not yet elapsed"
            );
            return Ok(SweepResult::default());
        }

        // Verify the output is still unspent on-chain
        if !self
            .is_output_unspent(&sweepable.txid, sweepable.vout)
            .await?
        {
            debug!(
                round_id = %round_id,
                txid = %sweepable.txid,
                vout = sweepable.vout,
                "Connector output already spent"
            );
            return Ok(SweepResult::default());
        }

        // Build sweep input from the sweepable connector output
        let input = dark_core::ports::SweepInput {
            txid: sweepable.txid.clone(),
            vout: sweepable.vout,
            amount: sweepable.amount,
            tapscripts: sweepable.tapscripts,
        };

        // Build sweep transaction via TxBuilder
        let (sweep_txid, sweep_tx_hex) = match tx_builder.build_sweep_tx(&[input]).await {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    round_id = %round_id,
                    error = %e,
                    "Failed to build connector sweep tx"
                );
                return Ok(SweepResult::default());
            }
        };

        // Broadcast the sweep transaction
        match wallet.broadcast_transaction(vec![sweep_tx_hex]).await {
            Ok(txid) => {
                info!(
                    round_id = %round_id,
                    txid = %txid,
                    sats = sweepable.amount,
                    "Connector sweep tx broadcast"
                );
                Ok(SweepResult {
                    vtxos_swept: 0, // Connectors are ASP-owned, not user VTXOs
                    sats_recovered: sweepable.amount,
                    tx_ids: vec![sweep_txid],
                })
            }
            Err(e) => {
                warn!(
                    round_id = %round_id,
                    error = %e,
                    "Connector sweep broadcast failed"
                );
                Ok(SweepResult::default())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sweep_expired_vtxos_stub_returns_empty() {
        let mut server = mockito::Server::new_async().await;

        let _tip_mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100000")
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.sweep_expired_vtxos(100000).await.unwrap();

        assert_eq!(result.vtxos_swept, 0);
        assert_eq!(result.sats_recovered, 0);
        assert!(result.tx_ids.is_empty());
    }

    #[tokio::test]
    async fn test_sweep_connectors_stub_returns_empty() {
        let service = EsploraSweepService::new("http://localhost:3000");
        let result = service.sweep_connectors("round-123").await.unwrap();

        assert_eq!(result.vtxos_swept, 0);
        assert_eq!(result.sats_recovered, 0);
        assert!(result.tx_ids.is_empty());
    }

    #[tokio::test]
    async fn test_check_sweepable_output_past_csv() {
        let mut server = mockito::Server::new_async().await;
        let txid = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        // Output is unspent
        let _outspend_mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;

        // Transaction confirmed at height 99_000
        let _tx_mock = server
            .mock("GET", format!("/tx/{}", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"txid":"{}","status":{{"confirmed":true,"block_height":99000}}}}"#,
                txid
            ))
            .create_async()
            .await;

        // Current tip is 100_000 (1000 blocks later)
        let _tip_mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100000")
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.check_sweepable(txid, 0, 50_000, 144).await.unwrap();

        assert!(
            result.is_some(),
            "Output should be sweepable (1000 > 144 CSV)"
        );
        let output = result.unwrap();
        assert_eq!(output.txid, txid);
        assert_eq!(output.amount, 50_000);
        assert_eq!(output.csv_delay, 144);
    }

    #[tokio::test]
    async fn test_check_sweepable_csv_not_elapsed() {
        let mut server = mockito::Server::new_async().await;
        let txid = "1122334455667788112233445566778811223344556677881122334455667788";

        let _outspend_mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;

        // Confirmed at 99_900
        let _tx_mock = server
            .mock("GET", format!("/tx/{}", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"txid":"{}","status":{{"confirmed":true,"block_height":99900}}}}"#,
                txid
            ))
            .create_async()
            .await;

        // Tip at 100_000 → only 100 blocks elapsed, CSV=144
        let _tip_mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100000")
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.check_sweepable(txid, 0, 50_000, 144).await.unwrap();

        assert!(
            result.is_none(),
            "CSV not elapsed — should not be sweepable"
        );
    }

    #[tokio::test]
    async fn test_check_sweepable_already_spent() {
        let mut server = mockito::Server::new_async().await;
        let txid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let _outspend_mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":true,"txid":"spending_tx"}"#)
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.check_sweepable(txid, 0, 50_000, 144).await.unwrap();

        assert!(result.is_none(), "Already spent — not sweepable");
    }
}
