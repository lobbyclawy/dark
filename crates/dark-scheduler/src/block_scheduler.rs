//! Block-height-based scheduler using the Esplora REST API.

use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::BlockScheduler;

/// Default polling interval for checking tip height (30 seconds).
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Scheduler that polls an Esplora-compatible API for the chain tip height
/// and emits on a channel every time the height advances by `n` blocks.
pub struct EsploraBlockScheduler {
    esplora_url: String,
    client: reqwest::Client,
    poll_interval: Duration,
}

impl EsploraBlockScheduler {
    /// Create a new scheduler pointing at the given Esplora base URL
    /// (e.g. `"http://localhost:3000"`).
    pub fn new(esplora_url: &str) -> Self {
        Self {
            esplora_url: esplora_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Override the default polling interval (useful for tests).
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Fetch the current tip height from Esplora.
    async fn fetch_height(&self) -> ArkResult<u32> {
        let url = format!("{}/blocks/tip/height", self.esplora_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("esplora request failed: {e}")))?;

        let text = resp
            .text()
            .await
            .map_err(|e| ArkError::Internal(format!("esplora body read failed: {e}")))?;

        text.trim()
            .parse::<u32>()
            .map_err(|e| ArkError::Internal(format!("invalid height from esplora: {e}")))
    }
}

#[async_trait]
impl BlockScheduler for EsploraBlockScheduler {
    async fn schedule_every_n_blocks(&self, n: u32) -> ArkResult<mpsc::Receiver<u32>> {
        let (tx, rx) = mpsc::channel(1);
        let url = self.esplora_url.clone();
        let client = self.client.clone();
        let poll = self.poll_interval;

        // Capture the current height as the baseline.
        let start_height = self.fetch_height().await?;

        tokio::spawn(async move {
            let mut last_emitted = start_height;
            let mut ticker = tokio::time::interval(poll);
            // skip the immediate first tick
            ticker.tick().await;

            loop {
                ticker.tick().await;
                let height = match Self::fetch_height_static(&client, &url).await {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("block scheduler poll error: {e}");
                        continue;
                    }
                };
                debug!(height, last_emitted, n, "block scheduler poll");
                if height >= last_emitted + n {
                    last_emitted = height;
                    if tx.send(height).await.is_err() {
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    async fn current_height(&self) -> ArkResult<u32> {
        self.fetch_height().await
    }
}

impl EsploraBlockScheduler {
    /// Static helper so the spawned task doesn't need `&self`.
    async fn fetch_height_static(client: &reqwest::Client, base_url: &str) -> ArkResult<u32> {
        let url = format!("{base_url}/blocks/tip/height");
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("esplora request failed: {e}")))?;
        let text = resp
            .text()
            .await
            .map_err(|e| ArkError::Internal(format!("esplora body read failed: {e}")))?;
        text.trim()
            .parse::<u32>()
            .map_err(|e| ArkError::Internal(format!("invalid height from esplora: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_esplora_block_scheduler_construction() {
        let scheduler = EsploraBlockScheduler::new("http://localhost:3000");
        assert_eq!(scheduler.esplora_url, "http://localhost:3000");
        assert_eq!(scheduler.poll_interval, DEFAULT_POLL_INTERVAL);
    }

    #[test]
    fn test_esplora_block_scheduler_trailing_slash() {
        let scheduler = EsploraBlockScheduler::new("http://localhost:3000/");
        assert_eq!(scheduler.esplora_url, "http://localhost:3000");
    }

    #[test]
    fn test_block_scheduler_trait_object() {
        // Verify Arc<dyn BlockScheduler> compiles — proves object safety.
        fn _accept(_s: Arc<dyn BlockScheduler>) {}
    }

    #[test]
    fn test_with_poll_interval() {
        let scheduler = EsploraBlockScheduler::new("http://localhost:3000")
            .with_poll_interval(Duration::from_secs(5));
        assert_eq!(scheduler.poll_interval, Duration::from_secs(5));
    }
}
