//! No-op blockchain scanner for dev/test environments.

use async_trait::async_trait;
use tokio::sync::broadcast;

use dark_core::error::ArkResult;
use dark_core::ports::{BlockchainScanner, ScriptSpentEvent};

/// A blockchain scanner that does nothing.
///
/// Used in development and test environments where on-chain monitoring
/// is not required.
pub struct NoopScanner {
    sender: broadcast::Sender<ScriptSpentEvent>,
}

impl NoopScanner {
    /// Create a new no-op scanner.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(16);
        Self { sender }
    }
}

impl Default for NoopScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockchainScanner for NoopScanner {
    async fn watch_script(&self, _script_pubkey: Vec<u8>) -> ArkResult<()> {
        Ok(())
    }

    async fn unwatch_script(&self, _script_pubkey: &[u8]) -> ArkResult<()> {
        Ok(())
    }

    fn notification_channel(&self) -> broadcast::Receiver<ScriptSpentEvent> {
        self.sender.subscribe()
    }

    async fn tip_height(&self) -> ArkResult<u32> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_noop_scanner_watch_unwatch() {
        let scanner = NoopScanner::new();
        assert!(scanner.watch_script(vec![0xab, 0xcd]).await.is_ok());
        assert!(scanner.unwatch_script(&[0xab, 0xcd]).await.is_ok());
    }

    #[tokio::test]
    async fn test_noop_scanner_tip_height_zero() {
        let scanner = NoopScanner::new();
        let height = scanner.tip_height().await.unwrap();
        assert_eq!(height, 0);
    }

    #[tokio::test]
    async fn test_noop_scanner_channel() {
        let scanner = NoopScanner::new();
        let _rx = scanner.notification_channel();
        // Channel created successfully — no messages expected
    }

    #[tokio::test]
    async fn test_blockchain_scanner_trait_object() {
        let scanner: Arc<dyn BlockchainScanner> = Arc::new(NoopScanner::new());
        assert!(scanner.watch_script(vec![0x01]).await.is_ok());
        assert_eq!(scanner.tip_height().await.unwrap(), 0);
    }
}
