//! Logging implementation of the `NotificationService` port.

use arkd_core::error::ArkResult;
use arkd_core::ports::NotificationService;
use async_trait::async_trait;

/// Logs all notifications via `tracing` — useful for development and debugging.
pub struct LoggingNotificationService;

#[async_trait]
impl NotificationService for LoggingNotificationService {
    async fn notify_vtxo_expiry(
        &self,
        pubkey: &str,
        vtxo_id: &str,
        blocks_remaining: u32,
    ) -> ArkResult<()> {
        tracing::info!(
            pubkey,
            vtxo_id,
            blocks_remaining,
            "VTXO expiry notification"
        );
        Ok(())
    }

    async fn notify_round_complete(
        &self,
        round_id: &str,
        vtxo_count: u32,
        total_sats: u64,
    ) -> ArkResult<()> {
        tracing::info!(
            round_id,
            vtxo_count,
            total_sats,
            "Round complete notification"
        );
        Ok(())
    }

    async fn notify_boarding_complete(&self, pubkey: &str, amount_sats: u64) -> ArkResult<()> {
        tracing::info!(pubkey, amount_sats, "Boarding complete notification");
        Ok(())
    }

    async fn notify(&self, pubkey: &str, subject: &str, message: &str) -> ArkResult<()> {
        tracing::info!(pubkey, subject, message, "Generic notification");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkd_core::ports::NoopNotificationService;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_logging_notification_service_ok() {
        let svc = LoggingNotificationService;
        svc.notify_vtxo_expiry("pk1", "vtxo1", 100).await.unwrap();
        svc.notify_round_complete("round1", 5, 100_000)
            .await
            .unwrap();
        svc.notify_boarding_complete("pk2", 50_000).await.unwrap();
        svc.notify("pk3", "Test", "Hello").await.unwrap();
    }

    #[tokio::test]
    async fn test_noop_notification_service_ok() {
        let svc = NoopNotificationService;
        svc.notify_vtxo_expiry("pk1", "vtxo1", 100).await.unwrap();
        svc.notify_round_complete("round1", 5, 100_000)
            .await
            .unwrap();
        svc.notify_boarding_complete("pk2", 50_000).await.unwrap();
        svc.notify("pk3", "Test", "Hello").await.unwrap();
    }

    #[tokio::test]
    async fn test_notification_service_object_safe() {
        // Prove that NotificationService is object-safe by creating a trait object.
        let svc: Arc<dyn NotificationService> = Arc::new(LoggingNotificationService);
        svc.notify("pk", "subject", "body").await.unwrap();
    }
}
