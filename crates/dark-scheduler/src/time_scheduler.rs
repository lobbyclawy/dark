//! Simple interval-based time scheduler.

use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::debug;

use dark_core::error::ArkResult;
use dark_core::ports::TimeScheduler;

/// A scheduler that fires a tick at a fixed time interval.
///
/// The first tick is sent immediately so that a round starts as soon as the
/// server boots, then subsequent ticks fire every `interval`.
pub struct SimpleTimeScheduler;

#[async_trait]
impl TimeScheduler for SimpleTimeScheduler {
    async fn schedule(&self, interval: Duration) -> ArkResult<mpsc::Receiver<()>> {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            // Send an immediate first tick so a round starts on server boot.
            if tx.send(()).await.is_err() {
                return;
            }
            let mut ticker = tokio::time::interval(interval);
            // Consume the immediate first tick from tokio::time::interval
            // (we already sent our own above).
            ticker.tick().await;
            loop {
                ticker.tick().await;
                debug!("time scheduler tick");
                if tx.send(()).await.is_err() {
                    break;
                }
            }
        });
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_time_scheduler_creates_channel() {
        let scheduler = SimpleTimeScheduler;
        let rx = scheduler.schedule(Duration::from_secs(60)).await;
        assert!(rx.is_ok(), "schedule should return a receiver");
    }

    #[tokio::test]
    async fn test_simple_time_scheduler_sends_tick() {
        let scheduler = SimpleTimeScheduler;
        let mut rx = scheduler.schedule(Duration::from_millis(10)).await.unwrap();
        let tick = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
        assert!(tick.is_ok(), "should receive a tick within the timeout");
        assert_eq!(tick.unwrap(), Some(()));
    }
}
