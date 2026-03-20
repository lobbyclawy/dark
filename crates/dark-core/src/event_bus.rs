//! Tokio broadcast-based event bus for in-process pub/sub.
//!
//! [`TokioBroadcastEventBus`] is the primary event bus implementation,
//! replacing [`LoggingEventPublisher`](super::ports::LoggingEventPublisher)
//! with richer functionality: subscriber counting, topic-filtered
//! subscriptions, and optional structured logging.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::domain::ArkEvent;
use crate::error::ArkResult;
use crate::ports::EventPublisher;

/// In-process event bus built on [`tokio::sync::broadcast`].
///
/// Features beyond the basic [`LoggingEventPublisher`](super::ports::LoggingEventPublisher):
/// - Atomic publish counter for metrics / health checks.
/// - Optional topic-filtered subscriptions via [`subscribe_filtered`](Self::subscribe_filtered).
/// - Configurable logging (can be disabled for high-throughput paths).
pub struct TokioBroadcastEventBus {
    sender: broadcast::Sender<ArkEvent>,
    publish_count: AtomicU64,
    log_events: bool,
}

impl TokioBroadcastEventBus {
    /// Create a new event bus with the given channel capacity.
    ///
    /// `capacity` determines the maximum number of unread events a slow
    /// subscriber can lag behind before messages are dropped (lagged error).
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            publish_count: AtomicU64::new(0),
            log_events: true,
        }
    }

    /// Create a new event bus with logging disabled.
    pub fn new_silent(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            publish_count: AtomicU64::new(0),
            log_events: false,
        }
    }

    /// Return the total number of events published since creation.
    pub fn publish_count(&self) -> u64 {
        self.publish_count.load(Ordering::Relaxed)
    }

    /// Return the current number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Subscribe to **all** events on the bus.
    pub fn subscribe(&self) -> broadcast::Receiver<ArkEvent> {
        self.sender.subscribe()
    }

    /// Subscribe with a topic filter.
    ///
    /// Returns a [`FilteredSubscriber`] that only yields events whose
    /// [`ArkEvent::kind()`] starts with the given `topic_prefix`
    /// (e.g. `"round."`, `"vtxo."`, `"intent."`).
    pub fn subscribe_filtered(&self, topic_prefix: impl Into<String>) -> FilteredSubscriber {
        FilteredSubscriber {
            inner: self.sender.subscribe(),
            prefix: topic_prefix.into(),
        }
    }
}

#[async_trait]
impl EventPublisher for TokioBroadcastEventBus {
    async fn publish_event(&self, event: ArkEvent) -> ArkResult<()> {
        if self.log_events {
            tracing::info!(kind = event.kind(), "ArkEvent published");
        }
        self.publish_count.fetch_add(1, Ordering::Relaxed);
        // Ignore send error — it just means there are no active receivers.
        let _ = self.sender.send(event);
        Ok(())
    }

    async fn subscribe(&self) -> ArkResult<broadcast::Receiver<ArkEvent>> {
        Ok(self.sender.subscribe())
    }
}

/// A subscriber that filters events by topic prefix.
pub struct FilteredSubscriber {
    inner: broadcast::Receiver<ArkEvent>,
    prefix: String,
}

impl FilteredSubscriber {
    /// Receive the next event matching the topic filter.
    ///
    /// Skips (drops) events that don't match. Returns errors from the
    /// underlying broadcast channel (e.g. [`broadcast::error::RecvError::Lagged`]).
    pub async fn recv(&mut self) -> Result<ArkEvent, broadcast::error::RecvError> {
        loop {
            let event = self.inner.recv().await?;
            if event.kind().starts_with(&self.prefix) {
                return Ok(event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_publish_and_receive() {
        let bus = TokioBroadcastEventBus::new(16);
        let mut rx = bus.subscribe();

        let event = ArkEvent::RoundStarted {
            round_id: "r1".into(),
            timestamp: 42,
        };
        bus.publish_event(event).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.kind(), "round.started");
        assert_eq!(bus.publish_count(), 1);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = TokioBroadcastEventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        assert_eq!(bus.subscriber_count(), 2);

        bus.publish_event(ArkEvent::ServerStopping).await.unwrap();

        assert_eq!(rx1.recv().await.unwrap().kind(), "server.stopping");
        assert_eq!(rx2.recv().await.unwrap().kind(), "server.stopping");
    }

    #[tokio::test]
    async fn test_filtered_subscriber() {
        let bus = TokioBroadcastEventBus::new(16);
        let mut round_sub = bus.subscribe_filtered("round.");

        // Publish a mix of events
        bus.publish_event(ArkEvent::IntentRegistered {
            intent_id: "i1".into(),
            pubkey: "pk".into(),
            amount: 1000,
        })
        .await
        .unwrap();

        bus.publish_event(ArkEvent::RoundStarted {
            round_id: "r1".into(),
            timestamp: 100,
        })
        .await
        .unwrap();

        // Filtered subscriber should skip intent event and get round event
        let received = round_sub.recv().await.unwrap();
        assert_eq!(received.kind(), "round.started");
    }

    #[tokio::test]
    async fn test_no_subscribers_does_not_error() {
        let bus = TokioBroadcastEventBus::new(4);
        for i in 0..10 {
            let result = bus
                .publish_event(ArkEvent::IntentRegistered {
                    intent_id: format!("i{i}"),
                    pubkey: "pk".into(),
                    amount: 100,
                })
                .await;
            assert!(result.is_ok());
        }
        assert_eq!(bus.publish_count(), 10);
    }

    #[tokio::test]
    async fn test_silent_mode() {
        let bus = TokioBroadcastEventBus::new_silent(16);
        let mut rx = bus.subscribe();

        bus.publish_event(ArkEvent::ServerStopping).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received.kind(), "server.stopping");
    }

    #[tokio::test]
    async fn test_trait_subscribe() {
        let bus = TokioBroadcastEventBus::new(16);
        // Use the trait method (async fn subscribe)
        let publisher: &dyn EventPublisher = &bus;
        let mut rx = publisher.subscribe().await.unwrap();

        publisher
            .publish_event(ArkEvent::ServerStopping)
            .await
            .unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.kind(), "server.stopping");
    }
}
