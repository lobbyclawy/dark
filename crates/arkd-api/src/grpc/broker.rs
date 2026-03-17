//! Event brokers for streaming events to clients.

use std::sync::Arc;
use tokio::sync::broadcast;

/// Broadcasts round lifecycle events to connected stream clients.
#[derive(Clone)]
pub struct EventBroker {
    sender: broadcast::Sender<crate::proto::ark_v1::RoundEvent>,
}

impl EventBroker {
    /// Create a new EventBroker with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish an event to all connected subscribers.
    pub fn publish(&self, event: crate::proto::ark_v1::RoundEvent) {
        let _ = self.sender.send(event);
    }

    /// Subscribe to the event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<crate::proto::ark_v1::RoundEvent> {
        self.sender.subscribe()
    }
}

/// Shared reference to an EventBroker.
pub type SharedEventBroker = Arc<EventBroker>;

/// Broadcasts transaction events to connected stream clients.
#[derive(Clone)]
pub struct TransactionEventBroker {
    sender: broadcast::Sender<crate::proto::ark_v1::TransactionEvent>,
}

impl TransactionEventBroker {
    /// Create a new TransactionEventBroker with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish a transaction event to all connected subscribers.
    pub fn publish(&self, event: crate::proto::ark_v1::TransactionEvent) {
        let _ = self.sender.send(event);
    }

    /// Subscribe to the transaction event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<crate::proto::ark_v1::TransactionEvent> {
        self.sender.subscribe()
    }
}

/// Shared reference to a TransactionEventBroker.
pub type SharedTransactionEventBroker = Arc<TransactionEventBroker>;
