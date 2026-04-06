//! Event brokers for streaming events to clients.

use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Broadcasts round lifecycle events to connected stream clients.
/// Buffers the last BatchStarted event synchronously so new subscribers
/// can receive it even if they connect after it was published.
#[derive(Clone)]
pub struct EventBroker {
    sender: broadcast::Sender<crate::proto::ark_v1::RoundEvent>,
    last_batch_started: Arc<Mutex<Option<crate::proto::ark_v1::RoundEvent>>>,
}

impl EventBroker {
    /// Create a new EventBroker with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            last_batch_started: Arc::new(Mutex::new(None)),
        }
    }

    /// Publish an event to all connected subscribers. Returns the number of receivers.
    /// BatchStarted events are buffered synchronously for replay to late subscribers.
    pub fn publish(&self, event: crate::proto::ark_v1::RoundEvent) -> usize {
        // Update the buffer BEFORE sending to the broadcast channel.
        // This ensures subscribe_with_replay always sees the latest state.
        if let Some(ref inner) = event.event {
            use crate::proto::ark_v1::round_event::Event;
            let mut buf = self.last_batch_started.lock().unwrap();
            match inner {
                Event::BatchStarted(_) => {
                    *buf = Some(event.clone());
                }
                // Only clear the buffer on batch-ending events.
                // Intermediate events (TreeNonces, TreeTx, TreeSignature)
                // are part of the active batch — don't clear.
                Event::BatchFinalized(_) | Event::BatchFailed(_) => {
                    *buf = None;
                }
                _ => {
                    // Keep existing buffer for intermediate events
                }
            }
        }
        self.sender.send(event).unwrap_or(0)
    }

    /// Subscribe and receive the buffered BatchStarted event (if any).
    /// The buffer is read synchronously — no race with publish().
    pub fn subscribe_with_replay(
        &self,
    ) -> (
        broadcast::Receiver<crate::proto::ark_v1::RoundEvent>,
        Option<crate::proto::ark_v1::RoundEvent>,
    ) {
        let rx = self.sender.subscribe();
        let buffered = self.last_batch_started.lock().unwrap().clone();
        (rx, buffered)
    }

    /// Subscribe to the event stream (without replay).
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
