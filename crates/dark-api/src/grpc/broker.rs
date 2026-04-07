//! Event brokers for streaming events to clients.

use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Broadcasts round lifecycle events to connected stream clients.
/// Buffers all events for the active batch (from BatchStarted to
/// BatchFinalized/BatchFailed) so new subscribers can replay them
/// even if they connect after the events were originally published.
#[derive(Clone)]
pub struct EventBroker {
    sender: broadcast::Sender<crate::proto::ark_v1::RoundEvent>,
    /// All events for the current active batch. Cleared on
    /// BatchFinalized or BatchFailed.
    batch_events: Arc<Mutex<Vec<crate::proto::ark_v1::RoundEvent>>>,
}

impl EventBroker {
    /// Create a new EventBroker with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            batch_events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Publish an event to all connected subscribers. Returns the number of receivers.
    /// Events between BatchStarted and BatchFinalized/BatchFailed are buffered
    /// for replay to late subscribers.
    pub fn publish(&self, event: crate::proto::ark_v1::RoundEvent) -> usize {
        // Update the buffer BEFORE sending to the broadcast channel.
        // This ensures subscribe_with_replay always sees the latest state.
        if let Some(ref inner) = event.event {
            use crate::proto::ark_v1::round_event::Event;
            let mut buf = self.batch_events.lock().unwrap();
            match inner {
                Event::BatchStarted(_) => {
                    // New batch — start fresh buffer.
                    buf.clear();
                    buf.push(event.clone());
                }
                // Batch-ending events clear the buffer.
                Event::BatchFinalized(_) | Event::BatchFailed(_) => {
                    buf.clear();
                }
                _ => {
                    // Intermediate events: append to buffer if a batch is active
                    // (i.e. buffer is non-empty, meaning BatchStarted was seen).
                    if !buf.is_empty() {
                        buf.push(event.clone());
                    }
                }
            }
        }
        self.sender.send(event).unwrap_or(0)
    }

    /// Subscribe and receive all buffered events for the active batch (if any).
    /// The buffer is read synchronously — no race with publish().
    pub fn subscribe_with_replay(
        &self,
    ) -> (
        broadcast::Receiver<crate::proto::ark_v1::RoundEvent>,
        Vec<crate::proto::ark_v1::RoundEvent>,
    ) {
        let rx = self.sender.subscribe();
        let buffered = self.batch_events.lock().unwrap().clone();
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
