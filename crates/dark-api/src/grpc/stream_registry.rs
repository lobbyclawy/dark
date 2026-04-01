//! Per-stream topic registry for topic-filtered event delivery.
//!
//! Each `GetEventStream` connection is assigned a unique stream ID and an
//! initial set of topics (typically the client's x-only pubkey). Events
//! carrying a non-empty `topic` list (e.g. `TreeNonces`, `TreeTx`) are only
//! delivered to streams whose topic set intersects the event's topics.
//! Events without topics are delivered to all streams.
//!
//! Mirrors the Go arkd broker's `listener.includesAny(ev.topics)` semantics.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared handle to the stream registry.
pub type SharedStreamRegistry = Arc<StreamRegistry>;

/// Registry tracking topic subscriptions for active event streams.
pub struct StreamRegistry {
    streams: RwLock<HashMap<String, HashSet<String>>>,
}

impl StreamRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            streams: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new stream with initial topics. Topics are lowercased and trimmed.
    pub async fn register(&self, stream_id: &str, topics: Vec<String>) {
        let normalized: HashSet<String> = topics
            .into_iter()
            .map(|t| t.trim().to_lowercase())
            .collect();
        self.streams
            .write()
            .await
            .insert(stream_id.to_string(), normalized);
    }

    /// Remove a stream from the registry (called on stream close).
    pub async fn unregister(&self, stream_id: &str) {
        self.streams.write().await.remove(stream_id);
    }

    /// Add topics to an existing stream. Returns the full topic set, or None if not found.
    pub async fn add_topics(&self, stream_id: &str, topics: &[String]) -> Option<Vec<String>> {
        let mut streams = self.streams.write().await;
        let entry = streams.get_mut(stream_id)?;
        for t in topics {
            entry.insert(t.trim().to_lowercase());
        }
        Some(entry.iter().cloned().collect())
    }

    /// Remove topics from an existing stream. Returns the full topic set, or None if not found.
    pub async fn remove_topics(&self, stream_id: &str, topics: &[String]) -> Option<Vec<String>> {
        let mut streams = self.streams.write().await;
        let entry = streams.get_mut(stream_id)?;
        for t in topics {
            entry.remove(&t.trim().to_lowercase());
        }
        Some(entry.iter().cloned().collect())
    }

    /// Overwrite the topic set for an existing stream. Returns the full topic set, or None if not found.
    pub async fn overwrite_topics(
        &self,
        stream_id: &str,
        topics: &[String],
    ) -> Option<Vec<String>> {
        let mut streams = self.streams.write().await;
        let entry = streams.get_mut(stream_id)?;
        *entry = topics.iter().map(|t| t.trim().to_lowercase()).collect();
        Some(entry.iter().cloned().collect())
    }

    /// Get the current topic set for a stream.
    pub async fn get_topics(&self, stream_id: &str) -> Option<Vec<String>> {
        let streams = self.streams.read().await;
        streams.get(stream_id).map(|s| s.iter().cloned().collect())
    }

    /// Check if a stream's topics include any of the given event topics.
    /// Returns true if:
    /// - event_topics is empty (broadcast to all), OR
    /// - the stream's topic set intersects with event_topics
    ///
    /// Returns false if the stream_id is not found.
    pub async fn includes_any(&self, stream_id: &str, event_topics: &[String]) -> bool {
        if event_topics.is_empty() {
            return true;
        }
        let streams = self.streams.read().await;
        match streams.get(stream_id) {
            None => false,
            Some(subscriber_topics) => {
                if subscriber_topics.is_empty() {
                    // No topics subscribed → receive all events (like Go's behavior
                    // when listener has no topics set)
                    return true;
                }
                event_topics.iter().any(|t| {
                    let normalized = t.trim().to_lowercase();
                    if subscriber_topics.contains(&normalized) {
                        return true;
                    }
                    // Cross-format matching: compressed pubkey (66 chars,
                    // "02"/"03" prefix) ↔ x-only pubkey (64 chars, no prefix).
                    // Go SDK clients register x-only topics while TreeTx events
                    // carry compressed-pubkey topics from PSBT cosigner fields.
                    let xonly = if normalized.len() == 66 {
                        &normalized[2..]
                    } else {
                        &normalized
                    };
                    subscriber_topics.iter().any(|sub| {
                        let sub_xonly = if sub.len() == 66 {
                            &sub[2..]
                        } else {
                            sub.as_str()
                        };
                        xonly == sub_xonly
                    })
                })
            }
        }
    }
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}
