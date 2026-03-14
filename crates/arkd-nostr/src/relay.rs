//! WebSocket relay connection for publishing Nostr events.

use futures_util::{future::join_all, SinkExt, StreamExt};
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use url::Url;

use crate::types::NostrEvent;

/// Error type for relay operations.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("Failed to connect to relay: {0}")]
    ConnectionFailed(String),
    #[error("Invalid relay URL: {0}")]
    InvalidUrl(String),
    #[error("Failed to send message: {0}")]
    SendFailed(String),
    #[error("Relay timeout")]
    Timeout,
    #[error("Relay closed connection")]
    ConnectionClosed,
    #[error("Failed to parse relay response: {0}")]
    ParseError(String),
}

/// Response from the relay after publishing an event.
#[derive(Debug, Clone)]
pub struct PublishResult {
    /// The event ID that was published
    pub event_id: String,
    /// Whether the relay accepted the event
    pub accepted: bool,
    /// Message from the relay (often empty on success)
    pub message: String,
}

/// Nostr relay connection for publishing events.
pub struct RelayConnection {
    relay_url: Url,
    connect_timeout: Duration,
    response_timeout: Duration,
}

impl RelayConnection {
    /// Create a new relay connection.
    pub fn new(relay_url: &str) -> Result<Self, RelayError> {
        let url = Url::parse(relay_url).map_err(|e| RelayError::InvalidUrl(e.to_string()))?;

        // Validate WebSocket URL scheme
        if url.scheme() != "wss" && url.scheme() != "ws" {
            return Err(RelayError::InvalidUrl(format!(
                "Expected ws:// or wss:// URL, got: {}",
                url.scheme()
            )));
        }

        Ok(Self {
            relay_url: url,
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(5),
        })
    }

    /// Set the connection timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the response timeout.
    pub fn with_response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = timeout;
        self
    }

    /// Publish an event to the relay.
    ///
    /// Connects, sends the event, waits for OK response, then disconnects.
    pub async fn publish(&self, event: &NostrEvent) -> Result<PublishResult, RelayError> {
        // Connect with timeout
        let (ws_stream, _) = timeout(self.connect_timeout, connect_async(self.relay_url.as_str()))
            .await
            .map_err(|_| RelayError::Timeout)?
            .map_err(|e| RelayError::ConnectionFailed(e.to_string()))?;

        let (mut write, mut read) = ws_stream.split();

        // Send the EVENT message: ["EVENT", <event>]
        let event_msg = serde_json::json!(["EVENT", event]);
        let msg_text =
            serde_json::to_string(&event_msg).map_err(|e| RelayError::SendFailed(e.to_string()))?;

        write
            .send(WsMessage::Text(msg_text))
            .await
            .map_err(|e| RelayError::SendFailed(e.to_string()))?;

        // Wait for OK response with timeout
        let response = timeout(self.response_timeout, async {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(WsMessage::Text(text)) => {
                        // Parse ["OK", event_id, accepted, message]
                        if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                            if parsed.len() >= 4 && parsed[0].as_str() == Some("OK") {
                                let event_id = parsed[1].as_str().unwrap_or("").to_string();
                                let accepted = parsed[2].as_bool().unwrap_or(false);
                                let message = parsed[3].as_str().unwrap_or("").to_string();
                                return Ok(PublishResult {
                                    event_id,
                                    accepted,
                                    message,
                                });
                            }
                            // Handle NOTICE messages
                            if parsed.len() >= 2 && parsed[0].as_str() == Some("NOTICE") {
                                let notice = parsed[1].as_str().unwrap_or("").to_string();
                                tracing::warn!(relay = %self.relay_url, notice = %notice, "Relay notice");
                            }
                        }
                    }
                    Ok(WsMessage::Close(_)) => {
                        return Err(RelayError::ConnectionClosed);
                    }
                    Err(e) => {
                        return Err(RelayError::SendFailed(e.to_string()));
                    }
                    _ => {} // Ignore ping/pong/binary
                }
            }
            Err(RelayError::ConnectionClosed)
        })
        .await
        .map_err(|_| RelayError::Timeout)??;

        // Close the connection gracefully
        let _ = write.close().await;

        Ok(response)
    }
}

/// Publish an event to multiple relays concurrently.
///
/// Returns results from all relays (successes and failures).
pub async fn publish_to_relays(
    event: &NostrEvent,
    relay_urls: &[String],
) -> Vec<Result<PublishResult, RelayError>> {
    let futures: Vec<_> = relay_urls
        .iter()
        .map(|url| {
            let event = event.clone();
            let url = url.clone();
            async move {
                let relay = RelayConnection::new(&url)?;
                relay.publish(&event).await
            }
        })
        .collect();

    join_all(futures).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_connection_valid_url() {
        let conn = RelayConnection::new("wss://relay.damus.io").unwrap();
        assert_eq!(conn.relay_url.scheme(), "wss");
    }

    #[test]
    fn test_relay_connection_invalid_scheme() {
        let result = RelayConnection::new("https://relay.damus.io");
        assert!(matches!(result, Err(RelayError::InvalidUrl(_))));
    }

    #[test]
    fn test_relay_connection_invalid_url() {
        let result = RelayConnection::new("not a url");
        assert!(matches!(result, Err(RelayError::InvalidUrl(_))));
    }

    #[test]
    fn test_relay_connection_with_timeouts() {
        let conn = RelayConnection::new("wss://relay.damus.io")
            .unwrap()
            .with_connect_timeout(Duration::from_secs(30))
            .with_response_timeout(Duration::from_secs(10));

        assert_eq!(conn.connect_timeout, Duration::from_secs(30));
        assert_eq!(conn.response_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_publish_result_debug() {
        let result = PublishResult {
            event_id: "abc123".to_string(),
            accepted: true,
            message: "".to_string(),
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("abc123"));
        assert!(debug.contains("true"));
    }
}
