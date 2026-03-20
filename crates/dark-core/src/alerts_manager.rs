//! Prometheus Alertmanager integration for operational alerts.
//!
//! Provides [`PrometheusAlertsManager`], a production implementation of the
//! [`Alerts`] trait that pushes structured alerts to a Prometheus Alertmanager
//! instance via its HTTP API (`/api/v2/alerts`).

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tracing::{debug, error, warn};

use crate::error::ArkResult;
use crate::ports::{AlertTopic, Alerts};

/// Maximum number of retry attempts for posting alerts.
const MAX_RETRIES: u32 = 5;

/// Initial backoff duration before first retry.
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);

/// Alert payload conforming to the Prometheus Alertmanager v2 API.
///
/// See <https://prometheus.io/docs/alerting/latest/clients/>.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AlertmanagerAlert {
    labels: HashMap<String, String>,
    annotations: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generator_url: Option<String>,
}

/// Production [`Alerts`] implementation that POSTs to Prometheus Alertmanager.
///
/// Each call to [`publish`](Alerts::publish) converts the alert topic and
/// payload into a structured Alertmanager alert with labels (service, severity,
/// topic) and annotations (description plus the serialized payload).
///
/// Retries up to 5 times with exponential backoff on transient
/// HTTP failures.
pub struct PrometheusAlertsManager {
    client: reqwest::Client,
    /// Full URL to the alerts endpoint, e.g. `http://alertmanager:9093/api/v2/alerts`.
    endpoint: String,
}

impl PrometheusAlertsManager {
    /// Create a new manager targeting the given Alertmanager base URL.
    ///
    /// The `/api/v2/alerts` path is appended automatically if the URL does not
    /// already end with it.
    pub fn new(base_url: &str) -> Self {
        let endpoint = if base_url.ends_with("/api/v2/alerts") {
            base_url.to_string()
        } else {
            format!("{}/api/v2/alerts", base_url.trim_end_matches('/'))
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");

        Self { client, endpoint }
    }

    /// Derive a severity string from the alert topic.
    fn severity(topic: &AlertTopic) -> &'static str {
        match topic {
            AlertTopic::BatchFinalized => "info",
            AlertTopic::ArkTx => "warning",
        }
    }

    /// Build the Alertmanager-compatible alert body.
    fn build_alert(topic: &AlertTopic, payload: &serde_json::Value) -> AlertmanagerAlert {
        let mut labels = HashMap::new();
        labels.insert("service".to_string(), "dark".to_string());
        labels.insert("severity".to_string(), Self::severity(topic).to_string());
        labels.insert("topic".to_string(), topic.to_string());

        let mut annotations = HashMap::new();
        annotations.insert("description".to_string(), format!("dark alert: {topic}"));
        annotations.insert("payload".to_string(), payload.to_string());

        AlertmanagerAlert {
            labels,
            annotations,
            generator_url: None,
        }
    }

    /// Post alerts with retry + exponential backoff.
    async fn post_with_retry(&self, body: &[AlertmanagerAlert]) -> ArkResult<()> {
        let mut backoff = INITIAL_BACKOFF;

        for attempt in 1..=MAX_RETRIES {
            match self.client.post(&self.endpoint).json(body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!(attempt, "alert posted to Alertmanager");
                    return Ok(());
                }
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    warn!(
                        attempt,
                        %status,
                        body = %text,
                        "Alertmanager returned non-success status"
                    );
                }
                Err(e) => {
                    warn!(attempt, error = %e, "failed to reach Alertmanager");
                }
            }

            if attempt < MAX_RETRIES {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }

        error!(
            endpoint = %self.endpoint,
            retries = MAX_RETRIES,
            "exhausted retries posting alert to Alertmanager"
        );
        Err(crate::error::ArkError::Internal(
            "failed to post alert to Alertmanager after retries".into(),
        ))
    }
}

#[async_trait]
impl Alerts for PrometheusAlertsManager {
    async fn publish(&self, topic: AlertTopic, payload: serde_json::Value) -> ArkResult<()> {
        let alert = Self::build_alert(&topic, &payload);
        self.post_with_retry(&[alert]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_alert_has_expected_labels() {
        let payload = serde_json::json!({"round_id": "abc123"});
        let alert = PrometheusAlertsManager::build_alert(&AlertTopic::BatchFinalized, &payload);

        assert_eq!(alert.labels.get("service").unwrap(), "dark");
        assert_eq!(alert.labels.get("severity").unwrap(), "info");
        assert_eq!(alert.labels.get("topic").unwrap(), "Batch Finalized");
        assert!(alert.annotations.get("payload").unwrap().contains("abc123"));
    }

    #[test]
    fn build_alert_ark_tx_severity() {
        let payload = serde_json::json!({});
        let alert = PrometheusAlertsManager::build_alert(&AlertTopic::ArkTx, &payload);

        assert_eq!(alert.labels.get("severity").unwrap(), "warning");
        assert_eq!(alert.labels.get("topic").unwrap(), "Ark Tx");
    }

    #[test]
    fn endpoint_normalization() {
        let mgr = PrometheusAlertsManager::new("http://localhost:9093");
        assert_eq!(mgr.endpoint, "http://localhost:9093/api/v2/alerts");

        let mgr2 = PrometheusAlertsManager::new("http://localhost:9093/");
        assert_eq!(mgr2.endpoint, "http://localhost:9093/api/v2/alerts");

        let mgr3 = PrometheusAlertsManager::new("http://localhost:9093/api/v2/alerts");
        assert_eq!(mgr3.endpoint, "http://localhost:9093/api/v2/alerts");
    }
}
