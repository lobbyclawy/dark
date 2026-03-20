//! HTTP server for health checks and Prometheus metrics.
//!
//! Runs on a separate port (default 9090) from the gRPC services,
//! providing:
//! - `GET /health` — JSON health check for Docker/Kubernetes probes
//! - `GET /metrics` — Prometheus text exposition format

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Health check response body.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Service status: "ok" or "degraded"
    pub status: &'static str,
    /// Server version
    pub version: &'static str,
    /// Seconds since server start
    pub uptime_secs: u64,
}

/// Shared state for the monitoring server.
#[derive(Clone)]
struct MonitoringState {
    start_time: Instant,
}

/// Configuration for the monitoring HTTP server.
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// Listen address for the monitoring server (default: 0.0.0.0:9090)
    pub addr: String,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:9090".to_string(),
        }
    }
}

/// GET /health handler
async fn health_handler(State(state): State<Arc<MonitoringState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let response = HealthResponse {
        status: "ok",
        version: arkd_core::VERSION,
        uptime_secs: uptime,
    };
    (StatusCode::OK, Json(response))
}

/// Query parameters for the pprof endpoint.
#[derive(serde::Deserialize)]
struct PprofParams {
    /// Profile duration in seconds (default: 30, max: 300).
    seconds: Option<u64>,
}

/// GET /debug/pprof — capture an on-demand CPU profile.
///
/// Returns a protobuf-encoded pprof profile. Use with `go tool pprof` or
/// compatible viewers. Requires the `profiling` feature flag.
///
/// Query params:
/// - `seconds` — profile duration (default 30, max 300)
#[cfg(feature = "profiling")]
async fn pprof_handler(Query(params): Query<PprofParams>) -> impl IntoResponse {
    let seconds = params.seconds.unwrap_or(30).min(300).max(1);

    info!(duration_secs = seconds, "Starting on-demand CPU profile");

    let result: Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> =
        tokio::task::spawn_blocking(move || {
            let guard = pprof::ProfilerGuardBuilder::default()
                .frequency(99)
                .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                .build()?;

            std::thread::sleep(std::time::Duration::from_secs(seconds));

            let report = guard.report().build()?;
            let profile = report.pprof()?;
            let mut body = Vec::new();
            profile
                .write_to_vec(&mut body)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            Ok(body)
        })
        .await
        .unwrap_or_else(|e| Err(Box::new(e) as _));

    match result {
        Ok(body) => (
            StatusCode::OK,
            [("content-type", "application/vnd.google.protobuf")],
            body,
        )
            .into_response(),
        Err(e) => {
            let msg = format!("pprof capture failed: {e}");
            tracing::warn!("{}", msg);
            (StatusCode::SERVICE_UNAVAILABLE, msg).into_response()
        }
    }
}

/// GET /debug/pprof — stub when profiling feature is disabled.
#[cfg(not(feature = "profiling"))]
async fn pprof_handler() -> impl IntoResponse {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "pprof endpoint requires the `profiling` feature flag. Rebuild with `--features profiling`.",
    )
}

/// GET /metrics handler — returns Prometheus text format
async fn metrics_handler() -> impl IntoResponse {
    let body = arkd_core::metrics::encode_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

/// Spawn the monitoring HTTP server.
///
/// Returns a `JoinHandle` that resolves when the server exits.
pub fn spawn_monitoring_server(
    config: MonitoringConfig,
    cancel: CancellationToken,
) -> Result<JoinHandle<()>, crate::ApiError> {
    let addr: SocketAddr = config
        .addr
        .parse()
        .map_err(|e| crate::ApiError::StartupError(format!("Invalid monitoring address: {e}")))?;

    let state = Arc::new(MonitoringState {
        start_time: Instant::now(),
    });

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/debug/pprof", get(pprof_handler))
        .with_state(state);

    info!(%addr, "Spawning monitoring HTTP server (/health, /metrics)");

    let handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("bind monitoring address");
        axum::serve(listener, app)
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await
            .expect("monitoring server error");
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_monitoring_config() {
        let config = MonitoringConfig::default();
        assert_eq!(config.addr, "0.0.0.0:9090");
    }

    #[tokio::test]
    async fn test_health_response_format() {
        let state = Arc::new(MonitoringState {
            start_time: Instant::now(),
        });
        let app = Router::new()
            .route("/health", get(health_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(cancel2.cancelled_owned())
                .await
                .unwrap();
        });

        // Make a request
        let resp = reqwest::get(format!("http://{}/health", addr))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], "0.1.0");
        assert!(body["uptime_secs"].is_number());

        cancel.cancel();
        let _ = server.await;
    }
}
