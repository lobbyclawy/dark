//! Telemetry initialization for dark.
//!
//! Provides a unified tracing subscriber setup with optional OpenTelemetry
//! OTLP export support (currently stubbed, ready to enable).
//!
//! See: <https://github.com/lobbyclawy/dark/issues/245>

use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Configuration for the telemetry subsystem.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TelemetryConfig {
    /// Optional OTLP endpoint for OpenTelemetry export (e.g. "http://localhost:4317").
    /// When `None`, only the fmt (console) layer is enabled.
    pub otlp_endpoint: Option<String>,
    /// Service name reported to the collector.
    pub service_name: String,
    /// Log level filter string (e.g. "info", "debug", "dark=debug").
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            service_name: "dark".to_string(),
            log_level: "info".to_string(),
        }
    }
}

/// Initialize the global tracing subscriber.
///
/// Sets up:
/// - A console (fmt) layer that is always active.
/// - An env-filter layer using `log_level` plus per-crate directives.
/// - (Future) An OpenTelemetry OTLP layer when `otlp_endpoint` is provided.
///
/// # Panics
///
/// Panics if a global subscriber has already been set.
pub fn init_telemetry(config: &TelemetryConfig) {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(
            format!("dark={}", config.log_level)
                .parse()
                .expect("invalid log directive"),
        )
        .add_directive(
            format!("dark_api={}", config.log_level)
                .parse()
                .expect("invalid log directive"),
        )
        .add_directive(
            format!("dark_core={}", config.log_level)
                .parse()
                .expect("invalid log directive"),
        );

    // OTLP tracing layer wiring is tracked in issue #245 — once the
    // `opentelemetry-otlp` dependency lands it should be added to the
    // subscriber here, gated on `config.otlp_endpoint.is_some()`.

    if let Some(ref endpoint) = config.otlp_endpoint {
        info!(
            endpoint = %endpoint,
            "OpenTelemetry OTLP endpoint configured (export not yet active — enable crate deps)"
        );
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(env_filter)
        .init();
}
