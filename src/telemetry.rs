//! Telemetry initialization for dark.
//!
//! Provides a unified tracing subscriber setup with optional OpenTelemetry
//! OTLP export support (currently stubbed, ready to enable).
//!
//! See: <https://github.com/lobbyclawy/dark/issues/245>

use thiserror::Error;
use tracing::info;
use tracing_subscriber::{
    filter::ParseError, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

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

/// Errors returned while configuring telemetry.
#[derive(Debug, Error)]
pub enum TelemetryInitError {
    /// The configured log level or directive string could not be parsed.
    #[error("invalid telemetry log directive '{directive}': {source}")]
    InvalidDirective {
        directive: String,
        #[source]
        source: ParseError,
    },
    /// A global tracing subscriber was already installed earlier in the process.
    #[error("telemetry subscriber is already initialized")]
    AlreadyInitialized,
}

/// Initialize the global tracing subscriber.
///
/// Sets up:
/// - A console (fmt) layer that is always active.
/// - An env-filter layer using `log_level` plus per-crate directives.
/// - (Future) An OpenTelemetry OTLP layer when `otlp_endpoint` is provided.
///
/// `RUST_LOG` still applies and can add or override target-specific directives.
pub fn init_telemetry(config: &TelemetryConfig) -> Result<(), TelemetryInitError> {
    let env_filter = build_env_filter(config)?;

    // TODO(#245): When opentelemetry-otlp is added as a dependency, wire in
    // the OTLP tracing layer here, gated on `config.otlp_endpoint.is_some()`.
    //
    // Example (requires uncommenting deps in workspace Cargo.toml):
    // ```
    // if let Some(ref endpoint) = config.otlp_endpoint {
    //     let tracer = opentelemetry_otlp::new_pipeline()
    //         .tracing()
    //         .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(endpoint))
    //         .install_batch(opentelemetry::runtime::Tokio)
    //         .expect("failed to init OTel tracer");
    //     let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    //     // add otel_layer to the subscriber
    // }
    // ```

    if let Some(ref endpoint) = config.otlp_endpoint {
        info!(
            endpoint = %endpoint,
            "OpenTelemetry OTLP endpoint configured (export not yet active — enable crate deps)"
        );
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(env_filter)
        .try_init()
        .map_err(|_| TelemetryInitError::AlreadyInitialized)
}

fn build_env_filter(config: &TelemetryConfig) -> Result<EnvFilter, TelemetryInitError> {
    let mut env_filter = EnvFilter::from_default_env();

    for target in ["dark", "dark_api", "dark_core"] {
        let directive = format!("{target}={}", config.log_level);
        env_filter = env_filter.add_directive(directive.parse().map_err(|source| {
            TelemetryInitError::InvalidDirective {
                directive: directive.clone(),
                source,
            }
        })?);
    }

    Ok(env_filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_level(log_level: &str) -> TelemetryConfig {
        TelemetryConfig {
            log_level: log_level.to_string(),
            ..TelemetryConfig::default()
        }
    }

    #[test]
    fn builds_env_filter_for_supported_targets() {
        let filter = build_env_filter(&config_with_level("debug")).expect("filter should build");
        let rendered = filter.to_string();

        assert!(rendered.contains("dark=debug"));
        assert!(rendered.contains("dark_api=debug"));
        assert!(rendered.contains("dark_core=debug"));
    }

    #[test]
    fn rejects_invalid_log_directive() {
        let err = build_env_filter(&config_with_level("definitely-not-a-level"))
            .expect_err("invalid directive should be rejected");

        match err {
            TelemetryInitError::InvalidDirective { directive, .. } => {
                assert_eq!(directive, "dark=definitely-not-a-level");
            }
            other => panic!("expected invalid directive error, got {other:?}"),
        }
    }
}
