//! Telemetry initialization for dark.
//!
//! Provides a unified tracing subscriber setup with optional OpenTelemetry
//! OTLP trace export.
//!
//! See: <https://github.com/lobbyclawy/dark/issues/245>

use anyhow::{Context, Result};
use opentelemetry::{global, trace::TracerProvider, KeyValue};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use tracing::info;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

/// Configuration for the telemetry subsystem.
#[derive(Debug, Clone)]
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

/// Owns OpenTelemetry resources that must be shut down when the process exits.
#[derive(Debug)]
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            if let Err(error) = provider.shutdown() {
                eprintln!("failed to shut down OpenTelemetry tracer provider: {error}");
            }
        }
    }
}

impl TelemetryGuard {
    fn disabled() -> Self {
        Self {
            tracer_provider: None,
        }
    }
}

fn build_env_filter(log_level: &str) -> Result<EnvFilter> {
    let default_directive = log_level
        .parse()
        .with_context(|| format!("invalid log level directive: {log_level}"))?;

    Ok(EnvFilter::from_default_env()
        .add_directive(default_directive)
        .add_directive("hyper=off".parse().expect("static directive is valid"))
        .add_directive("h2=off".parse().expect("static directive is valid"))
        .add_directive("reqwest=off".parse().expect("static directive is valid"))
        .add_directive("tonic=off".parse().expect("static directive is valid")))
}

fn build_resource(config: &TelemetryConfig) -> Resource {
    Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build()
}

fn build_tracer_provider(config: &TelemetryConfig, endpoint: &str) -> Result<SdkTracerProvider> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .context("failed to build OTLP span exporter")?;

    Ok(SdkTracerProvider::builder()
        .with_resource(build_resource(config))
        .with_batch_exporter(exporter)
        .build())
}

/// Initialize the global tracing subscriber.
///
/// Sets up:
/// - A console (fmt) layer that is always active.
/// - An env-filter layer using `log_level` plus loop-prevention directives for OTLP clients.
/// - An OpenTelemetry OTLP tracing layer when `otlp_endpoint` is provided.
///
/// # Errors
///
/// Returns an error if the log filter or OTLP exporter cannot be configured.
pub fn init_telemetry(config: &TelemetryConfig) -> Result<TelemetryGuard> {
    let env_filter = build_env_filter(&config.log_level)?;

    if let Some(endpoint) = config.otlp_endpoint.as_deref() {
        let tracer_provider = build_tracer_provider(config, endpoint)?;
        global::set_tracer_provider(tracer_provider.clone());

        let otel_layer: OpenTelemetryLayer<Registry, _> =
            tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("dark"));

        tracing_subscriber::registry()
            .with(otel_layer)
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();

        info!(endpoint = %endpoint, service = %config.service_name, "OpenTelemetry export enabled");

        return Ok(TelemetryGuard {
            tracer_provider: Some(tracer_provider),
        });
    }

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    Ok(TelemetryGuard::disabled())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_filter_accepts_plain_level() {
        build_env_filter("debug").expect("plain log level must parse");
    }

    #[test]
    fn env_filter_accepts_target_directive() {
        build_env_filter("dark_core=trace").expect("target directive must parse");
    }

    #[test]
    fn env_filter_rejects_invalid_directive() {
        let error = build_env_filter("not a directive").unwrap_err();
        assert!(
            error.to_string().contains("invalid log level directive"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn build_resource_sets_service_metadata() {
        let resource = build_resource(&TelemetryConfig {
            otlp_endpoint: Some("http://localhost:4317".to_string()),
            service_name: "dark-test".to_string(),
            log_level: "info".to_string(),
        });

        let rendered = format!("{resource:?}");
        assert!(rendered.contains("dark-test"));
        assert!(rendered.contains(env!("CARGO_PKG_VERSION")));
    }
}
