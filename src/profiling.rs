//! Continuous profiling integration for arkd-rs.
//!
//! Provides two complementary profiling capabilities behind the `profiling` feature flag:
//!
//! 1. **Pyroscope continuous profiling** — When `pyroscope_url` is configured, a background
//!    agent continuously sends CPU profiling data to a Pyroscope server. Round-phase labels
//!    (idle, registration, signing, finalization) are attached for fine-grained analysis.
//!
//! 2. **On-demand pprof endpoint** — A `/debug/pprof` HTTP endpoint on the admin/monitoring
//!    port that captures a CPU profile for the requested duration and returns it as a
//!    protobuf-encoded pprof profile.
//!
//! See: <https://github.com/lobbyclawy/arkd-rs/issues/274>

/// Configuration for continuous profiling.
#[derive(Debug, Clone)]
pub struct ProfilingConfig {
    /// Pyroscope server URL (e.g. "http://localhost:4040").
    /// When `None`, continuous profiling is disabled.
    pub pyroscope_url: Option<String>,
    /// Application name reported to Pyroscope (default: "arkd-rs").
    pub pyroscope_app_name: String,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            pyroscope_url: None,
            pyroscope_app_name: "arkd-rs".to_string(),
        }
    }
}

/// Round phase labels for Pyroscope tag filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundPhase {
    Idle,
    Registration,
    Signing,
    Finalization,
}

impl RoundPhase {
    /// Returns the label value string for this phase.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Registration => "registration",
            Self::Signing => "signing",
            Self::Finalization => "finalization",
        }
    }
}

// ── Feature-gated implementations ──────────────────────────────────────

#[cfg(feature = "profiling")]
mod inner {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    use tracing::{info, warn};

    /// Global round-phase state for Pyroscope labels.
    static ROUND_PHASE: AtomicU8 = AtomicU8::new(0); // 0 = idle

    fn phase_from_u8(v: u8) -> RoundPhase {
        match v {
            1 => RoundPhase::Registration,
            2 => RoundPhase::Signing,
            3 => RoundPhase::Finalization,
            _ => RoundPhase::Idle,
        }
    }

    fn phase_to_u8(p: RoundPhase) -> u8 {
        match p {
            RoundPhase::Idle => 0,
            RoundPhase::Registration => 1,
            RoundPhase::Signing => 2,
            RoundPhase::Finalization => 3,
        }
    }

    /// Update the current round phase label for Pyroscope tagging.
    pub fn set_round_phase(phase: RoundPhase) {
        ROUND_PHASE.store(phase_to_u8(phase), Ordering::Relaxed);
    }

    /// Get the current round phase.
    pub fn current_round_phase() -> RoundPhase {
        phase_from_u8(ROUND_PHASE.load(Ordering::Relaxed))
    }

    /// Handle to the running Pyroscope agent. Drop to stop profiling.
    pub struct ProfilingAgent {
        _agent: pyroscope::PyroscopeAgent<pyroscope_pprofrs::Pprofrs>,
    }

    /// Start the Pyroscope continuous profiling agent.
    ///
    /// Returns `Some(ProfilingAgent)` on success, which keeps the agent alive.
    /// Returns `None` if `pyroscope_url` is not configured.
    pub fn start_pyroscope(config: &ProfilingConfig) -> Option<ProfilingAgent> {
        let url = config.pyroscope_url.as_ref()?;

        info!(
            url = %url,
            app_name = %config.pyroscope_app_name,
            "Starting Pyroscope continuous profiling agent"
        );

        let agent = pyroscope::PyroscopeAgent::builder(url, &config.pyroscope_app_name)
            .tags([("service", "arkd-rs")].to_vec())
            .backend(pyroscope_pprofrs::Pprofrs::new(
                pyroscope_pprofrs::PprofrsConfig::new().sample_rate(100),
            ))
            .build();

        match agent {
            Ok(agent) => match agent.start() {
                Ok(running) => {
                    info!("Pyroscope agent started successfully");
                    Some(ProfilingAgent { _agent: running })
                }
                Err(e) => {
                    warn!(error = %e, "Failed to start Pyroscope agent");
                    None
                }
            },
            Err(e) => {
                warn!(error = %e, "Failed to build Pyroscope agent");
                None
            }
        }
    }

    /// Build a pprof CPU profile for the given duration and return the
    /// protobuf-encoded bytes.
    pub async fn capture_pprof_profile(
        duration_secs: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let duration = std::time::Duration::from_secs(duration_secs);

        // pprof::ProfilerGuard is !Send, so run in a blocking task
        let bytes = tokio::task::spawn_blocking(
            move || -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
                let guard = pprof::ProfilerGuardBuilder::default()
                    .frequency(99)
                    .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                    .build()?;

                std::thread::sleep(duration);

                let report = guard.report().build()?;
                let mut body = Vec::new();
                report
                    .pprof()?
                    .write_to_vec(&mut body)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                Ok(body)
            },
        )
        .await??;

        Ok(bytes)
    }
}

#[cfg(not(feature = "profiling"))]
mod inner {
    use super::*;
    use tracing::info;

    /// No-op: set round phase when profiling is disabled.
    pub fn set_round_phase(_phase: RoundPhase) {}

    /// No-op: always returns Idle when profiling is disabled.
    pub fn current_round_phase() -> RoundPhase {
        RoundPhase::Idle
    }

    /// Stub Pyroscope agent handle.
    pub struct ProfilingAgent;

    /// No-op: returns `None` when profiling feature is disabled.
    pub fn start_pyroscope(config: &ProfilingConfig) -> Option<ProfilingAgent> {
        if config.pyroscope_url.is_some() {
            info!(
                "Pyroscope URL configured but `profiling` feature is not enabled. \
                 Rebuild with `--features profiling` to enable continuous profiling."
            );
        }
        None
    }

    /// Returns an error when profiling feature is disabled.
    pub async fn capture_pprof_profile(
        _duration_secs: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        Err("pprof endpoint requires the `profiling` feature flag".into())
    }
}

// Re-export from the active implementation
pub use inner::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_phase_as_str() {
        assert_eq!(RoundPhase::Idle.as_str(), "idle");
        assert_eq!(RoundPhase::Registration.as_str(), "registration");
        assert_eq!(RoundPhase::Signing.as_str(), "signing");
        assert_eq!(RoundPhase::Finalization.as_str(), "finalization");
    }

    #[test]
    fn test_default_profiling_config() {
        let config = ProfilingConfig::default();
        assert!(config.pyroscope_url.is_none());
        assert_eq!(config.pyroscope_app_name, "arkd-rs");
    }

    #[test]
    fn test_set_and_get_round_phase() {
        // Without profiling feature, these are no-ops but should not panic
        set_round_phase(RoundPhase::Registration);
        let phase = current_round_phase();
        // With profiling: Registration; without: always Idle
        #[cfg(feature = "profiling")]
        assert_eq!(phase, RoundPhase::Registration);
        #[cfg(not(feature = "profiling"))]
        assert_eq!(phase, RoundPhase::Idle);
    }

    #[test]
    fn test_start_pyroscope_no_url_returns_none() {
        let config = ProfilingConfig::default();
        assert!(start_pyroscope(&config).is_none());
    }
}
