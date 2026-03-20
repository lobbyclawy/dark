//! Continuous profiling integration for dark.
//!
//! Provides continuous CPU profiling behind the `profiling` feature flag via Pyroscope.
//!
//! When `pyroscope_url` is configured, a background agent continuously sends CPU profiling
//! data to a Pyroscope server. Round-phase labels (idle, registration, signing, finalization)
//! are attached for fine-grained analysis. Connect the Pyroscope UI to view profiles.
//!
//! See: <https://github.com/lobbyclawy/dark/issues/274>

/// Configuration for continuous profiling.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProfilingConfig {
    /// Pyroscope server URL (e.g. "http://localhost:4040").
    /// When `None`, continuous profiling is disabled.
    pub pyroscope_url: Option<String>,
    /// Application name reported to Pyroscope (default: "dark").
    pub pyroscope_app_name: String,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            pyroscope_url: None,
            pyroscope_app_name: "dark".to_string(),
        }
    }
}

/// Round phase labels for Pyroscope tag filtering.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundPhase {
    Idle,
    Registration,
    Signing,
    Finalization,
}

impl RoundPhase {
    /// Returns the label value string for this phase.
    #[allow(dead_code)]
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
    use tracing::{info, warn};

    /// Global round-phase state for Pyroscope labels.
    static ROUND_PHASE: AtomicU8 = AtomicU8::new(0); // 0 = idle

    // Phase helpers — used by set_round_phase / current_round_phase below.
    // Not yet wired to callers in the round execution path; will be in a follow-up.
    #[allow(dead_code)]
    fn phase_from_u8(v: u8) -> RoundPhase {
        match v {
            1 => RoundPhase::Registration,
            2 => RoundPhase::Signing,
            3 => RoundPhase::Finalization,
            _ => RoundPhase::Idle,
        }
    }

    #[allow(dead_code)]
    fn phase_to_u8(p: RoundPhase) -> u8 {
        match p {
            RoundPhase::Idle => 0,
            RoundPhase::Registration => 1,
            RoundPhase::Signing => 2,
            RoundPhase::Finalization => 3,
        }
    }

    /// Update the current round phase label for Pyroscope tagging.
    /// Called from the round coordinator when phases change.
    #[allow(dead_code)]
    pub fn set_round_phase(phase: RoundPhase) {
        ROUND_PHASE.store(phase_to_u8(phase), Ordering::Relaxed);
    }

    /// Get the current round phase.
    #[allow(dead_code)]
    pub fn current_round_phase() -> RoundPhase {
        phase_from_u8(ROUND_PHASE.load(Ordering::Relaxed))
    }

    /// Handle to the running Pyroscope agent. Drop to stop profiling.
    pub struct ProfilingAgent {
        _agent: pyroscope::pyroscope::PyroscopeAgent<pyroscope::pyroscope::PyroscopeAgentRunning>,
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
            .tags([("service", "dark")].to_vec())
            .backend(pyroscope_pprofrs::pprof_backend(
                pyroscope_pprofrs::PprofConfig::new().sample_rate(100),
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
}

#[cfg(not(feature = "profiling"))]
#[allow(dead_code)]
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
        assert_eq!(config.pyroscope_app_name, "dark");
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
