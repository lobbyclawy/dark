//! Scheduled session configuration domain model.
//!
//! Represents the persisted configuration for automatic round scheduling,
//! including timing windows, period, duration, and participant limits.

use serde::{Deserialize, Serialize};

/// Persisted scheduled-session configuration.
///
/// When present, the ASP runs automatic rounds according to these parameters.
/// When absent (cleared), the ASP falls back to static config defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledSessionConfig {
    /// Round interval in seconds (how often a new round starts).
    pub round_interval_secs: u32,
    /// Round lifetime in seconds (how long a single round stays open).
    pub round_lifetime_secs: u32,
    /// Maximum number of intents accepted per round.
    pub max_intents_per_round: u32,
}

impl ScheduledSessionConfig {
    /// Create a new scheduled session configuration.
    pub fn new(
        round_interval_secs: u32,
        round_lifetime_secs: u32,
        max_intents_per_round: u32,
    ) -> Self {
        Self {
            round_interval_secs,
            round_lifetime_secs,
            max_intents_per_round,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduled_session_config_creation() {
        let config = ScheduledSessionConfig::new(10, 30, 128);
        assert_eq!(config.round_interval_secs, 10);
        assert_eq!(config.round_lifetime_secs, 30);
        assert_eq!(config.max_intents_per_round, 128);
    }

    #[test]
    fn test_scheduled_session_config_serde_roundtrip() {
        let config = ScheduledSessionConfig::new(15, 60, 256);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ScheduledSessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }
}
