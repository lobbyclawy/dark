//! Conviction domain model — matches Go dark's conviction system.
//!
//! A conviction records a protocol violation by a participant (identified by
//! script). Convictions can be time-limited or permanent, and can be pardoned
//! by an operator.

use std::time::{SystemTime, UNIX_EPOCH};

/// The type of crime that led to a conviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrimeType {
    /// Unspecified crime type.
    Unspecified,
    /// Failed to submit MuSig2 nonce on time.
    Musig2NonceSubmission,
    /// Failed to submit MuSig2 signature on time.
    Musig2SignatureSubmission,
    /// Submitted an invalid MuSig2 signature.
    Musig2InvalidSignature,
    /// Failed to submit forfeit transaction.
    ForfeitSubmission,
    /// Submitted an invalid forfeit signature.
    ForfeitInvalidSignature,
    /// Failed to submit boarding input.
    BoardingInputSubmission,
    /// Manually banned by operator.
    ManualBan,
    /// Double-spend: same VTXO submitted in multiple intents.
    DoubleSpend,
}

impl std::fmt::Display for CrimeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "unspecified"),
            Self::Musig2NonceSubmission => write!(f, "musig2_nonce_submission"),
            Self::Musig2SignatureSubmission => write!(f, "musig2_signature_submission"),
            Self::Musig2InvalidSignature => write!(f, "musig2_invalid_signature"),
            Self::ForfeitSubmission => write!(f, "forfeit_submission"),
            Self::ForfeitInvalidSignature => write!(f, "forfeit_invalid_signature"),
            Self::BoardingInputSubmission => write!(f, "boarding_input_submission"),
            Self::ManualBan => write!(f, "manual_ban"),
            Self::DoubleSpend => write!(f, "double_spend"),
        }
    }
}

/// The type of conviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvictionKind {
    /// Unspecified.
    Unspecified,
    /// Script-based conviction (bans a specific script).
    Script,
}

/// A conviction record — tracks a protocol violation.
#[derive(Debug, Clone)]
pub struct Conviction {
    /// Unique conviction ID.
    pub id: String,
    /// Type of conviction.
    pub kind: ConvictionKind,
    /// Unix timestamp when the conviction was created.
    pub created_at: i64,
    /// Unix timestamp when the conviction expires (0 = never).
    pub expires_at: i64,
    /// Whether the conviction has been pardoned.
    pub pardoned: bool,
    /// The script that was convicted (only for script convictions).
    pub script: String,
    /// The type of crime.
    pub crime_type: CrimeType,
    /// The round ID during which the violation occurred.
    pub round_id: String,
    /// Human-readable reason for the conviction.
    pub reason: String,
}

impl Conviction {
    /// Create a new conviction for a detected crime.
    pub fn new_for_crime(
        script: &str,
        crime_type: CrimeType,
        round_id: &str,
        reason: &str,
        ban_duration_secs: i64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let expires_at = if ban_duration_secs == 0 {
            0 // permanent
        } else {
            now + ban_duration_secs
        };

        Self {
            id: uuid_v4(),
            kind: ConvictionKind::Script,
            created_at: now,
            expires_at,
            pardoned: false,
            script: script.to_string(),
            crime_type,
            round_id: round_id.to_string(),
            reason: reason.to_string(),
        }
    }

    /// Create a new conviction for a manual script ban.
    pub fn manual_ban(script: &str, reason: &str, ban_duration_secs: i64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let expires_at = if ban_duration_secs == 0 {
            0 // permanent
        } else {
            now + ban_duration_secs
        };

        Self {
            id: uuid_v4(),
            kind: ConvictionKind::Script,
            created_at: now,
            expires_at,
            pardoned: false,
            script: script.to_string(),
            crime_type: CrimeType::ManualBan,
            round_id: String::new(),
            reason: reason.to_string(),
        }
    }

    /// Whether the conviction is currently active (not expired, not pardoned).
    pub fn is_active(&self) -> bool {
        if self.pardoned {
            return false;
        }
        if self.expires_at == 0 {
            return true; // permanent
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        now < self.expires_at
    }
}

/// Simple UUID v4 generator (no external dependency).
fn uuid_v4() -> String {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_ban_permanent() {
        let c = Conviction::manual_ban("deadbeef", "spam", 0);
        assert_eq!(c.expires_at, 0);
        assert!(c.is_active());
        assert_eq!(c.crime_type, CrimeType::ManualBan);
        assert_eq!(c.kind, ConvictionKind::Script);
    }

    #[test]
    fn test_manual_ban_with_duration() {
        let c = Conviction::manual_ban("deadbeef", "spam", 3600);
        assert!(c.expires_at > 0);
        assert!(c.is_active());
    }

    #[test]
    fn test_pardoned_conviction_inactive() {
        let mut c = Conviction::manual_ban("deadbeef", "spam", 0);
        c.pardoned = true;
        assert!(!c.is_active());
    }

    #[test]
    fn test_crime_type_display() {
        assert_eq!(CrimeType::ManualBan.to_string(), "manual_ban");
        assert_eq!(
            CrimeType::Musig2NonceSubmission.to_string(),
            "musig2_nonce_submission"
        );
    }
}
