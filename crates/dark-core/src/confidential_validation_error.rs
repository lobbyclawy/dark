//! Typed error surface for confidential transaction validation (issue #544).
//!
//! `ConfidentialValidationError` is the canonical error type emitted by the
//! confidential transaction validation pipeline (issue #538). Each variant
//! covers a distinct rejection branch and carries **structured, log-safe
//! context** so that operators can:
//!
//! - Match on a specific failure reason at API / RPC boundaries.
//! - Trace a rejection back to a VTXO id, transaction hash, nullifier, or
//!   fee/memo bound without scraping free-form strings.
//! - Aggregate failure rates per reason via the
//!   `confidential_validation_error_total{reason}` Prometheus counter.
//!
//! # Log hygiene contract
//!
//! Every field on every variant is intentionally bounded to data that is
//! safe to print, ship to a log aggregator, and graph on a Grafana panel.
//! In particular, the following items are **never** carried by this enum
//! and **must never** be added to it:
//!
//! - Blinding factors (`r`, `r'`, sum-of-blindings) used in Pedersen
//!   commitments. Leakage de-anonymises the amount immediately.
//! - One-time / ephemeral private keys used in ECDH or signing.
//! - Plaintext memos (only sizes are logged — see `MemoTooLarge`).
//! - Cleartext amounts (only fees, which are public, may be logged via
//!   `FeeTooLow`).
//!
//! See `docs/observability/confidential-validation-errors.md` for the
//! full review checklist and the Grafana panel suggestion.
//!
//! # Bridging from the in-flight `ValidationError` (issue #538)
//!
//! Issue #538 introduces a tighter, pipeline-local `ValidationError` enum
//! that mirrors a subset of these variants. When that lands, add a
//! `From<&ValidationError>` impl in this module so that the pipeline error
//! can surface through this richer enum without losing structured fields.
//! TODO(#538): wire that bridge once the upstream enum stabilises.

use thiserror::Error;

use crate::domain::vtxo::VtxoId;

/// Canonical typed error for confidential transaction validation failures.
///
/// All variants are constructable from validators in the confidential
/// pipeline (range proof verification, balance proof check, nullifier set
/// lookup, fee policy, memo length, commitment encoding, version
/// negotiation). The display strings follow the workspace
/// `docs/conventions/errors.md` rules: lowercase, sentence-form, no
/// trailing period.
///
/// Marked `#[non_exhaustive]` because the confidential validation pipeline
/// is expected to grow new branches over the CV-M3..M5 milestones.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfidentialValidationError {
    /// The bulletproof / range proof attached to a confidential output
    /// failed verification.
    ///
    /// `vtxo_id` is the public outpoint of the VTXO whose range proof was
    /// rejected. `commitment_hex` is the hex-encoded 33-byte Pedersen
    /// amount commitment — public by definition (it is broadcast as part
    /// of the VTXO).
    #[error("invalid range proof for vtxo {vtxo_id}, commitment {commitment_hex}")]
    InvalidRangeProof {
        /// Outpoint of the VTXO whose range proof failed.
        vtxo_id: VtxoId,
        /// Hex of the 33-byte Pedersen amount commitment (public).
        commitment_hex: String,
    },

    /// The aggregate balance proof (sum of input commitments minus sum of
    /// output commitments and fee) did not zero out.
    ///
    /// `tx_hash_hex` is the transaction identifier (hash of the public
    /// fields). No commitments, blindings, or amounts are carried.
    #[error("invalid balance proof for tx {tx_hash_hex}")]
    InvalidBalanceProof {
        /// Hex of the transaction hash (public).
        tx_hash_hex: String,
    },

    /// A spent nullifier was presented again, indicating a double-spend
    /// attempt against the global nullifier set.
    ///
    /// `nullifier_hex` is the 32-byte HMAC-SHA256 nullifier (ADR-0002).
    /// It is a public value once revealed by the spender; logging it is
    /// safe and lets operators correlate against the nullifier-set store.
    #[error("nullifier already spent: {nullifier_hex}")]
    NullifierAlreadySpent {
        /// Hex of the 32-byte nullifier (public on spend).
        nullifier_hex: String,
    },

    /// A transaction referenced an input VTXO that does not exist in the
    /// VTXO set (or has already been forgotten / pruned).
    #[error("unknown input vtxo: {vtxo_id}")]
    UnknownInputVtxo {
        /// Outpoint of the missing VTXO.
        vtxo_id: VtxoId,
    },

    /// The fee declared by the transaction is below the policy minimum.
    ///
    /// Fees in confidential transactions are **public** (only amounts and
    /// blinding factors are private), so logging both the provided and
    /// required fee is safe.
    #[error("fee too low: provided {provided_sats} sats, required {required_sats} sats")]
    FeeTooLow {
        /// Fee in satoshis declared by the transaction (public).
        provided_sats: u64,
        /// Fee in satoshis required by current policy (public).
        required_sats: u64,
    },

    /// The encrypted memo blob exceeds the per-tx policy ceiling.
    ///
    /// Only the byte sizes are logged. The plaintext memo and the
    /// ciphertext bytes are never included.
    #[error("memo too large: {actual_bytes} bytes, max {max_bytes}")]
    MemoTooLarge {
        /// Actual ciphertext size in bytes (length only — never content).
        actual_bytes: usize,
        /// Per-tx maximum ciphertext size from policy.
        max_bytes: usize,
    },

    /// A Pedersen commitment failed structural decoding (not a valid
    /// 33-byte compressed secp256k1 point, infinity, or otherwise
    /// malformed).
    ///
    /// `reason` is a short, controlled, human-readable tag (e.g.
    /// `"length"`, `"not on curve"`, `"infinity"`). It must never be a
    /// pass-through of attacker-supplied bytes.
    #[error("malformed commitment: {reason}")]
    MalformedCommitment {
        /// Controlled reason tag — see variant docs for allowed values.
        reason: String,
    },

    /// The client and server confidential protocol versions disagree and
    /// no negotiation path is available.
    #[error("protocol version mismatch: client={client_version}, server={server_version}")]
    VersionMismatch {
        /// Confidential protocol version advertised by the client.
        client_version: u32,
        /// Confidential protocol version supported by the server.
        server_version: u32,
    },
}

impl ConfidentialValidationError {
    /// Stable, low-cardinality reason label for metrics.
    ///
    /// Used as the `reason` label on the
    /// `confidential_validation_error_total{reason}` counter. The label
    /// set is fixed by this function so Prometheus cardinality stays
    /// bounded — never include `vtxo_id`, hashes, or sizes in the label.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRangeProof { .. } => "invalid_range_proof",
            Self::InvalidBalanceProof { .. } => "invalid_balance_proof",
            Self::NullifierAlreadySpent { .. } => "nullifier_already_spent",
            Self::UnknownInputVtxo { .. } => "unknown_input_vtxo",
            Self::FeeTooLow { .. } => "fee_too_low",
            Self::MemoTooLarge { .. } => "memo_too_large",
            Self::MalformedCommitment { .. } => "malformed_commitment",
            Self::VersionMismatch { .. } => "version_mismatch",
        }
    }

    /// Increment the
    /// `confidential_validation_error_total{reason}` Prometheus counter
    /// for this error and return `self` unchanged. Intended use:
    ///
    /// ```ignore
    /// return Err(ConfidentialValidationError::FeeTooLow {
    ///     provided_sats: 100,
    ///     required_sats: 500,
    /// }
    /// .observe());
    /// ```
    ///
    /// Centralising the counter increment on the error itself makes it
    /// impossible to forget the metric at a call-site.
    pub fn observe(self) -> Self {
        crate::metrics::record_confidential_validation_error(self.reason());
        self
    }
}

// TODO(#538): once the in-flight `ValidationError` enum lands, implement
// `From<&ValidationError> for ConfidentialValidationError` here so that
// pipeline errors flow into the canonical surface without losing
// structured fields. Searched local branches at the time of writing
// (`feat/confidential-tx-validation`) — no `enum ValidationError` was
// present (only a stringly-typed `ValidationError(String)` on
// `OffchainTxStage`), so the bridge is deferred.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vtxo::VtxoOutpoint;

    fn sample_vtxo_id() -> VtxoId {
        VtxoOutpoint::new("a".repeat(64), 7)
    }

    #[test]
    fn invalid_range_proof_carries_vtxo_and_commitment() {
        let vtxo_id = sample_vtxo_id();
        let err = ConfidentialValidationError::InvalidRangeProof {
            vtxo_id: vtxo_id.clone(),
            commitment_hex: "02".to_string() + &"ab".repeat(32),
        };

        match &err {
            ConfidentialValidationError::InvalidRangeProof {
                vtxo_id: id,
                commitment_hex,
            } => {
                assert_eq!(id, &vtxo_id);
                assert_eq!(commitment_hex.len(), 66);
            }
            _ => panic!("wrong variant"),
        }
        assert!(err.to_string().contains("invalid range proof"));
        assert_eq!(err.reason(), "invalid_range_proof");
    }

    #[test]
    fn invalid_balance_proof_carries_tx_hash() {
        let err = ConfidentialValidationError::InvalidBalanceProof {
            tx_hash_hex: "de".repeat(32),
        };
        match &err {
            ConfidentialValidationError::InvalidBalanceProof { tx_hash_hex } => {
                assert_eq!(tx_hash_hex.len(), 64);
            }
            _ => panic!("wrong variant"),
        }
        assert!(err.to_string().contains("invalid balance proof"));
        assert_eq!(err.reason(), "invalid_balance_proof");
    }

    #[test]
    fn nullifier_already_spent_carries_nullifier() {
        let err = ConfidentialValidationError::NullifierAlreadySpent {
            nullifier_hex: "00".repeat(32),
        };
        match &err {
            ConfidentialValidationError::NullifierAlreadySpent { nullifier_hex } => {
                assert_eq!(nullifier_hex.len(), 64);
            }
            _ => panic!("wrong variant"),
        }
        assert!(err.to_string().contains("nullifier already spent"));
        assert_eq!(err.reason(), "nullifier_already_spent");
    }

    #[test]
    fn unknown_input_vtxo_carries_outpoint() {
        let vtxo_id = sample_vtxo_id();
        let err = ConfidentialValidationError::UnknownInputVtxo {
            vtxo_id: vtxo_id.clone(),
        };
        match &err {
            ConfidentialValidationError::UnknownInputVtxo { vtxo_id: id } => {
                assert_eq!(id, &vtxo_id);
            }
            _ => panic!("wrong variant"),
        }
        assert!(err.to_string().contains("unknown input vtxo"));
        assert_eq!(err.reason(), "unknown_input_vtxo");
    }

    #[test]
    fn fee_too_low_carries_provided_and_required() {
        let err = ConfidentialValidationError::FeeTooLow {
            provided_sats: 100,
            required_sats: 500,
        };
        match &err {
            ConfidentialValidationError::FeeTooLow {
                provided_sats,
                required_sats,
            } => {
                assert_eq!(*provided_sats, 100);
                assert_eq!(*required_sats, 500);
                assert!(provided_sats < required_sats);
            }
            _ => panic!("wrong variant"),
        }
        assert!(err.to_string().contains("fee too low"));
        assert_eq!(err.reason(), "fee_too_low");
    }

    #[test]
    fn memo_too_large_carries_only_sizes() {
        let err = ConfidentialValidationError::MemoTooLarge {
            actual_bytes: 1024,
            max_bytes: 256,
        };
        match &err {
            ConfidentialValidationError::MemoTooLarge {
                actual_bytes,
                max_bytes,
            } => {
                assert_eq!(*actual_bytes, 1024);
                assert_eq!(*max_bytes, 256);
            }
            _ => panic!("wrong variant"),
        }
        let display = err.to_string();
        assert!(display.contains("memo too large"));
        // Sanity: log line must not include any fictional plaintext field.
        assert!(!display.to_lowercase().contains("plaintext"));
        assert_eq!(err.reason(), "memo_too_large");
    }

    #[test]
    fn malformed_commitment_carries_controlled_reason() {
        let err = ConfidentialValidationError::MalformedCommitment {
            reason: "not on curve".to_string(),
        };
        match &err {
            ConfidentialValidationError::MalformedCommitment { reason } => {
                assert_eq!(reason, "not on curve");
            }
            _ => panic!("wrong variant"),
        }
        assert!(err.to_string().contains("malformed commitment"));
        assert_eq!(err.reason(), "malformed_commitment");
    }

    #[test]
    fn version_mismatch_carries_versions() {
        let err = ConfidentialValidationError::VersionMismatch {
            client_version: 2,
            server_version: 1,
        };
        match &err {
            ConfidentialValidationError::VersionMismatch {
                client_version,
                server_version,
            } => {
                assert_eq!(*client_version, 2);
                assert_eq!(*server_version, 1);
            }
            _ => panic!("wrong variant"),
        }
        assert!(err.to_string().contains("protocol version mismatch"));
        assert_eq!(err.reason(), "version_mismatch");
    }

    #[test]
    fn reason_labels_are_unique_and_lowercase_snake() {
        let vtxo_id = sample_vtxo_id();
        let all = [
            ConfidentialValidationError::InvalidRangeProof {
                vtxo_id: vtxo_id.clone(),
                commitment_hex: "02".to_string(),
            },
            ConfidentialValidationError::InvalidBalanceProof {
                tx_hash_hex: "ab".to_string(),
            },
            ConfidentialValidationError::NullifierAlreadySpent {
                nullifier_hex: "ab".to_string(),
            },
            ConfidentialValidationError::UnknownInputVtxo {
                vtxo_id: vtxo_id.clone(),
            },
            ConfidentialValidationError::FeeTooLow {
                provided_sats: 1,
                required_sats: 2,
            },
            ConfidentialValidationError::MemoTooLarge {
                actual_bytes: 1,
                max_bytes: 0,
            },
            ConfidentialValidationError::MalformedCommitment {
                reason: "length".to_string(),
            },
            ConfidentialValidationError::VersionMismatch {
                client_version: 0,
                server_version: 0,
            },
        ];
        let labels: Vec<&'static str> = all.iter().map(|e| e.reason()).collect();
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len(), "labels must be unique");
        for label in &labels {
            assert!(
                label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "label {label} must be lowercase snake_case"
            );
        }
    }

    #[test]
    fn observe_increments_reason_counter() {
        // Use a variant that's unlikely to be shared with concurrent
        // tests in the same process — but tolerate concurrent increments
        // by snapshotting before/after and asserting strict-monotonic.
        let before =
            crate::metrics::confidential_validation_error_total_for("malformed_commitment");
        let returned = ConfidentialValidationError::MalformedCommitment {
            reason: "length".to_string(),
        }
        .observe();
        // observe() returns self unchanged
        assert_eq!(returned.reason(), "malformed_commitment");
        let after = crate::metrics::confidential_validation_error_total_for("malformed_commitment");
        assert!(
            after > before,
            "counter for malformed_commitment did not increment: {before} -> {after}"
        );
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ConfidentialValidationError>();
    }
}
