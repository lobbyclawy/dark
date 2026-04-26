//! Compliance bundle verifier — codec-agnostic dispatch over typed proofs.
//!
//! This module is the engine behind `ComplianceService::VerifyComplianceProof`
//! (#569). It is deliberately decoupled from gRPC concerns so it can be unit
//! tested without spinning up a server.
//!
//! ## Bundle format (pre-1.0)
//!
//! Until the compliance-bundle codec from #562 lands, bundles travel as a
//! UTF-8 JSON document of the shape:
//!
//! ```json
//! {
//!   "proofs": [
//!     { "proof_type": "source_of_funds", "payload": { ... } },
//!     { "proof_type": "...",            "payload": { ... } }
//!   ]
//! }
//! ```
//!
//! When #562 merges, replace [`decode_bundle`] with a call into the canonical
//! codec; nothing else in this module needs to change.
//!
//! ## Verifier dispatch
//!
//! Each known `proof_type` resolves to a [`ProofVerifier`] — a function from a
//! `serde_json::Value` payload to a `Result<(), String>`. Unknown proof types
//! are not an RPC error: they emit a [`ProofOutcome`] with `passed = false`
//! and a "unknown proof type …" reason, so a regulator's tool can surface
//! partial results.
//!
//! ## Stubbing
//!
//! The per-type verifiers are stubs in this milestone. They perform the cheap
//! structural checks the proofs from #565/#566/#567 will eventually require
//! and accept any payload that *looks* well-formed. Once those issues land,
//! swap the stub bodies for calls into the real verifiers — the dispatch
//! shape stays the same.

use serde::Deserialize;
use serde_json::Value;

/// One proof's verdict, ready to be turned into a wire `ProofResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOutcome {
    /// Zero-based position of the proof in the bundle.
    pub proof_index: u32,
    /// Type tag carried by the bundle (e.g. "source_of_funds").
    pub proof_type: String,
    /// True iff the type-specific verifier accepted the proof.
    pub passed: bool,
    /// Human-readable failure reason. `None` on success.
    pub error: Option<String>,
}

/// A type-specific proof verifier. Returns `Ok(())` if the proof passes, or
/// an error string that will be surfaced verbatim to the caller.
pub type ProofVerifier = fn(&Value) -> Result<(), String>;

/// Errors that prevent the bundle from being decoded at all. These map onto
/// `Status::invalid_argument` at the gRPC layer because the request itself is
/// malformed (no per-proof results can be produced).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleDecodeError {
    /// Bundle bytes were empty.
    #[error("bundle is empty")]
    Empty,
    /// Bundle bytes were not valid UTF-8 JSON.
    #[error("bundle is not valid UTF-8 JSON: {0}")]
    NotJson(String),
    /// Bundle JSON parsed but did not match the expected envelope shape.
    #[error("bundle has unexpected shape: {0}")]
    BadShape(String),
}

/// Decoded bundle: a flat list of `(proof_type, payload)` pairs in bundle
/// order. This is the contract between the codec layer and the dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBundle {
    /// Proofs in bundle order, each tagged with its type identifier.
    pub proofs: Vec<TaggedProof>,
}

/// One proof inside a decoded bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedProof {
    /// Proof type tag (e.g. "source_of_funds").
    pub proof_type: String,
    /// Opaque proof payload, decoded by the type-specific verifier.
    pub payload: Value,
}

/// Wire envelope used by the pre-1.0 JSON codec. Replace with the #562 codec
/// once it lands.
#[derive(Deserialize)]
struct BundleEnvelope {
    proofs: Vec<EnvelopeProof>,
}

#[derive(Deserialize)]
struct EnvelopeProof {
    proof_type: String,
    payload: Value,
}

/// Decode a serialized bundle into the canonical `(proof_type, payload)` list.
///
/// Replace with `dark_confidential::compliance_bundle::decode` when #562 lands.
pub fn decode_bundle(bytes: &[u8]) -> Result<DecodedBundle, BundleDecodeError> {
    if bytes.is_empty() {
        return Err(BundleDecodeError::Empty);
    }
    let envelope: BundleEnvelope = serde_json::from_slice(bytes).map_err(|e| {
        if e.is_syntax() || e.is_eof() {
            BundleDecodeError::NotJson(e.to_string())
        } else {
            BundleDecodeError::BadShape(e.to_string())
        }
    })?;
    Ok(DecodedBundle {
        proofs: envelope
            .proofs
            .into_iter()
            .map(|p| TaggedProof {
                proof_type: p.proof_type,
                payload: p.payload,
            })
            .collect(),
    })
}

/// Resolve the verifier for a known proof type. Returns `None` for unknown
/// types so the caller can produce a structured "unknown type" outcome.
pub fn verifier_for(proof_type: &str) -> Option<ProofVerifier> {
    match proof_type {
        "source_of_funds" => Some(verify_source_of_funds_stub),
        "non_inclusion" => Some(verify_non_inclusion_stub),
        "balance_within_range" => Some(verify_balance_within_range_stub),
        _ => None,
    }
}

/// Verify every proof in a decoded bundle, preserving bundle ordering.
pub fn verify_bundle(bundle: &DecodedBundle) -> Vec<ProofOutcome> {
    bundle
        .proofs
        .iter()
        .enumerate()
        .map(|(idx, proof)| evaluate_proof(idx, proof))
        .collect()
}

fn evaluate_proof(idx: usize, proof: &TaggedProof) -> ProofOutcome {
    let verifier = match verifier_for(&proof.proof_type) {
        Some(v) => v,
        None => {
            return ProofOutcome {
                proof_index: idx as u32,
                proof_type: proof.proof_type.clone(),
                passed: false,
                error: Some(format!("unknown proof type: {}", proof.proof_type)),
            };
        }
    };
    let (passed, error) = match verifier(&proof.payload) {
        Ok(()) => (true, None),
        Err(reason) => (false, Some(reason)),
    };
    ProofOutcome {
        proof_index: idx as u32,
        proof_type: proof.proof_type.clone(),
        passed,
        error,
    }
}

// ─── Stub verifiers ────────────────────────────────────────────────────────
//
// Each stub performs only the cheap structural check that the real verifier
// will require, and accepts any payload that looks well-formed. Once the
// upstream issues land, replace each body with a call into the real verifier.
//
// Every stub honours a `tampered: true` flag in the payload — this is the
// hook integration tests use to drive the per-proof failure path without
// pulling in real cryptography. Real verifiers will not have this hook.

/// Returns true when the payload carries a test-only `tampered: true` flag.
fn payload_is_tampered(payload: &Value) -> bool {
    payload
        .get("tampered")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Returns the value of a top-level string field, or an empty string when
/// absent or not a string.
fn payload_str<'a>(payload: &'a Value, key: &str) -> &'a str {
    payload.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Stub for #567 source-of-funds proofs. Accepts payloads whose `commitment_path`
/// is a non-empty array and whose `owner_signature` is a non-empty hex string.
fn verify_source_of_funds_stub(payload: &Value) -> Result<(), String> {
    if payload_is_tampered(payload) {
        return Err("source_of_funds: signature does not bind proof contents".to_string());
    }
    let commitment_path = payload
        .get("commitment_path")
        .and_then(Value::as_array)
        .ok_or_else(|| "source_of_funds: commitment_path must be a non-empty array".to_string())?;
    if commitment_path.is_empty() {
        return Err("source_of_funds: commitment_path must be a non-empty array".to_string());
    }
    if payload_str(payload, "owner_signature").is_empty() {
        return Err("source_of_funds: owner_signature is required".to_string());
    }
    Ok(())
}

/// Stub for #565 non-inclusion proofs. Accepts payloads with a non-empty
/// `nullifier` field.
fn verify_non_inclusion_stub(payload: &Value) -> Result<(), String> {
    if payload_is_tampered(payload) {
        return Err("non_inclusion: nullifier appears in the spent set".to_string());
    }
    if payload_str(payload, "nullifier").is_empty() {
        return Err("non_inclusion: nullifier is required".to_string());
    }
    Ok(())
}

/// Stub for #566 balance-within-range proofs. Accepts payloads with a
/// non-empty `commitment` field.
fn verify_balance_within_range_stub(payload: &Value) -> Result<(), String> {
    if payload_is_tampered(payload) {
        return Err("balance_within_range: commitment is outside the asserted range".to_string());
    }
    if payload_str(payload, "commitment").is_empty() {
        return Err("balance_within_range: commitment is required".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bundle_with(proofs: Vec<Value>) -> Vec<u8> {
        json!({ "proofs": proofs }).to_string().into_bytes()
    }

    #[test]
    fn decode_rejects_empty_bytes() {
        assert_eq!(decode_bundle(&[]).unwrap_err(), BundleDecodeError::Empty);
    }

    #[test]
    fn decode_rejects_non_json_bytes() {
        let err = decode_bundle(b"not-json").unwrap_err();
        assert!(matches!(err, BundleDecodeError::NotJson(_)));
    }

    #[test]
    fn decode_rejects_wrong_shape() {
        let err = decode_bundle(br#"{"proofs": [{"missing_proof_type": true}]}"#).unwrap_err();
        assert!(matches!(err, BundleDecodeError::BadShape(_)));
    }

    #[test]
    fn known_good_bundle_passes_every_proof() {
        let bytes = bundle_with(vec![
            json!({
                "proof_type": "source_of_funds",
                "payload": {
                    "commitment_path": ["c0", "c1"],
                    "owner_signature": "deadbeef",
                },
            }),
            json!({
                "proof_type": "non_inclusion",
                "payload": { "nullifier": "0x01" },
            }),
            json!({
                "proof_type": "balance_within_range",
                "payload": { "commitment": "0x02" },
            }),
        ]);
        let outcomes = verify_bundle(&decode_bundle(&bytes).unwrap());
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes.iter().all(|o| o.passed));
        assert!(outcomes.iter().all(|o| o.error.is_none()));
        assert_eq!(
            outcomes.iter().map(|o| o.proof_index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn tampered_proof_fails_with_reason() {
        let bytes = bundle_with(vec![json!({
            "proof_type": "source_of_funds",
            "payload": {
                "commitment_path": ["c0"],
                "owner_signature": "deadbeef",
                "tampered": true,
            },
        })]);
        let outcomes = verify_bundle(&decode_bundle(&bytes).unwrap());
        let only = outcomes.first().unwrap();
        assert!(!only.passed);
        assert!(only.error.as_ref().unwrap().contains("does not bind"));
    }

    #[test]
    fn unknown_proof_type_is_reported_not_panicked() {
        let bytes = bundle_with(vec![json!({
            "proof_type": "made_up_proof",
            "payload": {},
        })]);
        let outcomes = verify_bundle(&decode_bundle(&bytes).unwrap());
        let only = outcomes.first().unwrap();
        assert!(!only.passed);
        assert!(only.error.as_ref().unwrap().contains("unknown proof type"));
        assert_eq!(only.proof_type, "made_up_proof");
    }

    #[test]
    fn results_preserve_bundle_order_when_some_fail() {
        let bytes = bundle_with(vec![
            json!({
                "proof_type": "non_inclusion",
                "payload": { "nullifier": "ok" },
            }),
            json!({
                "proof_type": "non_inclusion",
                "payload": { "nullifier": "x", "tampered": true },
            }),
            json!({
                "proof_type": "made_up_proof",
                "payload": {},
            }),
        ]);
        let outcomes = verify_bundle(&decode_bundle(&bytes).unwrap());
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes[0].passed);
        assert!(!outcomes[1].passed);
        assert!(!outcomes[2].passed);
        assert_eq!(outcomes[2].proof_type, "made_up_proof");
    }
}
