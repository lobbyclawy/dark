//! Validation entry-point for confidential off-chain transactions.
//!
//! # Status
//!
//! This module is a *stub* for the deliverable of issue **#538**. The real
//! body — verifying input nullifiers against the unique-nullifier set,
//! verifying every output's range proof, verifying the balance proof, and
//! enforcing fee policy — is being implemented on the
//! `feat/confidential-tx-validation` branch and is not on `tmp/cv-m3-base`
//! yet.
//!
//! The gRPC handler added by issue **#542** (`feat/grpc-submit-confidential-tx`)
//! depends on a stable signature for [`validate_confidential_transaction`] and
//! on the [`ValidationError`] enum so the wire-error mapping can be wired up
//! and tested *before* #538 lands. When #538 lands it MUST keep the same
//! function signature and the same `ValidationError` variants — additive
//! changes (more variants, more context fields) are fine, but removing or
//! renaming variants would force #542 to be re-coded.
//!
//! # Why a stub here, not in `dark-confidential`?
//!
//! `dark-core` deliberately does not depend on `dark-confidential` (see the
//! note on `domain::vtxo::ConfidentialPayload`). The validation entry-point
//! is the *coordinator* — it invokes range-proof / balance-proof verifiers
//! that ultimately live in `dark-confidential`, but it owns the cross-cutting
//! checks (nullifier-set lookups, fee policy, schema version) that need access
//! to `dark-core`'s ports / repositories. So the *signature* belongs in
//! `dark-core`; the cryptographic primitives it eventually calls into stay in
//! `dark-confidential`.
//!
//! The stub returns `ValidationError::NotImplemented` so callers exercising the
//! happy path will visibly fail (rather than silently appear to succeed) until
//! #538 lands.

use thiserror::Error;

/// Wire shape of a confidential transaction as observed by the validator.
///
/// This intentionally does **not** import the protobuf types — `dark-core`
/// must remain free of `dark-api`'s codegen — and instead carries the raw
/// canonical byte slices that were already validated for length by the gRPC
/// handler. #538 will likely refine this into a richer typed struct; until
/// then the fields below are sufficient for the handler to populate.
///
/// # Field semantics
///
/// - `nullifiers`: 32-byte HMAC-SHA256 outputs (per ADR-0002). The validator
///   will look each one up in the unique-nullifier set.
/// - `outputs`: each entry carries the Pedersen commitment + range-proof
///   bytes the gRPC handler received. Decoding lives in #538.
/// - `balance_proof`: opaque bytes per `BalanceProof.sig`.
/// - `fee_amount` / `schema_version`: copied verbatim from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialTxView {
    /// Input nullifiers in submission order.
    pub nullifiers: Vec<Vec<u8>>,
    /// Output range-proof + commitment payloads in submission order.
    pub outputs: Vec<ConfidentialOutputView>,
    /// Opaque balance-proof bytes.
    pub balance_proof: Vec<u8>,
    /// Plaintext fee in satoshis.
    pub fee_amount: u64,
    /// Wire-schema version (per `confidential_tx.proto`).
    pub schema_version: u32,
}

/// One output as observed by the validator. See [`ConfidentialTxView`] for the
/// rationale around using raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialOutputView {
    /// 33-byte Pedersen commitment.
    pub commitment: Vec<u8>,
    /// Opaque range-proof bytes.
    pub range_proof: Vec<u8>,
    /// 33-byte compressed owner pubkey.
    pub owner_pubkey: Vec<u8>,
    /// 33-byte compressed ephemeral (ECDH) pubkey.
    pub ephemeral_pubkey: Vec<u8>,
    /// Optional encrypted-memo ciphertext. Empty means "no memo".
    pub encrypted_memo: Vec<u8>,
}

/// A confidential transaction that has passed validation, ready to be persisted
/// by the higher-level handler (nullifier insertion, output VTXO creation,
/// event emission). #538 will fill this in; for the stub it carries an opaque
/// canonical txid string only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTx {
    /// Server-assigned ark transaction ID (hex string), derived deterministically
    /// from the input commitments + outputs by #538.
    pub ark_txid: String,
}

/// Reasons a confidential transaction can fail validation.
///
/// Variants map 1:1 to the wire `Error` enum in
/// `proto/ark/v1/confidential_tx.proto`. The mapping is exhaustive and is
/// pinned by [`crate::confidential_validation`] tests in the dark-api crate.
///
/// `NotImplemented` is the *only* variant that is not present on the wire — it
/// is returned by the stub here and is mapped to `Status::unimplemented` by
/// the handler. Once #538 lands, `NotImplemented` will only appear if a code
/// path is wired to the validator before its real body exists; production
/// builds will never see it.
///
/// Extending this enum: any new variant added by #538 MUST be additive, and
/// the gRPC handler in `dark-api` MUST be updated in the same change to map
/// the new variant to a `tonic::Status` code. CI should fail on a missing arm
/// because the match in the handler is exhaustive.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// One of the input nullifiers was already present in the unique-nullifier
    /// set (or appeared more than once in the request).
    #[error("nullifier already spent")]
    NullifierAlreadySpent,

    /// Server has no record of the VTXO referenced by an input nullifier.
    /// Distinct from `NullifierAlreadySpent`: this is "we never saw this VTXO",
    /// while that one is "we saw it and it was spent already".
    #[error("unknown input VTXO")]
    UnknownInputVtxo,

    /// At least one output range proof failed verification.
    #[error("invalid range proof")]
    InvalidRangeProof,

    /// The balance proof failed verification (Σinputs != Σoutputs + fee).
    #[error("invalid balance proof")]
    InvalidBalanceProof,

    /// An output had structurally invalid contents (wrong commitment length,
    /// missing required field, malformed pubkey, etc.). The gRPC handler does
    /// length-shape checks itself and only forwards semantic violations here.
    #[error("malformed output: {0}")]
    MalformedOutput(String),

    /// Fee was below the operator-configured floor (#536 / ADR-0004).
    #[error("fee below minimum")]
    FeeBelowMinimum,

    /// Fee exceeded the operator-configured cap. The cap exists to prevent a
    /// misbehaving client from burning an excessive fee on a single tx.
    #[error("fee above operator cap")]
    FeeAboveOperatorCap,

    /// `schema_version` not in the server's supported set.
    #[error("schema version mismatch")]
    SchemaVersionMismatch,

    /// Stub-only: the real validator has not landed yet (#538 in flight).
    /// Mapped to `Status::unimplemented` by the gRPC handler.
    #[error("validate_confidential_transaction not implemented (#538 in flight)")]
    NotImplemented,
}

/// Validate a confidential transaction.
///
/// # TODO(#538)
///
/// Replace the body with the real verifier:
///
/// 1. Reject duplicate / already-spent nullifiers (look up in the unique
///    nullifier set; insertion happens later after persistence).
/// 2. Fetch input VTXOs by nullifier and assert each is `Some` -> otherwise
///    `UnknownInputVtxo`.
/// 3. For each output, verify the Bulletproofs range proof against the
///    Pedersen commitment.
/// 4. Verify the Schnorr-like balance proof: Σ(inputs) == Σ(outputs) + fee*H.
/// 5. Enforce `MIN_FEE <= fee_amount <= OPERATOR_FEE_CAP`. The fee floor is
///    served by `dark-fee-manager` (#543, separate issue).
/// 6. Reject `schema_version` not in the supported set.
/// 7. On success, derive the canonical `ark_txid` and return `ValidatedTx`.
///
/// Until that lands, the stub returns `ValidationError::NotImplemented` so
/// callers crash visibly.
pub async fn validate_confidential_transaction(
    _tx: ConfidentialTxView,
) -> Result<ValidatedTx, ValidationError> {
    // #538 placeholder. See module-level docs and the #538 TODO above.
    Err(ValidationError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_returns_not_implemented() {
        // Until #538 lands, the validator must reject every input with
        // `NotImplemented`. This guards against the stub being silently
        // replaced by a no-op that pretends to accept everything.
        let view = ConfidentialTxView {
            nullifiers: vec![],
            outputs: vec![],
            balance_proof: vec![],
            fee_amount: 0,
            schema_version: 1,
        };
        let err = validate_confidential_transaction(view).await.unwrap_err();
        assert_eq!(err, ValidationError::NotImplemented);
    }

    #[test]
    fn validation_error_variants_are_distinct() {
        // Sanity-check: every variant has a distinct `Display` so log scrapers
        // and tests can pattern-match on the message safely.
        let msgs: Vec<String> = vec![
            ValidationError::NullifierAlreadySpent.to_string(),
            ValidationError::UnknownInputVtxo.to_string(),
            ValidationError::InvalidRangeProof.to_string(),
            ValidationError::InvalidBalanceProof.to_string(),
            ValidationError::MalformedOutput("x".into()).to_string(),
            ValidationError::FeeBelowMinimum.to_string(),
            ValidationError::FeeAboveOperatorCap.to_string(),
            ValidationError::SchemaVersionMismatch.to_string(),
            ValidationError::NotImplemented.to_string(),
        ];
        let mut sorted = msgs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(msgs.len(), sorted.len(), "duplicate Display strings");
    }
}
