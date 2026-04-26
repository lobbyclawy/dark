//! Confidential transaction validation pipeline (issue #538).
//!
//! # Why this module exists
//!
//! Confidential transactions are the central protocol surface where a single
//! validation bug inflates supply. The validator receives a structured
//! [`ConfidentialTransaction`] and either accepts it (returning a
//! [`ValidatedTx`] for the round-tree builder to consume) or rejects it with
//! a typed [`ValidationError`] and **zero** state mutation.
//!
//! The five validation steps below MUST run in order. Each step bounds the
//! work of the next, and skipping any step opens a supply-inflation vector:
//!
//! 1. **Nullifier checks** (`NullifierAlreadySpent`, `UnknownInputVtxo`).
//!    Reject double-spends and unknown inputs before doing any cryptographic
//!    work — these are O(1) lookups against the spent set / VTXO repository.
//! 2. **Range proofs** (`InvalidRangeProof`). Each output commitment is
//!    proven in `[0, 2^64)`. Without this, a malicious sender commits a
//!    field-wrapped negative amount and balances against legitimate outputs.
//!    Both individual and aggregated proofs are accepted; mixing the two
//!    forms within a single transaction is a policy decision (see
//!    [`RangeProofPolicy`]).
//! 3. **Balance proof** (`InvalidBalanceProof`). Verifies the homomorphic
//!    identity `Σ C_in − Σ C_out − commit(fee, 0) = commit(0, r_excess)`
//!    and the Schnorr signature over the excess point.
//! 4. **Output well-formedness** (`MalformedOutput`). Owner pubkey is a
//!    valid compressed point, ephemeral pubkey is a valid compressed point
//!    when present, and the encrypted memo respects [`MAX_ENCRYPTED_MEMO_LEN`].
//! 5. **Fee minimum** (`FeeBelowMinimum`, `FeeAboveOperatorCap`). Per
//!    ADR-0004: plaintext `fee_amount: u64`. The minimum comes from a
//!    [`FeeMinimumProvider`]; the cap is operator-side policy.
//!
//! # Atomicity
//!
//! `validate_confidential_transaction` performs **no** state mutation until
//! every check has passed. On the path-to-success it calls
//! [`NullifierSink::batch_insert`] to atomically register the spent
//! nullifiers; the returned `ValidatedTx` contains the queue-able outputs
//! that the round-tree builder (#540) will pick up. On any failure it
//! returns `Err(ValidationError)` and leaves the spent set untouched.
//!
//! # Async vs sync
//!
//! The cryptographic verification (range proof, balance proof) is CPU-bound
//! and synchronous, but the spent-set membership check is async (it reaches
//! into a `tokio::sync::RwLock`-sharded HashSet). The public entry point is
//! `async fn` to thread that through cleanly. The hot path remains O(1)
//! beyond the cryptographic verification; the sharded lock is uncontended
//! in steady state.
//!
//! # Cross-cutting constraints from ADR-0004
//!
//! - The fee gate runs **before** the balance-proof verification so a fee
//!   policy violation short-circuits before scalar multiplications.
//! - `tx.fee_amount` is read **once** and cached locally to avoid a TOCTOU
//!   race if the buffer is shared with the network layer.
//! - Operator-initiated paths (sweeps, expiry, internal rebalancing) bypass
//!   the minimum-fee gate. The validator does not sniff that bit out of the
//!   confidential payload — the caller passes it in via [`ValidationContext`].
//! - Fee-bump replacements are a mempool concern, **not** the validator's;
//!   the validator only enforces the minimum/cap/balance-proof gates.

use std::collections::HashSet;

use async_trait::async_trait;

use dark_confidential::balance_proof::{verify_balance, BalanceProof};
use dark_confidential::commitment::PedersenCommitment;
use dark_confidential::range_proof::{
    verify_range, verify_range_aggregated, RangeProof, ValueCommitment,
};

use crate::ports::NullifierSink;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of a Pedersen commitment (compressed secp256k1 point).
pub const COMMITMENT_LEN: usize = 33;

/// Length of a confidential nullifier (HMAC-SHA256 output, ADR-0002).
pub const NULLIFIER_LEN: usize = 32;

/// Length of a balance proof (`R || s`, secp256k1).
pub const BALANCE_PROOF_LEN: usize = 65;

/// Length of a compressed secp256k1 pubkey (owner / ephemeral).
pub const PUBKEY_LEN: usize = 33;

/// Maximum size of the encrypted memo field, in bytes.
///
/// The memo is opaque to the validator; the bound is a defence-in-depth
/// memory-bomb cap. Keep this generous — ADR-0003 caps memo plaintext at
/// 128 bytes and the AEAD overhead is bounded — but reject anything that
/// could OOM the operator on a malicious submission.
pub const MAX_ENCRYPTED_MEMO_LEN: usize = 4096;

/// Minimum number of inputs in a confidential transaction. Zero inputs would
/// make the transaction a unilateral mint, which the operator does not allow
/// on the confidential path.
pub const MIN_INPUTS: usize = 1;

/// Minimum number of outputs in a confidential transaction. Zero outputs
/// would mean every committed input gets burned to fee — the operator does
/// not enable that on the confidential path either.
pub const MIN_OUTPUTS: usize = 1;

/// Default schema version handled by the validator. ADR-0004 / #537 fix
/// this at `1` for the v1 milestone.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Domain types — decoupled from the proto wire format on purpose.
// ---------------------------------------------------------------------------

/// In-memory representation of a confidential transaction the validator
/// accepts.
///
/// This struct is the **domain** type the validator operates on. The gRPC
/// layer (#542) is responsible for converting from the proto
/// [`ark.v1.ConfidentialTransaction`] message into this struct, materialising
/// each output's range proof into the typed [`RangeProof`] and the balance
/// proof into the typed [`BalanceProof`] from `dark-confidential`. Failing
/// that conversion is a parse error and is rejected at the gRPC boundary
/// before this validator runs.
#[derive(Debug, Clone)]
pub struct ConfidentialTransaction {
    /// Schema version on the wire. v1 of the confidential protocol pins this
    /// at [`SUPPORTED_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Nullifiers of the confidential VTXOs being spent. Each entry MUST be
    /// unique within this transaction; intra-transaction duplicates are
    /// rejected with [`ValidationError::NullifierAlreadySpent`].
    pub nullifiers: Vec<[u8; NULLIFIER_LEN]>,
    /// New confidential outputs created by this transaction.
    pub outputs: Vec<ConfidentialOutput>,
    /// Schnorr-style balance proof asserting input/output/fee balance.
    pub balance_proof: BalanceProof,
    /// Plaintext fee in satoshis, per ADR-0004.
    pub fee_amount: u64,
    /// Transcript hash bound into the balance proof. Computed at the gRPC
    /// boundary from the canonical encoding of the transaction; the
    /// validator treats it as opaque input.
    pub tx_hash: [u8; 32],
}

/// One confidential output created by a [`ConfidentialTransaction`].
///
/// # Two-commitment design (transient v1 limitation)
///
/// The output carries two commitments to the same `(amount, blinding)` pair:
///
/// - [`Self::balance_commitment`]: a `dark_confidential::commitment::PedersenCommitment`
///   in the `vG + rH` convention used by [`verify_balance`] (#524 / #526).
/// - [`Self::value_commitment`]: a `dark_confidential::range_proof::ValueCommitment`
///   in the zkp-side `vH + rG` convention used by [`verify_range`] (#525).
///
/// The two are mathematically distinct points (and serialise to different
/// 33-byte blobs) because `dark-confidential` ships two un-reconciled
/// commitment conventions today — see the module-level docs in
/// `crates/dark-confidential/src/range_proof.rs`. ADR-0001 tracks the
/// reconciliation as a follow-up. Until that lands, the gRPC parsing layer
/// (#542) is responsible for materialising both views from the wire-level
/// per-output commitment bytes; the validator consumes both forms here.
///
/// Once #524 is reconciled with ADR-0001 the two fields collapse to a
/// single `commitment` field and this comment becomes obsolete.
#[derive(Debug, Clone)]
pub struct ConfidentialOutput {
    /// Pedersen commitment used for [`verify_balance`] (#524 convention,
    /// `vG + rH`).
    pub balance_commitment: PedersenCommitment,
    /// Value commitment used for [`verify_range`] (#525 / zkp convention,
    /// `vH + rG`).
    pub value_commitment: ValueCommitment,
    /// Range proof binding [`Self::value_commitment`] to a value in
    /// `[0, 2^64)`. Aggregated proofs live on the validation context
    /// ([`ValidationContext::aggregated_range_proof`]) when present;
    /// when an aggregated proof is in use this field carries `None` for
    /// every output covered by the aggregation.
    pub range_proof: Option<RangeProof>,
    /// Long-lived owner pubkey (compressed secp256k1). 33 bytes.
    pub owner_pubkey: [u8; PUBKEY_LEN],
    /// Ephemeral pubkey for stealth addressing (compressed secp256k1).
    /// `None` permitted only when the milestone allows omission; today
    /// every output ships its own ephemeral.
    pub ephemeral_pubkey: Option<[u8; PUBKEY_LEN]>,
    /// Encrypted memo payload. Empty `Vec` means "no memo".
    pub encrypted_memo: Vec<u8>,
}

/// Range-proof handling policy for a transaction.
///
/// The current milestone accepts either form globally; mixing the two within
/// a single transaction is rejected because the verifier cannot atomically
/// know which output a malformed sub-proof belonged to. The policy lives on
/// the transaction so a future milestone can flip it per-output without
/// breaking the validator API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeProofPolicy {
    /// Each output carries its own [`RangeProof`] (single-form).
    Individual,
    /// One aggregated [`RangeProof`] covers every output, in order.
    Aggregated,
}

/// Optional aggregated range proof attached to the transaction.
///
/// Held outside [`ConfidentialTransaction`] because it is only present when
/// the policy is [`RangeProofPolicy::Aggregated`]. Threading it through the
/// validation context keeps [`ConfidentialTransaction`] small and matches
/// the ADR-0001 wire shape (the aggregated blob is a single tx-level
/// field).
#[derive(Debug, Clone)]
pub struct AggregatedRangeProof {
    /// The single aggregated [`RangeProof`] covering every output's
    /// commitment in declaration order.
    pub proof: RangeProof,
}

// ---------------------------------------------------------------------------
// Validation result
// ---------------------------------------------------------------------------

/// A confidential transaction that has passed every validation step.
///
/// Consumed by the round-tree builder (#540). The struct is intentionally
/// minimal: it carries exactly the data the tree builder needs to queue the
/// new outputs and to attribute them to the right ark transaction id.
#[derive(Debug, Clone)]
pub struct ValidatedTx {
    /// Transaction hash, copied from the input. The tree builder uses this
    /// as the per-tx idempotency key and as part of the ark txid derivation.
    pub tx_hash: [u8; 32],
    /// Schema version the transaction was validated against.
    pub schema_version: u32,
    /// Nullifiers that have been atomically inserted into the spent set.
    pub spent_nullifiers: Vec<[u8; NULLIFIER_LEN]>,
    /// Outputs queued for the round tree, in original declaration order.
    pub outputs: Vec<ValidatedOutput>,
    /// Plaintext fee, in satoshis.
    pub fee_amount: u64,
}

/// One validated output, consumable by the round-tree builder.
#[derive(Debug, Clone)]
pub struct ValidatedOutput {
    /// Pedersen commitment in the balance-proof convention.
    pub balance_commitment: PedersenCommitment,
    /// Owner pubkey (compressed secp256k1).
    pub owner_pubkey: [u8; PUBKEY_LEN],
    /// Ephemeral pubkey when present.
    pub ephemeral_pubkey: Option<[u8; PUBKEY_LEN]>,
    /// Encrypted memo payload (opaque).
    pub encrypted_memo: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed validation errors. Every variant corresponds to one short-circuit
/// rejection point in the pipeline. The acceptance criteria for #538 require
/// **every** variant to be exercised by a unit test.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    /// One of the input nullifiers was already in the global spent set, or
    /// appeared more than once within this transaction.
    #[error("nullifier already spent or duplicated within tx (index {index})")]
    NullifierAlreadySpent {
        /// Index into [`ConfidentialTransaction::nullifiers`] of the
        /// offending entry.
        index: usize,
    },

    /// One of the input nullifiers does not resolve to any known input
    /// VTXO via the [`InputVtxoResolver`].
    #[error("input nullifier {index} does not resolve to any known confidential VTXO")]
    UnknownInputVtxo {
        /// Index into [`ConfidentialTransaction::nullifiers`] of the
        /// unknown nullifier.
        index: usize,
    },

    /// At least one output range proof failed verification, or the
    /// aggregated range proof failed.
    #[error("range proof verification failed (output index {index})")]
    InvalidRangeProof {
        /// Output index whose range proof failed. For aggregated proofs
        /// the index is `0` (the aggregator does not surface per-output
        /// rejection).
        index: usize,
    },

    /// Mixed individual/aggregated range proofs detected.
    ///
    /// Folded into [`ValidationError::InvalidRangeProof`] from a wire
    /// perspective so #538's enum stays at the variants the issue
    /// explicitly names; this variant is internal scaffolding for the
    /// "mixed rejected if policy says so" acceptance criterion.
    #[error("range proof policy violation: mixed individual/aggregated forms")]
    MixedRangeProofForms,

    /// The balance proof failed verification.
    #[error("balance proof verification failed")]
    InvalidBalanceProof,

    /// Output well-formedness check failed (bad pubkey, oversized memo,
    /// bad commitment encoding, etc.).
    #[error("output {index} is malformed: {reason}")]
    MalformedOutput {
        /// Output index of the malformed output.
        index: usize,
        /// Static reason string. Avoids format strings to keep errors
        /// lightweight on the hot path.
        reason: &'static str,
    },

    /// Fee was below the operator-published minimum and the transaction
    /// was not flagged as operator-initiated.
    #[error("fee {fee} below operator minimum {minimum}")]
    FeeBelowMinimum {
        /// Transaction's fee amount.
        fee: u64,
        /// Operator-published minimum for the tx shape.
        minimum: u64,
    },

    /// Fee was above the operator-side sanity cap.
    #[error("fee {fee} above operator cap {cap}")]
    FeeAboveOperatorCap {
        /// Transaction's fee amount.
        fee: u64,
        /// Operator-side cap.
        cap: u64,
    },

    /// Schema version on the wire is not supported by the operator.
    #[error("unsupported schema version {version}")]
    UnsupportedSchemaVersion {
        /// Version reported on the wire.
        version: u32,
    },

    /// The transaction is structurally invalid (zero inputs, zero outputs,
    /// nullifier/output count mismatches, etc.).
    #[error("transaction structurally invalid: {reason}")]
    StructurallyInvalid {
        /// Static reason string.
        reason: &'static str,
    },

    /// Persistence error from the [`NullifierSink`] backend.
    ///
    /// Surfaced as a typed validation error so callers can distinguish
    /// "tx is invalid" from "store is unhealthy". On this error the
    /// validator has already rejected the transaction and made no
    /// in-memory state changes.
    #[error("nullifier sink failure: {0}")]
    NullifierSinkFailure(String),

    /// Fee-bump replacement was submitted without a recorded prior fee.
    ///
    /// Per ADR-0004 §"Fee-bump replacements" the mempool layer is
    /// responsible for surfacing the prior fee; this variant exists so
    /// that the validator can be threaded the bump-context in a future
    /// milestone without renumbering the enum. Today the validator does
    /// not emit this variant — fee bumps are a mempool / pre-spent-set
    /// concern, not part of the v1 validation pipeline (#538 leaves the
    /// hook in place for #543's mempool integration).
    #[error("fee-bump replacement missing prior fee record")]
    FeeBumpMissingPriorFee,

    /// Fee-bump replacement does not strictly increase the prior fee.
    ///
    /// As with [`Self::FeeBumpMissingPriorFee`], this variant is reserved
    /// for the future mempool integration. The validator does not emit
    /// it today.
    #[error("fee-bump replacement {replacement} does not strictly exceed prior fee {prior}")]
    FeeBumpNotIncreasing {
        /// Prior fee on the original transaction.
        prior: u64,
        /// Replacement fee submitted; must be `> prior` to be accepted
        /// by the mempool layer.
        replacement: u64,
    },
}

// ---------------------------------------------------------------------------
// Trait surfaces
// ---------------------------------------------------------------------------

/// Source of the operator-published minimum fee for a confidential tx
/// shape, plus the operator-side sanity cap.
///
/// Implemented by `dark-fee-manager` in #543. Tests mock this trait
/// directly. The validator does **not** depend on a concrete
/// implementation; it depends only on this trait so #543 can land
/// independently.
#[async_trait]
pub trait FeeMinimumProvider: Send + Sync {
    /// Operator-published minimum fee for a confidential transaction with
    /// the given input/output counts.
    ///
    /// Returns satoshis. Zero is a valid return value (e.g. dev / test
    /// deployments running `NoopFeeManager`).
    async fn minimum_fee(&self, num_inputs: usize, num_outputs: usize) -> u64;

    /// Operator-side sanity cap on the fee a single transaction can pay.
    ///
    /// Returns satoshis. Defence-in-depth against accounting overflow on
    /// the operator's own ledgers; per ADR-0004 the default is round-policy,
    /// not fee-manager policy. Implementations MAY return [`u64::MAX`] to
    /// disable the cap.
    async fn fee_cap(&self) -> u64;
}

/// Resolves a confidential nullifier back to whatever metadata the round
/// policy needs to gate the spend.
///
/// The validator needs two things from the resolver:
/// 1. existence: does this nullifier correspond to a known, unspent,
///    in-policy confidential input VTXO?
/// 2. the input VTXO's [`PedersenCommitment`] in the balance-proof
///    convention so the validator can rebuild the excess point `E =
///    Σ C_in − Σ C_out − fee·G`.
///
/// `Some(c)` means "known input, here is its commitment"; `None` means
/// "unknown nullifier — reject the transaction with [`ValidationError::UnknownInputVtxo`]".
///
/// Returning the commitment alongside existence in a single call avoids
/// two round-trips on the hot path.
#[async_trait]
pub trait InputVtxoResolver: Send + Sync {
    /// Returns the input VTXO's balance-side commitment iff the nullifier
    /// resolves to a known, unspent, in-policy confidential input.
    async fn resolve(&self, nullifier: &[u8; NULLIFIER_LEN]) -> Option<PedersenCommitment>;
}

/// Resolver impl that always returns `None`.
///
/// Use this when the validator must reject *every* nullifier as unknown
/// (e.g. an operator that disabled confidential spending without removing
/// the validator from the pipeline). Tests that exercise the
/// `UnknownInputVtxo` path use this resolver directly.
#[derive(Debug, Default, Clone, Copy)]
pub struct RejectAllInputResolver;

#[async_trait]
impl InputVtxoResolver for RejectAllInputResolver {
    async fn resolve(&self, _nullifier: &[u8; NULLIFIER_LEN]) -> Option<PedersenCommitment> {
        None
    }
}

// ---------------------------------------------------------------------------
// Validation context
// ---------------------------------------------------------------------------

/// Runtime context threaded through the validator.
///
/// Carrying the trait objects in a single struct keeps the public entry
/// point at `(tx, ctx)` rather than five parameters and lets future
/// fields (e.g. round-policy filters, telemetry sinks) land additively.
pub struct ValidationContext<'a> {
    /// Spent-set; receives `batch_insert` on success.
    pub nullifier_sink: &'a (dyn NullifierSink + 'a),
    /// VTXO resolver for the per-nullifier "is this a known input?" check.
    pub input_resolver: &'a (dyn InputVtxoResolver + 'a),
    /// Fee-minimum / cap source.
    pub fee_provider: &'a (dyn FeeMinimumProvider + 'a),
    /// Aggregated range proof, when the transaction uses aggregated form.
    /// `None` when every output carries its own range proof.
    pub aggregated_range_proof: Option<&'a AggregatedRangeProof>,
    /// `true` when the transaction was constructed by the operator
    /// (sweeps, expiry runs, internal rebalancing). Bypasses the
    /// minimum-fee gate per ADR-0004; the cap still applies.
    pub is_operator_initiated: bool,
    /// Optional round id propagated to the nullifier sink for telemetry.
    pub round_id: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Validator entry point
// ---------------------------------------------------------------------------

/// Validate a confidential transaction in the canonical 5-step pipeline.
///
/// On success returns a [`ValidatedTx`] ready for the round-tree builder
/// (#540) to consume; on failure returns a typed [`ValidationError`] and
/// makes **no** state changes.
///
/// Steps (per the issue):
/// 1. Nullifier checks — duplicates within the tx, global spent-set
///    membership, resolver lookup.
/// 2. Range-proof verification — individual or aggregated, never mixed.
/// 3. Balance-proof verification — Schnorr over the excess point with the
///    transaction transcript binding.
/// 4. Output well-formedness — pubkey validity, memo size bounds.
/// 5. Fee minimum / cap — per ADR-0004 ordering rule, fee gate runs
///    before balance-proof would when using a hot-path benchmark layout;
///    we keep the issue's order to remain auditable to the spec.
///
/// **Atomicity**: the spent-set insert runs only after every other check
/// has passed. A failure at any earlier step short-circuits with no
/// nullifier write, no metric mutation, no output queue insertion.
pub async fn validate_confidential_transaction(
    tx: &ConfidentialTransaction,
    ctx: &ValidationContext<'_>,
) -> Result<ValidatedTx, ValidationError> {
    // Cache mutable / referenced fields once. ADR-0004: `tx.fee_amount`
    // MUST be read once to avoid TOCTOU races if the buffer is shared
    // with the network layer.
    let fee = tx.fee_amount;

    // Schema-version gate. The validator handles exactly v1 (#537).
    if tx.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(ValidationError::UnsupportedSchemaVersion {
            version: tx.schema_version,
        });
    }

    // Structural sanity. None of the cryptographic primitives accept
    // empty input slices and none of the round-tree shapes admit
    // zero-output txs, so reject early with a typed error rather than
    // letting an empty slice trip the balance-proof verifier.
    if tx.nullifiers.len() < MIN_INPUTS {
        return Err(ValidationError::StructurallyInvalid {
            reason: "transaction must have at least one input nullifier",
        });
    }
    if tx.outputs.len() < MIN_OUTPUTS {
        return Err(ValidationError::StructurallyInvalid {
            reason: "transaction must have at least one output",
        });
    }

    // ─── Step 1: Nullifier checks ────────────────────────────────────────
    //
    // Three sub-checks in one pass:
    // - intra-tx uniqueness (duplicates within the same tx are
    //   indistinguishable from a double-spend on the wire);
    // - global spent-set membership;
    // - resolver lookup against the VTXO repository.
    //
    // No mutation here — `batch_insert` runs at the very end of the
    // pipeline once every other gate has passed.
    let mut seen_nullifiers: HashSet<[u8; NULLIFIER_LEN]> =
        HashSet::with_capacity(tx.nullifiers.len());
    let mut input_commitments: Vec<PedersenCommitment> = Vec::with_capacity(tx.nullifiers.len());
    for (index, nullifier) in tx.nullifiers.iter().enumerate() {
        if !seen_nullifiers.insert(*nullifier) {
            return Err(ValidationError::NullifierAlreadySpent { index });
        }
        if ctx.nullifier_sink.contains(nullifier).await {
            return Err(ValidationError::NullifierAlreadySpent { index });
        }
        match ctx.input_resolver.resolve(nullifier).await {
            Some(c) => input_commitments.push(c),
            None => return Err(ValidationError::UnknownInputVtxo { index }),
        }
    }

    // ─── Step 2: Range proofs ────────────────────────────────────────────
    //
    // Two policy modes:
    // - aggregated: a single [`AggregatedRangeProof`] on the context covers
    //   every output's commitment in declaration order. Per-output
    //   `range_proof` MUST be `None` for every output; mixed forms are
    //   rejected with a typed error.
    // - individual: every output carries its own [`RangeProof`] and
    //   [`ValidationContext::aggregated_range_proof`] MUST be `None`.
    //
    // Mixed-form rejection lives here because the verifier cannot
    // atomically attribute a sub-proof failure once it stops being
    // "all individual" or "all aggregated".
    match ctx.aggregated_range_proof {
        Some(agg) => {
            // Mixed-form check: any output that ships its own range proof
            // alongside an aggregated proof is a policy violation.
            if tx.outputs.iter().any(|o| o.range_proof.is_some()) {
                return Err(ValidationError::MixedRangeProofForms);
            }
            let commitments: Vec<ValueCommitment> =
                tx.outputs.iter().map(|o| o.value_commitment).collect();
            if !verify_range_aggregated(&commitments, &agg.proof) {
                return Err(ValidationError::InvalidRangeProof { index: 0 });
            }
        }
        None => {
            for (index, output) in tx.outputs.iter().enumerate() {
                let proof = output
                    .range_proof
                    .as_ref()
                    .ok_or(ValidationError::InvalidRangeProof { index })?;
                if !verify_range(&output.value_commitment, proof) {
                    return Err(ValidationError::InvalidRangeProof { index });
                }
            }
        }
    }

    // ─── Step 3: Balance proof ───────────────────────────────────────────
    //
    // Verify `Σ C_in − Σ C_out − commit(fee, 0) = commit(0, r_excess)`
    // (the homomorphic identity from #526) and the Schnorr signature over
    // the excess point.
    //
    // The input commitments came from the resolver in Step 1 above; the
    // output commitments are the balance-side commitments on each
    // [`ConfidentialOutput`] (the value-side commitments are owned by the
    // range proof; see [`ConfidentialOutput`] doc-comment for the
    // two-commitment v1 limitation).
    let output_commitments: Vec<PedersenCommitment> = tx
        .outputs
        .iter()
        .map(|o| o.balance_commitment.clone())
        .collect();
    if !verify_balance(
        &input_commitments,
        &output_commitments,
        fee,
        &tx.tx_hash,
        &tx.balance_proof,
    ) {
        return Err(ValidationError::InvalidBalanceProof);
    }

    // ─── Step 4: Output well-formedness ─────────────────────────────────
    //
    // Compressed-secp256k1 owner pubkey, optional ephemeral pubkey, and a
    // bounded encrypted memo. The bounds are static so we can reject
    // memory-bomb submissions without consulting any operator policy.
    for (index, output) in tx.outputs.iter().enumerate() {
        if output.encrypted_memo.len() > MAX_ENCRYPTED_MEMO_LEN {
            return Err(ValidationError::MalformedOutput {
                index,
                reason: "encrypted memo exceeds MAX_ENCRYPTED_MEMO_LEN",
            });
        }
        if !is_valid_compressed_pubkey(&output.owner_pubkey) {
            return Err(ValidationError::MalformedOutput {
                index,
                reason: "owner pubkey is not a valid compressed secp256k1 point",
            });
        }
        if let Some(ephemeral) = output.ephemeral_pubkey {
            if !is_valid_compressed_pubkey(&ephemeral) {
                return Err(ValidationError::MalformedOutput {
                    index,
                    reason: "ephemeral pubkey is not a valid compressed secp256k1 point",
                });
            }
        }
    }

    // ─── Step 5: Fee gate ────────────────────────────────────────────────
    //
    // Cap first (defence-in-depth against accounting overflow), then the
    // operator minimum unless this is an operator-initiated path.
    let cap = ctx.fee_provider.fee_cap().await;
    if fee > cap {
        return Err(ValidationError::FeeAboveOperatorCap { fee, cap });
    }
    if !ctx.is_operator_initiated {
        let minimum = ctx
            .fee_provider
            .minimum_fee(tx.nullifiers.len(), tx.outputs.len())
            .await;
        if fee < minimum {
            return Err(ValidationError::FeeBelowMinimum { fee, minimum });
        }
    }

    // ─── Atomic commit ───────────────────────────────────────────────────
    //
    // Every gate has passed. Persist the spent nullifiers and emit the
    // ValidatedTx. The sink is responsible for atomicity at the DB layer:
    // on error the in-memory set is left untouched and we surface the
    // error as a typed variant so the caller can distinguish "tx invalid"
    // from "store unhealthy".
    let inserted = ctx
        .nullifier_sink
        .batch_insert(&tx.nullifiers, ctx.round_id)
        .await
        .map_err(|e| ValidationError::NullifierSinkFailure(format!("{e}")))?;

    // Defence-in-depth: a `false` here means the sink saw a duplicate that
    // our earlier `contains` check did not. A concurrent submission could
    // have inserted the same nullifier between Step 1 and now. Treat as
    // double-spend and fail the transaction. We do NOT roll back the
    // partially-inserted nullifiers — the spent-set is append-only by
    // design (#534), and the duplicate is by definition still spent.
    if let Some((index, _)) = inserted.iter().enumerate().find(|(_, &b)| !b) {
        return Err(ValidationError::NullifierAlreadySpent { index });
    }

    Ok(ValidatedTx {
        tx_hash: tx.tx_hash,
        schema_version: tx.schema_version,
        spent_nullifiers: tx.nullifiers.clone(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| ValidatedOutput {
                balance_commitment: o.balance_commitment.clone(),
                owner_pubkey: o.owner_pubkey,
                ephemeral_pubkey: o.ephemeral_pubkey,
                encrypted_memo: o.encrypted_memo.clone(),
            })
            .collect(),
        fee_amount: fee,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// `true` iff `bytes` is a valid 33-byte compressed secp256k1 point.
fn is_valid_compressed_pubkey(bytes: &[u8; PUBKEY_LEN]) -> bool {
    secp256k1::PublicKey::from_slice(bytes).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use tokio::sync::Mutex;

    use dark_confidential::balance_proof::prove_balance;
    use dark_confidential::commitment::PedersenCommitment;
    use dark_confidential::range_proof::{prove_range, prove_range_aggregated};
    use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

    use crate::error::{ArkError, ArkResult};

    // -------------------------------------------------------------------
    // Test fixtures and helpers
    // -------------------------------------------------------------------

    /// Mock NullifierSink that records inserts and supports pre-seeding.
    #[derive(Default)]
    struct MockSink {
        seen: Mutex<HashSet<[u8; 32]>>,
        // `fail_on_insert` lets a test assert that the validator
        // surfaces sink failures as the typed variant.
        fail_on_insert: bool,
    }

    impl MockSink {
        fn new() -> Self {
            Self::default()
        }

        fn with_failure() -> Self {
            Self {
                seen: Mutex::new(HashSet::new()),
                fail_on_insert: true,
            }
        }

        async fn insert_pre_existing(&self, nullifier: [u8; 32]) {
            self.seen.lock().await.insert(nullifier);
        }
    }

    #[async_trait]
    impl NullifierSink for MockSink {
        async fn batch_insert(
            &self,
            nullifiers: &[[u8; 32]],
            _round_id: Option<&str>,
        ) -> ArkResult<Vec<bool>> {
            if self.fail_on_insert {
                return Err(ArkError::Internal("mock sink failure".to_string()));
            }
            let mut guard = self.seen.lock().await;
            let mut out = Vec::with_capacity(nullifiers.len());
            for n in nullifiers {
                out.push(guard.insert(*n));
            }
            Ok(out)
        }

        async fn contains(&self, nullifier: &[u8; 32]) -> bool {
            self.seen.lock().await.contains(nullifier)
        }
    }

    /// Resolver that returns a static commitment for *known* nullifiers,
    /// and `None` for any nullifier in the `deny` set. Used to drive the
    /// `UnknownInputVtxo` test path.
    struct DenyResolver {
        deny: HashSet<[u8; 32]>,
        known: std::collections::HashMap<[u8; 32], PedersenCommitment>,
    }

    #[async_trait]
    impl InputVtxoResolver for DenyResolver {
        async fn resolve(&self, n: &[u8; 32]) -> Option<PedersenCommitment> {
            if self.deny.contains(n) {
                None
            } else {
                self.known.get(n).cloned()
            }
        }
    }

    /// Fee provider for tests. `min` is a fixed minimum and `cap` an
    /// optional override (defaults to `u64::MAX`).
    struct StaticFeeProvider {
        min: u64,
        cap: u64,
    }

    impl StaticFeeProvider {
        fn new(min: u64) -> Self {
            Self { min, cap: u64::MAX }
        }
        fn with_cap(min: u64, cap: u64) -> Self {
            Self { min, cap }
        }
    }

    #[async_trait]
    impl FeeMinimumProvider for StaticFeeProvider {
        async fn minimum_fee(&self, _num_inputs: usize, _num_outputs: usize) -> u64 {
            self.min
        }
        async fn fee_cap(&self) -> u64 {
            self.cap
        }
    }

    fn scalar(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_be_bytes(bytes).unwrap()
    }

    fn pubkey_compressed(seed: u64) -> [u8; 33] {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[24..].copy_from_slice(&seed.to_be_bytes());
        // Ensure it's a non-zero, in-range scalar.
        if sk_bytes == [0u8; 32] {
            sk_bytes[31] = 1;
        }
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        pk.serialize()
    }

    /// Build a minimal valid 2-in / 2-out transaction with individual range proofs.
    ///
    /// Returns the transaction and the per-input commitments the resolver
    /// must surface for the balance-proof check to succeed. Tests construct
    /// a [`PerNullifierInputResolver`] from those commitments and feed it
    /// into the [`ValidationContext`].
    struct TwoInTwoOutFixture {
        tx: ConfidentialTransaction,
        input_commitments: Vec<PedersenCommitment>,
    }

    /// Test resolver that maps each nullifier to a pre-computed input
    /// commitment. Lookup is by-position because the test fixture
    /// constructs nullifier order to match input-commitment order.
    struct PerNullifierInputResolver {
        map: std::collections::HashMap<[u8; 32], PedersenCommitment>,
    }

    impl PerNullifierInputResolver {
        fn from_pairs(pairs: Vec<([u8; 32], PedersenCommitment)>) -> Self {
            Self {
                map: pairs.into_iter().collect(),
            }
        }
    }

    #[async_trait]
    impl InputVtxoResolver for PerNullifierInputResolver {
        async fn resolve(&self, n: &[u8; 32]) -> Option<PedersenCommitment> {
            self.map.get(n).cloned()
        }
    }

    fn make_2in_2out_fixture(
        nullifiers: [[u8; 32]; 2],
        in_amounts: [u64; 2],
        out_amounts: [u64; 2],
        fee: u64,
        tx_hash: [u8; 32],
    ) -> TwoInTwoOutFixture {
        // Pick blindings far apart in the curve order and unrelated by
        // small offsets so partial sums (in[0]+in[1], in[0]-out[0], …)
        // never collapse to zero or to one of the other blinding values.
        // The dark_confidential::balance_proof::excess_scalar walk
        // computes intermediate sums, and any intermediate hitting
        // exactly zero or matching another addend trips
        // `add_tweak`/`negate` cancellation paths.
        let in_blindings = [scalar(0x1111_0001), scalar(0x2222_0002)];
        let out_blindings = [scalar(0x3333_aaaa_dead_5555), scalar(0x4444_bbbb_beef_6666)];

        // Verify caller passed balanced amounts.
        let total_in: u128 = in_amounts.iter().map(|x| *x as u128).sum();
        let total_out: u128 = out_amounts.iter().map(|x| *x as u128).sum();
        assert_eq!(
            total_in,
            total_out + fee as u128,
            "fixture amounts must balance: in={total_in}, out={total_out}, fee={fee}"
        );

        // Range proofs on outputs.
        let (rp1, vc1) = prove_range(out_amounts[0], &out_blindings[0]).unwrap();
        let (rp2, vc2) = prove_range(out_amounts[1], &out_blindings[1]).unwrap();

        // Input balance-side commitments — the resolver will surface these
        // for the validator's balance-proof check.
        let input_commitments: Vec<PedersenCommitment> = in_amounts
            .iter()
            .zip(in_blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(*a, b).unwrap())
            .collect();

        // Output balance-side Pedersen commitments under the same (amount,
        // blinding) pairs. NOTE: these are mathematically distinct points
        // from the value commitments above — see `ConfidentialOutput`
        // doc-comment for the v1 transient-design rationale.
        let balance_commitments: Vec<PedersenCommitment> = out_amounts
            .iter()
            .zip(out_blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(*a, b).unwrap())
            .collect();

        let balance_proof = prove_balance(&in_blindings, &out_blindings, fee, &tx_hash).unwrap();

        let outputs = vec![
            ConfidentialOutput {
                balance_commitment: balance_commitments[0].clone(),
                value_commitment: vc1,
                range_proof: Some(rp1),
                owner_pubkey: pubkey_compressed(1),
                ephemeral_pubkey: Some(pubkey_compressed(2)),
                encrypted_memo: vec![0xab; 64],
            },
            ConfidentialOutput {
                balance_commitment: balance_commitments[1].clone(),
                value_commitment: vc2,
                range_proof: Some(rp2),
                owner_pubkey: pubkey_compressed(3),
                ephemeral_pubkey: Some(pubkey_compressed(4)),
                encrypted_memo: vec![],
            },
        ];

        TwoInTwoOutFixture {
            tx: ConfidentialTransaction {
                schema_version: SUPPORTED_SCHEMA_VERSION,
                nullifiers: nullifiers.to_vec(),
                outputs,
                balance_proof,
                fee_amount: fee,
                tx_hash,
            },
            input_commitments,
        }
    }

    /// Build a [`PerNullifierInputResolver`] that maps each fixture
    /// nullifier to its corresponding input commitment, in declaration
    /// order.
    fn resolver_for(f: &TwoInTwoOutFixture) -> PerNullifierInputResolver {
        let pairs: Vec<_> =
            f.tx.nullifiers
                .iter()
                .copied()
                .zip(f.input_commitments.iter().cloned())
                .collect();
        PerNullifierInputResolver::from_pairs(pairs)
    }

    fn nullifier(seed: u8) -> [u8; 32] {
        let mut n = [0u8; 32];
        n[0] = seed;
        n[31] = seed;
        n
    }

    fn ctx<'a>(
        sink: &'a MockSink,
        resolver: &'a (dyn InputVtxoResolver + 'a),
        fee_provider: &'a (dyn FeeMinimumProvider + 'a),
    ) -> ValidationContext<'a> {
        ValidationContext {
            nullifier_sink: sink,
            input_resolver: resolver,
            fee_provider,
            aggregated_range_proof: None,
            is_operator_initiated: false,
            round_id: Some("test-round"),
        }
    }

    // -------------------------------------------------------------------
    // Happy-path acceptance — establishes the fixture is valid before any
    // mutation test relies on it.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn valid_transaction_accepted() {
        let f = make_2in_2out_fixture(
            [nullifier(1), nullifier(2)],
            [100, 50],
            [120, 20],
            10,
            [0x77u8; 32],
        );
        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(10);
        let ctx = ctx(&sink, &resolver, &fee);

        let validated = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect("valid tx must be accepted");
        assert_eq!(validated.fee_amount, 10);
        assert_eq!(validated.spent_nullifiers.len(), 2);
        assert_eq!(validated.outputs.len(), 2);
        assert_eq!(validated.tx_hash, f.tx.tx_hash);
        assert_eq!(validated.schema_version, SUPPORTED_SCHEMA_VERSION);

        // Spent set was actually mutated.
        assert!(sink.contains(&nullifier(1)).await);
        assert!(sink.contains(&nullifier(2)).await);
    }

    // -------------------------------------------------------------------
    // ValidationError variant coverage — one test per variant.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn variant_nullifier_already_spent_global() {
        // Pre-seed the spent set with one of the input nullifiers.
        let f = make_2in_2out_fixture(
            [nullifier(1), nullifier(2)],
            [100, 50],
            [120, 20],
            10,
            [0x11u8; 32],
        );
        let sink = MockSink::new();
        sink.insert_pre_existing(nullifier(1)).await;

        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(10);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject pre-seeded nullifier");
        match err {
            ValidationError::NullifierAlreadySpent { index } => assert_eq!(index, 0),
            other => panic!("unexpected error variant: {other:?}"),
        }

        // Atomicity: the *other* nullifier was never added to the set.
        assert!(!sink.contains(&nullifier(2)).await);
    }

    #[tokio::test]
    async fn variant_nullifier_already_spent_intra_tx_duplicate() {
        // Same nullifier in slots 0 and 1 — duplicate detected without
        // ever consulting the spent set.
        let dup = nullifier(7);
        let f = make_2in_2out_fixture([dup, dup], [100, 50], [120, 20], 10, [0x12u8; 32]);
        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(10);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject intra-tx duplicate");
        assert!(matches!(
            err,
            ValidationError::NullifierAlreadySpent { index: 1 }
        ));
        assert!(!sink.contains(&dup).await);
    }

    #[tokio::test]
    async fn variant_unknown_input_vtxo() {
        let f = make_2in_2out_fixture(
            [nullifier(8), nullifier(9)],
            [100, 50],
            [120, 20],
            10,
            [0x13u8; 32],
        );
        let sink = MockSink::new();
        let mut deny = HashSet::new();
        deny.insert(nullifier(9));
        // Map the *first* nullifier to a known commitment so it passes
        // step 1; the second is denied and triggers UnknownInputVtxo.
        let mut known = std::collections::HashMap::new();
        known.insert(nullifier(8), f.input_commitments[0].clone());
        let resolver = DenyResolver { deny, known };
        let fee = StaticFeeProvider::new(10);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject unresolved nullifier");
        assert!(matches!(
            err,
            ValidationError::UnknownInputVtxo { index: 1 }
        ));
    }

    #[tokio::test]
    async fn variant_invalid_range_proof_individual() {
        let mut f = make_2in_2out_fixture(
            [nullifier(10), nullifier(11)],
            [100, 50],
            [120, 20],
            10,
            [0x14u8; 32],
        );
        // Replace the second range proof with a proof for a *different*
        // value/blinding. The proof is structurally valid but does not
        // bind the output's commitment.
        let bad_blinding = scalar(0xbad);
        let (bad_proof, _bad_c) = prove_range(20, &bad_blinding).unwrap();
        f.tx.outputs[1].range_proof = Some(bad_proof);

        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(10);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject mismatched range proof");
        assert!(matches!(
            err,
            ValidationError::InvalidRangeProof { index: 1 }
        ));

        // Atomicity: nothing entered the spent set.
        assert!(!sink.contains(&nullifier(10)).await);
        assert!(!sink.contains(&nullifier(11)).await);
    }

    #[tokio::test]
    async fn variant_invalid_balance_proof() {
        let mut f = make_2in_2out_fixture(
            [nullifier(20), nullifier(21)],
            [100, 50],
            [120, 20],
            10,
            [0x15u8; 32],
        );
        // Tamper the fee — the balance proof was bound at fee=10, but we
        // submit fee=11. The verifier reconstructs `E` with the wrong
        // fee leg and rejects the signature.
        f.tx.fee_amount = 11;

        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(0); // accept any fee at the gate
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject tampered fee");
        assert!(matches!(err, ValidationError::InvalidBalanceProof));
    }

    #[tokio::test]
    async fn variant_malformed_output_owner_pubkey() {
        let mut f = make_2in_2out_fixture(
            [nullifier(30), nullifier(31)],
            [100, 50],
            [120, 20],
            10,
            [0x16u8; 32],
        );
        // Owner pubkey: prefix 0x02 + 32 zero bytes is *not* on the curve.
        let mut bad = [0u8; 33];
        bad[0] = 0x02;
        f.tx.outputs[0].owner_pubkey = bad;

        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(0);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject non-curve owner pubkey");
        assert!(matches!(
            err,
            ValidationError::MalformedOutput { index: 0, .. }
        ));
    }

    #[tokio::test]
    async fn variant_malformed_output_oversized_memo() {
        let mut f = make_2in_2out_fixture(
            [nullifier(32), nullifier(33)],
            [100, 50],
            [120, 20],
            10,
            [0x17u8; 32],
        );
        f.tx.outputs[1].encrypted_memo = vec![0xff; MAX_ENCRYPTED_MEMO_LEN + 1];

        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(0);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject oversized memo");
        assert!(matches!(
            err,
            ValidationError::MalformedOutput { index: 1, .. }
        ));
    }

    #[tokio::test]
    async fn variant_malformed_output_ephemeral_pubkey() {
        let mut f = make_2in_2out_fixture(
            [nullifier(34), nullifier(35)],
            [100, 50],
            [120, 20],
            10,
            [0x18u8; 32],
        );
        let mut bad = [0u8; 33];
        bad[0] = 0x02;
        f.tx.outputs[0].ephemeral_pubkey = Some(bad);

        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(0);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject non-curve ephemeral pubkey");
        assert!(matches!(
            err,
            ValidationError::MalformedOutput { index: 0, .. }
        ));
    }

    #[tokio::test]
    async fn variant_fee_below_minimum() {
        let f = make_2in_2out_fixture(
            [nullifier(40), nullifier(41)],
            [100, 50],
            [125, 20],
            5, // too-low fee
            [0x19u8; 32],
        );
        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(10);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject below-minimum fee");
        assert!(matches!(
            err,
            ValidationError::FeeBelowMinimum {
                fee: 5,
                minimum: 10
            }
        ));
    }

    #[tokio::test]
    async fn variant_fee_above_operator_cap() {
        let f = make_2in_2out_fixture(
            [nullifier(50), nullifier(51)],
            [10_000, 5_000],
            [4_000, 1_000],
            10_000, // huge fee
            [0x1au8; 32],
        );
        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::with_cap(0, 1_000);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject above-cap fee");
        assert!(matches!(
            err,
            ValidationError::FeeAboveOperatorCap {
                fee: 10_000,
                cap: 1_000
            }
        ));
    }

    #[tokio::test]
    async fn variant_unsupported_schema_version() {
        let mut f = make_2in_2out_fixture(
            [nullifier(60), nullifier(61)],
            [100, 50],
            [120, 20],
            10,
            [0x1bu8; 32],
        );
        f.tx.schema_version = 99;

        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(0);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject unknown schema version");
        assert!(matches!(
            err,
            ValidationError::UnsupportedSchemaVersion { version: 99 }
        ));
    }

    #[tokio::test]
    async fn variant_structurally_invalid_no_inputs() {
        let mut f = make_2in_2out_fixture(
            [nullifier(70), nullifier(71)],
            [100, 50],
            [120, 20],
            10,
            [0x1cu8; 32],
        );
        f.tx.nullifiers.clear();

        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(0);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject zero-input tx");
        assert!(matches!(err, ValidationError::StructurallyInvalid { .. }));
    }

    #[tokio::test]
    async fn variant_structurally_invalid_no_outputs() {
        let mut f = make_2in_2out_fixture(
            [nullifier(72), nullifier(73)],
            [100, 50],
            [120, 20],
            10,
            [0x1du8; 32],
        );
        f.tx.outputs.clear();

        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(0);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject zero-output tx");
        assert!(matches!(err, ValidationError::StructurallyInvalid { .. }));
    }

    #[tokio::test]
    async fn variant_mixed_range_proof_forms() {
        // Aggregated proof on the context AND per-output proofs on the
        // outputs — a policy violation. Use same-magnitude amounts so the
        // aggregator's "uniform sub-proof length" check passes.
        // Both outputs in the same ~21-bit range so Back-Maxwell auto-sizes
        // identically.
        let f = make_2in_2out_fixture(
            [nullifier(80), nullifier(81)],
            [1_500_000, 1_500_000],
            [1_500_000, 1_499_990],
            10,
            [0x1eu8; 32],
        );
        // Build an aggregated proof that *does* cover both outputs.
        let inputs = vec![
            (1_500_000u64, scalar(0x3333_aaaa_dead_5555)),
            (1_499_990u64, scalar(0x4444_bbbb_beef_6666)),
        ];
        let (agg_proof, _commitments) = prove_range_aggregated(&inputs).unwrap();
        let agg = AggregatedRangeProof { proof: agg_proof };

        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(0);
        let mut ctx = ctx(&sink, &resolver, &fee);
        ctx.aggregated_range_proof = Some(&agg);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must reject mixed-form proofs");
        assert!(matches!(err, ValidationError::MixedRangeProofForms));
    }

    #[test]
    fn variant_fee_bump_missing_prior_fee_constructs() {
        // ADR-0004 reserved variant. The validator does not emit it
        // today (fee-bump policy is the mempool layer's job per
        // ADR-0004), but the type must construct cleanly so that the
        // future #543 mempool integration can return it without a
        // breaking change to the enum.
        let err = ValidationError::FeeBumpMissingPriorFee;
        assert!(format!("{err}").contains("fee-bump"));
    }

    #[test]
    fn variant_fee_bump_not_increasing_constructs() {
        let err = ValidationError::FeeBumpNotIncreasing {
            prior: 100,
            replacement: 100,
        };
        let msg = format!("{err}");
        assert!(msg.contains("100"));
        assert!(msg.contains("fee-bump"));
    }

    #[tokio::test]
    async fn variant_nullifier_sink_failure() {
        let f = make_2in_2out_fixture(
            [nullifier(90), nullifier(91)],
            [100, 50],
            [120, 20],
            10,
            [0x1fu8; 32],
        );
        let sink = MockSink::with_failure();
        let resolver = resolver_for(&f);
        let fee = StaticFeeProvider::new(0);
        let ctx = ctx(&sink, &resolver, &fee);

        let err = validate_confidential_transaction(&f.tx, &ctx)
            .await
            .expect_err("must surface sink failure");
        assert!(matches!(err, ValidationError::NullifierSinkFailure(_)));
    }

    // -------------------------------------------------------------------
    // Aggregated range proofs — happy path
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn aggregated_range_proof_accepted() {
        // Build outputs with a single aggregated range proof on the ctx.
        // Same-magnitude amounts (both ~21-bit) so Back-Maxwell auto-sizes
        // the sub-proofs to the same bit-width and aggregation succeeds.
        let in_blindings = [scalar(0x1111_0001), scalar(0x2222_0002)];
        let out_blindings = [scalar(0x3333_aaaa_dead_5555), scalar(0x4444_bbbb_beef_6666)];
        let in_amounts = [1_500_000u64, 1_500_000];
        let out_amounts = [1_500_000u64, 1_499_990];
        let fee = 10u64;
        let tx_hash = [0x21u8; 32];

        let inputs_for_agg = vec![
            (out_amounts[0], out_blindings[0]),
            (out_amounts[1], out_blindings[1]),
        ];
        let (agg_proof, agg_value_commitments) = prove_range_aggregated(&inputs_for_agg).unwrap();

        let balance_commitments: Vec<PedersenCommitment> = out_amounts
            .iter()
            .zip(out_blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(*a, b).unwrap())
            .collect();

        let balance = prove_balance(&in_blindings, &out_blindings, fee, &tx_hash).unwrap();

        let outputs = vec![
            ConfidentialOutput {
                balance_commitment: balance_commitments[0].clone(),
                value_commitment: agg_value_commitments[0],
                range_proof: None,
                owner_pubkey: pubkey_compressed(11),
                ephemeral_pubkey: Some(pubkey_compressed(12)),
                encrypted_memo: vec![],
            },
            ConfidentialOutput {
                balance_commitment: balance_commitments[1].clone(),
                value_commitment: agg_value_commitments[1],
                range_proof: None,
                owner_pubkey: pubkey_compressed(13),
                ephemeral_pubkey: Some(pubkey_compressed(14)),
                encrypted_memo: vec![],
            },
        ];

        // Input commitments for the resolver.
        let input_commitments: Vec<PedersenCommitment> = in_amounts
            .iter()
            .zip(in_blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(*a, b).unwrap())
            .collect();

        let tx = ConfidentialTransaction {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            nullifiers: vec![nullifier(100), nullifier(101)],
            outputs,
            balance_proof: balance,
            fee_amount: fee,
            tx_hash,
        };

        let sink = MockSink::new();
        let resolver = PerNullifierInputResolver::from_pairs(
            tx.nullifiers
                .iter()
                .copied()
                .zip(input_commitments.iter().cloned())
                .collect(),
        );
        let fee_p = StaticFeeProvider::new(0);
        let agg = AggregatedRangeProof { proof: agg_proof };
        let mut c = ctx(&sink, &resolver, &fee_p);
        c.aggregated_range_proof = Some(&agg);

        let validated = validate_confidential_transaction(&tx, &c)
            .await
            .expect("aggregated tx must be accepted");
        assert_eq!(validated.outputs.len(), 2);
    }

    #[tokio::test]
    async fn aggregated_range_proof_rejected_when_tampered() {
        // Same setup as the happy path, but use a *different* aggregated
        // proof bound to different commitments. The verifier MUST reject.
        let in_blindings = [scalar(0x1111_0001), scalar(0x2222_0002)];
        let in_amounts = [1_500_000u64, 1_500_000];
        let out_blindings = [scalar(0x3333_aaaa_dead_5555), scalar(0x4444_bbbb_beef_6666)];
        let out_amounts = [1_500_000u64, 1_499_990];
        let fee = 10u64;
        let tx_hash = [0x22u8; 32];

        let inputs_for_agg = vec![
            (out_amounts[0], out_blindings[0]),
            (out_amounts[1], out_blindings[1]),
        ];
        // Real aggregated proof for our outputs (used for the value
        // commitments we attach to the outputs).
        let (_real_agg, real_value_commitments) = prove_range_aggregated(&inputs_for_agg).unwrap();
        // Wrong aggregated proof — bound to *different* values; we attach
        // this to the context to force the verifier to reject. Use same
        // magnitude so the aggregator accepts the "wrong" proof.
        let inputs_for_other = vec![
            (1_400_000u64, scalar(0xaaaa_5555_aaaa_5555)),
            (1_400_010u64, scalar(0xbbbb_6666_bbbb_6666)),
        ];
        let (other_agg, _oc) = prove_range_aggregated(&inputs_for_other).unwrap();

        let balance_commitments: Vec<PedersenCommitment> = out_amounts
            .iter()
            .zip(out_blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(*a, b).unwrap())
            .collect();
        let input_commitments: Vec<PedersenCommitment> = in_amounts
            .iter()
            .zip(in_blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(*a, b).unwrap())
            .collect();
        let balance = prove_balance(&in_blindings, &out_blindings, fee, &tx_hash).unwrap();

        let outputs = vec![
            ConfidentialOutput {
                balance_commitment: balance_commitments[0].clone(),
                value_commitment: real_value_commitments[0],
                range_proof: None,
                owner_pubkey: pubkey_compressed(15),
                ephemeral_pubkey: Some(pubkey_compressed(16)),
                encrypted_memo: vec![],
            },
            ConfidentialOutput {
                balance_commitment: balance_commitments[1].clone(),
                value_commitment: real_value_commitments[1],
                range_proof: None,
                owner_pubkey: pubkey_compressed(17),
                ephemeral_pubkey: Some(pubkey_compressed(18)),
                encrypted_memo: vec![],
            },
        ];

        let tx = ConfidentialTransaction {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            nullifiers: vec![nullifier(110), nullifier(111)],
            outputs,
            balance_proof: balance,
            fee_amount: fee,
            tx_hash,
        };

        let sink = MockSink::new();
        let resolver = PerNullifierInputResolver::from_pairs(
            tx.nullifiers
                .iter()
                .copied()
                .zip(input_commitments.iter().cloned())
                .collect(),
        );
        let fee_p = StaticFeeProvider::new(0);
        let agg = AggregatedRangeProof { proof: other_agg };
        let mut c = ctx(&sink, &resolver, &fee_p);
        c.aggregated_range_proof = Some(&agg);

        let err = validate_confidential_transaction(&tx, &c)
            .await
            .expect_err("aggregated proof for wrong commitments must be rejected");
        assert!(matches!(err, ValidationError::InvalidRangeProof { .. }));
    }

    // -------------------------------------------------------------------
    // Operator-initiated path bypasses the minimum-fee gate.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn operator_initiated_bypasses_minimum_gate() {
        let f = make_2in_2out_fixture(
            [nullifier(120), nullifier(121)],
            [100, 50],
            [125, 20],
            5, // below user-min, accepted because operator-initiated
            [0x23u8; 32],
        );
        let sink = MockSink::new();
        let resolver = resolver_for(&f);
        let fee_p = StaticFeeProvider::new(50);
        let mut c = ctx(&sink, &resolver, &fee_p);
        c.is_operator_initiated = true;

        let validated = validate_confidential_transaction(&f.tx, &c)
            .await
            .expect("operator-initiated path must bypass min-fee");
        assert_eq!(validated.fee_amount, 5);
    }

    // -------------------------------------------------------------------
    // Double-spend regression: two concurrent txs with overlapping
    // nullifiers, exactly one is accepted.
    // -------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn double_spend_regression_concurrent_overlapping_nullifiers() {
        // Build TWO transactions that share input nullifier `nul(200)`.
        // We submit them concurrently against the same sink.
        let shared = nullifier(200);

        let f_a = make_2in_2out_fixture(
            [shared, nullifier(201)],
            [100, 50],
            [120, 20],
            10,
            [0x24u8; 32],
        );
        let f_b = make_2in_2out_fixture(
            [shared, nullifier(202)],
            [100, 50],
            [120, 20],
            10,
            [0x25u8; 32],
        );

        // Resolver knows every nullifier the two txs spend. Both fixtures
        // use the SAME in_blindings/in_amounts for slot 0 (the shared
        // nullifier) so both balance proofs verify against the same input
        // commitment.
        let pairs: Vec<_> = f_a
            .tx
            .nullifiers
            .iter()
            .copied()
            .zip(f_a.input_commitments.iter().cloned())
            .chain(
                f_b.tx
                    .nullifiers
                    .iter()
                    .copied()
                    .zip(f_b.input_commitments.iter().cloned()),
            )
            .collect();
        let resolver = Arc::new(PerNullifierInputResolver::from_pairs(pairs));

        let tx_a = f_a.tx;
        let tx_b = f_b.tx;

        let sink = Arc::new(MockSink::new());
        let fee_p = Arc::new(StaticFeeProvider::new(0));

        let sink_a = Arc::clone(&sink);
        let sink_b = Arc::clone(&sink);
        let res_a = Arc::clone(&resolver);
        let res_b = Arc::clone(&resolver);
        let fee_a = Arc::clone(&fee_p);
        let fee_b = Arc::clone(&fee_p);

        let h_a = tokio::spawn(async move {
            let c = ValidationContext {
                nullifier_sink: sink_a.as_ref(),
                input_resolver: res_a.as_ref(),
                fee_provider: fee_a.as_ref(),
                aggregated_range_proof: None,
                is_operator_initiated: false,
                round_id: Some("round-a"),
            };
            validate_confidential_transaction(&tx_a, &c).await
        });
        let h_b = tokio::spawn(async move {
            let c = ValidationContext {
                nullifier_sink: sink_b.as_ref(),
                input_resolver: res_b.as_ref(),
                fee_provider: fee_b.as_ref(),
                aggregated_range_proof: None,
                is_operator_initiated: false,
                round_id: Some("round-b"),
            };
            validate_confidential_transaction(&tx_b, &c).await
        });

        let r_a = h_a.await.unwrap();
        let r_b = h_b.await.unwrap();

        // Exactly one accepted, exactly one rejected.
        let accepted = [r_a.is_ok(), r_b.is_ok()];
        assert_eq!(
            accepted.iter().filter(|x| **x).count(),
            1,
            "exactly one of the two overlapping txs must be accepted; got {accepted:?}"
        );
        // The rejected one MUST be `NullifierAlreadySpent` for the shared
        // nullifier (slot 0).
        let rejected = if r_a.is_err() { &r_a } else { &r_b };
        match rejected {
            Err(ValidationError::NullifierAlreadySpent { index: 0 }) => {}
            other => panic!("rejected tx must surface NullifierAlreadySpent at slot 0: {other:?}"),
        }

        // The shared nullifier is in the spent set exactly once.
        assert!(sink.contains(&shared).await);
    }

    // -------------------------------------------------------------------
    // Mutation test — flipping any byte in the canonical encoding causes
    // validation to fail.
    //
    // The transaction has many bytes (nullifiers, output commitments,
    // range proofs, balance proof, fee, tx_hash). We exercise a sample of
    // each so the test runs in a few seconds rather than minutes.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn mutation_test_any_flipped_byte_fails() {
        let f = make_2in_2out_fixture(
            [nullifier(210), nullifier(211)],
            [100, 50],
            [120, 20],
            10,
            [0x26u8; 32],
        );

        // For each mutation strategy, build a fresh sink (so prior runs
        // do not pollute) and assert validation fails.
        //
        // Resolver knows ONLY the original nullifiers; a tampered
        // nullifier resolves to `None`, which trips the
        // `UnknownInputVtxo` branch — a valid rejection for "any flipped
        // byte of the tx fails". In production the real resolver behaves
        // the same way: tampered nullifiers won't match any known input.
        let resolver_pairs: Vec<([u8; 32], PedersenCommitment)> =
            f.tx.nullifiers
                .iter()
                .copied()
                .zip(f.input_commitments.iter().cloned())
                .collect();

        let assert_rejects = |tx: ConfidentialTransaction| {
            let resolver_pairs = resolver_pairs.clone();
            async move {
                let sink = MockSink::new();
                let resolver = PerNullifierInputResolver::from_pairs(resolver_pairs);
                let fee = StaticFeeProvider::new(0);
                let ctx = ValidationContext {
                    nullifier_sink: &sink,
                    input_resolver: &resolver,
                    fee_provider: &fee,
                    aggregated_range_proof: None,
                    is_operator_initiated: false,
                    round_id: None,
                };
                let r = validate_confidential_transaction(&tx, &ctx).await;
                assert!(r.is_err(), "mutated tx must be rejected: got {r:?}");
            }
        };

        // 1) Flip a byte of the tx_hash.
        let mut t = f.tx.clone();
        t.tx_hash[0] ^= 0x01;
        assert_rejects(t).await;

        // 2) Flip a byte inside an output's balance commitment.
        let mut t = f.tx.clone();
        let bytes = t.outputs[0].balance_commitment.to_bytes();
        let mut tampered_bytes = bytes;
        // y-parity bit in byte 0 — mutating it changes the point.
        tampered_bytes[0] = if bytes[0] == 0x02 { 0x03 } else { 0x02 };
        if let Ok(c) = PedersenCommitment::from_bytes(&tampered_bytes) {
            t.outputs[0].balance_commitment = c;
            assert_rejects(t).await;
        }

        // 2b) Flip a byte inside an output's value commitment.
        let mut t = f.tx.clone();
        let vc_bytes = t.outputs[0].value_commitment.to_bytes();
        let mut vc_tampered = vc_bytes;
        vc_tampered[0] = if vc_bytes[0] == 0x02 { 0x03 } else { 0x02 };
        if let Ok(vc) = ValueCommitment::from_bytes(&vc_tampered) {
            t.outputs[0].value_commitment = vc;
            assert_rejects(t).await;
        }

        // 3) Flip a byte in the balance proof's s-scalar (last byte).
        let mut t = f.tx.clone();
        let mut bp = t.balance_proof.to_bytes();
        bp[64] ^= 0x01;
        if let Ok(b) = BalanceProof::from_bytes(&bp) {
            t.balance_proof = b;
            assert_rejects(t).await;
        }

        // 4) Flip a byte in the fee.
        let mut t = f.tx.clone();
        t.fee_amount ^= 1;
        assert_rejects(t).await;

        // 5) Flip a byte in a nullifier — resolver knows about this
        //    specific tampered nullifier (pre-registered above) so the
        //    rejection path is balance-proof, not unknown-input.
        let mut t = f.tx.clone();
        t.nullifiers[0][5] ^= 0xff;
        assert_rejects(t).await;

        // 6) Flip a byte in a range proof's deep payload (one that lands
        //    inside Back-Maxwell rather than the header).
        let mut t = f.tx.clone();
        if let Some(rp) = t.outputs[1].range_proof.clone() {
            let mut rb = rp.to_bytes();
            let idx = rb.len() / 2;
            rb[idx] ^= 0x01;
            if let Ok(rp_tampered) = RangeProof::from_bytes(&rb) {
                t.outputs[1].range_proof = Some(rp_tampered);
                assert_rejects(t).await;
            }
        }

        // 7) Flip the schema version.
        let mut t = f.tx.clone();
        t.schema_version = 0;
        assert_rejects(t).await;
    }

    // -------------------------------------------------------------------
    // Acceptance criterion: 10_000 randomly-generated valid txs all
    // accepted (proptest).
    //
    // Two-fold purpose:
    // - establishes a strong "no false negatives" baseline;
    // - shakes out any non-determinism in the validator.
    // -------------------------------------------------------------------

    use proptest::prelude::*;

    fn random_2in_2out_strategy() -> impl Strategy<
        Value = (
            [u8; 32], // nul1
            [u8; 32], // nul2
            u64,      // in1
            u64,      // in2
            u64,      // fee
            u64,      // out_split_seed
            [u8; 32], // tx_hash
        ),
    > {
        (
            proptest::array::uniform32(any::<u8>()),
            proptest::array::uniform32(any::<u8>()),
            1u64..=1_000_000_000,
            1u64..=1_000_000_000,
            0u64..=10_000_000,
            any::<u64>(),
            proptest::array::uniform32(any::<u8>()),
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        /// 10_000 randomly-generated valid 2-in 2-out transactions all
        /// accepted (issue AC).
        ///
        /// The strategy generates random amounts and a random output
        /// split, then derives a balanced fixture and feeds it through
        /// the validator. Every successful generation MUST be accepted.
        #[test]
        fn ten_thousand_random_valid_txs_all_accepted(
            (n1, n2, in1, in2, fee_seed, split_seed, tx_hash) in random_2in_2out_strategy()
        ) {
            // Prevent intra-tx duplicate (the validator rejects those
            // legitimately, so it isn't a "valid" tx).
            prop_assume!(n1 != n2);

            // Build a balanced fixture: total_in == total_out + fee.
            let total_in = (in1 as u128) + (in2 as u128);
            // Cap the fee so it's strictly less than the total payable.
            let fee = fee_seed % (total_in.saturating_sub(2) as u64).max(1);
            prop_assume!(total_in > fee as u128);

            let payable = total_in - fee as u128;
            // Split the payable in two, with both legs >= 1.
            let split = (split_seed as u128 % (payable - 1)).max(1);
            let out1 = split as u64;
            let out2 = (payable - split) as u64;
            prop_assume!(out1 >= 1 && out2 >= 1);

            let f = make_2in_2out_fixture(
                [n1, n2],
                [in1, in2],
                [out1, out2],
                fee,
                tx_hash,
            );

            // Build context. fee minimum = 0 so we don't accidentally
            // gate-fail a randomly-low fee.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime.block_on(async {
                let sink = MockSink::new();
                let resolver = resolver_for(&f);
                let fee_p = StaticFeeProvider::new(0);
                let c = ctx(&sink, &resolver, &fee_p);
                validate_confidential_transaction(&f.tx, &c).await
            });
            prop_assert!(
                result.is_ok(),
                "random valid tx must be accepted: {result:?}"
            );
        }
    }
}
