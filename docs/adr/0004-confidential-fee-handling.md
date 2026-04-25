# ADR-0004: Fee handling in confidential transactions

- **Status:** Proposed
- **Date:** 2026-04-24
- **Milestone:** CV-M3 (Confidential Transaction Protocol)
- **Drives:** #536 → unblocks #537, #538, #543
- **Affects:** confidential transaction wire only; transparent paths untouched (#520 parity gate)

## Context

Confidential transactions in `dark-confidential` balance per the identity
established by ADR-0001 / #524 / #526:

```text
    Σ C_in − Σ C_out − commit(fee, 0) = commit(0, r_excess)
```

The operator must learn the fee component because it is the operator that
funds L1 anchor transactions, sweeps connectors, and enforces the round-level
economic policy. There is no operating mode in which the fee is opaque to the
operator. The design question, captured in #536, is **how the fee enters the
balance equation on the wire** — plaintext, committed and ranged, or paid via
a separate transparent VTXO. Each scheme imposes a different cost on the
validator pipeline (#538), the proto schema (#537), and the integration with
the existing `dark-fee-manager` programs (#543).

The choice has to be made before #537 freezes the
`ConfidentialTransaction` proto field that carries the fee, and before #538
specifies the validator's balance check; otherwise both rework once the fee
representation moves.

## Requirements

- Operator can compute and verify, in O(1), that the fee on a submitted
  confidential transaction meets the operator-set minimum derived from the
  same `dark-fee-manager` infrastructure that scores transparent intents.
- Fee handling must not weaken the privacy guarantees the rest of the
  confidential design buys: per ADR-0003 and #530, the transaction MUST NOT
  reveal input amounts, output amounts, or recipient identity; the fee is
  permitted to reveal **the fee itself**, nothing more.
- Reuses the existing balance-proof construction in `dark-confidential`
  (#526). The verifier already evaluates `commit(fee, 0)` against the
  excess point; whatever the wire format is, it must lower into a `u64`
  fee value the verifier can plug into that subtraction without further
  cryptographic work.
- Compatible with `dark-fee-manager`'s static, weight-based, and CEL
  programs without a parallel evaluator that sees plaintext amounts.
- Wire-additive on the `ConfidentialTransaction` message: a new field on a
  new message, no renumbering of any existing transparent surface. Old
  transparent clients keep working unchanged (#520 gate).
- Versioning lives outside the fee field: the schema version on
  `ConfidentialTransaction` (#537) is the version axis; the fee field is a
  fixed `u64` whose semantics are pinned by this ADR.

## Candidates

The issue text specifies three. Each is evaluated below; a fourth combination
("commit + plaintext disclosure side-channel") is mentioned only to rule it
out, since it is strictly worse than every option that survives.

### Option 1 — Plaintext fee field on the confidential transaction

The transaction carries `fee_amount: u64` as a normal proto field. The
balance proof verifier computes `commit(fee_amount, 0) = fee_amount · G`
and subtracts it from the homomorphic sum of input and output commitments
exactly as #526 already specifies. Nothing about the wire format of input
or output commitments changes.

- Privacy delta: leaks the fee amount. Does **not** leak input amounts,
  output amounts, or recipient identity.
- Validation cost: one scalar multiplication on the verifier (already done
  by #526); zero new range proofs.
- Operator integration: trivial; the existing fee-manager programs return
  a `u64` minimum and the validator compares against the field.

### Option 2 — Confidential fee with operator-chosen minimum

The transaction carries `fee_commitment: PedersenCommitment` and
`fee_range_proof: RangeProof`. The operator publishes a minimum fee
`min_fee` (still `u64`, still operator-side); the sender additionally
proves `fee ≥ min_fee` by submitting a range proof on `fee − min_fee` over
`[0, 2^64)`. The balance proof modifies to subtract `fee_commitment`
rather than `commit(fee, 0)`.

- Privacy delta: hides the *exact* fee amount, but only down to the
  granularity of `min_fee`. Operators set the minimum from the same
  bandwidth signal they would otherwise see in the plaintext fee, so the
  privacy gain is bounded by how often `fee == min_fee` (in steady state,
  often).
- Validation cost: one extra range-proof verification per transaction
  (~2 ms at the bench numbers from ADR-0001's PoC, scaled by the chosen
  proof bit-width). At a 500-tx round this is ~1 s of additional verifier
  CPU on the operator's hot path.
- Operator integration: non-trivial. The fee-manager programs (#543
  surface) currently return a single `u64`; under Option 2 they must
  return a `(min_fee, allowable_range_bits)` tuple, the CEL grammar grows
  a new return type, and the validator has to thread the operator's
  minimum into the verifier alongside the proof bytes. The CEL programs
  also keep seeing plaintext input/output counts (the CEL evaluator does
  not gain access to the new commitments), so the privacy improvement
  applies only to passive observers of the wire — not to the operator
  who runs CEL.

### Option 3 — Separate transparent fee VTXO

The sender pays the fee as a transparent VTXO alongside the confidential
transaction. The confidential balance equation reduces to a zero-fee
transaction:

```text
    Σ C_in − Σ C_out = commit(0, r_excess)
```

and the fee is a parallel transparent transfer the operator scores with
its existing transparent-tx fee logic.

- Privacy delta: catastrophic. The transparent fee VTXO carries a
  `script` the operator can attribute to the sender; round-level
  observers can correlate the transparent fee with the confidential
  transaction's submission timestamp and tie a sender identity to the
  confidential graph. This is precisely the leakage the
  confidential-VTXO milestone exists to remove.
- Validation cost: low (existing transparent path).
- Operator integration: trivial (already there).

## Evaluation matrix

| Criterion | Opt 1 (plaintext fee) | Opt 2 (confidential fee) | Opt 3 (transparent fee VTXO) |
|---|---|---|---|
| Reveals fee amount to wire observers | Yes | Bucketed to `min_fee` | Yes |
| Reveals input/output amounts | No | No | No (confidential leg) |
| Reveals sender identity | No | No | **Yes** (transparent fee leg) |
| Reuses #526 balance proof unchanged | Yes | No (verifier subtracts a commitment, not a `u64`) | Yes (zero-fee form) |
| Extra range proofs | 0 | 1 per tx | 0 |
| Verifier hot-path delta vs. transparent baseline | 0 | ~+2 ms / tx | 0 |
| Fee-manager program shape (#543) | unchanged: `u64` | grows to `(min, bits)` tuple; CEL return-type change | unchanged: `u64` |
| Wire-format complexity on `ConfidentialTransaction` | one `uint64` field | one `bytes` (commitment) + one `bytes` (range proof) field | none on the confidential side |
| Privacy signal beyond Option 1 | — | *only against passive wire observers; not against the operator* | strictly worse |
| Audit surface added on top of CV-M1 / CV-M2 primitives | none | one extra range proof + new bucketed-min CEL grammar | none |
| Round-level fingerprintability | per-tx fee value | per-tx (`min_fee`, range-bits) tuple | sender-identifying |
| Failure mode if the fee field is forged | balance proof fails (#526) | balance proof or range proof fails | transparent fee path catches; confidential leg accepts a 0-fee tx |

## Decision

**Adopt Option 1.** The `ConfidentialTransaction` carries a plaintext
`fee_amount: u64` field. The balance proof verifier (#526) computes
`commit(fee_amount, 0)` and subtracts it from the homomorphic sum exactly
as today. No new range proof, no new commitment, no change to the
fee-manager surface.

### Rationale (why not Option 2)

The privacy win Option 2 buys is bounded by the granularity of the
operator's published minimum fee. In the steady state where the fee
manager publishes `min_fee` matching realistic mempool conditions, every
sender pays `fee == min_fee` and the wire-level entropy collapses to the
operator's broadcast. Wire observers learn the same thing they would
under Option 1, namely the prevailing fee at submission time. The
verifier pays an extra ~2 ms range proof for that bounded privacy gain;
the fee-manager surface gains a tuple return that propagates through
every CEL program, REST admin endpoint, and integration test in #543.
Worst, the operator — who runs the CEL evaluator and is the only entity
that could otherwise act on the fee leak — already sees the
plaintext-equivalent of `min_fee` because it set the minimum. The party
that loses privacy under Option 1 is the only party Option 2 fails to
hide the value from. Concretely:

- The privacy gain is **at most** `log2(unique_fee_values_in_round)`
  bits per transaction, and **at least** zero when every sender uses
  the operator-published minimum.
- The validation cost is a flat ~2 ms range-proof verification per
  transaction that lands on the operator's hot path.
- The architectural cost is a new return type across the entire
  `dark-fee-manager` surface (#543) that propagates into every fee
  program, REST endpoint, and integration test.
- The CEL evaluator gains nothing; CEL programs already see only the
  data the operator already knows (input/output counts, intent
  metadata). The privacy improvement does not extend to CEL.

The cost/benefit is unfavourable for v1. A future v2 can revisit Option 2
if (a) sender behaviour stops clustering at `min_fee` for some workload,
or (b) Bulletproofs aggregation per ADR-0001's [FU-BP] makes the per-tx
range-proof cost negligible.

### Rationale (why not Option 3)

Option 3 leaks sender identity through the transparent fee VTXO's script.
That is the exact information the confidential-VTXO milestone exists to
suppress. Option 3 is rejected unconditionally. It is documented here
only because the issue lists it; it is not a viable v2 candidate either.

## Wire format

`ConfidentialTransaction` (the message #537 will produce) carries the fee
in a single field:

```protobuf
message ConfidentialTransaction {
  // … nullifiers, outputs, balance proof per #537 …
  uint64 fee_amount = 4;  // plaintext fee in satoshis (sats)
  // … schema_version, etc. per #537 …
}
```

### Units and value range

- **Field name:** `fee_amount` (snake_case in proto; idiomatic Rust
  binding: `fee_amount: u64`).
- **Type:** unsigned 64-bit integer (`uint64` in proto3,
  `u64` in Rust). Encoded as proto3 varint.
- **Units:** **satoshis** (sats), not millisatoshis, not BTC. This
  matches the units used everywhere in `dark-fee-manager`
  (`fee_rate_sats_per_vbyte` in `static_fee.rs` / `simple.rs` /
  `weight.rs`) and in `dark-core`'s `FeeManagerService::round_fee`
  return value. Implementations MUST NOT scale by 1000.
- **Range:** `[0, u64::MAX]`. Zero is permitted (see "zero-fee tx"
  below). Values exceeding the operator's per-round economic
  configuration are rejected at validation, not at parse.
- **Default:** proto3 default of `0`. A `ConfidentialTransaction` with
  the field absent is equivalent to a zero-fee transaction.

### Balance-equation lowering

The verifier in #538 lowers the field into the same `u64` argument
already accepted by `dark_confidential::balance_proof::verify_balance`:

```text
verify_balance(
    input_commitments  = tx.inputs.map(|i| i.commitment),
    output_commitments = tx.outputs.map(|o| o.amount_commitment),
    fee                = tx.fee_amount,          // <-- plaintext u64
    tx_hash            = transcript_hash(tx),
    proof              = tx.balance_proof,
) → bool
```

No transformation, no scaling, no per-version branching. The fee field
is the same `u64` `prove_balance` was called with on the sender side.

## Validation pseudocode

The validator (#538) MUST run the following checks, in this order, and
MUST short-circuit on the first failure with the named typed error.
Order matters because earlier checks bound the work later checks have to
do, and because the operator's accounting must not commit any partial
state if any check fails.

```rust
fn validate_fee(
    tx: &ConfidentialTransaction,
    operator_min_fee: u64,                   // from dark-fee-manager
    operator_max_fee: u64,                   // operator-side sanity cap
    is_operator_initiated: bool,             // sweeps, fee bumps
    is_fee_bump_replacement: bool,           // see fee-bump rules
    prior_tx_fee: Option<u64>,               // for fee-bump validation
) -> Result<(), ValidationError> {

    // (1) Parse-time sanity. The proto layer already typed fee_amount
    //     as u64; nothing to do here beyond confirming presence. proto3
    //     gives us 0 by default, which is a legal fee value (see #4).
    let fee = tx.fee_amount;

    // (2) Sanity cap. Reject obviously absurd fees before doing any
    //     cryptographic work. The cap is operator policy, not protocol.
    if fee > operator_max_fee {
        return Err(ValidationError::FeeAboveOperatorCap { fee, cap: operator_max_fee });
    }

    // (3) Minimum-fee gate. The operator's fee-manager publishes a u64
    //     minimum derived from the same metadata the operator already
    //     sees: nullifier count = input count, commitment count =
    //     output count, plus round-level overhead. CEL / RPC / static
    //     all collapse to a single u64 here.
    //
    //     Operator-initiated sweeps (round closures, expiry sweeps,
    //     unilateral exits the operator covers) bypass the minimum
    //     gate — the operator is its own counterparty and is free to
    //     accept a zero-fee or below-minimum transaction it
    //     constructed.
    if !is_operator_initiated && fee < operator_min_fee {
        return Err(ValidationError::FeeBelowMinimum { fee, min: operator_min_fee });
    }

    // (4) Zero-fee transactions: explicitly allowed for
    //     operator-initiated paths (sweeps, fee-manager-zero programs
    //     such as NoopFeeManager in tests, internal rebalancing). For
    //     user-submitted transactions, fee == 0 is a special case of
    //     check (3): it passes only if operator_min_fee == 0.
    //     There is no separate zero-fee branch — the gate above is
    //     sufficient and avoids having two ways to express the same
    //     policy.

    // (5) Fee-bump replacements: a replacement transaction that spends
    //     the same input nullifier(s) and the same output recipients
    //     but pays a higher fee. The validator's spent-set check
    //     (#538 step 1) rejects the second tx as a double-spend; fee
    //     bumps are therefore handled at the mempool / pre-spent-set
    //     layer, NOT inside validate_confidential_transaction. The
    //     mempool layer MUST require:
    //
    //         replacement_fee >= prior_fee + bump_increment
    //
    //     where bump_increment is operator policy (default: same as
    //     transparent BIP-125 bump policy). Once the mempool admits the
    //     replacement, the confidential-tx validator runs its full
    //     pipeline including this fee gate against the replacement's
    //     fee_amount, with no special-casing.
    if is_fee_bump_replacement {
        let prior = prior_tx_fee
            .ok_or(ValidationError::FeeBumpMissingPriorFee)?;
        if fee <= prior {
            return Err(ValidationError::FeeBumpNotIncreasing { prior, replacement: fee });
        }
        // The mempool layer has already enforced the bump_increment
        // delta; the validator only re-asserts the strict increase as
        // defence in depth.
    }

    // (6) Balance-proof binding. The fee is part of the transcript
    //     hashed into the balance proof's challenge (#526). Tampering
    //     the fee post-prove flips the challenge and the balance proof
    //     fails verification. validate_fee does NOT verify the balance
    //     proof itself — that is step (3) of the #538 pipeline — but
    //     this gate runs BEFORE balance-proof verification so a fee
    //     policy violation short-circuits before the expensive scalar
    //     multiplications.

    Ok(())
}
```

### Edge-case matrix

| Scenario | Behaviour | Rationale |
|---|---|---|
| `fee_amount` field absent on the wire | Treated as `0`. | proto3 default. Matches static-fee config returning `0`. |
| `fee_amount = 0`, `operator_min_fee = 0` | Accepted. | Consistent with `NoopFeeManager` in tests; covers fee-free deployments. |
| `fee_amount = 0`, `operator_min_fee > 0`, user-submitted | Rejected: `FeeBelowMinimum`. | Standard gate. |
| `fee_amount = 0`, operator-initiated sweep | Accepted. | Operator is its own counterparty. |
| `fee_amount` overflow in `Σ inputs − Σ outputs − fee` | Cannot occur arithmetically: the balance equation is over scalar field of secp256k1 (mod n), not over `u64`; `u64` overflow concerns the operator's own accounting only. | The verifier subtracts a curve point, not a `u64`. |
| `fee_amount = u64::MAX` | Rejected: `FeeAboveOperatorCap` (cap is operator policy, defaults to e.g. `1 BTC = 100_000_000` sats). | Defence-in-depth against accounting overflow on the operator's *own* ledgers. |
| `fee_amount` mutated post-prove | Rejected: `BalanceProofInvalid` at step (3) of #538. | `tx_hash` transcript binds `fee_amount`; mutation flips the Schnorr challenge. |
| Two concurrent submissions with overlapping nullifiers, both pass fee gate | One accepted, one rejected at step (1) of #538 (spent-set). | Fee gate is independent of double-spend detection. |
| Fee-bump replacement with `replacement_fee == prior_fee` | Rejected: `FeeBumpNotIncreasing`. | Bumps must strictly increase fee. |
| Fee-bump replacement that flips a non-fee field | Mempool rejects (replacement must preserve recipients/inputs); if it slips through, balance proof catches the input/output set change. | Defence-in-depth. |

## Interaction with `dark-fee-manager`

`dark-fee-manager` already exposes three modes against transparent
transactions, all of which reduce to a `u64` fee value the operator
publishes as the minimum acceptable amount:

| Mode | Source file | Output | Confidential-tx applicability |
|---|---|---|---|
| **Static** | `static_fee.rs` (`StaticFeeManager::estimate_fee_rate`) | fixed `u64` fee rate (sat/vbyte) | **Applies unchanged.** Operator multiplies by an estimated weight (see "Weight estimation" below) to produce `min_fee`. Suitable for dev / test deployments and `NoopFeeManager`. |
| **Bitcoin Core RPC** | `bitcoin_core.rs` (`BitcoinCoreFeeManager`) | `u64` fee rate from `estimatesmartfee` | **Applies unchanged.** The RPC sees only the operator's own node; no confidential metadata leaves the operator. |
| **mempool.space** | `mempool_space.rs` (`MempoolSpaceFeeManager`) | `u64` fee rate from public API | **Applies unchanged.** Same rationale: the operator queries an external API for *its own* fee target, not for any confidential-tx metadata. |
| **Weight-based** | `weight.rs` (`WeightBasedFeeManager`) | `u64` fee from `(num_inputs, num_outputs, fee_rate)` | **Applies with fixed-weight constants for confidential-tx weight.** See below. |
| **CEL fee program** | `dark-core::domain::fee::FeeProgram::calculate_intent_fee` | `u64` fee from per-input / per-output / base-fee parameters | **Applies unchanged.** CEL evaluates against `(offchain_inputs, onchain_inputs, offchain_outputs, onchain_outputs)` counts — *not* amounts. The counts on a confidential transaction are exactly the nullifier and output-commitment counts, both of which are public on the wire (the operator already counts them to verify nullifier non-replay and to size the round tree). CEL cannot leak amounts because CEL never sees them. |

### Weight estimation for confidential transactions

A confidential transaction's wire size is dominated by per-output range
proofs (~1.3 KB each at the Back-Maxwell sizing in ADR-0001) and the
balance proof (65 bytes). Per-input cost is dominated by the 32-byte
nullifier plus a fixed per-input metadata block. The fee-manager
infrastructure does not need to know these constants exactly — that is a
sizing concern, not a fee-handling concern — but `WeightBasedFeeManager`
needs *some* constants to score confidential-tx weight. Issue #543 owns
the calibration; this ADR fixes only the *interface*: the fee-manager
returns a `u64` minimum, and the validator compares `tx.fee_amount`
against it. Whether the manager arrived at that `u64` via static,
weight-based, RPC, or CEL is opaque to the validator.

### What the fee-manager surface MUST NOT change

Adding confidential-tx fee handling MUST NOT alter the existing
`FeeManager` / `FeeManagerService` traits in
`crates/dark-core/src/ports.rs`. The trait already returns `u64` from
every method (`boarding_fee`, `transfer_fee`, `round_fee`,
`estimate_fee_rate`, `compute_intent_fees`); confidential-tx fee scoring
adds a new method (e.g. `confidential_tx_fee` taking
nullifier/commitment counts) that returns `u64`. No existing method
signature moves.

### Privacy boundary for CEL

CEL fee programs run inside the operator. They evaluate against
metadata the operator already sees: nullifier count, output count,
intent shape. They do **not** see input or output *amounts* on a
confidential transaction (those amounts are committed and unavailable
even to the operator). CEL therefore cannot leak amount information no
matter how the operator writes the program. This is a structural
property of the data CEL receives, not a policy we have to enforce in
#543; the integration in #543 just has to ensure the CEL evaluator's
input struct does **not** include a plaintext-amount field.

## Consequences

### Positive

- **Zero new cryptography.** ADR-0001 / #524 / #525 / #526 are unchanged.
  The balance-proof verifier already takes a `u64 fee` argument; this
  ADR pins the wire encoding of that argument.
- **Zero new audit surface in `dark-fee-manager`.** Static, RPC,
  weight-based, and CEL all reduce to a `u64` minimum. The same
  programs that score transparent transactions score confidential ones.
- **Verifier hot path unchanged.** No additional range proof, no
  additional curve operations beyond what #526 already does.
- **Wire-additive.** A single `uint64` field on a new message; no
  renumbering of any transparent surface; #520 parity gate is met
  trivially.
- **CEL privacy is structural, not policy.** The CEL evaluator never
  sees amounts on a confidential tx, so there is nothing to redact.

### Negative / follow-ups

- **Fee amount visible on the wire.** A passive observer of the
  operator's gRPC ingress learns the fee. They do not learn input
  amounts, output amounts, or recipient identity. We accept this leak.
- **Fee-bump fingerprint.** Each successive bump exposes a new fee
  value, allowing a passive observer to learn that the same logical
  transaction was rebroadcast at a higher fee. The mempool layer
  should ratelimit bumps (operator policy); the leak is bounded by the
  number of bump attempts and is no worse than the transparent path.
- **No future v2 path inside this field.** If we ever decide to move
  to Option 2, we will mint a new `ConfidentialTransaction` schema
  version per #537 with a different fee field; we will not retrofit the
  existing `fee_amount` to mean "commitment". A follow-up issue
  **[FU-CONF-FEE-V2]** is appropriate if the privacy/cost tradeoff
  shifts (e.g. Bulletproofs aggregation per [FU-BP] makes the extra
  range proof cheap enough).
- **Operator-set fee minimum is global, not per-sender.** A sender who
  wants to pay below the operator minimum has no recourse other than
  finding a different operator. This is the same property transparent
  paths already have; the ADR does not change it.

### Cross-cutting — constraints on downstream issues

These are not suggestions; they are requirements for this ADR's
soundness. Any deviation must reopen ADR-0004 before landing.

#### #537 (`ConfidentialTransaction` proto + RPC surface) MUST

- Encode the fee as exactly one `uint64 fee_amount` field on
  `ConfidentialTransaction`. **Not** `bytes`, **not**
  `PedersenCommitment`, **not** a oneof.
- Use units of **satoshis** in the field's documentation block. The
  field comment MUST read literally: *"fee in satoshis (sats); plaintext
  per ADR-0004"* so future contributors do not have to read this ADR
  to learn the unit.
- Place `fee_amount` outside the confidential payload boundary — it is
  on the transaction message, not on any per-output message. There is
  exactly one fee per transaction.
- Carry the schema version on `ConfidentialTransaction` (per #537's own
  acceptance criteria). The version is the migration axis for any
  future v2 fee scheme; the fee field itself is unversioned.

#### #537 MUST NOT

- Add a `fee_commitment`, `fee_range_proof`, or `min_fee` field. These
  are reserved for a hypothetical v2; including them in v1 is a
  schema-design error that #537 reviewers MUST reject.
- Encode the fee at any per-output message (e.g. on
  `ConfidentialVtxoOutput`). Per-output fees are not a thing on the
  confidential side.
- Permit the `fee_amount` field to be a `oneof` with another encoding.
  The wire is one `uint64`; downgrading to `oneof` invites future
  ambiguity at parse time.

#### #538 (validation pipeline) MUST

- Run the fee gate before invoking
  `dark_confidential::balance_proof::verify_balance`, so a fee-policy
  failure short-circuits before scalar multiplications.
- Pass `tx.fee_amount` directly as the `fee: u64` argument to
  `verify_balance` with no transformation, no scaling, no `Option`
  wrapping. Absent fee on the wire lowers to `0` per proto3.
- Treat operator-initiated sweeps (round closures, expiry sweeps,
  operator-side rebalancing) as exempt from the minimum-fee gate. The
  operator-initiated bit comes from intent metadata (already in
  `dark-core`'s round/intent layer); the validator does not sniff it
  from the confidential payload.
- Surface a typed `ValidationError` enum variant for each failure mode
  named in the pseudocode above (`FeeBelowMinimum`,
  `FeeAboveOperatorCap`, `FeeBumpMissingPriorFee`,
  `FeeBumpNotIncreasing`). #538's acceptance criterion 1 ("unit tests
  cover every branch of `ValidationError`") encompasses these branches.
- Atomically reject the entire transaction on any fee-gate failure: no
  nullifier write, no output queue insertion, no metric mutation. This
  is the same invariant #538 already specifies for cryptographic
  failures.

#### #538 MUST NOT

- Read `tx.fee_amount` more than once during a validation pass (cache
  it in a local). A second read is a vector for a TOCTOU bug if the
  proto buffer is shared with the network layer.
- Verify a separate range proof on the fee. There is no fee range
  proof in v1.
- Compare `tx.fee_amount` against any value other than the
  `dark-fee-manager` minimum and the operator-side cap. In particular,
  the validator MUST NOT consult per-sender or per-key fee policies
  unless the operator's intent-layer surfaces them via the existing
  CEL/static/RPC funnel. There are no parallel fee data paths.

#### #543 (fee-manager integration) MUST

- Add a single new method on `FeeManagerService` (or a sibling trait
  living in `dark-fee-manager`) that takes confidential-tx metadata
  (nullifier count, output count, optionally the operator's
  intent-layer hints) and returns `u64`. Semantically, this is the
  same shape as `compute_intent_fees` already has for transparent
  intents.
- Wire the new method through Static, RPC (Bitcoin Core +
  mempool.space), Weight-based, and CEL. CEL takes the exact same
  evaluator the transparent intents take, with the same input struct
  shape (counts, not amounts).
- Document the calibration constants for confidential-tx weight in
  `docs/protocol/confidential-fees.md` (per #543's own acceptance
  criteria). This ADR does not pin those constants — they are sizing
  concerns, not fee-handling concerns.
- Provide an integration test that submits a confidential tx with
  `fee_amount = operator_min_fee − 1` (rejected) and another with
  `fee_amount = operator_min_fee` (accepted), per #543's acceptance
  criterion 2.

#### #543 MUST NOT

- Pass plaintext input or output amounts to the CEL evaluator on the
  confidential path. Amounts are not part of the CEL input struct.
  This is a structural invariant: the operator does not have the
  amounts to pass.
- Return a tuple `(min_fee, range_bits)` or any non-`u64` shape. The
  v1 fee-manager surface returns `u64`; #543 keeps it that way.
- Introduce a parallel fee-manager trait for confidential
  transactions. The same trait services both paths; the new method
  takes confidential metadata where applicable.
- Set or read `operator_max_fee` from `dark-fee-manager`. The
  operator-side sanity cap is round-policy, not fee-manager-policy;
  it lives in `dark-core`'s round layer.

## References

- Issue #536 (this ADR)
- Issue #537 — `ConfidentialTransaction` proto + RPC surface
- Issue #538 — validation pipeline in `dark-core`
- Issue #543 — fee-manager integration
- Issue #520 — Go `arkd` E2E parity gate
- Issue #526 — balance proof (excess Schnorr) in `dark-confidential`
- ADR-0001 — secp256k1-zkp integration strategy
- ADR-0002 — nullifier derivation scheme and domain separation
- ADR-0003 — confidential VTXO memo format and encryption scheme
- `crates/dark-fee-manager/` — static / RPC / weight-based / CEL backends
- `crates/dark-core/src/ports.rs` — `FeeManager`, `FeeManagerService` traits
- `crates/dark-core/src/domain/fee.rs` — `FeeProgram` (CEL surface)
- `crates/dark-confidential/src/balance_proof.rs` — verifier consuming `u64 fee`
