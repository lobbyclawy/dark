# Confidential transaction fee handling (#543)

This document is the operator-facing reference for how
`dark-fee-manager` scores confidential transactions. It is the deliverable
named in issue #543 ("document the exact fee-calculation path") and
implements the constraints in
[ADR-0004](../adr/0004-confidential-fee-handling.md).

The wire shape (plaintext `fee_amount: u64` on
`ConfidentialTransaction`) and the validator-side gate (#538) are out of
scope for this file — see ADR-0004 §"Wire format" and §"Validation
pseudocode" respectively.

## Scope

ADR-0004 §"Constraints on #543" requires:

> Add a single new method on `FeeManagerService` (or a sibling trait
> living in `dark-fee-manager`) that takes confidential-tx metadata
> (nullifier count, output count, optionally the operator's intent-layer
> hints) and returns `u64`.

Issue #543 lands the method, wires it through every existing fee program
(static, RPC, weight-based, CEL), pins the calibration constants for the
weight-based backend, and ships an integration test proving
fee-too-low / correct-fee acceptance against each backend.

## Trait surface

The method is added to the existing `FeeManagerService` trait in
`crates/dark-core/src/ports.rs`:

```rust
async fn minimum_fee_confidential(
    &self,
    inputs: usize,
    outputs: usize,
) -> ArkResult<u64>;
```

Inputs:

- `inputs`: nullifier count from `ConfidentialTransaction.nullifiers`.
- `outputs`: output-commitment count from
  `ConfidentialTransaction.outputs`.

Output: a single `u64` minimum-fee value in **satoshis**, comparable
directly against `tx.fee_amount` on the wire.

The trait stays object-safe and keeps its existing object-safety
property (`dyn FeeManagerService` continues to compile and is exercised
by `crates/dark-core/src/ports.rs::tests::test_fee_manager_service_object_safe`).

A default implementation falls back to `round_fee(inputs + outputs)` so
existing backends that have not opted in (e.g. third-party
`FeeManagerService` implementors) keep compiling unchanged.

### What the surface MUST NOT do

Per ADR-0004 §"Constraints on #543" the method MUST NOT:

- Return a tuple `(min_fee, range_bits)` or any non-`u64` shape.
- Receive plaintext input or output amounts. The operator does not have
  the amounts; the trait does not surface them.
- Set or read `operator_max_fee` — that is round-policy and lives in
  `dark-core`'s round layer.
- Spawn a parallel trait. The same `FeeManagerService` services
  transparent and confidential paths.

## Per-backend wiring

Every backend implements `minimum_fee_confidential` and reduces, by its
own internal logic, to a single `u64` minimum fee.

### Static (`SimpleFeeManager`)

`crates/dark-fee-manager/src/simple.rs`. Configured with a flat fee rate
in `sat/vbyte` and a deployment minimum:

```text
minimum_fee_confidential(inputs, outputs)
  = max(
      confidential_vbytes(inputs, outputs) × fee_rate_sats_per_vbyte,
      min_fee_sats
    )
```

Suitable for dev / test deployments and the `NoopFeeManager`-equivalent
zero-rate configuration.

### RPC (`BitcoinCoreFeeManager`, `MempoolSpaceFeeManager`)

`crates/dark-fee-manager/src/bitcoin_core.rs` and `mempool_space.rs`. The
RPC backend queries `estimatesmartfee` (Bitcoin Core) or
`/api/v1/fees/recommended` (mempool.space) for the operator's **own**
node — confidential metadata never leaves the operator. The
`minimum_fee_confidential` method lowers the fetched `sat/vbyte` rate
through the shared confidential weight table:

```text
minimum_fee_confidential(inputs, outputs)
  = max(
      confidential_vbytes(inputs, outputs) × estimate_fee_rate(Conservative),
      0
    )
```

Operators wanting a deployment-side fee floor wrap the RPC manager in
`ConfidentialFeeAdapter` (see
`crates/dark-fee-manager/src/confidential.rs`), which exposes the same
`FeeManagerService` surface and clamps the result to a configured
minimum.

### Weight-based (`WeightBasedFeeManager`)

`crates/dark-fee-manager/src/weight.rs`. The dedicated weight backend
charges a per-input, per-output, per-tx weight calibrated against
`docs/benchmarks/confidential-primitives.md`:

```text
weight_mvb = CONFIDENTIAL_TX_OVERHEAD_MVB
           + inputs  × CONFIDENTIAL_INPUT_MVB
           + outputs × CONFIDENTIAL_OUTPUT_MVB

vbytes     = ceil(weight_mvb / 1000)

minimum_fee_confidential(inputs, outputs)
  = max(vbytes × fee_rate_sats_per_vbyte, min_fee_sats)
```

The constants live in `crates/dark-fee-manager/src/confidential.rs` and
are reused by all rate-only backends through `confidential_vbytes`.

### CEL (`FeeProgram`)

`crates/dark-core/src/domain/fee.rs`. A new method on `FeeProgram`
scores confidential intents from counts only:

```rust
pub fn calculate_confidential_intent_fee(&self, inputs: u32, outputs: u32) -> u64 {
    self.base_fee
        + self.offchain_input_fee  * inputs  as u64
        + self.offchain_output_fee * outputs as u64
}
```

Confidential VTXOs are off-chain by construction — the `onchain_*_fee`
rates are deliberately ignored on this surface (a sentinel test pins the
contract). Operators wanting per-confidential pricing tune the
`offchain_*_fee` rates that already drive transparent off-chain VTXO
intents.

Per ADR-0004 §"Privacy boundary for CEL" the program receives no
plaintext amounts — it cannot, because the operator does not have them.
This is a structural property of the input shape, not a policy enforced
by code review.

## Calibration constants

The weight constants in `crates/dark-fee-manager/src/confidential.rs`:

| Constant                          | Value        | Source                                  |
|-----------------------------------|--------------|-----------------------------------------|
| `CONFIDENTIAL_TX_OVERHEAD_MVB`    | `80_000`     | balance proof (65 B) + framing + varints |
| `CONFIDENTIAL_INPUT_MVB`          | `40_000`     | 32-byte nullifier + per-input metadata  |
| `CONFIDENTIAL_OUTPUT_MVB`         | `1_500_000`  | range proof (~1.3 KB) + commitment (33 B) + ephemeral pubkey (33 B) + owner pubkey (33 B) + memo envelope (~80 B) + framing |

All values are in **milli-vbytes** (mvB); divide by 1000 (with `div_ceil`)
to obtain vbytes. Pure integer arithmetic — no floating point.

The numbers are derived from
[`docs/benchmarks/confidential-primitives.md`](../benchmarks/confidential-primitives.md)
(range proofs, balance proofs, Pedersen commitments) and from the
on-the-wire byte counts pinned in
[`docs/protocol/confidential-vtxo-schema.md`](confidential-vtxo-schema.md).
A bench regression that shifts proof-byte sizes is the trigger for
updating these constants in the same PR that touches the bench doc.

### Worked example

For a confidential transaction with 1 input and 1 output:

```text
weight_mvb = 80_000 + 1×40_000 + 1×1_500_000 = 1_620_000
vbytes     = ceil(1_620_000 / 1000) = 1_620
```

At 5 sat/vB this lowers to a minimum fee of `1_620 × 5 = 8_100 sats`.
At 1 sat/vB (testnet default) the minimum is `1_620 sats` — directly
comparable against the `fee_amount` field on the wire.

## Validator integration (cross-issue)

The validator (#538) uses the result of `minimum_fee_confidential`
exactly once per submission, per the ADR-0004 §"Validation pseudocode":

```text
let min  = fee_manager.minimum_fee_confidential(inputs, outputs).await?;
let fee  = tx.fee_amount;                            // single read

if !is_operator_initiated && fee < min {
    return Err(ValidationError::FeeBelowMinimum { fee, min });
}
```

Operator-initiated sweeps bypass the gate (see ADR-0004 step (3) of
`validate_fee`). The validator also enforces the per-deployment cap
`operator_max_fee` and the fee-bump increment, both of which live in
`dark-core` and are out of scope for the fee-manager.

## Tests

### Unit tests (per backend)

- `crates/dark-fee-manager/src/confidential.rs::tests` — weight constants,
  `confidential_vbytes`, `minimum_fee_for_rate`, `ConfidentialFeeAdapter`.
- `crates/dark-fee-manager/src/simple.rs::tests` —
  `minimum_fee_confidential` clamping, scaling, rate behaviour.
- `crates/dark-fee-manager/src/weight.rs::tests` —
  `estimate_confidential_fee`, count-only contract, scaling per
  input / per output.
- `crates/dark-core/src/domain/fee.rs::tests` —
  `calculate_confidential_intent_fee` zero-program, base-only,
  offchain-only invariant, scaling.

### Integration test (acceptance criterion 2)

`crates/dark-fee-manager/tests/confidential_fee_integration.rs` exercises
the rejected/accepted contract for every wired backend (Static / Weight
/ RPC-adapter / CEL / Noop) against a tiny in-test fee gate that mirrors
the ADR-0004 §"Validation pseudocode". For each backend it asserts:

1. `fee_amount = min - 1` rejects with `ERROR_FEE_TOO_LOW` (mapped to
   the `Verdict::RejectedFeeTooLow` variant in-test).
2. `fee_amount = min` accepts.
3. `fee_amount = min + 1` accepts.
4. The CEL surface ignores `onchain_*_fee` (sentinel value pins this).
5. `NoopFeeManager` accepts a zero-fee confidential tx (zero-min config,
   per ADR-0004 edge-case row "`fee_amount = 0`,
   `operator_min_fee = 0`").

## References

- [ADR-0004 — Fee handling in confidential transactions](../adr/0004-confidential-fee-handling.md)
- [Confidential VTXO + transaction proto schema](confidential-vtxo-schema.md)
- [`dark-confidential` benchmark baseline](../benchmarks/confidential-primitives.md)
- Issue #536 — ADR drafting
- Issue #537 — `ConfidentialTransaction` proto + RPC surface
- Issue #538 — validation pipeline in `dark-core`
- Issue #543 — this document's owning issue
- `crates/dark-fee-manager/src/confidential.rs` — weight constants and
  `ConfidentialFeeAdapter`
- `crates/dark-core/src/ports.rs` — `FeeManagerService` trait
- `crates/dark-core/src/domain/fee.rs` — `FeeProgram` (CEL) surface
