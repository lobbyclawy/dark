# Confidential validation errors — observability and log hygiene

Issue: [#544](https://github.com/lobbyclawy/dark/issues/544) (depends on #538).

This document is the operational contract for the
`ConfidentialValidationError` enum in `dark-core` and its companion
Prometheus counter. It exists so that:

- On-call engineers know which fields are safe to grep, alert on, and
  expose in dashboards.
- Implementers extending the enum know which fields must **never** be
  added.
- Auditors can verify by inspection that no secret material leaks
  through error paths.

## What this enum is

`crate::confidential_validation_error::ConfidentialValidationError` is
the canonical typed error surface returned by the confidential
transaction validation pipeline (issue #538). It replaces stringly-typed
`Validation(String)` errors at the confidential boundary with a fixed
set of variants, each carrying public, structured context.

## Variants and what they carry

All hex strings are lowercase. All sizes are byte counts of public
material (commitments) or ciphertext (memo) — never plaintext lengths
that could leak structural info about secrets.

| Variant | Structured fields | Safe to log? | Notes |
|---|---|---|---|
| `InvalidRangeProof` | `vtxo_id: VtxoId`, `commitment_hex: String` | Yes | Outpoint + 33-byte commitment are public. |
| `InvalidBalanceProof` | `tx_hash_hex: String` | Yes | Public transaction hash. |
| `NullifierAlreadySpent` | `nullifier_hex: String` | Yes | Nullifier is public once revealed (ADR-0002). |
| `UnknownInputVtxo` | `vtxo_id: VtxoId` | Yes | Outpoint is public. |
| `FeeTooLow` | `provided_sats: u64`, `required_sats: u64` | Yes | Fees are public in confidential txs. |
| `MemoTooLarge` | `actual_bytes: usize`, `max_bytes: usize` | Yes | Sizes only — never content. |
| `MalformedCommitment` | `reason: String` | Yes | Controlled tag (e.g. `"length"`, `"not on curve"`). Never raw bytes. |
| `VersionMismatch` | `client_version: u32`, `server_version: u32` | Yes | Public protocol negotiation. |

## What MUST never appear

These items are explicitly **forbidden** in any current or future
variant. A code review that adds any of them must be rejected:

- **Blinding factors** — `r`, `r'`, sum-of-blindings, scalar randomness
  used in Pedersen commitments. Leaking a blinding factor immediately
  reveals the corresponding amount.
- **One-time / ephemeral private keys** — including the ECDH ephemeral
  `e` published with VTXOs and any signing nonces.
- **Memo plaintext or memo ciphertext bytes** — `MemoTooLarge` carries
  sizes only. Bytes (including hex of the ciphertext) are not error
  context.
- **Cleartext amounts** — only fees (which are public) may be logged via
  `FeeTooLow`.
- **Untrusted attacker-supplied bytes pass-through in `reason` strings**
  — `MalformedCommitment::reason` must be a fixed, controlled tag from a
  small allowed set, not a stringified copy of the offending input.

If a future variant needs to expose more context, that context must be
public information (existing on-chain or in plaintext request fields).
When in doubt, prefer adding a separate metric label over a free-form
field.

## Per-variant log-hygiene rule (one line each)

- `InvalidRangeProof` — log VTXO outpoint + commitment hex; never log
  range-proof bytes or amounts.
- `InvalidBalanceProof` — log transaction hash; never log per-output
  commitments, blinding sums, or amounts.
- `NullifierAlreadySpent` — log nullifier hex; never log the spending
  key, nor the input VTXO's blinding key.
- `UnknownInputVtxo` — log outpoint; never log any decryption attempt
  state.
- `FeeTooLow` — log provided & required fees in sats; never log output
  amounts or change.
- `MemoTooLarge` — log actual & max byte sizes; never log memo bytes
  (plaintext or ciphertext).
- `MalformedCommitment` — log a controlled `reason` tag; never echo the
  malformed input bytes back into the log line.
- `VersionMismatch` — log both protocol version numbers; nothing else.

## Counter: where it is incremented

The Prometheus counter

```text
dark_confidential_validation_error_total{reason="<reason>"}
```

is exported from `dark_core::metrics` and lives in the global
`dark_core::metrics::REGISTRY`. The label set is closed and produced by
`ConfidentialValidationError::reason()`:

- `invalid_range_proof`
- `invalid_balance_proof`
- `nullifier_already_spent`
- `unknown_input_vtxo`
- `fee_too_low`
- `memo_too_large`
- `malformed_commitment`
- `version_mismatch`

Incrementation is centralised on the error itself: callers in the
validation pipeline construct the variant and call
`.observe()` before returning it. This makes it impossible to forget the
metric at a call-site:

```rust
return Err(ConfidentialValidationError::FeeTooLow {
    provided_sats,
    required_sats,
}
.observe());
```

`observe()` calls `dark_core::metrics::record_confidential_validation_error`,
which performs an `IntCounterVec::with_label_values(&[reason]).inc()`.
All eight `reason` values are pre-touched at registry initialisation so
they appear at `0` in the first `/metrics` scrape — Grafana panels
grouped by `reason` therefore show a stable legend.

## Grafana panel suggestion

Recommended panel for the on-call dashboard (one panel per cluster):

- **Title:** Confidential validation rejections by reason
- **Type:** Time series, stacked
- **Query (PromQL):**
  ```promql
  sum by (reason) (
    rate(dark_confidential_validation_error_total[5m])
  )
  ```
- **Legend:** `{{reason}}`
- **Unit:** errors/sec
- **Companion stat panel:** total reject rate
  ```promql
  sum(rate(dark_confidential_validation_error_total[5m]))
  ```
- **Alert candidates** (start permissive, tighten with traffic data):
  - Page when `nullifier_already_spent` rate > N/s for 5 minutes
    (sustained double-spend attempts).
  - Page when `invalid_balance_proof` rate spikes > 3x the 24h baseline
    (possible client bug or attack).
  - Warn on any `version_mismatch` > 0 for more than 15 minutes after a
    server upgrade window (clients failing to migrate).

## Audit checklist (commit-time)

Use this checklist when adding or modifying a variant:

1. [ ] Each new field is public material (or a size in bytes).
2. [ ] No blinding factor, no one-time key, no plaintext is referenced.
3. [ ] `reason()` returns a unique, lowercase, snake_case tag.
4. [ ] The new tag is added to `CONFIDENTIAL_VALIDATION_ERROR_REASONS`.
5. [ ] A `#[test]` exercises the structured context and asserts the tag.
6. [ ] This document's variant table is updated.
