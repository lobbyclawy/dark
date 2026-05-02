# ADR-0009: PSAR mode integration — parallel pipeline inside `dark-psar`

- **Status:** Accepted
- **Date:** 2026-05-01
- **Milestone:** VON-M1 (phase/5-integration)
- **Drives:** #677 → unblocks #678 → #679 → #680
- **Affects:** new `dark_core::asp_mode` (~30 LOC enum + per-cohort
  dispatch tag), new adapter module inside `crates/dark-psar`, new
  `[ark.psar]` section in `config.example.toml`. Existing
  `crates/dark-core/src/{application,round_loop,round_scheduler,
  round_tree,cosigning}.rs` and `crates/dark-bitcoin/src/signing.rs`
  are **untouched** — see "Parity gate" below.

## Context

Phase 4 (#672–#676) landed a self-contained PSAR pipeline inside
`crates/dark-psar`: `boarding::asp_board`, `epoch::process_epoch`,
`resurface::user_resurface`, with the cryptographic core delegated to
`crates/dark-von-musig2` (`presign::presign_horizon`,
`epoch::sign_epoch`, `epoch::operator_partial`). Phase 5 has to make
this pipeline reachable from operator-facing surfaces (#678 mode tag,
#679 CLI, #680 demo binary) without disturbing the standard-mode
round flow.

This ADR makes the integration design choice between (a) an in-place
**adapter inside `dark-core`** that splices PSAR into the existing
round loop, and (b) a **parallel pipeline inside `dark-psar`** that
runs alongside the standard round loop and is selected by a per-cohort
mode tag.

## Survey — what exists today

The four files cited in #677 each have a different role; conflating
them obscures the actual integration surface, so they are recorded
separately here.

| File | LoC | Role | MuSig2 today |
|---|---|---|---|
| `crates/dark-core/src/application.rs` | 10,817 | `ArkService::start_round` and the round-loop body — registration, confirmation, finalization, broadcast | Calls `dark_bitcoin::signing::{generate_nonce, aggregate_nonces, create_partial_sig, aggregate_signatures}` at `application.rs:1776, 6860, 8460, 8475, 8676` |
| `crates/dark-bitcoin/src/signing.rs` | 398 | Standard MuSig2 plumbing on `musig2 = 0.3.1` | Owns the standard-mode `(nonce → partial → aggregate)` surface |
| `crates/dark-client/src/batch.rs` | 1,134 | Client-side batch flow: `secret_key`, `sec_nonces`, `pub_nonces`, `agg_nonces` | Calls `dark_bitcoin::generate_nonce` at `batch.rs:146` |
| `crates/dark-core/src/round_tree.rs` | 1,115 | VTXO Merkle tree for inclusion proofs at exit time | **No MuSig2 references.** Pure leaf-and-branch hashing; cited in #677 because it is co-located, not because it signs |
| `crates/dark-core/src/cosigning.rs` | 553 | Session-state manager (hex-typed nonce/partial-sig containers, state machine) | **Does not call MuSig2** — it orchestrates collection and stores opaque hex |
| `crates/dark-core/src/round_loop.rs` | 398 | Tick-driven driver around `ArkService::start_round` | Indirect (through `application.rs`) |

**Shape mismatch** between the two flows is the load-bearing fact for
this ADR:

- **Standard mode** signs once per round on a freshly-generated nonce
  pair; nonces are collected interactively each round and discarded
  after aggregation.
- **PSAR mode** pre-signs an entire horizon of `N` per-epoch renewals
  at boarding time (`dark_von_musig2::presign::presign_horizon`),
  binds each renewal to its epoch index `t` via
  `dark_psar::message::derive_message_for_epoch`, and then merely
  *consumes* the pre-signatures across `N` later epochs (the per-epoch
  loop in `dark_psar::epoch::process_epoch` does not request fresh
  nonces — that is the whole point of VON's hibernation property).

The two flows are not drop-in substitutable per round: PSAR's nonces
come from `dark_von::wrapper::nonce` once at boarding, not from
`dark_bitcoin::signing::generate_nonce` once per round. Any in-place
splice has to teach the round loop's nonce-collection phase to be
absent for PSAR cohorts and to instead read pre-signed material from
an `ActiveCohort` store.

## Candidates

### Option A — Adapter inside `dark-core` (rejected)

Teach `application.rs` to branch on a per-cohort mode tag at every
MuSig2 call site (`application.rs:1776, 6860, 8460, 8475, 8676`),
suppress nonce collection for `Psar` cohorts, route partial-sig
generation to `dark_von_musig2::epoch::operator_partial`, and route
aggregation to the existing path.

- 10,817-line `application.rs` is the single biggest file in the
  repo. Five MuSig2 call sites, each on a different round-loop
  state. Suppressing nonce collection for PSAR cohorts requires
  re-shaping the state machine in `application.rs` and the
  `cosigning.rs` session manager (which assumes one nonce per signer
  per session) — neither is a 1-2 day refactor by any reasonable
  estimate.
- Touching `application.rs` puts every standard-mode test in
  `crates/dark-core/tests/integration/` and `tests/e2e_regtest.rs`
  on the line. That is the parity gate from #520; the cost of
  protecting it grows with the size of the patch.
- The `cosigning.rs` session manager types nonces and partial sigs
  as hex `String`s. PSAR partial sigs are 32-byte scalars with an
  associated horizon-bound aggregator nonce — fitting them through
  the existing `String`-typed surface would either widen the type
  (breaking standard mode) or stringify the PSAR data (lossy and
  pointless).

#677's acceptance criterion #3 says: *"Recommends parallel-pipeline
if integration would block the AFT timeline; integration if it's a
1-2 day refactor."* Adapter-in-dark-core is not a 1-2 day refactor.

### Option B — Parallel pipeline inside `dark-psar` (chosen)

Keep the standard-mode round loop in `application.rs` exactly as it
is. Add a thin `AspMode { Standard, Psar(HibernationHorizon) }` enum
in `dark-core` whose role is selecting *which loop is alive* per
cohort, not branching inside the round loop. Standard cohorts
continue through `ArkService::start_round`. Psar cohorts run an
independent driver in `dark-psar` that calls
`dark_psar::epoch::process_epoch` on a per-epoch tick.

The `AspMode` enum lives in `dark-core` so that operator
configuration code can reference it without depending on
`dark-psar`. The actual dispatch — pick the loop, hand it an
`ActiveCohort`, observe `EpochArtifacts` — lives in `dark-psar` as
the natural home for PSAR-aware orchestration. Configuration is
declared per-cohort in `[ark.psar]` (no-op default; standard mode
unchanged when the section is absent).

| Pros | Cons |
|---|---|
| `application.rs`, `round_loop.rs`, `cosigning.rs`, `round_tree.rs`, `dark-bitcoin::signing` all untouched — parity gate trivially holds | Two parallel ASP loops coexist; operator config has to declare per cohort |
| Naturally accommodates the shape mismatch (per-round vs pre-signed-horizon) | Demo binary (#680) re-implements a tiny sliver of round driver, not exposed as `ArkService` integration |
| Fits Phase 4's existing surface — `process_epoch` is already self-contained | Future "mixed cohort within one round" support would require revisiting (out of scope for VON-M1) |
| Standard-mode tests in `tests/e2e_regtest.rs` remain bit-identical (only depend on `application.rs` state) | Live ASP integration deferred — `psar-demo` (#680) is the integration target for Phase 5, not `dark-bin` |

## Decision

**Adopt Option B.** Phase 5 implements PSAR as a parallel pipeline
inside `dark-psar`, selected by a per-cohort `AspMode` tag declared
in `dark-core`. The standard-mode round loop and its supporting
infrastructure are not modified.

### Per-cohort mode tag

Add `crates/dark-core/src/asp_mode.rs` (new):

```rust
pub enum AspMode {
    Standard,
    Psar(dark_psar::HibernationHorizon),
}
```

The enum is constructed by `dark_core::config` from the new
`[ark.psar]` config section and stored on a new
`AspModeRegistry: HashMap<CohortId, AspMode>` (in-memory for #678,
persistence is out of scope for VON-M1). The registry has one
public method, `dispatch_signing(cohort_id) -> AspMode`, used by
the parallel pipeline driver in `dark-psar` to pick its branch.
`application.rs` does **not** consult the registry — standard rounds
ignore PSAR cohorts entirely.

### Parallel-pipeline driver

Add `crates/dark-psar/src/adapter.rs` (new): a thin ASP-side loop
that, for each `Psar` cohort in the registry, calls
`dark_psar::epoch::process_epoch` on a per-epoch tick. The driver
owns the `ActiveCohortStore` from #671 and surfaces
`EpochArtifacts` to the demo binary's report writer (#680).

### Configuration

Add to `config.example.toml`:

```toml
[ark.psar]
# Default mode; cohorts not listed here are Standard.
default_mode = "standard"

# Optional: per-cohort overrides (used by the demo binary in #680).
# cohorts = [
#   { id = "...", mode = "psar", n = 12, max_n = 24 },
# ]
```

When the section is absent, every cohort is `Standard` and the
parallel pipeline driver is not spawned. This is the no-op default
required by #678's acceptance criterion #4.

## Parity gate

Standard-mode flows must remain bit-identical, mirroring the
transparent-VTXO parity gate from #520. The mechanism:

- **No file under `crates/dark-core/src/` outside `asp_mode.rs`
  changes in #678–#680.** A grep over the diff for the Phase 5 PR
  must show only `crates/dark-core/src/asp_mode.rs` (added),
  `crates/dark-core/src/lib.rs` (one-line `pub mod asp_mode`),
  `config.example.toml`, and the dark-psar / ark-cli additions.
- **`tests/e2e_regtest.rs` runs unchanged** in CI. Any regression
  in standard-mode parity surfaces as a failed test in that suite.
- **Golden vector for standard 2-of-2:** #678 lands a small golden
  vector (32-byte msg, two pinned secret keys, expected 64-byte
  Schnorr aggregate) verifying that
  `dark_bitcoin::signing::sign_full_session` still produces the
  pre-PSAR-Phase-5 byte sequence. This guards against accidental
  drift in `dark-bitcoin` deps if a transitive `musig2 = 0.3.1`
  bump slips in.

## Per-issue file plan (#678–#680)

The acceptance criterion for #677 (#2) requires this to be enumerated
explicitly. "Additive" = new file or new `pub` item; "refactor" =
edits to existing types/signatures.

### #678 — `AspMode` adapter

| File | Kind | Notes |
|---|---|---|
| `crates/dark-core/src/asp_mode.rs` | additive (new) | `AspMode` enum + `AspModeRegistry` + `dispatch_signing` |
| `crates/dark-core/src/lib.rs` | additive (one line) | `pub mod asp_mode;` |
| `crates/dark-psar/src/adapter.rs` | additive (new) | Parallel-pipeline driver consuming the registry |
| `crates/dark-psar/src/lib.rs` | additive (one line) | `pub mod adapter;` |
| `config.example.toml` | additive | New `[ark.psar]` section |
| `crates/dark-core/src/config.rs` (if it exists, else `src/config.rs`) | additive | Parse `[ark.psar]` into `PsarConfigSection` |
| `crates/dark-bitcoin/tests/golden_2of2.rs` | additive | Standard-mode parity golden vector |

No refactors. Five new files, two one-line additions, one new test.

### #679 — `ark-cli psar` subcommands

| File | Kind | Notes |
|---|---|---|
| `crates/ark-cli/src/psar.rs` | additive (new) | `board / advance-epoch / resurface` handlers, JSON-line stdout |
| `crates/ark-cli/src/main.rs` | refactor (one new `Commands::Psar` variant) | Wire the new subcommand tree |
| `crates/ark-cli/tests/psar_cli.rs` | additive (new) | CLI integration test mirroring `ark-cli/tests/test_cli_*` style |
| `docs/sdk/psar.md` | additive (new) | Manual smoke (boarding → 2 epochs → resurface) |

One refactor (the main.rs Clap subcommand variant), three additive.

### #680 — `psar-demo` binary

| File | Kind | Notes |
|---|---|---|
| `crates/dark-psar/src/bin/psar-demo.rs` | additive (new) | Demo entry point with `clap` flags `--k 100 --n 12 --report-path -` |
| `crates/dark-psar/src/report.rs` | additive (new) | `RunReport` struct + JSON ser/deser; stable schema for #687 |
| `crates/dark-psar/Cargo.toml` | refactor (one `[[bin]]` block) | Register `psar-demo` |
| `crates/dark-psar/tests/e2e_psar_demo.rs` | additive (new) | Reuses #676's K=10/N=4 smoke fixture; asserts JSON report parses back |

One refactor (Cargo.toml `[[bin]]`), three additive.

## Cross-cutting — constraints on downstream issues

- **#678** MUST keep the `AspMode` enum in `dark-core`, not
  `dark-psar`. The parallel-pipeline driver uses
  `dark_psar::HibernationHorizon` re-exported through
  `dark-core::asp_mode::AspMode::Psar(_)`. Cyclic-dep gotcha:
  `dark-core` already declares `dark-psar` in `Cargo.toml` (or will
  in #678) — verify with `cargo tree -i dark-psar` before merging.
  If a cycle appears, move `HibernationHorizon` into a shared
  leaf crate (out of scope; flag in the PR for follow-up).
- **#678** MUST add the standard-mode golden-vector test as an
  acceptance gate. Without it, this ADR's parity-gate claim is
  unverified.
- **#678** MUST NOT touch `crates/dark-core/src/application.rs`,
  `round_loop.rs`, `round_scheduler.rs`, `cosigning.rs`,
  `round_tree.rs`, or `crates/dark-bitcoin/src/signing.rs`. If a
  reviewer finds a hunk in any of those files, fail the review.
- **#679** MUST emit one structured JSON line per subcommand on
  stdout (per the spec). Stderr remains free-form for `tracing`
  output. Tests assert exit code 0 + JSON parses to the expected
  schema; they do not assert on stderr content.
- **#679** depends on #675's `user_resurface` surface (already
  merged in Phase 4) — re-export through `dark_psar::ResurfaceArtifact`.
- **#680** MUST land before phase 6 benchmarking (#681–#687).
  The `--report-path` JSON schema is the contract #687 plots
  against; once #680 merges, the schema is frozen for that phase.
- **#680** MUST run `K=100, N=12` in under 5 minutes on dev
  hardware (the per-epoch e2e #676 already runs in 18s; demo wraps
  it with N=12 epochs + boarding + resurface, ≈ 4 minutes
  expected). The `K=1000, N=12` gate is for #684, not #680.

## Consequences

### Positive

- **Parity gate trivially holds.** No file in `dark-core` outside
  the new `asp_mode.rs` changes; existing tests need no edits.
- **Shape mismatch is honoured.** The pre-signed-horizon flow does
  not have to pretend to be a per-round flow.
- **Phase 4 surface stays the integration boundary.**
  `dark_psar::epoch::process_epoch` is already self-contained and
  tested against K=100/N=12 in #676; #678 adds an orchestrator
  around it, not a refactor of it.
- **Operator config is declarative.** Switching a cohort to PSAR is
  a `[ark.psar]` edit, not a code change.

### Negative / follow-ups

- **Two ASP loops coexist** until a future phase consolidates them.
  This is the same posture ADR-0008 took for the two MuSig2
  implementations: live with the duplication, gate cross-validation
  on every PR, plan a follow-up. **Follow-up [FU-PSAR-CONSOLIDATE]:**
  once the demo binary stabilises and PSAR cohorts run on a real
  ASP, evaluate whether `application.rs` should grow a thin
  `AspMode` branch (re-evaluating the cost-benefit at that point;
  estimate today: ~1 week).
- **Mixed cohorts in a single round are out of scope.** A round
  containing both `Standard` and `Psar` participants is not
  supported by this design. The Ark protocol does not currently
  require it; if a future use case appears, it would warrant a
  new ADR and is not a regression introduced here.
- **Live ASP integration deferred.** `psar-demo` (#680) is the
  Phase 5 integration target; wiring `dark-bin` to actually run
  PSAR cohorts in production is a Phase 6+ concern. Reproducibility
  for the AFT submission is satisfied by the demo binary, not by a
  live deployment.

## References

- Issue #677 (this ADR), #678–#680 (downstream).
- ADR-0007 — VON wrapper construction (origin of pre-signed
  horizon scalars).
- ADR-0008 — MuSig2 nonce-injection strategy; precedent for
  "two implementations coexist behind cross-validation".
- `crates/dark-core/src/application.rs:1776, 6860, 8460, 8475, 8676`
  — the standard MuSig2 call sites that this ADR commits to leaving
  untouched.
- `crates/dark-bitcoin/src/signing.rs` — standard-mode MuSig2 plumbing.
- `crates/dark-psar/src/epoch.rs` — Phase 4 `process_epoch`,
  the parallel pipeline's per-epoch entry point.
- `crates/dark-von-musig2/src/{epoch,presign}.rs` —
  `sign_epoch`, `operator_partial`, `presign_horizon`,
  the cryptographic core called from the parallel pipeline.
- Issue #520 — transparent-VTXO parity gate, the prior-art for the
  parity discipline this ADR adopts.
