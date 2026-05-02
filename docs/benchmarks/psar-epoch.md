# PSAR per-epoch ASP latency

Source of truth for issue #683's per-epoch ASP-side latency curve.
Regenerate with:

```bash
cargo bench -p dark-psar --bench epoch -- --quick

# Optional K=10000 stretch row (≈10 min including setup):
BENCH_LONG=1 cargo bench -p dark-psar --bench epoch -- long
```

Numbers below are the median of one Criterion `--quick` run (3 s
measurement, 1 s warm-up, sample size 10 — overridden because per-K
iteration cost grows linearly).

## Hardware context

| Field     | Value                                       |
|-----------|---------------------------------------------|
| CPU       | Apple M3 Max                                |
| Cores     | 14 (10 performance + 4 efficiency)          |
| Memory    | 36 GB                                       |
| OS        | macOS 26.3.1 (Darwin 25.3.0)                |
| Toolchain | rustc 1.95.0 (release profile, lto = false) |

## What `process_epoch` does

For each cohort member at fixed epoch `t` (`crates/dark-psar/src/epoch.rs`):

1. Look up the participant's pre-signed `(pub_nonce, partial_sig)` for
   `t-1` from the in-memory `ActiveCohort.artifacts` map.
2. Rebuild the 2-of-2 `KeyAggCtx` over `[asp_pk, member_pk]`.
3. Invoke `dark_von_musig2::epoch::sign_epoch`, which:
   a. Re-derives the operator's `(R₁, R₂)` for `t` from
      `RetainedScalars`.
   b. Aggregates `(R_op, participant_R)` into `agg_nonce`.
   c. Calls `partial_sig_verify` against the participant's partial.
   d. Computes the operator's partial via `partial_sign_with_scalars`.
   e. Aggregates the two partials into a 64-byte BIP-340 signature.

The cost is dominated by step 3.c (`partial_sig_verify` ≈ 225 µs) per
the standalone numbers in
`docs/benchmarks/von-musig2-primitives.md`.

The horizon `N` does not affect per-epoch cost (one epoch is one
epoch's worth of work regardless of horizon length); the bench
fixture uses the smallest legal `N=2` to keep boarding-side setup
fast.

## Per-epoch latency vs K

| `K`    | Median       | Per-user (`/K`) | Notes |
|--------|--------------|-----------------|-------|
| 100    | 22.9 ms      | 229 µs          |       |
| 1 000  | 226.8 ms     | 226 µs          |       |
| 10 000 | TBD (`BENCH_LONG=1`) | TBD     | Long-run group; documented when first measured |

Per-user cost stays in the **226–229 µs band** — confirms linearity
with no hidden quadratic (consistent with the standalone primitives:
~225 µs `partial_sig_verify` + ~45 µs `partial_sign` + ~20 µs
`aggregate` overlapping with KeyAggCtx caching).

## Rate

At K=1000, **226 ms per epoch** = **4 410 user-renewals/second**
sustained on dev hardware. The lead-config table for the paper at
K=100 / N=12 cohorts:

```text
process_epoch(K=100)  = 22.9 ms / epoch
total per cohort      = N × process_epoch = 12 × 22.9 ms ≈ 275 ms
```

## Parallelisation outlook

`process_epoch` walks `cohort.members` serially. Per-user work is
trivially parallelisable (each user's `KeyAggCtx + sign_epoch` is
independent). At K=1000 a 14-core M3 Max would expect ~14× speedup
modulo NUMA — i.e. ~16 ms per epoch. **Phase 6 does not implement
parallelisation**; the speedup is reported as a follow-up if
serial latency becomes a bottleneck on the production ASP path.

## Threshold sentinels

| Bench                    | Envelope (Apple M-series) | Notes |
|--------------------------|---------------------------|-------|
| `process_epoch/100`      | ≤ 50 ms                   | ~2× slack over measured 23 ms |
| `process_epoch/1000`     | ≤ 500 ms                  | ~2.2× slack over measured 227 ms |
| Per-user cost            | linear in K, slope ≤ 500 µs/user | Consistent with primitives |
