# `dark-von-musig2` performance baseline

Source of truth for issue #681's "publish baseline numbers" criterion.
Pairs with `docs/benchmarks/von-primitives.md` (the underlying ECVRF
and `wrapper::nonce` costs are reported there). Regenerate with:

```bash
cargo bench -p dark-von-musig2 --bench partial_sign --bench aggregate -- --quick
```

Numbers below are the median of one Criterion `--quick` run (3 s
measurement, 1 s warm-up). Use them as upper-bound expectations.

## Hardware context

| Field     | Value                                       |
|-----------|---------------------------------------------|
| CPU       | Apple M3 Max                                |
| Cores     | 14 (10 performance + 4 efficiency)          |
| Memory    | 36 GB                                       |
| OS        | macOS 26.3.1 (Darwin 25.3.0)                |
| Toolchain | rustc 1.95.0 (release profile, lto = false) |

Curve-arithmetic-heavy paths (`partial_sign_with_scalars`,
`aggregate_and_finalize`) sit on `secp256k1 = 0.29` from libsecp;
Linux / x86_64 numbers on `ubuntu-latest` typically run 1.5–2×
slower per the same envelope as `dark-von`.

## Operator partial signature (`sign::sign_partial_with_von`)

The operator's per-epoch partial signature consumes the VON-bound
`(r₁, r₂)` scalars retained from `Setup::run` and produces a
32-byte BIP-327 partial. No nonce is generated inside this call —
VON's binding is preserved end-to-end.

| Operation                         | Median   | Notes                                                   |
|-----------------------------------|----------|---------------------------------------------------------|
| `partial_sign/operator`           | 45.4 µs  | KeyAggCtx coefficient compute + `s = k₁ + b·k₂ + e·a·sk` |

## Participant horizon (`presign::presign_horizon`)

Each iteration verifies the entire published Λ (`2N` `wrapper::verify`
calls), generates `N` participant nonces, and produces `N` partial
signatures. Reported as a horizon-wide cost per call; per-epoch cost
is `total / N` and the linear-fit slope is the per-epoch participant
partial-sign primitive cost.

| `N` | Median (full horizon) | Per-epoch | Notes |
|-----|------------------------|-----------|-------|
| 1   | 226.1 µs               | 226.1 µs  | 1 partial sign + 2 ECVRF verifies + 2 nonce generations |
| 4   | 924.8 µs               | 231.2 µs  |       |
| 12  | 2.728 ms               | 227.3 µs  |       |
| 50  | 11.232 ms              | 224.6 µs  |       |

Per-epoch cost stays in **224–231 µs** across `N` — confirms there's
no hidden quadratic in the horizon-verify pipeline. Of the per-epoch
~225 µs, roughly:

- 2 × `wrapper::verify` ≈ 170 µs (from `dark-von` baseline at
  85 µs/verify)
- 1 × `partial_sign_with_scalars` ≈ 45 µs (matches operator path)
- ~10 µs nonce-aggregation + bookkeeping

## Aggregation (`sign::aggregate`)

Combines the operator's and the participant's 32-byte partials into a
single 64-byte BIP-340 signature. PSAR's setting is always 2-of-2
(operator + one user) so this bench reports a single point estimate.

| Operation         | Median   | Notes                                                  |
|-------------------|----------|--------------------------------------------------------|
| `aggregate/2of2`  | 19.9 µs  | Sum of partials + parity flips + R-projection to BIP-340 64-byte form |

## Cohort budget at K=100, N=12

Combining the per-epoch participant cost with `dark-von`'s
`schedule::generate` cost (Phase 1's bench) gives a back-of-envelope
budget for one user boarding into a K=100 cohort with horizon N=12:

```text
boarding(N=12)        = schedule_generate(N=12) + presign_horizon(N=12)
                      ≈   1.88 ms              +   2.73 ms
                      ≈   4.61 ms / user
```

ASP per-epoch cost is per-user 2 × `partial_sign/operator` (one for the
operator's partial, one for the verification of the participant's
incoming partial inside `sign_epoch`) plus one `aggregate/2of2`:

```text
process_epoch(K=100)  ≈ 100 × (45 µs + 45 µs + 20 µs)
                      ≈ 11.0 ms / epoch
```

These envelopes feed the K-vs-N table in
`docs/benchmarks/psar-scaling.md` (#684).

## Threshold sentinels

If a future change moves any of the medians outside these envelopes,
investigate before merging — the integration tests in #678 / #680 are
green by accident under regression as long as the numbers fit.

| Bench                                | Envelope (Apple M-series) | Notes                                    |
|--------------------------------------|---------------------------|------------------------------------------|
| `partial_sign/operator`              | ≤ 100 µs                  | ~2.2× slack over measured 45 µs           |
| `partial_sign_participant_horizon/N` | linear in N, slope ≈ 230 µs/epoch | Constant in `K` — does not vary with cohort size |
| `aggregate/2of2`                     | ≤ 50 µs                   | ~2.5× slack over measured 20 µs           |
