# `dark-von` performance baseline

Source of truth for issue #658's "publish baseline numbers" criterion
and the latency thresholds in ADR-0006 / ADR-0007. Regenerate with:

```bash
cargo bench -p dark-von --bench von -- --quick
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

The library has no architecture-specific tuning. Linux / x86_64
numbers on the GitHub Actions `ubuntu-latest` runner will run roughly
1.5–2× slower for curve-arithmetic-heavy paths (ECVRF prove / verify,
schedule generation) and similar for HMAC / SHA-256.

## ECVRF (`ecvrf`)

Project-pinned ciphersuite `DARK-VRF-SECP256K1-SHA256-TAI` per
ADR-0006. Implementation in `crates/dark-von/src/ecvrf.rs`.

| Operation     | Median   | Notes                                   |
|---------------|----------|-----------------------------------------|
| `prove`       | 62.9 µs  | One TAI hash-to-curve loop (~2 attempts on average), one `sk·H` and `k·G`/`k·H` scalar-mul |
| `verify`      | 73.2 µs  | Hash-to-curve + two scalar-muls (`s·G − c·pk`, `s·H − c·Gamma`) |

### Threshold check (ADR-0006)

ADR-0006 reopens if `ecvrf::prove` median exceeds **200 µs** on
Apple silicon. Measured **62.9 µs** — comfortably under, no reopen.

## VON wrapper (`wrapper`)

Construction (c) per ADR-0007: HMAC-derived hidden `r` + R-bound
ECVRF proof. Implementation in `crates/dark-von/src/wrapper.rs`.

| Operation        | Median   | Delta vs ECVRF |
|------------------|----------|----------------|
| `wrapper::nonce` | 87.0 µs  | +24.1 µs over `ecvrf::prove`  |
| `wrapper::verify`| 85.0 µs  | +11.8 µs over `ecvrf::verify` |

The deltas are dominated by:

- **`nonce`** (+24 µs): one HMAC-SHA-256 over `R_DERIVATION_TAG || x`,
  one `r·G` scalar-mul (re-derived for `R`), and the longer ECVRF
  input `alpha' = x || R_compressed` (one extra hash-to-curve digest
  attempt on average).
- **`verify`** (+12 µs): one `proof_to_hash` invocation (single SHA-256)
  plus the longer `alpha'` assembly.

### Threshold check (ADR-0007)

ADR-0007 reopens if `wrapper::nonce` median exceeds `ecvrf::prove`
median by more than **30 µs**. Measured delta **24.1 µs** — under,
no reopen.

## Schedule generation (`schedule::generate`)

Bench at the horizons that matter for the paper (`N ∈ {4, 12, 50}`).
Each schedule does `2N` `wrapper::nonce` calls (one per `(t, b)` slot).

| `N` | Median   | Per-slot (`/2N`) | Wire size (`PublicSchedule.byte_len`) |
|-----|----------|------------------|---------------------------------------|
| 4   | 631 µs   | 78.9 µs          | 948 B                                 |
| 12  | 1.88 ms  | 78.4 µs          | 2 772 B                               |
| 50  | 7.98 ms  | 79.8 µs          | 11 436 B                              |

Per-slot cost is **78–80 µs**, slightly under the standalone
`wrapper::nonce` median (87 µs) because the criterion harness amortises
`Secp256k1::new()` and per-call vec allocations across the loop.
Linear in `N` to within measurement noise — confirms there's no
hidden quadratic in the H_nonce / wrapper / schedule pipeline.

### Wire size formula

`PublicSchedule.byte_len = 36 + 228 * N` bytes.
At `N = 256` (the `MAX_HORIZON` cap from #657) the public schedule
is **58 404 bytes** (~57 KB).

## Threshold sentinels

If a future change moves any of the medians outside these envelopes,
re-open the relevant ADR before merging.

| Bench                  | Envelope (Apple M-series) | Source ADR |
|------------------------|---------------------------|------------|
| `ecvrf::prove`         | ≤ 200 µs                  | ADR-0006   |
| `wrapper::nonce` delta | ≤ 30 µs over `ecvrf::prove` | ADR-0007 |
| `schedule_generate/N`  | linear in `N`, slope ≈ 80 µs/slot | (this doc) |
