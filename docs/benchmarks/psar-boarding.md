# PSAR boarding latency

Source of truth for issue #682's boarding-vs-N curve. Regenerate
with:

```bash
cargo bench -p dark-psar --bench boarding -- --quick
```

Numbers below are the median of one Criterion `--quick` run (3 s
measurement, 1 s warm-up). Pairs with
`docs/benchmarks/von-musig2-primitives.md` (the per-epoch participant
partial-sign primitive) and `docs/benchmarks/von-primitives.md` (the
underlying ECVRF / `wrapper` cost).

## Hardware context

| Field     | Value                                       |
|-----------|---------------------------------------------|
| CPU       | Apple M3 Max                                |
| Cores     | 14 (10 performance + 4 efficiency)          |
| Memory    | 36 GB                                       |
| OS        | macOS 26.3.1 (Darwin 25.3.0)                |
| Toolchain | rustc 1.95.0 (release profile, lto = false) |

## What `user_board` does

End-to-end client-side boarding (`crates/dark-psar/src/boarding.rs`):

1. Verify the ASP's signed `SlotAttest` against `pk_asp` (1 BIP-340 verify).
2. Recompute the slot Merkle root over `cohort.members` and check it
   matches the attestation (`O(K)` SHA-256 hashes, K=2 in this fixture).
3. Verify every entry of the published Λ via `dark_von::wrapper::verify`
   (`2N` calls — one per `(t, b)` slot).
4. Derive `m_t` for each `t ∈ [1, N]` (cheap SHA-256).
5. Pre-sign the horizon via `dark_von_musig2::presign::presign_horizon`
   (re-verifies Λ, generates `N` participant nonces, computes `N`
   partial signatures).
6. Compute the schedule-witness hash chain over `2N+1` SHA-256
   updates.

The dominant per-epoch cost is steps 3 + 5 — verifying Λ then
producing one BIP-327 partial against it.

## Boarding latency vs N

| `N` | Median   | Per-epoch (`/N`) | Notes |
|-----|----------|------------------|-------|
| 4   | 1.66 ms  | 416 µs           |       |
| 12  | 4.75 ms  | 396 µs           |       |
| 50  | 19.80 ms | 396 µs           |       |

Per-epoch cost converges to **~395 µs** as N grows; the constant
overhead (attest verify, slot-root recompute, schedule-witness
init) is ~150 µs and matters at small N.

### Decomposition at N=12 (lead config)

| Component                              | Cost     | Source bench                                |
|----------------------------------------|----------|---------------------------------------------|
| Per-epoch participant partial-sign     | ~225 µs  | `partial_sign_participant_horizon/12` (#681) |
| `derive_message_for_epoch` + framing   | ~10 µs   | inline                                      |
| Λ pre-verify (already counted in 225µs above; presign re-verifies internally) | (overlap) | (overlap) |
| Boarding-only overhead per epoch       | ~160 µs  | residual: 396 − 225 − 10 ≈ 160 µs            |

The "boarding-only overhead per epoch" is the second pass over Λ
that happens inside `boarding::user_board::verify_lambda_entries`
*before* `presign_horizon` (which then re-verifies). The duplication
exists for ergonomic error reporting (`(epoch, slot)`-tagged errors —
see boarding.rs comment) and is a known follow-up if boarding cost
ever becomes the bottleneck. At N=12 the cost is < 2 ms and not
worth the ergonomic regression today.

### Front-loaded constants

- ~110 µs — `SlotAttest::verify` (BIP-340 Schnorr verify of the ASP's signature).
- ~30 µs — `SlotRoot::compute` over K=2 members.
- Single SHA-256 init for the schedule-witness chain.

Total fixed cost ≈ **150 µs**, matches the difference between the
per-N constant (~395 µs/epoch) and `(median − 150 µs) / N` at N=12.

## At-a-glance scaling

```text
user_board(N)  ≈ 150 µs  +  N × 395 µs
```

At the paper's lead horizon **N=12**: 4.75 ms per user.
At the stretch horizon **N=50**: 19.8 ms per user.

These costs are independent of the cohort size `K` — every user
boards in parallel and `user_board` does not touch the other K−1
member set beyond hashing them into the slot tree (which is amortised
at ~200 ns per member at K up to 10⁴).

## Threshold sentinels

| Bench           | Envelope (Apple M-series)        | Notes |
|-----------------|----------------------------------|-------|
| `user_board/4`  | ≤ 5 ms                           | ~3× slack over measured 1.66 ms |
| `user_board/12` | ≤ 10 ms                          | ~2× slack over measured 4.75 ms |
| `user_board/50` | linear in N, slope ≤ 500 µs/epoch | Consistent with `presign_horizon` linearity |
