# `dark-confidential` performance baseline

Source of truth for issue #528's "publish baseline numbers" acceptance
criterion. Regenerate with:

```bash
cargo bench -p dark-confidential --bench range_proof
cargo bench -p dark-confidential --bench balance_proof
cargo bench -p dark-confidential --bench pedersen
cargo bench -p dark-confidential --bench nullifier
```

Numbers below are the median of three Criterion `--quick` runs (3 s
measurement, 1 s warm-up) — they are conservative and inflated relative
to a full Criterion run. Use them as upper-bound expectations; CI
regression alerts against this baseline allow ±25 % slack.

## Hardware context

| Field   | Value                              |
|---------|------------------------------------|
| CPU     | Apple M3 Max                       |
| Cores   | 14 (10 performance + 4 efficiency) |
| Memory  | 36 GB                              |
| Toolchain | rustc 1.95.0 (release profile)   |
| OS      | macOS Darwin 25.3.0                |

The library has no architecture-specific tuning. Linux / x86_64 numbers
on the GitHub Actions `ubuntu-latest` (Standard_DS2_v2-class) runner
will run roughly 1.5-2× slower for curve-arithmetic-heavy paths
(range proof, Pedersen commit) and similar for HMAC.

## Range proofs (`range_proof`)

Back-Maxwell range proof bound by `secp256k1-zkp = 0.11`. Aggregated
form uses the shared-length wire encoding (uniform sub-proof sizes).

| Shape                       | prove (median) | verify (median) | proof bytes |
|-----------------------------|----------------|-----------------|-------------|
| single (1 output)           | 1.26 ms        | 0.80 ms         | ~1.3 KB     |
| aggregated, 2 outputs       | 2.40 ms        | 1.60 ms         | ~2.6 KB     |
| aggregated, 4 outputs       | 4.71 ms        | 3.19 ms         | ~5.2 KB     |
| aggregated, 16 outputs      | 18.61 ms       | 13.26 ms        | ~21 KB      |

Per ADR-0001 §"Bandwidth delta", the absolute bytes/proof are roughly
2× a hypothetical Bulletproofs construction; this is the expected cost
of the `secp256k1-zkp` audit-stable bridge until follow-up FU-BP
swaps the backend.

## Balance proofs (`balance_proof`)

Hand-rolled Schnorr over generator `H` with BIP-340-style tagged hash
challenge. `prove_balance` is dominated by a single nonce derivation +
two scalar multiplications, so prove time is **independent of the
input/output count** to within noise. `verify_balance` walks the input
and output commitment lists once each (one point combine per
commitment), so verify time scales linearly with `n`.

| Shape                  | prove (median) | verify (median) |
|------------------------|----------------|-----------------|
| 1 input,  1 output     | ~42 µs         | 80 µs           |
| 4 inputs, 4 outputs    | 42.4 µs        | 108.7 µs        |
| 8 inputs, 8 outputs    | 42.9 µs        | 149.4 µs        |
| 16 inputs, 16 outputs  | 43.1 µs        | 230.4 µs        |

## Pedersen commitments (`pedersen`)

| Operation             | median       |
|-----------------------|--------------|
| `commit`              | 36.7 µs      |
| `add`                 | 2.44 µs      |
| `serialize` (33 B)    | 25.9 ns      |

`commit` is dominated by two scalar multiplications and one point
combine; `add` is one combine; `serialize` is a copy.

## Nullifier (`nullifier`)

HMAC-SHA256(sk_bytes, dst || 0x00 || 0x01 || vtxo_id_bytes) per
ADR-0002. Cost is essentially one HMAC-SHA256 call.

| Operation             | median   | throughput          |
|-----------------------|----------|---------------------|
| `compute_nullifier`   | 798 ns   | ~1.25 M ops / s     |

## Regression policy

A median prove-time regression of more than **+25 %** against the
numbers above blocks CI. The threshold is intentionally external to the
benchmark harness so the regression check stays dependency-free.

Until the central CI script lands, individual benchmark targets carry a
`Regression policy` doc-comment pointing here. Track the wiring under
the follow-up "CV-M1 bench regression gate" — it should:

1. Run all four benches with the same `--quick` parameters.
2. Compare the medians against the table above (or a snapshot file).
3. Fail the job if any median exceeds its baseline by more than 25 %.

This file is the single source of truth: any baseline shift requires
updating the table here in the same PR.
