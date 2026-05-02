# `dark-von` + MuSig2 primitive baseline

Source of truth for issue #681's benchmark publication step. Regenerate with:

```bash
cargo bench -p dark-von --bench von -- --quick
cargo bench -p dark-bitcoin --bench partial_sign -- --quick
cargo bench -p dark-bitcoin --bench aggregate -- --quick
```

Running the two packages in one invocation also works and produces a
single Criterion report tree under `target/criterion/`:

```bash
cargo bench -p dark-von -p dark-bitcoin -- --quick
```

## Scope

These measurements cover the cryptographic primitives that are
independent of cohort size (`K`) and epoch horizon (`N`):

- `VON.Nonce` via `dark-von::wrapper::nonce`
- `VON.Verify` via `dark-von::wrapper::verify`
- MuSig2 partial signing for a participant path
- MuSig2 partial signing for an operator/ASP path
- MuSig2 public nonce aggregation
- MuSig2 partial-signature aggregation

The VON numbers are reused from `docs/benchmarks/von-primitives.md`.
MuSig2 numbers below come from the new `dark-bitcoin` Criterion benches.

## Hardware context

| Field     | Value                                       |
|-----------|---------------------------------------------|
| CPU       | Raspberry Pi 5                              |
| Cores     | 4                                           |
| Memory    | 8 GB                                        |
| OS        | Linux 6.12.47+rpt-rpi-2712 (aarch64)        |
| Toolchain | rustc 1.94.1 (release profile, default lto) |


These numbers are intended as a local baseline for regression tracking,
not as absolute limits across machines.

## VON wrapper primitives

Reused from `docs/benchmarks/von-primitives.md`:

| Operation         | Median |
|-------------------|--------|
| `wrapper::nonce`  | 600.64 µs |
| `wrapper::verify` | 604.53 µs |

## MuSig2 primitives

The current benchmark fixtures use a fixed 3-party signing set. They are
small on purpose: the goal here is primitive-level regression tracking,
not end-to-end protocol scaling.

| Operation                         | Median |
|-----------------------------------|--------|
| `partial_sign` participant path   | 905.59 µs |
| `partial_sign` operator path      | 920.53 µs |
| `aggregate_nonces`                | 17.293 µs |
| `aggregate_signatures`            | 441.92 µs |
