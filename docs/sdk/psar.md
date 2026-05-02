# PSAR demo CLI

`ark-cli psar` exposes the three calls of the PSAR boarding-and-renewal
flow as in-process subcommands. They generate synthetic users from a
deterministic seed, run the corresponding `dark-psar` call, and emit
one JSON line on stdout.

These commands exist to make the demo binary in `dark-psar`
(issue #680) scriptable and to serve as the worked example for the
AFT submission's reproducibility section. They do **not** talk to a
running ASP — every call is self-contained.

See `docs/adr/0009-psar-integration.md` for the design choice
(parallel pipeline) and `crates/dark-psar/README` for protocol-level
context.

## Subcommands

```text
ark-cli psar board --k <K> --n <N> [--setup-id <hex32>] [--seed <u64>]
ark-cli psar advance-epoch --k <K> --n <N> --through-epoch <T> \
    [--setup-id <hex32>] [--seed <u64>]
ark-cli psar resurface --k <K> --n <N> --slot-index <S> --epoch <T> \
    [--setup-id <hex32>] [--seed <u64>]
```

Defaults: `K = 4`, `N = 2`, `setup_id = c4×32`, `seed = 0xDA4C50A45EED2026`.

## Manual smoke (boarding → 2 epochs → resurface)

The full happy-path can be exercised end-to-end with three commands.
Each prints a single JSON line; pipe through `jq` to read it
comfortably.

### 1. Board a fresh K=4, N=2 cohort

```sh
ark-cli psar board --k 4 --n 2 | jq .
```

Expected fields:

| Field | Type | Meaning |
|---|---|---|
| `kind` | string `"board"` | Discriminant |
| `cohort_id` | 64-char hex | 32-byte cohort id (deterministic in `--seed`) |
| `k` | int | Cohort size |
| `n` | int | Hibernation horizon |
| `slot_root` | 64-char hex | Root of the slot Merkle tree (#667) |
| `batch_tree_root` | 64-char hex | Batch-tree root committed at boarding (#672) |
| `schedule_witness` | 64-char hex | Per-user hash-chain over Λ (#670); identical across the cohort |
| `members` | int | Should equal `k` |

### 2. Advance through both epochs

```sh
ark-cli psar advance-epoch --k 4 --n 2 --through-epoch 2 | jq .
```

Expected fields (in addition to the cohort fields above):

| Field | Type | Meaning |
|---|---|---|
| `through_epoch` | int | Equal to `--through-epoch` |
| `epochs` | array | One entry per processed epoch |
| `epochs[].t` | int | Epoch index (1-based) |
| `epochs[].signatures` | int | Successful per-user signatures this epoch |
| `epochs[].failures` | int | Users whose partial sig was rejected |
| `final_state` | string | `Active`, `InProgress`, or `Concluded` |

For `--through-epoch == n` the cohort lifecycle ends in
`"Concluded"`; per-epoch `signatures` should equal `k` and
`failures` should be `0`.

### 3. Resurface slot 0 at epoch 1

```sh
ark-cli psar resurface --k 4 --n 2 --slot-index 0 --epoch 1 | jq .
```

Expected fields:

| Field | Type | Meaning |
|---|---|---|
| `kind` | string `"resurface"` | Discriminant |
| `cohort_id` | 64-char hex | Same id as the boarding output for the same `--seed` |
| `slot_index` | int | Equal to `--slot-index` |
| `t_prime` | int | Equal to `--epoch` |
| `renewal_sig` | 128-char hex | 64-byte BIP-340 sig that this user's VTXO was renewed at `t_prime` |
| `renewal_msg` | 64-char hex | 32-byte sighash the renewal was produced over |

`renewal_sig` verifies under the 2-of-2 aggregate of `(asp_pk, user_pk)`
against `renewal_msg`. The verifier needs the per-cohort `slot_root`
and `batch_tree_root` from step 1 to recompute the message
independently — see `dark_psar::message::derive_message_for_epoch`.

## Determinism

Identical `--seed` values produce identical `cohort_id`, `slot_root`,
`batch_tree_root`, and per-user keys. This is deliberate so the
integration test in `crates/ark-cli/tests/psar_cli.rs` and the demo
binary in #680 can pin observable outputs.

## Troubleshooting

- *"--setup-id must decode to 32 bytes"* — provide 64 lowercase hex
  characters.
- *"--through-epoch X out of range [1, N]"* — `t` must be in
  `[1, n]`; this command sequence does not advance beyond the
  boarded horizon.
- *"--slot-index X out of range [0, K)"* — `slot_index < k`.
