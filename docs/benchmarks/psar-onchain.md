# PSAR on-chain footprint

Source of truth for issue #685's on-chain footprint numbers.
Regenerate measurements by running:

```bash
nigiri start
scripts/psar-onchain.sh
```

Until a Nigiri-backed run lands, the formulas below are the
authoritative source — they're derived directly from
`crates/dark-psar/src/publish.rs` and the SlotAttest layout in
`crates/dark-psar/src/attest.rs`.

## What touches L1 in PSAR

PSAR's design intent is to **minimise L1 footprint per cohort**.
Per-epoch renewals are off-chain MuSig2 signatures bound to the
cohort's pre-published `Λ` — they do not produce on-chain
transactions. The only PSAR-specific tx that hits L1 is:

- **`slot_attest_S`** — a single OP_RETURN tx that the ASP
  publishes once per cohort, committing to the slot Merkle root
  and the cohort metadata. Implemented by
  `dark_psar::publish::publish_slot_attest`.

Everything else on L1 (cohort funding, batch settlement at
exit/sweep, unilateral exits) is **standard Ark** — not introduced
by PSAR. The "per-batch overhead" the issue text alludes to is the
Ark commitment-tx cost when a cohort settles, not a new PSAR-specific
transaction structure.

## `slot_attest_S` analytical breakdown

From `publish.rs:73`–`121` and `attest.rs:154`–`183`:

| Component                           | Size (B) | Notes                                       |
|-------------------------------------|----------|---------------------------------------------|
| Tx version                          | 4        | Fixed — version 2                            |
| Tx locktime                         | 4        | Fixed — `LockTime::ZERO`                     |
| Input count + output count          | 2        | varints                                      |
| **Input**: outpoint + sequence      | 41       | 32 (txid) + 4 (vout) + 4 (sequence) + 1 (empty scriptSig length) |
| **Output 0** (OP_RETURN)            | ~80      | 8 (zero amount) + 1 (length) + 1 (OP_RETURN) + 1 (push 68) + 68 (payload: 4 magic + 64 sig) + alignment |
| **Output 1** (P2WPKH change)        | 43       | 8 (amount) + 1 (length) + 31 (P2WPKH script) + 3 alignment |
| **Witness** (P2WPKH input)          | 107      | 1 (item count) + 1 (length) + 71 (DER+sighash sig) + 1 (length) + 33 (pubkey) |
| **Total non-witness**               | ~174     | excl. witness                               |
| **Total raw size**                  | ~281     | non-witness + witness                       |
| **Weight units (WU)**               | ~803     | non-witness × 4 + witness                   |
| **Virtual bytes (vbytes)**          | ~201     | ⌈WU / 4⌉                                    |

The OP_RETURN payload is exactly **68 bytes** —
`OP_RETURN_MAGIC` (4 B, `b"PSAR"`) + the 64-byte BIP-340 signature.
The other `SlotAttest` fields (`slot_root`, `cohort_id`, `setup_id`,
`n`, `k`) are **not on-chain**: verifiers reconstruct them from the
cohort metadata they already share with the ASP, then check the
on-chain signature.

## Per-cohort total L1 cost

```text
on_chain_footprint(cohort)
    = slot_attest_S
    + per-cohort funding tx (standard Ark)
    + per-renewal materialisation tx (only at exit, standard Ark)
```

Substituting:

| Component                                   | Cost (vbytes)         | Frequency               |
|---------------------------------------------|-----------------------|-------------------------|
| `slot_attest_S`                             | ~201 vbytes           | once per cohort         |
| Cohort funding (standard Ark commitment tx) | ~50 + 32 × K vbytes   | once per cohort         |
| Per-VTXO settlement (standard Ark)          | depends on exit shape | only at exit/settlement |

PSAR's contribution to L1 footprint is **a fixed ~201 vbytes per
cohort**, regardless of `K` or `N`. Standard Ark dominates the rest
once `K` exceeds ~10.

### Per-user amortised PSAR-specific cost

| K     | slot_attest vbytes | per-user share |
|-------|---------------------|----------------|
| 100   | 201                 | 2.01 vbytes    |
| 1 000 | 201                 | 0.20 vbytes    |

At cohorts of K=1000 the amortised PSAR-specific on-chain cost is
**~0.2 vbytes per VTXO** — well below the noise floor of any
realistic Bitcoin-fee-market scenario.

## Formula for arbitrary N

Per the issue text:

```text
per_cohort = attest_size + N × renewal_tx_size
```

In PSAR's hibernation design, `renewal_tx_size = 0` for
non-materialised renewals — the renewal sigs are off-chain. A
renewal only hits L1 when a user actually exits at that epoch's
sig, in which case `renewal_tx_size` is the standard Ark
unilateral-exit cost. So:

```text
per_cohort_PSAR_specific = attest_size  ≈ 201 vbytes        (always)
per_cohort_total         = attest_size + sum over realised exits of (Ark exit tx size)
```

## Measurement protocol

1. `nigiri start` — boots regtest bitcoind on port 18443.
2. `scripts/psar-onchain.sh` — runs the existing #669 e2e regtest
   test (`crates/dark-psar/tests/e2e_psar_regtest.rs`) which
   publishes one slot_attest, parses the txid from the test output,
   and queries `bitcoin-cli getrawtransaction` for canonical
   weight/vbyte numbers. Output is a markdown table.
3. Append the measured row to the table below.

## Measured (Nigiri regtest)

_Pending Nigiri run — when populated, replace the row below with the
output of `scripts/psar-onchain.sh`._

| Tx kind        | size (B) | input (B) | witness (B) | output (B) | weight (WU) | vbytes |
|----------------|----------|-----------|-------------|------------|-------------|--------|
| slot_attest_S  | TBD      | TBD       | TBD         | TBD        | TBD         | TBD    |

The analytical table above (`~281` raw, `~803` WU, `~201` vbytes) is
the upper bound the measurement should land within ±5 %.
