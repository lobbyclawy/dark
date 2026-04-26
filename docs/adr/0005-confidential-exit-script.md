# ADR-0005: Confidential VTXO unilateral-exit script construction

- **Status:** Proposed
- **Date:** 2026-04-24
- **Milestone:** CV-M4 (Confidential Exit & Sweep)
- **Drives:** #546 → unblocks #547 → #548 → #549 → #550
- **Affects:** confidential exit path only; transparent-exit Tapscript untouched (#520 parity gate)

## Context

Confidential VTXOs hide the per-output amount behind a Pedersen commitment
(`commit(amount, blinding) = amount·G + blinding·H` per ADR-0001 / #524).
The commitment is published in the round tree's confidential leaf
(`LeafV2`, #540) and never leaves the operator's database in plaintext
during the happy path.

When a user exits unilaterally — the emergency path that has to work
without operator cooperation — the Bitcoin chain validates the chain of
intermediate transactions from the round root down to a single leaf
output that pays the user. To validate that leaf-level spend, **the L1
chain must learn `amount`**: every Bitcoin output carries a plaintext
satoshi value, every Bitcoin transaction must balance to a non-negative
fee, and every full node has to be able to evaluate the spending
script. The exit therefore reveals the amount on chain — that is
explicitly accepted in the issue text as the cost of the emergency
path.

What is *not* automatic is the **binding** between the revealed amount
and the published commitment. If the only L1-visible binding were the
output's plaintext satoshi value, a colluding exiter could publish any
amount their inputs allow regardless of what the operator committed
to, and the commitment would carry no on-chain meaning. The script
must enforce: *the amount the exit tx pays is the amount the round
committed to for this VTXO*. Bitcoin Script cannot evaluate Pedersen
arithmetic (no `OP_PEDERSEN_VERIFY`, no scalar multiplication on
secp256k1, no OP_CAT in mainnet Tapscript), so the commitment cannot be
re-checked directly on chain. The design question, captured in #546,
is **how to construct an L1-verifiable binding from the published
Pedersen commitment to the revealed `(amount, blinding)`** under the
opcode budget Tapscript actually gives us.

The choice has to be made before #547 freezes the per-VTXO Taproot
output's leaf set, and before #548 builds the client-side opening
retrieval, otherwise both rework once the leaf format moves.

The framing of #546 lists three "leaf encoding" candidates; the
underlying decision can be expressed equivalently as three "opening
reveal mechanisms" (where, on the wire, the opening is exposed). The
two framings cover the same design space and are evaluated together
below.

## Requirements

- **L1 binding**: any full node (no operator help) MUST be able to
  reject an exit whose revealed `amount` does not match the commitment
  the round published for this VTXO. The check MUST run inside the
  Bitcoin Script interpreter, not in operator policy.
- **Atomicity**: a single confirmed exit transaction MUST be
  sufficient for the user's funds to land at an L1 address they
  control. No second confirming transaction, no operator
  acknowledgment, no two-phase ritual.
- **Unilateral**: the script-path spend MUST be executable with only
  the user's spend key + locally-stored opening data. No multisig, no
  operator signature.
- **Minimum opcode budget**: the script MUST only use opcodes that are
  enabled in mainnet Tapscript (BIP-342 / activated soft forks). In
  particular, OP_CAT, OP_SUBSTR, OP_CHECKSIGFROMSTACK are *not*
  available; no covenant opcodes.
- **Source-of-truth for the amount**: the same `amount` value the user
  reveals on the wire MUST equal the satoshi value of the spending
  transaction's input (otherwise the whole tree of intermediate txs
  fails to balance at L1). The script enforces that the *opening*
  matches what the commitment hides; the L1 amount-conservation rule
  enforces that the *spend amount* equals the input UTXO's value.
  Both binding rails fail closed.
- **Round-tree consistency**: the binding the exit script enforces
  MUST be the same binding the round tree's `LeafV2` already encodes
  (#540). One source of truth for the leaf hash; the exit verifier
  re-derives the leaf's preimage and walks the merkle proof to the
  round root, refusing any opening whose hash does not match the leaf
  preimage's amount-bearing field.
- **Compat**: the new exit Tapscript leaf MUST coexist on the
  per-VTXO Taproot output with the existing transparent-exit /
  collaborative leaves. A given VTXO uses one path or the other based
  on its variant; the transparent-exit leaf's bytes do not move (#520
  parity gate, #547 acceptance criterion).
- **Wire-additive**: any new field in `LeafV2` lives on the
  confidential leaf only. `LeafV1` stays bit-identical to Go `arkd`
  per #540.

## Candidates

The issue lists three framings. They are evaluated below in the
"opening reveal" framing — i.e. *where* the opening data lives on the
exit transaction's wire — because that maps directly to the script
opcodes each option requires.

### Option 1 — Reveal `(amount, blinding)` in the Tapscript witness, hash-bound by a per-VTXO leaf

The per-VTXO Taproot output for a confidential VTXO carries a new
**confidential-exit Tapscript leaf** alongside the existing
collaborative / expiry leaves. Its script bakes a 32-byte
`opening_hash = SHA256(amount_LE_8B || blinding_32B || owner_pubkey_33B)`
as a literal push and verifies it against a 73-byte witness item
(`opening_blob`):

```text
OP_SIZE <0x49>                 # 73
OP_EQUALVERIFY                 # opening_blob is exactly 73 bytes
OP_SHA256
<opening_hash_32B>             # baked into the script
OP_EQUALVERIFY
<owner_xonly_pubkey_32B>
OP_CHECKSIG
```

The `opening_hash` is **also embedded as a 32-byte slot in the
`LeafV2` preimage** (the confidential leaf the round tree commits
to per #540). The exit verifier does not need to know the script
bytes ahead of time — the merkle inclusion proof + the LeafV2
preimage (which the witness reproduces) carry `opening_hash`, and
SHA-256 binds the whole opening to that hash. From the L1 chain's
point of view: the witness pushes a 73-byte blob whose SHA-256 equals
the script's literal, and the script's literal equals the leaf
preimage's `opening_hash` slot, and the leaf preimage's `commitment`
slot is the published Pedersen commitment that hides the same
`(amount, blinding)` (the operator and sender both compute the
commitment; the round refuses to admit a leaf whose commitment and
opening_hash do not jointly verify). The merkle proof to the round
root closes the loop.

The exit transaction is a single tx whose output pays
`amount − exit_fee` to the user's L1 address. Bitcoin's own
amount-conservation rule enforces that the input UTXO's value (which
is `amount`, by construction of the intermediate-tx tree) equals
output + fee.

- **L1 binding strength**: full. Every full node enforces the
  hash-equality check inside Tapscript. No operator policy required.
- **Disclosure**: the witness pushes 73 bytes that include `amount`
  in plaintext (first 8 bytes LE). This is the accepted leak for the
  emergency path.
- **Round-trip cost**: one tx, no second confirmation, no operator
  hop.
- **Script opcode budget**: 6 opcodes + 2 literals. Fits comfortably
  inside Tapscript's 10000-byte script size limit and the standard
  policy budget.
- **Round-tree consistency**: `LeafV2` gains one 32-byte field
  (`opening_hash`) that replaces the placeholder
  `encrypted_memo_hash` slot's role *for exit binding* (the encrypted
  memo's content is still bound by ADR-0003, but its leaf-hash
  embedding moves to a different slot — see "Constraints on
  downstream issues" below). Single source of truth.

### Option 2 — Reveal the opening in an OP_RETURN sibling output

The exit transaction has an extra OP_RETURN output carrying
`amount_LE || blinding`. The Tapscript leaf is the existing
collaborative-exit shape (no new on-chain check). The operator
validates the binding off-chain before broadcasting / observing the
exit, but Bitcoin full nodes do not enforce it.

- **L1 binding strength**: zero. OP_RETURN is data-only; no Bitcoin
  full node compares its content to anything. A misbehaving exiter
  who controls their own broadcast can publish a tx whose OP_RETURN
  is wrong (or absent); Bitcoin accepts it. Validation devolves to
  off-chain operator policy or to a second party who reads the chain
  and fails the exit downstream.
- **Disclosure**: same as Option 1 (40 bytes in OP_RETURN); no
  privacy difference.
- **Round-trip cost**: one tx — but the binding is not enforced by
  the chain, so the operator's "exit acknowledged" step happens in a
  second message off-chain. Effectively two-party.
- **Script opcode budget**: 0. Trivially within budget.
- **Round-tree consistency**: leaf format unchanged, but the
  *binding* is no longer enforced by the same artefact the round tree
  commits to; consistency is a policy claim, not a structural one.

### Option 3 — Reveal in a separate confirming transaction

Two-tx exit. Tx A spends the VTXO leaf to a Taproot output whose only
Tapscript leaf is `OP_SHA256 <opening_hash> OP_EQUALVERIFY <user>
OP_CHECKSIG`. Tx B (broadcast after Tx A confirms) spends Tx A's
output by revealing `(amount, blinding)`. The user's funds land at
their final destination only after Tx B confirms.

- **L1 binding strength**: full (Tx B carries the same in-script
  check as Option 1).
- **Disclosure**: same as Option 1.
- **Round-trip cost**: two txs, two confirmation windows. On the
  emergency path (typically a 6-block-deep settlement target) this is
  ~12 hours of additional waiting in the median, ~24 hours in the
  tail.
- **Script opcode budget**: same as Option 1 split across two
  scripts; total is the same.
- **Round-tree consistency**: same as Option 1 (the binding lives on
  Tx B's leaf script and in `LeafV2`).
- **Failure mode**: between Tx A's confirmation and Tx B's
  confirmation, the funds sit in a UTXO with a known opening hash.
  An attacker who learns the opening (e.g. from a Tx A witness
  broadcast over an unprotected P2P channel — non-issue with current
  Tapscript witness format, but flagged for completeness) could front-
  run Tx B with their own. We can mitigate with `OP_CHECKSIG` against
  `<user>`, but the user has now spent twice the fee, twice the
  vbytes, and twice the wait for an "atomic" exit that is no more
  binding than Option 1.

## Evaluation matrix

| Criterion | Opt 1 (Tapscript witness reveal) | Opt 2 (OP_RETURN reveal) | Opt 3 (two-tx reveal) |
|---|---|---|---|
| L1-enforced binding (no operator help) | Yes | **No** — operator policy only | Yes |
| Single-confirmation exit | Yes | Yes | **No** — two confirms |
| Extra opcode budget vs. transparent leaf | +6 opcodes / +1 literal | 0 | +6 opcodes / +1 literal, split |
| Extra `LeafV2` field | one 32 B `opening_hash` | none | one 32 B `opening_hash` |
| Total exit vbytes (typical) | ~150 vB | ~165 vB (extra OP_RETURN) | ~300 vB (two txs + change rotation) |
| Total exit fees (median fee env) | 1× | 1× | ~2× |
| Witness size on the script-path spend | 73 B opening + 64 B sig + 33 B control block + script bytes | 64 B sig + control block | 73 B opening + 64 B sig + control block + script bytes (split) |
| Front-running window between Tx A and Tx B | n/a | n/a | yes — bounded but real |
| Reveals amount on chain | Yes | Yes | Yes |
| Reveals blinding on chain | Yes | Yes | Yes |
| Privacy delta (round-tree → exit) | identical to Opt 2 / Opt 3 | identical | identical |
| Off-chain "exit acknowledged" handshake required | No | Yes (operator-side) | No |
| Round-tree consistency (one source of truth for leaf hash) | Structural (leaf preimage carries the binding) | **Policy only** (binding lives off-chain) | Structural |
| Tapscript opcodes used (mainnet-activated) | OP_SIZE, OP_EQUALVERIFY, OP_SHA256, OP_CHECKSIG | none new | same as Opt 1 |
| Failure mode on misbehaving exiter | Tx invalid → not confirmed | Tx confirms with garbage OP_RETURN; operator detects later | Tx A confirms; Tx B may fail the binding (same as Opt 1) |
| Failure mode on operator collusion with exiter | Cannot occur — full nodes enforce | **Catastrophic** — operator signs off, chain accepts | Cannot occur |
| Audit surface added on top of CV-M3 primitives | one tapscript leaf shape, one new leaf-preimage field | none on chain; large off-chain policy surface | two tapscript leaves, two-tx state machine |

## Decision

**Adopt Option 1.** The confidential exit reveals `(amount, blinding)`
in the **Tapscript witness** of a per-VTXO Taproot leaf. The leaf
script enforces a hash-binding to a 32-byte `opening_hash` baked into
the script, and `LeafV2` (per #540) carries the same `opening_hash`
slot so the merkle inclusion proof + leaf preimage close the loop
back to the round root. Single confirmation, full L1 enforcement, no
operator hop.

### Rationale (why not Option 2)

Option 2 collapses the L1 binding to operator-side policy. The
confidential-VTXOs milestone exists *precisely* to remove that
trust assumption from the unilateral path; Option 2 reintroduces it
in the strongest possible form (operator decides whether the chain's
view of the exit is canonical). A passive observer of the chain has
no way to know whether an OP_RETURN-attached exit is honest. We
reject Option 2 unconditionally — it does not satisfy the "L1
binding" requirement and is documented here only because the issue
lists it.

### Rationale (why not Option 3)

Option 3 buys nothing over Option 1 except an additional tx, an
additional confirmation window, doubled fees, and a non-trivial
front-running surface during the inter-tx interval. Its only argued
advantage — separating the "emerge to L1" step from the "open the
commitment" step — is not a property the protocol benefits from:
both steps reveal the amount the moment Tx A's leaf script is on
chain, since the leaf script itself bakes `opening_hash` and an
attacker can correlate `opening_hash` with the eventual Tx B reveal.
We reject Option 3.

### Concur with the suggestion

The task description suggests Option 1 (Tapscript witness reveal) as
the intended decision, citing "leans on existing tapscript
verification, keeps the exit atomic, no extra round trips." We
concur and adopt it. The detailed shape of the leaf script and
witness layout is specified in the next section.

## Specification

### `LeafV2` extension (one new 32-byte field)

`LeafV2` (per #540) gains an `opening_hash` field. The encrypted-memo
hash slot stays in place — it carries different data and serves a
different purpose (memo authenticity per ADR-0003). The new field is
placed *before* the encrypted-memo hash in the preimage so the
exit-binding fields cluster contiguously:

```text
0x02                                          ← LEAF_V2_PREFIX (unchanged)
33 B   owner_pubkey      (compressed secp256k1)
33 B   commitment        (compressed Pedersen point — hides `amount`, `blinding`)
33 B   ephemeral_pubkey  (compressed secp256k1, ECDH per ADR-0003)
32 B   opening_hash      ← NEW. SHA-256 of (LE u64 amount || 32 B blinding || 33 B owner_pubkey)
32 B   encrypted_memo_hash (SHA-256 of the encrypted memo bytes — unchanged role per ADR-0003)
LE u32 vout
var    txid              (varint len || bytes)
```

Total fixed-width preimage cost rises from 131 B to 163 B before
varint payloads (still well under any practical bound).

The `opening_hash` is computed by both sender and operator at VTXO
creation, exactly as the Pedersen commitment is. The round refuses
to admit a confidential leaf whose `(commitment, opening_hash)` pair
fails the joint check `opening_hash == SHA256(amount_LE || blinding
|| owner_pubkey)` *and* `commitment == amount·G + blinding·H` (this
is a CV-M3 round-admission check, owned by #538; it is **not** an L1
check). At L1, only the SHA-256 binding fires; the Pedersen binding
is implicit via the round-tree commitment itself.

#### Domain separation of the opening hash

The opening hash uses a tagged-SHA256 with a dedicated domain
separator so it cannot collide with any other 32-byte hash the
crate computes:

```text
opening_hash = TaggedHash(
    tag = "DarkConfidentialOpeningV1",
    msg = amount_LE_8B || blinding_32B || owner_pubkey_compressed_33B,
)
```

The tag is materialised by BIP-340's tagged-hash construction:
`SHA256(SHA256(tag) || SHA256(tag) || msg)`. This matches the
construction already used by `tagged_hash` in `dark-core::round_tree`
and by the LeafV1 / LeafV2 hashers, so we reuse one helper across
the crate.

The L1 script does **not** use the tagged form — it uses raw
`OP_SHA256` because Tapscript has no tagged-hash opcode. The leaf
script therefore commits to the *raw* SHA-256 of a fixed-format
73-byte blob; the *tagged* hash above is the artefact `LeafV2`
carries. The two hashes are different bytes and serve different
purposes:

- **Raw `OP_SHA256` hash** — embedded in the Tapscript leaf, computed
  by the L1 interpreter on the witness blob.
- **Tagged-SHA256 `opening_hash`** — embedded in `LeafV2`, computed
  by the round-tree leaf hasher.

The exit verifier (full node) only sees the raw form (it executes
the script). The round verifier (`#538` admission check) sees both
and ties them together by recomputing the leaf preimage from the
same `(amount, blinding, owner_pubkey)` it just used to verify the
Pedersen commitment.

To avoid carrying *two* 32-byte slots in `LeafV2`, the `opening_hash`
field stored in `LeafV2` IS the **raw** `SHA256(amount_LE ||
blinding || owner_pubkey)` — exactly the bytes the L1 script's
`OP_SHA256` consumes. Tagged separation is unnecessary because the
opening hash's preimage shape (8 B + 32 B + 33 B = 73 B) cannot
collide with any other tagged or untagged hash in the crate (no
other artefact hashes a 73-byte fixed blob; LeafV1 / LeafV2
preimages are always >> 73 bytes and start with a structural prefix
byte). One slot, one value, one source of truth.

### Per-VTXO Taproot output

A confidential VTXO's per-VTXO Taproot output (the leaf of the
intermediate-tx tree, i.e. what gets spent on the unilateral-exit
path) has three Tapscript leaves at depth 2 of a balanced tree:

| Leaf | Purpose | Source |
|---|---|---|
| Leaf 0 | Cooperative spend (MuSig2 happy path) | `vtxo_collaborative_script_two_key` (existing) |
| Leaf 1 | CSV-gated transparent expiry exit (still valid for confidential variants — operator can still sweep after the timelock) | `vtxo_expiry_script` (existing, unchanged) |
| Leaf 2 | **Confidential unilateral exit** — script defined below | NEW, owned by #547 |

The internal key remains the BIP-341 unspendable key per the
existing pattern in `crates/dark-bitcoin/src/tapscript.rs::build_vtxo_taproot`.

### Tapscript leaf shape (Leaf 2)

Bitcoin script bytes (Tapscript leaf version `0xc0`).

The witness items are pushed onto the stack in order, with `witness[0]`
ending up at the BOTTOM. Therefore at script entry, top-of-stack is
the Schnorr signature and bottom-of-stack is the 73-byte opening blob.
The leading `OP_SWAP` brings the opening blob to the top so the size
check, the SHA-256, and the equality check all operate on it; the
signature stays underneath until `OP_CHECKSIG` consumes it last.

```text
OP_SWAP                 # bring opening_blob to top of stack
OP_SIZE
<0x49>                  # 73 (1-byte minimal push)
OP_EQUALVERIFY
OP_SHA256
<opening_hash_32B>      # 32-byte literal push
OP_EQUALVERIFY
<owner_xonly_pubkey_32B>
OP_CHECKSIG
```

In ASM:

```text
OP_SWAP OP_SIZE OP_PUSHBYTES_1 49 OP_EQUALVERIFY OP_SHA256
OP_PUSHBYTES_32 <opening_hash> OP_EQUALVERIFY
OP_PUSHBYTES_32 <owner_xonly> OP_CHECKSIG
```

Total script length: 1 + 1 + 2 + 1 + 1 + 33 + 1 + 33 + 1 = **74 bytes**.

#### Opcode-by-opcode justification

- `OP_SIZE` → pushes the size of the top-of-stack item without
  removing it. We need this to refuse witnesses whose opening blob
  is anything other than 73 bytes; without the size check, a
  malicious blob of length 74 (`amount || blinding || owner_pubkey
  || extra_byte`) could in principle hash to the same value as the
  intended 73-byte blob (it cannot, by SHA-256 collision resistance,
  but `OP_SIZE`-checking the input is the standard defensive
  pattern and costs 4 bytes of script).
- `OP_EQUALVERIFY` (twice) → defensive non-equality short-circuits;
  the alternative (`OP_EQUAL` + `OP_VERIFY`) costs the same and is
  no more expressive. We use `OP_EQUALVERIFY` to match the existing
  `vtxo_collaborative_script_two_key` style in the same crate.
- `OP_SHA256` → SHA-256 of the top-of-stack item, single-iteration
  (no double-SHA, no tagged hash). Mainnet-enabled in Tapscript.
- `OP_CHECKSIG` (terminal) → x-only Schnorr signature check against
  the owner pubkey. The signature commits to the entire spending
  transaction's sighash, which includes the prevout amount and the
  output amount/script — so a misbehaving exiter cannot mutate the
  destination address or pay-amount post-sign without invalidating
  the signature.

#### Why amount is bound transitively (not directly readable from the script)

The leaf script does not extract `amount` from the witness blob and
push it onto the stack as an integer. Tapscript without OP_CAT /
OP_SUBSTR cannot perform that extraction. Instead:

- The script commits to `opening_hash`, which is `SHA256(amount_LE
  || blinding || owner_pubkey)`.
- The witness reveals the 73-byte blob; SHA-256 collision resistance
  ties the blob to the unique `(amount, blinding, owner_pubkey)`
  that was committed at VTXO creation.
- The signature in `OP_CHECKSIG` covers the spending tx's sighash,
  which includes the input UTXO's amount (BIP-341 sighash mode
  `SIGHASH_DEFAULT` includes the `prevouts` in the sighash digest).
- The input UTXO's amount is `amount` by construction of the
  intermediate-tx tree (each parent tx pays exactly the per-leaf
  satoshi value to the leaf output). A misbehaving operator who
  tries to ship a smaller leaf output than the user's amount fails
  the round-admission check at #538, where the round refuses to
  publish a commitment-tx whose leaf-payment doesn't match the
  Pedersen-committed amount.

So the L1 binding chain is:

```text
exit-tx-input.value     == leaf-utxo.value
                        == amount   (committed at round-admission time)

exit-tx-witness.opening_blob[0..8]  == amount_LE
exit-tx-witness.opening_blob[0..73] -- SHA256 --> opening_hash
                                                   |
                                                   == leaf script literal
                                                   == LeafV2.opening_hash
                                                   == merkle-binds to round root
```

The chain has two anchor points: (a) the script's `OP_CHECKSIG` ties
the spend to `owner`, and (b) the script's
`OP_SHA256 OP_EQUALVERIFY` ties the witness blob to the round's
published `opening_hash`. There is no circular dependency: the
script's literal is fixed at the moment the per-VTXO Taproot output
is constructed, the witness blob is provided at exit time, and full
nodes verify both rails independently.

### Witness layout

The script-path spend witness, in stack order (bottom to top):

```text
witness[0] = opening_blob               (73 bytes: amount_LE_8B || blinding_32B || owner_pubkey_33B)
witness[1] = schnorr_signature          (64 or 65 bytes — 65 if non-default sighash)
witness[2] = leaf_script                (73 bytes: the script bytes specified above)
witness[3] = control_block              (33 + 32·d bytes; d = tree depth, 2 here, so 33 + 64 = 97 B)
```

Total witness size for a typical confidential exit:

| Component | Size |
|---|---|
| `opening_blob` | 73 |
| `schnorr_signature` (SIGHASH_DEFAULT) | 64 |
| `leaf_script` | 73 |
| `control_block` (depth 2) | 97 |
| varint stack-item-count | 1 |
| varint per-item lengths (4 items) | 4 |
| **Total witness** | **312 bytes** |

Multiplied by the 0.25 witness discount factor: ~78 vB of witness
weight. The full unilateral exit tx (1 input, 1 output, P2TR
addresses) lands around ~150 vB.

### Validation pseudocode (Bitcoin full node, evaluating the leaf script)

Stack trace, top of stack on the right:

```text
# witness pushed: [opening_blob, schnorr_sig]   (opening_blob at bottom)
# stack at entry: [opening_blob, schnorr_sig]

OP_SWAP            -> [schnorr_sig, opening_blob]
OP_SIZE            -> [schnorr_sig, opening_blob, 73]    # OP_SIZE pushes size; doesn't pop
push <0x49>        -> [schnorr_sig, opening_blob, 73, 73]
OP_EQUALVERIFY     -> [schnorr_sig, opening_blob]        # 73 == 73 → pass; pops both
OP_SHA256          -> [schnorr_sig, sha256(opening_blob)]
push <opening_hash>-> [schnorr_sig, sha256(opening_blob), opening_hash]
OP_EQUALVERIFY     -> [schnorr_sig]                      # hash matches → pass
push <owner_xonly> -> [schnorr_sig, owner_xonly]
OP_CHECKSIG        -> [true]                             # signature valid → success
```

Full validation flow at the L1 full node:

```rust
// Pseudocode — the actual implementation is in the Bitcoin Core /
// rust-bitcoin script interpreter, not in our crate. We do not
// touch this code; we generate scripts that fit the existing rules.

fn verify_confidential_exit_leaf(
    witness: &Witness,
    leaf_script: &Script,
    prevout_amount: u64,           // from the spending tx's prevout
    spending_tx: &Transaction,
) -> Result<(), ScriptError> {
    // 1. Tapscript machinery: extract control block, verify merkle
    //    proof of leaf_script under the per-VTXO output's tweaked
    //    output key. (Standard BIP-341 / 342 — no new code.)
    verify_tapscript_control_block(witness.control_block, leaf_script,
                                   prevout.script_pubkey)?;

    // 2. Execute the leaf script with witness[0..2] on the stack.
    //    Stack at entry (bottom to top): [opening_blob, schnorr_sig].
    let mut stack = vec![witness.opening_blob.clone(), witness.schnorr_sig.clone()];

    // OP_SWAP
    stack.swap(stack.len() - 1, stack.len() - 2);
    // Stack: [schnorr_sig, opening_blob]

    // OP_SIZE
    let top_size = stack.last().unwrap().len();
    stack.push(encode_int(top_size as i64));   // pushes 73 (or whatever)
    // Stack: [schnorr_sig, opening_blob, 73]

    // <0x49> OP_EQUALVERIFY
    let lit = stack.pop().unwrap();
    let computed = stack.pop().unwrap();
    if lit != [0x49] { return Err(ScriptError::EqualVerify); }
    if computed != lit { return Err(ScriptError::EqualVerify); }
    // Stack: [schnorr_sig, opening_blob]

    // OP_SHA256
    let blob = stack.pop().unwrap();
    let h = sha256(&blob);
    stack.push(h.to_vec());
    // Stack: [schnorr_sig, sha256(opening_blob)]

    // <opening_hash> OP_EQUALVERIFY
    let baked = leaf_script_extract_pushed_hash();   // 32 B literal in the script
    let computed_hash = stack.pop().unwrap();
    if computed_hash != baked { return Err(ScriptError::EqualVerify); }
    // Stack: [schnorr_sig]

    // <owner_xonly_pubkey> OP_CHECKSIG
    let owner = leaf_script_extract_pushed_pubkey();
    let sig = stack.pop().unwrap();
    let sighash = compute_taproot_sighash(spending_tx, prevout_amount, /* ... */);
    verify_schnorr(&sig, &sighash, &owner)?;
    // Stack: [true]

    Ok(())
}
```

The full node never sees `LeafV2`, the round tree, or the Pedersen
commitment. It only sees: a 32-byte hash literal, a 32-byte pubkey
literal, a 73-byte witness blob, and a Schnorr signature. The
binding to the off-chain commitment is established at round-admission
time (#538) by recomputing both the tagged-leaf-hash and the
Pedersen commitment from the same `(amount, blinding,
owner_pubkey)` and refusing to admit any leaf whose two checks
disagree. The L1 then enforces the SHA-256 rail; the round-admission
check enforces the Pedersen rail; together they bind the exit to
the published commitment.

### Threat model

#### Honest user, honest operator

Happy path. The user retrieves `(amount, blinding)` from local
storage (#548), constructs the witness blob, signs the exit tx with
their spend key, broadcasts. The chain verifies, the user receives
funds.

#### Misbehaving exiter (correct opening, wrong amount on output)

Cannot happen. The exit tx's input is the per-VTXO leaf UTXO; its
value is `amount` by construction. The output value is `amount −
fee`. Bitcoin's amount-conservation rule rejects any output sum that
exceeds the input. The misbehaving exiter cannot pay themselves more
than the leaf UTXO holds.

#### Misbehaving exiter (forged opening, claims a larger amount)

The witness blob's first 8 bytes encode `amount` in LE. SHA-256 of
the blob must equal the literal in the script, which is fixed at
VTXO-creation time. Any change to the blob — including the amount
slice — flips the hash and the script fails. The exiter cannot
forge an opening for a different amount than the one committed at
creation.

#### Misbehaving exiter (truncated / oversize blob)

`OP_SIZE` + `OP_EQUALVERIFY` rejects any blob whose length is not
exactly 73. The exiter cannot bypass the binding by submitting a
shorter or longer blob.

#### Misbehaving operator (commits a wrong opening hash to LeafV2)

The round-admission verifier (#538) refuses any leaf whose
`opening_hash` does not derive from the same `(amount, blinding,
owner_pubkey)` the Pedersen commitment hides. The operator cannot
bind a confidential leaf to an `opening_hash` that doesn't match
its commitment.

#### Misbehaving operator (publishes correct opening_hash in LeafV2 but constructs the per-VTXO Taproot leaf with a different baked literal)

The user's wallet (`#548`) recomputes the per-VTXO Taproot output
key from the same `(opening_hash, owner_pubkey)` it expects and
refuses to spend any leaf UTXO whose tweaked output key does not
match. This is a client-side check (the user knows what tree they
should see); it MUST be implemented in #548. If skipped, the user
might attempt to broadcast an exit whose Tapscript control block is
not satisfiable (the user's blob hashes to one value, the operator's
baked literal is another), and the script fails on chain. In all
cases the exiter cannot extract funds: the failure mode is "no
confirmation," not "wrong amount paid."

#### Operator + exiter collusion to inflate amount

Both parties would have to: (a) re-sign and re-broadcast the chain
of intermediate transactions all the way up to the round-commitment
tx, (b) get the operator to admit a different round, (c) get the
chain to reorg the original round-commitment-tx out. The operator
can't force a reorg; the round-commitment-tx is already on chain
once the round closes; the per-VTXO leaf UTXO's amount is fixed by
that on-chain history. Inflation attack reduces to "deep reorg of
the operator's round-commitment-tx," which is the same security
boundary the transparent path already lives behind.

#### Replay across rounds

Each VTXO has a unique `opening_hash` (the `owner_pubkey` and
`(amount, blinding)` are per-output; even if two VTXOs share the
same amount, their blindings are independent CSPRNG samples —
required by ADR-0003's per-output ephemeral freshness
requirement and by Pedersen security). Two distinct VTXOs cannot
share an `opening_hash`. The L1 script's literal differs per VTXO,
so a witness valid for VTXO A cannot satisfy VTXO B's leaf script.

#### Witness blob fingerprinting

A passive observer who watches the chain learns: `amount`,
`blinding`, `owner_pubkey`. Two of those (`amount`, `owner_pubkey`)
are observable on any transparent exit too; `blinding` is a 32-byte
random scalar with no semantic content. The marginal privacy cost
of revealing `blinding` is zero (it is by design unrecoverable from
the commitment alone, and once revealed it serves no further
purpose). Pre-exit, the blinding's role is to hide the amount in
the commitment; post-exit, the amount is on chain and the blinding
is irrelevant.

## Consequences

### Positive

- **Single-tx unilateral exit.** Same confirmation count as the
  transparent path; no two-phase ritual.
- **Full L1 enforcement.** No operator policy on the unilateral path.
  Every Bitcoin full node verifies the binding inside Tapscript.
- **One source of truth for the leaf hash.** `LeafV2` carries the
  `opening_hash`; the per-VTXO Taproot leaf script bakes the same
  bytes; the round-admission check (#538) enforces both rails. No
  divergence between off-chain and on-chain views of the binding.
- **Fits inside mainnet Tapscript.** No covenants, no soft-fork
  dependency, no OP_CAT. The leaf script is 74 bytes, comfortably
  within standardness and the 10000-byte script limit.
- **Reuses existing Taproot machinery.** The per-VTXO output is the
  same `build_vtxo_taproot` shape with one extra leaf; the existing
  tests for that path stay green; #547 extends the function with a
  confidential variant rather than forking.
- **Marginal privacy cost is zero.** `blinding` carries no
  post-exit information.

### Negative / follow-ups

- **Witness is ~78 vB heavier than a pure transparent exit.** A
  confidential unilateral exit costs ~150 vB vs. ~110 vB for a
  transparent expiry exit. Acceptable on the emergency path; the
  fee delta at typical mempool conditions is < 200 sats.
- **Reveals `blinding` on chain.** Documented as expected. A future
  v2 might compress the opening blob to 41 bytes by omitting the
  redundant `owner_pubkey` (it is already pushed by `OP_CHECKSIG`),
  but the `OP_CHECKSIG` happens after the SHA-256 check and the
  script cannot reuse the pubkey across opcodes without OP_DUP — a
  follow-up issue **[FU-EXIT-OPENING-COMPACT]** is appropriate if
  exit fee pressure makes this worthwhile.
- **Domain rotation requires a new `LeafV2` version.** If a future
  primitive changes the opening-hash construction (e.g. switching to
  BLAKE3 for performance, or to a SNARK-friendlier hash), `LeafV2`
  must mint a new prefix byte (`0x03`). The current encoding is
  pinned to raw SHA-256 of the 73-byte blob. Migration is a
  protocol-level event, not an internal refactor.
- **`opening_hash` adds 32 bytes per confidential leaf to the round
  tree's wire.** A 500-output round therefore carries ~16 KB of
  additional `opening_hash` bytes. Negligible relative to range
  proofs (~650 KB at the Back-Maxwell sizing in ADR-0001).
- **No SNARK migration path inside this construction.** A future
  privacy-preserving exit (one that does not reveal the amount) would
  need a SNARK that proves the exit transaction balances against
  the commitment without disclosing `amount`. This is out of scope
  for CV-M4 and CV-M5; the current design accepts the disclosure as
  the cost of the unilateral path. **[FU-EXIT-PRIVATE]** is the
  follow-up tracking issue.

### Cross-cutting — constraints on downstream issues

These are not suggestions; they are requirements for this ADR's
soundness. Any deviation must reopen ADR-0005 before landing.

#### #547 (Tapscript exit path with commitment opening) MUST

- Build the confidential per-VTXO Taproot output with **exactly
  three Tapscript leaves**: collaborative (existing,
  `vtxo_collaborative_script_two_key`), expiry (existing,
  `vtxo_expiry_script`), and confidential-exit (new, this ADR).
  The first two leaves' bytes MUST be bit-identical to the
  transparent variant's bytes — this is the #520 parity gate.
- Place the confidential-exit leaf at depth 2 in a balanced tree
  with the existing two leaves at depth 2 as well. Leaf ordering on
  a Taproot output is canonicalised by the `TaprootBuilder`; #547
  must ensure the leaf ordering is deterministic given
  `(owner_pubkey, asp_pubkey, opening_hash, csv_delay)`.
- Construct the leaf script as exactly:
  `OP_SWAP OP_SIZE <0x49> OP_EQUALVERIFY OP_SHA256
  <opening_hash_32B> OP_EQUALVERIFY <owner_xonly_32B> OP_CHECKSIG`.
  Byte-for-byte; no variations, no additional opcodes, no
  alternative orderings. The ADR's golden-fixture script byte
  string is the authority.
- Expose a function `confidential_exit_script(opening_hash:
  &[u8; 32], owner_xonly: &XOnlyPublicKey) -> ScriptBuf` in
  `crates/dark-bitcoin/src/tapscript.rs`. It MUST NOT take `amount`
  or `blinding` as parameters — the script bakes only the hash, not
  the opening data.
- Build the witness blob as exactly 73 bytes: `amount_LE_8B ||
  blinding_32B || owner_pubkey_compressed_33B`. The compressed
  pubkey is the 33-byte form, NOT the 32-byte x-only form (the
  x-only form drops the parity bit, which is needed to reproduce
  the SHA-256 of the LeafV2 preimage's `opening_hash` slot
  consistently with the round verifier).
- Sign the exit tx with `SIGHASH_DEFAULT` (BIP-341). Other sighash
  flags MUST be rejected — the leaf script does not push a sighash
  type byte after the signature, so the verifier defaults to
  `SIGHASH_DEFAULT`.
- Provide a regression test that submits the exit tx to regtest
  with a wrong `blinding` (held constant amount) and asserts the
  tx is rejected by the script interpreter. This is the issue's
  acceptance criterion 3.
- Provide a property test (per #547 acceptance criterion 4) over
  random `(amount, blinding, tree_position)` that constructs a
  valid confidential VTXO, derives the per-VTXO Taproot output,
  builds the exit tx, signs, and asserts the script interpreter
  accepts it.
- Record a golden fixture for the leaf script bytes given
  deterministic test inputs `(owner_pubkey = 0x02 || ones,
  opening_hash = SHA256(...))`. The fixture lives at
  `crates/dark-bitcoin/tests/fixtures/confidential_exit_script.golden`.
- Coexist with the existing transparent exit path: the
  `Confidential` and `Transparent` Vtxo variants MUST dispatch to
  different per-VTXO Taproot constructors (`build_vtxo_taproot` for
  `Transparent`, a new `build_confidential_vtxo_taproot` for
  `Confidential`). Both functions live in the same module; neither
  calls the other.
- Compute fees from the exiter's wallet, NOT from the VTXO amount.
  The exit tx's input is the leaf UTXO (full `amount`); the output
  is `amount` minus the on-chain fee that the wallet's fee estimator
  produces. This matches the issue's task description.

#### #547 MUST NOT

- Bake `amount` or `blinding` into the leaf script as literals. Only
  `opening_hash` and `owner_xonly` are baked; everything else lives
  in the witness.
- Use OP_CAT, OP_SUBSTR, OP_CHECKSIGFROMSTACK, OP_PAIRCOMMIT,
  OP_VAULT, or any other opcode not enabled on Bitcoin mainnet
  Tapscript as of 2026-04-24. The leaf MUST be standardness-clean
  on every mainnet node.
- Include a CSV / CLTV / nLockTime gate on the confidential-exit
  leaf. The unilateral exit is *immediate* (the user can broadcast
  the moment they hold the opening data); the CSV gate lives only
  on the existing transparent expiry leaf, which remains valid for
  operator-side sweep recovery.
- Add an OP_RETURN output to the exit tx. The opening lives in the
  witness, not in any transaction output.
- Construct a second confirming transaction. The exit is one tx.
- Read or modify `LeafV2.encrypted_memo_hash`. That slot is owned
  by ADR-0003 and #530; this ADR adds a sibling `opening_hash` slot
  and does not perturb the memo's role.
- Compute `opening_hash` with any tag prefix or domain separator.
  The hash is raw `SHA256(amount_LE || blinding || owner_pubkey)`,
  matching what `OP_SHA256` produces inside the script.

#### #547 SHOULD

- Ship a benchmark that measures script-interpreter cost on a
  confidential exit witness (~200 µs at the rust-bitcoin script
  interpreter's current per-byte cost). The number is informational
  but useful for capacity planning.

#### #548 (client-side confidential exit flow) MUST

- Retrieve `(amount, blinding, merkle_proof, owner_pubkey,
  ephemeral_pubkey, encrypted_memo_hash, opening_hash)` from local
  state for the target VTXO. The local state is the wallet's
  confidential-VTXO database; the data was stored at scan time
  (#555) when the wallet decrypted the memo (ADR-0003).
- Reconstruct the per-VTXO Taproot output's expected output key
  from the local state and verify it matches the leaf UTXO's
  `script_pubkey` before signing. This is the client-side defence
  against a misbehaving operator who tries to substitute a
  different per-VTXO leaf.
- Recompute `opening_hash = SHA256(amount_LE || blinding ||
  owner_pubkey_compressed)` and assert it equals the
  `opening_hash` field stored in `LeafV2`. If the assertion fails,
  return `ConfidentialExitError::OpeningMismatch` with remediation
  guidance: "your stored opening data is inconsistent with the
  round's published commitment; this VTXO cannot be unilaterally
  exited from this wallet."
- Surface a typed error (`ConfidentialExitError::MissingOpening`)
  if any of `(amount, blinding)` is missing from local state. The
  user CANNOT unilaterally exit a confidential VTXO whose opening
  they have lost; recovery requires either operator help (Mnemonic
  / scan-and-decrypt the memo from a stored ephemeral_pubkey) or
  the cooperative spend path. This is the issue's acceptance
  criterion 2.
- Display a CLI warning before broadcast: "Unilateral exit reveals
  this VTXO's amount and blinding factor on the Bitcoin chain.
  Anyone watching the chain will see the amount. Continue?
  [y/N]". Ack required before broadcast. The exact wording lives
  with #548; this ADR mandates the *substance*: the user is
  warned about on-chain disclosure.
- Use `SIGHASH_DEFAULT` for the exit-tx signature. Match the
  on-chain script's expectation set by this ADR.
- Provide an `ark-cli exit <vtxo_id>` wrapper that calls
  `dark_client::exit_confidential_vtxo` for a confidential VTXO and
  the existing transparent-exit function for a transparent VTXO,
  dispatching on `vtxo.confidential.is_some()`.

#### #548 MUST NOT

- Construct the witness blob without first asserting
  `amount.to_le_bytes().len() == 8` and `blinding.len() == 32` and
  `owner_pubkey_compressed.len() == 33`. The total length MUST be
  73 bytes; the script's `OP_SIZE` check rejects any other length,
  but the client should fail early with a typed error rather than
  let the broadcast bounce.
- Submit the exit tx without first calling the local
  `confidential_exit_script` builder and verifying the resulting
  Taproot output key matches the on-chain UTXO. A mismatch means
  the operator's tree disagrees with the wallet's view; broadcasting
  is futile and exposes the opening for nothing.
- Reuse a previously-broadcast exit's witness blob for a different
  VTXO. Each VTXO has its own `(amount, blinding, owner_pubkey)`;
  cross-VTXO reuse is impossible by construction (the script
  literal differs) but the client should not attempt it.
- Cache the opening blob on disk in plaintext after the exit tx
  confirms. Once the exit is confirmed, the opening serves no
  further purpose (the amount is on chain and the VTXO is
  consumed); the wallet SHOULD scrub the stored `(amount,
  blinding)` on confirmation. This is hygiene, not a security
  invariant of this ADR, but it bounds the blast radius of a
  later wallet compromise.

#### #549 (sweep / reclaim path) MUST

- Use the existing CSV-gated expiry leaf (`vtxo_expiry_script`)
  for the operator-side sweep, not the new confidential-exit leaf.
  The operator does not hold the user's `(amount, blinding)`; the
  sweep path falls through to the timelock-gated transparent leaf
  (which on a confidential VTXO pays the per-VTXO leaf's full
  amount back to the operator, recouping the round's settlement
  amount). #549's acceptance criteria are unchanged by this ADR.

#### #550 (E2E integration tests) MUST

- Cover a confidential unilateral exit on regtest using the
  full path defined here (round → tree → leaf → exit-tx →
  confirm). The fixture data MUST include the deterministic
  `opening_hash` derivation and assert byte-equality of the leaf
  script against the golden fixture from #547.
- Cover a negative case where the wallet's stored `(amount,
  blinding)` is mutated post-storage; assert that
  `dark_client::exit_confidential_vtxo` returns
  `OpeningMismatch` and never broadcasts.

## References

- Issue #546 (this ADR)
- Issue #547 — Tapscript exit path with commitment opening
- Issue #548 — Client-side confidential exit flow
- Issue #549 — Sweep / reclaim path for expired confidential VTXOs
- Issue #550 — E2E integration tests for confidential exit + sweep
- Issue #520 — Go `arkd` E2E parity gate
- Issue #530 — `Vtxo` enum extension (defines `Confidential` variant)
- Issue #538 — confidential-tx validation pipeline (round-admission check for `(commitment, opening_hash)` pair)
- Issue #540 — round tree leaf encoding (`LeafV2`, gains `opening_hash` slot per this ADR)
- ADR-0001 — secp256k1-zkp integration strategy (Pedersen commitments, range proofs)
- ADR-0002 — nullifier derivation scheme and domain separation
- ADR-0003 — confidential VTXO memo format (per-output ephemeral freshness; encrypted memo)
- ADR-0004 — fee handling in confidential transactions (plaintext fee on confidential txs)
- BIP-340 — Schnorr signatures (tagged-hash construction)
- BIP-341 — Taproot
- BIP-342 — Tapscript opcodes (defines available opcodes; OP_CAT remains disabled)
- `crates/dark-bitcoin/src/tapscript.rs` — `build_vtxo_taproot`, `vtxo_expiry_script`, `vtxo_collaborative_script_two_key` (existing leaves; #547 extends)
- `crates/dark-bitcoin/src/exit.rs` — `TreeBranch`, `CollaborativeExitBuilder` (transparent-path patterns this ADR mirrors)
- `crates/dark-core/src/round_tree.rs` — `LeafV1`, `LeafV2`, `tree_leaf_hash` (the leaf-hash dispatcher this ADR extends)
- `crates/dark-confidential/src/commitment.rs` — `PedersenCommitment` (commits the same `(amount, blinding)` as the script)
