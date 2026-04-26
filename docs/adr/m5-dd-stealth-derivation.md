# ADR-M5-DD: Stealth address key derivation paths (BIP-32 / BIP-44 compatibility)

- **Status:** Proposed
- **Date:** 2026-04-25
- **Milestone:** CV-M5 (Stealth Addresses)
- **Drives:** #551 → unblocks #553 → constrains #554, #555, #558, #559, #560
- **Affects:** stealth-address path only; transparent BIP-86 paths and the
  existing `derive_asp_keypair` (`m/86'/{coin}'/1'/0/0`) are untouched
  (#520 parity gate)
- **Companion ADRs:** ADR-0003 (memo format — pins `scan_pk` as a
  33-byte compressed secp256k1 point and reuses the sender's
  per-output ephemeral keypair for both ECDH and one-time-key
  derivation)

## Context

A confidential VTXO is locked to a **one-time public key** that the
sender derives per output by ECDH against the recipient's published
**meta-address** (`MetaAddress { scan_pk, spend_pk }`, defined in
#553). The recipient runs a **scanning loop** (#558) that re-derives
the same one-time public key from each round announcement and
recognises the outputs they own. To spend, the recipient combines
their **spend key** with the same ECDH-derived tweak.

The two recipient-side keys play very different roles:

- **`scan_sk` / `scan_pk`** — read-only credential. Anyone who holds
  `scan_sk` can detect every incoming VTXO for the meta-address.
  They cannot spend. The scan key lives on the always-online
  scanning host (the user's daemon, or an untrusted watch-only
  relay the user shares it with). Compromise of `scan_sk` reveals
  the user's incoming-payment graph but not their funds.
- **`spend_sk` / `spend_pk`** — full spending authority. Combined
  with the per-output `H(shared_secret)` tweak, it produces the
  one-time secret that signs the VTXO leaf script. Compromise of
  `spend_sk` is complete loss of funds (and, by inversion of the
  tweak, retroactive de-anonymisation when the watcher also has
  `scan_sk`).

The two keys must therefore derive from **disjoint regions of the
BIP-32 tree** so that exporting `scan_sk` to a third-party scanner
cannot leak any information about `spend_sk`. They must also derive
**deterministically from the wallet seed** so that:

- A user can restore the entire stealth wallet from their BIP-39
  mnemonic without operator help. Restore semantics live in
  `dark-wallet-bin` and today's restore flow is BIP-86 only
  (`m/86'/{coin}'/0'/{0,1}/{idx}`); this ADR extends the same flow
  with stealth-specific paths.
- A multi-device flow (mobile scanner + cold-storage signer) can
  share the same meta-address by handing the scanner only
  `scan_sk` while keeping `spend_sk` air-gapped.
- Test vectors are reproducible across implementations: a fixed
  `(mnemonic, account_index)` produces a fixed
  `(scan_pk, spend_pk, meta_address_bech32m)`.

The choice of derivation paths affects four things, in this order
of importance:

1. **Wallet portability.** Any BIP-32 implementation (including
   third-party recovery tools) must be able to recompute the
   scan and spend keys from the mnemonic. This rules out custom
   non-BIP-32 derivations (e.g. SLIP-10 over a non-secp256k1
   curve) and pins us to standard `derive_priv` calls on a
   `secp256k1` `Xpriv`.
2. **Coin-type registration.** SLIP-44 publishes a registry of
   coin types under purpose `44'` / `49'` / `84'` / `86'`. Ark
   does not have a registered coin type, and the registration
   process takes weeks. We need a path that does not block on
   external registration but also does not collide with any
   currently-registered coin type or with our own ASP/wallet
   keys.
3. **Multi-account support.** A user may want to receive payments
   under several disjoint stealth identities (work / personal /
   high-value). Each identity is one `(scan_sk, spend_sk)` pair;
   they MUST live at different sub-paths of the same parent so a
   single mnemonic backs all of them.
4. **Hardened-vs-unhardened indices.** Hardened derivation
   (`H_i = HMAC-SHA512(parent_chaincode, 0x00 || parent_priv ||
   i_be)` for `i >= 0x80000000`) breaks the public-key derivation
   property: knowing `parent_xpub` and `i_h` is not enough to
   compute `child_pub` without `parent_priv`. Unhardened
   derivation (`i < 0x80000000`) keeps the property but means
   that leaking the `parent_xpub` plus any single child private
   key reveals every other child private key under the same
   parent. The choice has direct security consequences.

The framing of #551 lists the canonical scan/spend paths
(`m/44'/0'/0'/ark_scan'/account'`,
`m/44'/0'/0'/ark_spend'/account'`) as a starting point and asks for
a decision on coin-type registration, hardened-vs-unhardened
choice, the BIP-85 child-derivation angle, and the exact one-time
private-key tweak. This ADR makes those decisions and pins the
paths so #553 / #554 / #555 / #560 build against a single source
of truth.

## Requirements

- **Disjoint key trees.** `scan_sk` and `spend_sk` MUST derive
  from non-overlapping branches such that no ancestor or sibling
  of `spend_sk`'s path is reachable from `scan_sk` (and vice
  versa). The minimum requirement is that there is no path
  `m/X'` that is a prefix of both.
- **Deterministic from seed.** Given the BIP-39 mnemonic
  (optional passphrase per BIP-39) and an `account_index ∈
  [0, 2^31)`, a wallet MUST produce one canonical
  `(scan_sk, spend_sk)` pair. The derivation MUST NOT depend on
  the network (mainnet/testnet/regtest) — the same seed produces
  the same pair on every network.
- **BIP-32 compatible.** All path components MUST be valid
  BIP-32 indices (`u32 < 2^32`). The hardened bit (`0x80000000`)
  is set per-component as specified below.
- **No external coin-type registration on the critical path.**
  The chosen path MUST NOT depend on SLIP-44 registering an
  "Ark" coin type before milestone CV-M5 ships. We adopt a
  **private-use coin type** for the design decision and document
  the migration path to a registered coin type as an additive
  follow-up.
- **Compatible with `dark-wallet-bin` restore.** The existing
  restore flow (mnemonic → `Xpriv` → BIP-86 templates) MUST keep
  working unchanged for transparent VTXOs and L1 funds. Stealth
  paths are an additive layer on the same `Xpriv`. The
  ASP-key path `m/86'/{coin}'/1'/0/0` is also unchanged.
- **Multi-device hand-off.** A user MUST be able to export
  `scan_sk` (or the `scan_xprv` extended key) to a separate
  scanning host without ever exposing `spend_sk`. The path
  layout MUST make this a single sub-tree export, not a
  per-account dance.
- **Multi-account.** Each `account_index` MUST yield an
  independent `(scan_sk, spend_sk)` pair such that linking two
  meta-addresses requires either holding both `scan_sk`s or
  performing a 2-of-2 re-association attack outside this ADR's
  threat model.
- **One-time-key tweak deterministic from `(spend_pk, shared_secret)`.**
  The construction `one_time_pk = spend_pk + H(shared_secret) · G`
  MUST use a domain-separated hash so the tweak cannot be
  computed by accident from any other shared-secret-shaped
  bytes (e.g. the memo's HKDF output).
- **No new curve assumption.** All keys live on `secp256k1`,
  the only curve `dark-confidential` (and the rest of the
  workspace) depends on. No ed25519, no Ristretto, no curve25519.
- **Test-vector parity.** Seed-to-`(scan_pk, spend_pk)` vectors
  MUST be byte-exact across implementations and language ports.

## Options Considered

The design space splits along two axes:

- **Path layout** — where in the BIP-32 tree the scan and spend
  keys live, which determines compatibility with third-party
  tools and the multi-device hand-off shape.
- **Coin-type strategy** — registered SLIP-44 coin type vs.
  private-use range vs. piggy-backing the existing `m/86'/...`
  ASP path.

Three concrete schemes are evaluated below. Each scheme fixes a
path layout and a coin-type strategy together — they are not
independent decisions.

### Option 1 — Private-use coin type under purpose `44'`, separate `scan'` / `spend'` purpose-like component

```text
scan_sk_path  = m/44'/1237'/{account}'/0'/0
spend_sk_path = m/44'/1237'/{account}'/1'/0
```

Where `1237'` is the **private-use coin-type slot** chosen for Ark.
SLIP-44's reserved range starts at `0x80000000` (registered coin
types live in `[0, 0x7FFFFFFF]` once the hardened bit is added);
`1237'` is a low, memorable slot that is **not** registered to any
chain in the SLIP-44 registry as of 2026-04-24. We claim it for
internal use without going through the SLIP-44 PR process; the
"production" registration is a follow-up.

The fourth component (`0'` / `1'`) acts as a **purpose-like
selector** between scan and spend. It is hardened so the two
sub-trees cannot be linked by inspecting their xpubs.

- **Disjoint trees**: yes. `m/44'/1237'/{a}'/0'` and
  `m/44'/1237'/{a}'/1'` share only the parent
  `m/44'/1237'/{a}'`, and that parent is hardened. Compromise of
  `scan_xprv` (any node at or below `m/44'/1237'/{a}'/0'`) yields
  no information about `spend_xprv` because the hardened CKD step
  one level up already broke the linkage.
- **Multi-account**: yes. Bumping `{account}` produces a fresh
  pair. Each account has its own `(scan_xprv, spend_xprv)`.
- **Multi-device hand-off**: trivial. Export
  `scan_xprv = derive(m/44'/1237'/{a}'/0')` to the scanning host;
  the host can derive `scan_sk = scan_xprv/0` for each address
  without ever touching the spend tree.
- **Coin-type collision risk**: low but non-zero. `1237'` is
  not assigned today; it could be claimed by another project
  during the time it takes us to optionally upstream the
  Ark registration. Mitigation: pin `1237'` as the v1
  derivation, document the registered-slot migration as a
  v2 follow-up that an opt-in restore flag selects.
- **BIP-44 conformance**: this is a *BIP-44-shaped* path, not a
  literal BIP-44 path. BIP-44 specifies the fourth component as
  `change` (`0` for receive, `1` for change), unhardened and
  followed by an unhardened `address_index`. We deliberately
  reuse the slot for `scan'/spend'` selection and harden it.
  The deviation is documented in this ADR; tooling that
  blindly assumes BIP-44 layout (e.g. some hardware-wallet UIs)
  may display the path as "non-standard".
- **Standard tooling**: works in any BIP-32 implementation
  (`bip32.derive_priv` of a hardened path is a primitive
  operation). Hardware wallets that restrict policy to
  registered SLIP-44 paths would refuse to sign for `1237'`;
  this is acceptable because spend signing for stealth VTXOs
  happens inside `dark-wallet-bin` / `dark-confidential` for
  v1, not on a hardware device. (Hardware support is a v2
  question.)
- **One-time-key tweak**: orthogonal to path choice; defined in
  the "Decision" section.

### Option 2 — Reuse the existing BIP-86 coin type, sub-account 2 / 3

```text
scan_sk_path  = m/86'/{coin}'/2'/0/0
spend_sk_path = m/86'/{coin}'/3'/0/0
```

Where `{coin}` is `0` for mainnet, `1` for testnet/regtest, mirroring
`derive_asp_keypair` (which uses account `1'`). The user's primary
wallet uses account `0'`; ASP uses account `1'`; we claim `2'` for
scan and `3'` for spend.

- **Disjoint trees**: partially. The two sub-trees share
  `m/86'/{coin}'`, which is the same parent that backs the user's
  primary L1 wallet. A breach that exposes
  `m/86'/{coin}'_xprv` (the BIP-86 account-level extended key)
  exposes scan + spend + L1 wallet + ASP key all at once. In
  practice this xprv is not exported (BDK only exposes the
  derived descriptors), but the layout couples three security
  domains under one xprv.
- **Multi-account**: collides. The user's primary BIP-86 account
  hierarchy uses `m/86'/{coin}'/{n}'/{0,1}/{i}` for `n = 0, 1, 2,
  …`. We would need to reserve account slots `2'+` permanently
  for stealth, and the user can never run a fourth or fifth
  primary account without overlapping our scan tree. The
  account-collision risk is real because BDK's BIP-86 template
  generator does not know about our reservation.
- **Multi-device hand-off**: messy. The "scan-only" export
  derived from `m/86'/{coin}'/2'` would also let the recipient
  trial-decrypt every output owned by the user's L1 BIP-86
  wallet (no — BIP-86 outputs aren't ECDH-encrypted; but the
  *xpub* leaks the user's L1 receive-history root). Sharing
  `scan_xprv` to a third-party scanner inadvertently shares an
  xpub that lets that third party also derive every L1 receive
  address.
- **Coin-type collision risk**: zero (we already use `86'`).
- **Standard tooling**: every BIP-86 wallet recognises this
  shape. Hardware wallets that already accept `m/86'/0'/2'/0/0`
  would sign for it. Whether that's a feature or a footgun
  depends on whether you want hardware-wallet support for
  stealth signing (we don't, for v1 — see below).
- **Network parameter coupling**: `coin = 0` vs `coin = 1`
  changes the path between mainnet and testnet. The Ark
  protocol's stealth identity should NOT change shape when a
  user moves between networks (a meta-address generated on
  regtest must round-trip on mainnet for pre-prod testing).
  Option 2 fails this requirement.

### Option 3 — Custom non-BIP-44 layout under a fresh purpose

```text
scan_sk_path  = m/2147483648'/1237'/{account}'/0
spend_sk_path = m/2147483648'/1237'/{account}'/1
```

Use a **fresh purpose component** (`2147483648 == 0x80000000`,
i.e. the lowest "all bits clear except the hardened bit"
purpose, conventionally interpreted as the *hardened-only*
namespace start). Distinguish scan and spend at the leaf level
(`/0` vs `/1`, unhardened).

- **Disjoint trees**: weakly. Scan and spend sit one CKD step
  apart at the deepest level, both unhardened. Leaking the
  parent xpub (`m/2147483648'/1237'/{a}'`) plus *either*
  `scan_sk` or `spend_sk` reveals the *other* private key.
  This is the unhardened-CKD footgun. Mitigation would be to
  harden the leaf, but then we no longer get the public-key
  derivation property we wanted in the first place.
- **Multi-account**: yes (per `{account}`).
- **Multi-device hand-off**: structurally fragile — the
  scanner needs the parent xpub to derive scan addresses, and
  that xpub plus a leaked `scan_sk` reveals `spend_sk`. We
  must export `scan_sk` directly (one key per account, no
  derivation chain), which kills the BIP-32 derivation
  property the unhardened layout was supposed to buy.
- **Coin-type collision risk**: same as Option 1.
- **Standard tooling**: poor. Most third-party tools do not
  expose paths starting with a purpose component outside the
  registered range (`44'`, `49'`, `84'`, `86'`, etc.). We would
  ship our own derivation helper.
- **No upside.** The "fresh purpose" buys nothing: `44'` already
  separates us from `86'` (BDK's wallet) and from `49'` /
  `84'` (legacy/segwit tooling). The unhardened leaves
  introduce a new attack surface (xpub-leak → key-recovery)
  for no portability gain.

## Evaluation matrix

| Criterion | Opt 1 (`44'/1237'/{a}'/{role}'/0`) | Opt 2 (`86'/{coin}'/{2,3}'/0/0`) | Opt 3 (`2147483648'/1237'/{a}'/{0,1}`) |
|---|---|---|---|
| Disjoint scan/spend trees | Yes (hardened role boundary) | Partial (shared `m/86'/{coin}'` parent) | Weak (unhardened leaves) |
| Multi-account independence | Yes | Conflicts with primary BIP-86 accounts | Yes |
| Multi-device hand-off | Single sub-tree export | Couples L1 + scan exposure | Per-account export only |
| Network-independent | Yes (no `coin` in path) | **No** (`coin` differs mainnet/testnet) | Yes |
| BIP-32 third-party recovery | Standard `derive_priv` | Standard `derive_priv` | Standard `derive_priv` |
| Hardware-wallet path policy | "Non-standard purpose 44'/1237'" warning | Accepted as BIP-86 account | Almost certainly rejected |
| External coin-type registration required | No (private slot) | No (reuses 86') | No |
| Couples to existing ASP key (`m/86'/{c}'/1'/0/0`) | No | **Yes** (sibling under `86'/{c}'`) | No |
| Single-xpub leak compromises spend key | No | No (BDK does not expose) | **Yes** (with sibling priv) |
| Extra bytes per derivation step | ~40 B per node (chaincode) | same | same |
| Round-trip testability across networks | Yes | **No** | Yes |
| Conforms to BIP-44 layout literally | No (`role'` repurposes `change`) | No (`86'` is BIP-86, not BIP-44) | No |
| Failure mode on misimplemented hardened bit | Wrong-tree derivation; safe (different xprv) | Wrong-tree derivation; safe | Wrong-tree derivation but linkable via xpub |
| Audit surface added on top of BIP-86 wallet | Two new derivation calls per account | Two new derivation calls per account | Two new derivation calls + custom purpose handling |

## Decision

**Adopt Option 1** with the canonical path

```text
scan_sk_path  = m/44'/1237'/{account}'/0'/0
spend_sk_path = m/44'/1237'/{account}'/1'/0
```

and pin the **private-use coin type `1237'`** for Ark v1. The
fourth component (`0'` for scan, `1'` for spend) is **hardened**.
The fifth component (`0`) is fixed as a deterministic terminal —
not a BIP-44 `address_index` — because each account's stealth
identity is a single `(scan_sk, spend_sk)` pair, not an
enumeration of addresses (the per-output diversification happens
via the sender's ECDH ephemeral, not via successive child indices).

The `account` parameter is a **hardened** index in
`[0, 2^31)`. Account `0` is the default for `ark-cli` without
explicit selection. Multi-account users specify `--account N`
and the wallet derives `m/44'/1237'/N'/{0,1}'/0`.

### Why `1237'` as the private-use coin type

- **Not in the SLIP-44 registry as of 2026-04-24.** A scan of
  the [satoshilabs/slips](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
  registry shows `1237'` unassigned. (The closest neighbours
  are `1236'` and `1238'`, also unassigned.) Picking an
  unassigned slot avoids any current chain claim.
- **Stable across networks.** No `coin = 0 / 1 / regtest`
  branch. A meta-address generated under a regtest mnemonic
  round-trips to mainnet using the same path. This matches
  the requirement that stealth identities be network-agnostic
  at the key-derivation layer (network selection happens at
  the address-encoding layer via the bech32m HRP, defined in
  #553).
- **Memorable.** `1237` is small enough to type in test
  vectors and CLI commands, distinct enough from `1234`
  (occasionally seen as a placeholder) that it does not look
  like a typo.
- **Migration path to a registered slot.** If we later
  register an "Ark" coin type via a SLIP-44 PR, a v2 derivation
  spec will introduce a parallel path (e.g. `m/44'/{registered}'/{a}'/{0,1}'/0`)
  and ship a wallet upgrade that derives both, scans both,
  and lets users opt into the new one with a CLI flag. Funds
  derived under v1 remain spendable forever; the v2 path is
  additive.

### Why `m/44'/...` rather than `m/86'/...` or a fresh purpose

- **BIP-44 is the most widely supported "I have multiple coin
  types" purpose.** Recovery tools (Electrum, Sparrow, Trust
  Wallet, hardware-wallet companion apps) all accept `44'`-
  prefixed paths even for non-Bitcoin coins. Choosing `44'`
  maximises the surface of third-party tools that can at
  least *display* an Ark stealth derivation, even if they
  cannot sign for it.
- **`86'` (BIP-86 Taproot) is reserved for the user's L1
  Bitcoin wallet inside `dark-wallet-bin`.** Reusing it for
  stealth keys would couple the security of the user's L1
  funds to the security of the stealth scan key, which is
  explicitly designed to be exportable to less-trusted
  hosts.
- **A fresh purpose component (e.g. `9999'`) buys nothing
  beyond `44'`.** It loses third-party tool support and gains
  no isolation that `44'` plus a private coin type does not
  already provide.

### Why the role component (`0'` / `1'`) is hardened

- **Defence against xpub-leak attacks.** If a user shares
  `scan_xprv` (or even just `scan_xpub`) with a third-party
  scanner, that share MUST NOT enable any inference about
  `spend_xprv`. With both the role component and the account
  component hardened, the third party only sees a sub-tree
  rooted at `m/44'/1237'/{a}'/0'` and cannot walk back up to
  `m/44'/1237'/{a}'` (since hardened CKD requires the parent
  *private* key, not the chaincode + xpub).
- **The "public derivation property" is not needed for
  stealth scanning.** The recipient does not enumerate
  successive child addresses under `scan_xpub`; they take the
  single `scan_sk` and run the stealth-detection routine
  (`shared_secret = scan_sk · ephemeral_pk`, then
  `expected_one_time_pk = spend_pk + H(shared_secret) · G`)
  for every announced output. There is no per-address xpub
  walk that the unhardened CKD property would optimise.
- **Cost is one extra HMAC-SHA512 per derivation** —
  imperceptible at wallet-load time and zero cost during
  steady-state scanning (the keys are derived once and held
  in memory).

### Why `account'` is hardened

- **Account isolation.** A breach of one account's
  `(scan_sk, spend_sk)` pair MUST NOT enable derivation of
  any other account's keys. Hardening the account component
  is the standard BIP-44 idiom that gives this property.
- **Aligns with BIP-86's current usage in the workspace.**
  `derive_asp_keypair` already uses `m/86'/{coin}'/1'/0/0`
  with a hardened account component. We mirror the
  hardening choice for consistency.

### Why the terminal `0` is unhardened (and not `0'`)

- **Reserved-for-future-use slot.** The terminal `0` is a
  fixed deterministic address index, not a hardened
  boundary. Keeping it unhardened lets a v2 spec (if it
  needs per-meta-address rotation under one account)
  introduce `m/44'/1237'/{a}'/{role}'/{i}` with `i` running
  through unhardened indices. v1 pins `i = 0`.
- **No security cost in v1.** Because `i` is fixed at `0` and
  there are no siblings, the unhardened-CKD footgun does not
  apply: there is no `scan_sk_at_index_1` whose existence
  could leak `scan_sk_at_index_0` from `scan_xpub`. The
  xprv at `m/44'/1237'/{a}'/{role}'` is itself derived under
  hardened CKD, so the parent-priv-required property holds.

### One-time public-key tweak (the construction)

For each output, the sender:

1. Generates an ephemeral keypair `(ephemeral_sk, ephemeral_pk)`
   with `ephemeral_sk ← CSPRNG(32 bytes)` and
   `ephemeral_pk = ephemeral_sk · G`. The same keypair is reused
   for memo ECDH per ADR-0003 — single source of truth on the
   wire (the VTXO carries one `ephemeral_pk`; both the
   stealth-detection routine and memo decryption consume it).
2. Computes the **shared secret** as the compressed serialisation
   of the ECDH point:

   ```text
   shared_point        = ephemeral_sk · scan_pk
                       = scan_sk · ephemeral_pk           (recipient)
   shared_secret_bytes = compressed_serialize(shared_point)    (33 bytes)
   ```

3. Derives the **scalar tweak** with a **tagged-SHA256** so the
   tweak cannot collide with any other 32-byte hash the wallet
   computes:

   ```text
   t = TaggedHash(
           tag = "DarkConfidentialStealthTweakV1",
           msg = shared_secret_bytes,                       (33 bytes)
       )
   t  = scalar_reduce(t mod n_secp256k1)                    (32 bytes scalar)
   ```

   The BIP-340 tagged-hash construction is
   `SHA256(SHA256(tag) || SHA256(tag) || msg)`. The scalar
   reduction (`mod n` where `n` is the secp256k1 group order)
   uses the same path as `secp256k1::SecretKey::from_slice` with
   a final `secp256k1::Scalar` conversion. The probability that
   `t == 0` after reduction is negligible (`~2^-256`); the
   wallet MUST surface a typed error
   (`StealthError::TweakIsZero`) on the off chance it occurs
   and the sender MUST resample `ephemeral_sk` and retry.
4. Computes the **one-time public key**:

   ```text
   one_time_pk = spend_pk + t · G                           (point addition on secp256k1)
   ```

   (This is point addition; the tweaked point's compressed
   serialisation is the 33-byte VTXO-locking key that goes on
   the wire.)

5. Computes the **one-time private key** (recipient side, when
   spending):

   ```text
   one_time_sk = (spend_sk + t)  mod  n_secp256k1
   ```

   By construction `one_time_sk · G == spend_pk + t · G == one_time_pk`.

The tweak's domain-separation tag `DarkConfidentialStealthTweakV1`
is distinct from the memo's HKDF info string (`dark-confidential/memo/v1`,
ADR-0003) and from the opening-hash domain in ADR-0005
(`DarkConfidentialOpeningV1`). All three are derived from the
same `ephemeral_pk · scan_pk` shared point but produce
non-overlapping byte strings, so a future wallet bug that
accidentally feeds the wrong derived value into the wrong
slot fails to validate cryptographically (the AEAD tag will
fail, or the one-time-key match will fail) rather than
silently producing a valid-but-wrong artefact.

The recipient's scanning loop (#558) computes, for each
announced `(ephemeral_pk, one_time_pk_candidate)` pair:

```text
shared_point          = scan_sk · ephemeral_pk
shared_secret_bytes   = compressed_serialize(shared_point)
t                     = TaggedHash("DarkConfidentialStealthTweakV1",
                                   shared_secret_bytes)
expected_one_time_pk  = spend_pk + t · G
match                 = expected_one_time_pk == one_time_pk_candidate
```

The recipient holds `scan_sk` and `spend_pk` in scanning state
(NOT `spend_sk`); this lets the scanner run on a host that
cannot spend even if compromised.

### Specification

The full canonical specification, in pseudo-Rust, lives in
`crates/dark-confidential/src/stealth.rs` (currently a stub) and
is owned by #553. The behavioural contract:

```rust
// pseudocode — implementation lives in #553/#554
pub struct ScanKey([u8; 32]);          // zeroize-on-drop
pub struct SpendKey([u8; 32]);         // zeroize-on-drop, no Copy/no Clone
pub struct MetaAddress {
    pub scan_pk:  PublicKey,           // 33-byte compressed
    pub spend_pk: PublicKey,           // 33-byte compressed
}

pub fn derive_scan_key(seed: &[u8; 64], account: u32) -> ScanKey {
    // seed: BIP-39 → BIP-32 master seed (post-passphrase)
    let xpriv = Xpriv::new_master(Network::Bitcoin /* irrelevant */, seed)
        .expect("master derivation");
    let path: DerivationPath = format!("m/44'/1237'/{}'/0'/0", account)
        .parse().expect("static path");
    let derived = xpriv.derive_priv(&secp, &path).expect("hardened deriv");
    ScanKey(derived.private_key.secret_bytes())
}

pub fn derive_spend_key(seed: &[u8; 64], account: u32) -> SpendKey {
    let xpriv = Xpriv::new_master(Network::Bitcoin, seed).expect("master derivation");
    let path: DerivationPath = format!("m/44'/1237'/{}'/1'/0", account)
        .parse().expect("static path");
    let derived = xpriv.derive_priv(&secp, &path).expect("hardened deriv");
    SpendKey(derived.private_key.secret_bytes())
}
```

The `Network::Bitcoin` argument to `Xpriv::new_master` is a
serialisation hint only (it controls the version bytes if the
xpriv is ever exported as base58); it does NOT change the
derived bytes. We pass `Network::Bitcoin` unconditionally for
stealth derivation so the same seed produces the same
`(scan_sk, spend_sk)` regardless of which network the parent
wallet was constructed for.

### Test vectors

Four positive vectors and two negative scenarios are
materialised byte-exactly in
`docs/adr/vectors/m5-stealth-derivation-vectors.json` (created
by the implementation issue #553; this ADR specifies the inputs
and outputs the vectors must contain).

Vector V1 — canonical happy path (account 0):

| Field                              | Value                                                                          |
|------------------------------------|--------------------------------------------------------------------------------|
| `mnemonic` (BIP-39, no passphrase) | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |
| `account`                          | `0`                                                                            |
| `scan_sk_path`                     | `m/44'/1237'/0'/0'/0`                                                          |
| `spend_sk_path`                    | `m/44'/1237'/0'/1'/0`                                                          |
| → `scan_sk` (32 B hex)             | *(materialised by #553)*                                                       |
| → `scan_pk` (33 B compressed hex)  | *(materialised by #553)*                                                       |
| → `spend_sk` (32 B hex)            | *(materialised by #553)*                                                       |
| → `spend_pk` (33 B compressed hex) | *(materialised by #553)*                                                       |

Vectors V2–V4 use the same mnemonic with `account = 1`,
`account = 5`, and a non-zero BIP-39 passphrase respectively.
Negative scenarios cover (a) a wallet that derives spend at
the scan path (asserts the resulting `one_time_sk` does not
sign valid VTXO leaves), and (b) a wallet that uses
`m/44'/0'/0'/0'/0` (Bitcoin BIP-44 receive path) and produces
a *different* `(scan_sk, spend_sk)`, confirming the
private-use coin type is not silently substituted.

The vector generator lives at
`contrib/stealth-vector-gen/` (created by #553), reuses the
`secp256k1 = 0.29` and `bdk_wallet = 1.2` pins from the
workspace, and produces deterministic output given the same
input scalars.

## Consequences

### Positive

- **Stealth keys are isolated from L1 funds.** A leak of
  `scan_xprv` reveals the user's incoming-payment graph but
  not their L1 BIP-86 wallet. A leak of `spend_xprv` does not
  reveal `scan_xprv` (separate hardened sub-trees).
- **Network-independent meta-address.** A meta-address
  generated on regtest works as a bech32m payload on mainnet
  (modulo HRP per #553); test setups can use the same seed.
- **Multi-device hand-off is one xprv export.** The user
  hands `scan_xprv` (the extended key at
  `m/44'/1237'/{a}'/0'`) to a scanning host; the host runs
  `derive_priv("/0")` to get the per-account `scan_sk`. The
  spend xprv stays on the cold-storage device.
- **Multi-account is `--account N`.** The wallet exposes
  `ark-cli stealth address --account N` as a single CLI
  flag; #559 implements the surface.
- **Restoring a stealth wallet is the same flow as restoring
  a transparent wallet.** `dark-wallet-bin` already supports
  mnemonic-based restore for BIP-86; #560 adds the parallel
  scan loop using the new paths. Users do not need to write
  down anything new beyond the mnemonic they already have.
- **No external dependency on SLIP-44 registration.** We can
  ship the v1 spec without waiting for a registry PR. The
  registered-slot migration is a v2 follow-up that does not
  block CV-M5.
- **Domain-separated tweak.** The one-time-key tweak's
  tagged-SHA256 cannot collide with the memo's HKDF output or
  ADR-0005's opening hash even though all three derive from
  the same shared point.

### Negative / follow-ups

- **`1237'` is not in the SLIP-44 registry.** Hardware wallets
  that allowlist registered coin types will refuse to display
  the path as anything but "non-standard". Acceptable for v1
  because hardware-wallet stealth signing is not in scope; a
  follow-up issue **[FU-STEALTH-SLIP44]** tracks the
  upstream registration and the v2 derivation spec.
- **Custom "role" component (`0'` / `1'` for scan/spend)
  deviates from BIP-44's `change` slot semantics.** Tools
  that strictly enforce BIP-44 layout will display the path
  as malformed. Documented; the deviation is intentional.
- **Wallet restore replays both scan and spend derivations.**
  Compared to BIP-86 restore (one descriptor pair), stealth
  restore adds two derivations per account. Negligible
  performance cost (< 1 ms per account on commodity
  hardware).
- **No BIP-85 child-derivation in v1.** BIP-85 (deterministic
  entropy from a parent seed) lets a user generate ephemeral
  "session" mnemonics from a parent. Issue #551 lists this
  as out of scope but worth noting; we agree. A future use
  case (e.g. per-merchant disposable scan keys) could derive
  a child seed under `m/83696968'/.../0'` (BIP-85 path) and
  treat it as the parent of a fresh stealth account. This is
  additive and does not change any v1 path. Tracked as
  **[FU-STEALTH-BIP85]**.
- **No forward secrecy on `scan_sk`.** A future compromise
  of `scan_sk` retroactively de-anonymises every previously-
  received VTXO. This is inherent to the stealth-address
  scheme, not a property of the path layout. Forward
  secrecy would require interactive key rotation, out of
  scope for stealth scanning.
- **`spend_sk` lives on the same machine as
  `dark-wallet-bin` for v1.** No air-gap signing for stealth
  spends in v1. Hardware-wallet support for stealth spend
  signing requires either a custom HW firmware (knows about
  `1237'` and the tagged-hash tweak) or PSBT-style flow that
  the HW understands generically. Both are out of scope.
- **Coin-type squatting risk.** If another project claims
  `1237'` between now and CV-M5 ship, our wallets are still
  fine (we never published `1237'` as Ark's slot externally
  and no other wallet derives keys at our exact full path),
  but the documentation will eventually need to either
  upstream `1237'` or migrate to a different slot. Mitigated
  by **[FU-STEALTH-SLIP44]**.

### Cross-cutting — constraints on downstream issues

These are not suggestions; they are requirements for this ADR's
soundness. Any deviation must reopen this ADR before landing.

#### #553 (dual-key meta-address) MUST

- Implement `MetaAddress::from_seed(seed: &[u8; 64], account:
  u32)` that derives `scan_sk` from `m/44'/1237'/{account}'/0'/0`
  and `spend_sk` from `m/44'/1237'/{account}'/1'/0` and returns
  `MetaAddress { scan_pk, spend_pk }`. The seed is the
  BIP-39-post-passphrase 64-byte master seed, NOT the entropy.
- Pass `Network::Bitcoin` to `Xpriv::new_master` regardless of
  which Bitcoin network the wallet runs on. The stealth
  identity is network-independent at the derivation layer.
- Encode the meta-address as bech32m with HRP `ark` (mainnet),
  `tark` (testnet), `rark` (regtest); the HRP is the *only*
  network-aware part of the meta-address. Version byte
  `0x00` for v1.
- Provide `ScanKey` and `SpendKey` newtype wrappers around
  `[u8; 32]` with `Zeroize` derived and `Copy` / `Clone` /
  `Debug` / `Display` explicitly NOT derived. Implement a
  redacted `Debug` that prints `"ScanKey(redacted)"` only.
- Embed test vectors V1–V4 from this ADR as Rust fixtures in
  `crates/dark-confidential/tests/stealth_vectors.rs` and
  assert byte-equality of `(scan_pk, spend_pk,
  meta_address_bech32m)` for each.
- Provide a property test that asserts:
  - `MetaAddress::from_seed(seed, a)` is deterministic across
    runs for any `(seed, a)`.
  - `MetaAddress::from_seed(seed, a) != MetaAddress::from_seed(seed, b)`
    for `a != b` (account isolation).
  - `MetaAddress::from_seed(seed_a, a) != MetaAddress::from_seed(seed_b, a)`
    for `seed_a != seed_b` (seed isolation).

#### #553 MUST NOT

- Derive `scan_sk` or `spend_sk` from any path other than the
  ones specified above. In particular MUST NOT use
  `m/86'/...` (collides with BIP-86), MUST NOT use
  `m/44'/0'/...` (Bitcoin BIP-44 — the resulting key would
  be derivable by any Bitcoin wallet), MUST NOT use a
  network-aware coin type.
- Expose any API that returns `scan_sk` and `spend_sk` from
  the same call without explicit role-naming. The two keys
  must be returned through separately-typed wrappers
  (`ScanKey` vs `SpendKey`) so it is impossible to swap them
  by accident at a call site.
- Implement `From<ScanKey> for SpendKey` or vice versa.
- Hardcode `account = 0` anywhere outside the CLI default.
  Library APIs MUST take `account: u32` explicitly.

#### #554 (sender-side one-time-key derivation) MUST

- Sample `ephemeral_sk` from a CSPRNG fresh per output (matches
  ADR-0003's per-output ephemeral freshness requirement; the
  same `ephemeral_sk` is reused for memo ECDH and one-time-key
  derivation, NOT a separate keypair).
- Compute the tweak as
  `t = TaggedHash("DarkConfidentialStealthTweakV1",
  compressed_serialize(ephemeral_sk · scan_pk))` and reduce
  `mod n_secp256k1`.
- Compute `one_time_pk = spend_pk + t · G` using
  `secp256k1::PublicKey::add_exp_tweak` (or equivalent;
  `secp256k1 = 0.29` on the workspace).
- Refuse to emit a VTXO if `t == 0` after reduction; surface
  `StealthError::TweakIsZero` and bubble up to the caller so
  the sender can resample `ephemeral_sk`.
- Export the `shared_secret_bytes` (the 33-byte compressed
  point) so the caller can pipe it into the memo encryption
  per ADR-0003. The same bytes feed both the tweak's
  tagged-SHA256 and the memo's HKDF; they MUST be the
  bit-identical 33-byte serialisation, NOT the x-coordinate
  alone.
- Provide a property test asserting
  `one_time_pk == spend_pk + H(ECDH(ephemeral_sk, scan_pk)) · G`
  where `H = TaggedHash("DarkConfidentialStealthTweakV1", _)`.

#### #554 MUST NOT

- Use a non-tagged hash (`SHA256(shared_secret_bytes)`) for
  the tweak. The tag is not optional — it prevents collision
  with any other 32-byte hash the wallet computes.
- Use the x-only serialisation of the shared point. The
  tagged-hash input is the 33-byte compressed point.
- Compute the tweak from the HKDF output the memo encryption
  derives. The two derivations consume the same shared-point
  bytes but produce independent outputs; sharing the
  intermediate would couple the memo and stealth domains.
- Reuse `ephemeral_sk` across two outputs, even to the same
  recipient.

#### #555 (recipient stealth scanning) MUST

- Recompute `expected_one_time_pk = spend_pk + TaggedHash(
  "DarkConfidentialStealthTweakV1", compressed_serialize(
  scan_sk · ephemeral_pk)) · G` and compare against the
  `one_time_pk` field of each announced VTXO.
- Hold `scan_sk` and `spend_pk` in the scanning state, NOT
  `spend_sk`. The scanner never has spending authority.
- On match, surface the recovered `(amount, blinding,
  one_time_spend_tag)` from the memo (per ADR-0003) and
  store the `(shared_secret_bytes, t, one_time_pk)` triple
  for later spending. The actual spend (`one_time_sk =
  spend_sk + t mod n`) requires loading `spend_sk` from
  cold storage and is performed by `dark-client::spend`,
  not by the scanner.

#### #560 (wallet-restore for stealth) MUST

- Re-derive `(scan_sk, spend_sk)` for accounts `0..N` (where
  `N` is configurable, default `5`) on restore from
  mnemonic. Each account triggers a re-scan over the
  retained announcement window.
- Honour the same BIP-39 passphrase the user provided on
  initial wallet creation. Stealth derivation does not have
  its own passphrase layer.
- Coexist with the BIP-86 restore for transparent wallets:
  the same mnemonic produces the BIP-86 wallet AND the
  stealth keys; restore runs both derivations from one
  seed.

#### #559 (`ark-cli` stealth commands) MUST

- Expose `--account N` flag on every stealth-related
  subcommand (`address`, `scan`, `spend`, `balance`).
- Default `--account 0` when omitted.
- Print the canonical derivation path
  (`m/44'/1237'/{account}'/{role}'/0`) in `ark-cli stealth
  info` for transparency / third-party recovery.

## Open Questions / TODO

- **SLIP-44 registration of an "Ark" coin type.** Tracked as
  **[FU-STEALTH-SLIP44]**. Out of scope for CV-M5; if
  registered, a v2 derivation spec will introduce the
  registered slot in addition to `1237'` and ship a parallel
  derivation. v1 wallets continue to work indefinitely.
- **BIP-85 child-derivation for session keys.** Tracked as
  **[FU-STEALTH-BIP85]**. The use case is per-merchant or
  per-counterparty disposable meta-addresses derived from a
  parent seed without revealing the parent. v1 does not
  ship this; the path layout above is forward-compatible
  with a BIP-85-derived child seed becoming the parent of a
  fresh `m/44'/1237'/...` tree.
- **Hardware-wallet support for stealth spending.** Tracked
  as **[FU-STEALTH-HW]**. Requires either custom HW firmware
  (knows about `1237'` and the tagged-hash tweak) or a
  PSBT-style flow that the HW signs generically. The path
  choice in this ADR does not preclude either; it defers
  the decision.
- **Per-meta-address rotation under one account.** The
  terminal `0` slot at depth 5 is a fixed deterministic
  index in v1. If a future spec needs to rotate
  meta-addresses without bumping the account, it can
  introduce `m/44'/1237'/{a}'/{role}'/{i}` with `i` running
  through unhardened indices. Tracked as
  **[FU-STEALTH-ROTATE]**.
- **Cross-implementation test-vector exchange.** Tracked as
  **[FU-STEALTH-VECTOR-XCHECK]**. Once a second
  stealth-address implementation exists in another language
  (e.g. a TypeScript wallet SDK), the `m5-stealth-derivation-
  vectors.json` file MUST be re-run against it and any
  byte-mismatch reopens this ADR.
- **Scanning-host trust model.** A scanner host with
  `scan_xprv` learns every incoming payment but cannot
  spend. A formal threat-model document for "untrusted
  scanner" deployments is out of scope for this ADR;
  tracked separately under the privacy-deployment
  workstream.

## References

- Issue #551 (this ADR)
- Issue #553 — dual-key meta-address (consumes the paths
  defined here)
- Issue #554 — sender-side one-time-key derivation (consumes
  the tweak construction defined here)
- Issue #555 — recipient stealth scanning (consumes the same
  tweak construction)
- Issue #558 — background stealth scanning loop in `dark-client`
- Issue #559 — `ark-cli` stealth commands
- Issue #560 — wallet-restore with stealth VTXO re-scan
- ADR-0001 — secp256k1-zkp integration strategy (curve choice)
- ADR-0002 — nullifier derivation scheme and domain separation
- ADR-0003 — confidential VTXO memo format (per-output
  ephemeral freshness; reuses `ephemeral_sk` for ECDH and
  AAD binding)
- ADR-0005 — confidential VTXO unilateral-exit script
  construction (uses an independent domain-separation tag
  `DarkConfidentialOpeningV1`; this ADR's
  `DarkConfidentialStealthTweakV1` does not collide)
- BIP-32 — Hierarchical Deterministic Wallets (CKD,
  hardened-vs-unhardened semantics)
- BIP-39 — Mnemonic codes (seed source)
- BIP-44 — Multi-account hierarchy (path layout shape, with
  documented deviations above)
- BIP-85 — Deterministic entropy from BIP-32 (out of scope
  for v1; noted as forward-compatible)
- BIP-86 — Single-key Taproot output descriptors (used by
  `dark-wallet-bin` for L1; not reused here)
- BIP-340 — Schnorr signatures (tagged-hash construction
  reused for the tweak)
- SLIP-44 — Coin types registry
  (<https://github.com/satoshilabs/slips/blob/master/slip-0044.md>;
  `1237'` unassigned at 2026-04-24)
- `crates/dark-wallet/src/manager.rs` —
  `derive_asp_keypair` (existing `m/86'/{coin}'/1'/0/0`
  reference)
- `crates/dark-confidential/src/stealth.rs` — stub module
  that #553 implements against this ADR
- Test vectors:
  `docs/adr/vectors/m5-stealth-derivation-vectors.json`
  (created by #553)
- Vector generator: `contrib/stealth-vector-gen/`
  (created by #553)
