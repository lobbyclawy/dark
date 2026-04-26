//! On-chain unilateral exit tapscript for **confidential** VTXOs (issue #547).
//!
//! ## Why a separate exit path?
//!
//! Transparent VTXOs publish the amount in the clear; their exit script
//! (see [`crate::tapscript::vtxo_expiry_script`]) is just
//! `<csv> OP_CSV OP_DROP <user> OP_CHECKSIG` — the amount is implicit because
//! the spend descends the tree of pre-signed transactions whose outputs already
//! carry plaintext values.
//!
//! Confidential VTXOs (issue #530) replace the plaintext amount with a
//! Pedersen commitment `C = amount·G + blinding·H` (see
//! `dark_confidential::commitment::PedersenCommitment`). When the owner
//! unilaterally exits to L1, **the on-chain script must check that the spender
//! knows an opening of that commitment**. Otherwise nothing on-chain ties the
//! claim transaction to the off-chain confidential balance, and a malicious
//! exiter could siphon funds that don't match their commitment.
//!
//! ## Design choice (interim — option 1 of the task instructions for #547)
//!
//! Issue #546 (the in-flight ADR for confidential exit script construction)
//! deliberates between three constructions; at the time this module landed
//! that ADR was not yet on `main`, so per the #547 task instructions we
//! implement **option 1: reveal `(amount, blinding)` in the tapscript witness
//! so the on-chain verifier re-computes `commit(amount, blinding) ==
//! published_commitment`.**
//!
//! Bitcoin Script cannot do Pedersen / secp256k1 scalar arithmetic, so the
//! "commitment" the script verifies is a domain-separated SHA-256 of the
//! opening bytes — a *script-level* binding that is published alongside the
//! Pedersen commitment when the confidential VTXO is created. The Pedersen
//! binding itself is checked off-chain by `dark-confidential` during VTXO
//! validation; the script-level digest is what the unilateral exit path
//! re-checks on-chain.
//!
//! The hash digest is computed as
//!
//! ```text
//! script_commitment = SHA256( amount_le_8B || blinding_32B )
//! ```
//!
//! and is sometimes called the **commitment opening digest** in the rest of
//! this module. The 8-byte little-endian encoding of `amount` matches Bitcoin
//! Core's natural u64 LE wire format and the encoding used by
//! [`amount_to_opening_bytes`].
//!
//! ## Script layout
//!
//! ```text
//! <csv_blocks> OP_CSV OP_DROP                      ; relative timelock gate
//! OP_SHA256                                        ; hash the witness opening
//! <commitment_digest_32B> OP_EQUALVERIFY           ; opening must match
//! <owner_xonly_pubkey_32B> OP_CHECKSIG             ; final signature gate
//! ```
//!
//! ## Witness layout
//!
//! Pushed in order (first pushed = bottom of stack):
//!
//! 1. `owner_signature` — Schnorr signature for the spend (64 or 65 bytes).
//! 2. `opening` — `amount_le_8B || blinding_32B` (40 bytes total).
//!
//! After all witness items are pushed the stack top is `opening`, which is
//! exactly what `OP_SHA256` consumes first.
//!
//! Bitcoin Script does **not** ship `OP_CAT`, so we cannot reconstruct the
//! `amount || blinding` blob from two separate stack items. The witness
//! builder therefore concatenates them into a single 40-byte stack element,
//! while the public API still takes `amount` and `blinding` as distinct
//! parameters.
//!
//! ## Compatibility with the transparent exit path
//!
//! The transparent expiry leaf is `<csv> OP_CSV OP_DROP <user> OP_CHECKSIG`.
//! The confidential leaf adds the `OP_SHA256 <digest> OP_EQUALVERIFY` block
//! between the timelock and the signature check. The CSV encoding (block- vs
//! seconds-based BIP68 sequence) is shared via [`crate::tapscript::bip68_sequence`]
//! so the two paths produce byte-identical CSV pushes for the same `delay`.
//! See [`build_confidential_exit_script`] / [`build_confidential_exit_witness`]
//! for the public surface used by clients.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

use crate::error::{BitcoinError, BitcoinResult};
use crate::tapscript::bip68_sequence;

/// Length in bytes of a Pedersen commitment (compressed secp256k1 point).
///
/// Mirrors `dark_core::domain::PEDERSEN_COMMITMENT_LEN` without taking a
/// dependency on `dark-core` — `dark-bitcoin` is intentionally a leaf crate.
pub const PEDERSEN_COMMITMENT_LEN: usize = 33;

/// Length in bytes of the blinding factor used in the commitment opening.
pub const BLINDING_LEN: usize = 32;

/// Length of the script-level commitment digest (`SHA256` output).
pub const COMMITMENT_DIGEST_LEN: usize = 32;

/// Length of a serialised opening blob: `amount_le_8B || blinding_32B`.
pub const OPENING_LEN: usize = 8 + BLINDING_LEN;

/// Domain-separated tag prefixed to the opening before SHA-256, so this
/// digest cannot be confused with other 40-byte SHA-256 inputs the protocol
/// might produce in the future.
///
/// Bitcoin Script's `OP_SHA256` does **not** prepend this tag — it operates
/// on the raw witness blob. We therefore commit to the un-tagged digest in
/// the script. The tagging policy is purely an off-chain convention and is
/// documented here for forward-compatibility with #546's eventual ADR;
/// today's verifier ([`build_confidential_exit_script`]) consumes the
/// raw `SHA256(opening)` output. If #546 lands a tagged variant the bump
/// must update both this module and the corresponding off-chain check.
pub const COMMITMENT_OPENING_DST: &[u8] = b"dark-bitcoin/confidential-exit/opening/v1";

/// Encode an opening (amount + blinding) into the canonical 40-byte blob the
/// tapscript hashes.
///
/// Layout: `amount.to_le_bytes() || blinding`. Little-endian for `amount`
/// matches Bitcoin Core's natural u64 wire format and is what `OP_SHA256`
/// will see at script-execution time.
pub fn amount_to_opening_bytes(amount: u64, blinding: &[u8; BLINDING_LEN]) -> [u8; OPENING_LEN] {
    let mut out = [0u8; OPENING_LEN];
    out[..8].copy_from_slice(&amount.to_le_bytes());
    out[8..].copy_from_slice(blinding);
    out
}

/// Compute the script-level commitment digest published in the tapscript.
///
/// This is the SHA-256 of the canonical opening blob; it is what
/// [`build_confidential_exit_script`] embeds via `OP_EQUALVERIFY`. The
/// off-chain Pedersen commitment binding (over the same `(amount, blinding)`)
/// is checked separately by `dark-confidential`.
pub fn commitment_opening_digest(
    amount: u64,
    blinding: &[u8; BLINDING_LEN],
) -> [u8; COMMITMENT_DIGEST_LEN] {
    let opening = amount_to_opening_bytes(amount, blinding);
    sha256::Hash::hash(&opening).to_byte_array()
}

/// Build the tapscript leaf that authorises a unilateral exit of a
/// **confidential** VTXO.
///
/// # Arguments
///
/// * `commitment_digest` - 32-byte `SHA256` digest of the canonical opening
///   `(amount, blinding)`. Compute via [`commitment_opening_digest`] from the
///   plaintext opening, or treat as opaque when received from elsewhere.
///   This MUST match the digest that the confidential VTXO publication
///   (`dark_core::domain::ConfidentialPayload`) advertises as part of its
///   tapscript-level binding.
/// * `owner_pubkey` - x-only public key of the VTXO owner. The exit signature
///   is checked against this key.
/// * `csv_blocks` - relative timelock value, interpreted exactly like the
///   transparent expiry path (`< 512` → blocks; `≥ 512` → seconds, must be a
///   multiple of 512). See [`crate::tapscript::bip68_sequence`].
///
/// # Errors
///
/// Returns [`BitcoinError::ScriptError`] if `csv_blocks == 0`, BIP68 encoding
/// fails, or the digest can't be embedded as a script push.
///
/// # Example layout (annotated bytes)
///
/// ```text
/// <bip68(csv_blocks)>  OP_CSV  OP_DROP
/// OP_SHA256
/// <commitment_digest>  OP_EQUALVERIFY
/// <owner_pubkey>       OP_CHECKSIG
/// ```
pub fn build_confidential_exit_script(
    commitment_digest: &[u8; COMMITMENT_DIGEST_LEN],
    owner_pubkey: &XOnlyPublicKey,
    csv_blocks: u32,
) -> BitcoinResult<ScriptBuf> {
    if csv_blocks == 0 {
        return Err(BitcoinError::ScriptError(
            "csv_blocks must be > 0".to_string(),
        ));
    }
    let sequence = bip68_sequence(csv_blocks)?;

    let digest_push = PushBytesBuf::try_from(commitment_digest.to_vec()).map_err(|e| {
        BitcoinError::ScriptError(format!("failed to encode commitment digest: {e}"))
    })?;

    Ok(Builder::new()
        // 1) Relative timelock — same encoding as the transparent expiry leaf
        //    so byte-compatible CSV pushes are produced for equal `csv_blocks`.
        .push_int(sequence as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        // 2) Re-compute the script-level commitment from the witness opening
        //    and verify it matches the published digest.
        .push_opcode(OP_SHA256)
        .push_slice(digest_push.as_push_bytes())
        .push_opcode(OP_EQUALVERIFY)
        // 3) Owner signature gate, byte-identical to the transparent path.
        .push_x_only_key(owner_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

/// Build the witness stack for a confidential unilateral-exit spend.
///
/// The returned vector is in **push order**: index `0` is pushed first
/// (becomes the bottom of the stack), index `1` is pushed last (becomes the
/// top, where `OP_SHA256` will consume it).
///
/// Layout:
///
/// 1. `owner_signature` — Schnorr signature bytes (64 or 65 bytes; the
///    optional sighash-flag byte is allowed for non-default sighashes).
/// 2. `opening` — `amount.to_le_bytes() || blinding` (40 bytes), produced via
///    [`amount_to_opening_bytes`].
///
/// Note that the **control block** and the **leaf script** are *not* part of
/// this return value — taproot spends append them after the script-defined
/// witness items, and that is the responsibility of the higher-level PSBT
/// signer (issue #548 will own that flow). This helper produces only the
/// script-defined slice of the witness, mirroring the shape of
/// [`crate::tapscript::vtxo_expiry_script`] callers in the transparent path.
///
/// # Errors
///
/// Returns [`BitcoinError::ScriptError`] if the signature length is implausible
/// (must be 64 or 65 bytes for Schnorr).
pub fn build_confidential_exit_witness(
    amount: u64,
    blinding: &[u8; BLINDING_LEN],
    owner_signature: &[u8],
) -> BitcoinResult<Vec<Vec<u8>>> {
    if owner_signature.len() != 64 && owner_signature.len() != 65 {
        return Err(BitcoinError::ScriptError(format!(
            "owner Schnorr signature must be 64 or 65 bytes, got {}",
            owner_signature.len()
        )));
    }

    let opening = amount_to_opening_bytes(amount, blinding);

    // First push (stack-bottom) → signature; second push (stack-top) → opening.
    Ok(vec![owner_signature.to_vec(), opening.to_vec()])
}

/// Convenience: build the witness directly from a precomputed opening blob.
///
/// Useful in tests and for callers that already have the canonical 40-byte
/// `amount || blinding` representation in hand and don't want to round-trip
/// through `(u64, [u8;32])`.
pub fn build_confidential_exit_witness_from_opening(
    opening: &[u8; OPENING_LEN],
    owner_signature: &[u8],
) -> BitcoinResult<Vec<Vec<u8>>> {
    if owner_signature.len() != 64 && owner_signature.len() != 65 {
        return Err(BitcoinError::ScriptError(format!(
            "owner Schnorr signature must be 64 or 65 bytes, got {}",
            owner_signature.len()
        )));
    }
    Ok(vec![owner_signature.to_vec(), opening.to_vec()])
}

/// Derive the script-level commitment digest that should be embedded in the
/// tapscript for a confidential VTXO whose Pedersen commitment is
/// `pedersen_commitment` and whose opening is `(amount, blinding)`.
///
/// The Pedersen commitment is **not** consumed by Bitcoin Script — Bitcoin
/// can't re-derive it. We accept it here purely to enforce that callers
/// always have the matching off-chain commitment in hand: the Pedersen
/// binding is what gives the digest its meaning. The function returns the
/// raw SHA-256 over the canonical opening; equality of this digest with the
/// `commitment_digest` argument of [`build_confidential_exit_script`] is what
/// the on-chain `OP_EQUALVERIFY` checks.
pub fn digest_for_published_commitment(
    pedersen_commitment: &[u8; PEDERSEN_COMMITMENT_LEN],
    amount: u64,
    blinding: &[u8; BLINDING_LEN],
) -> [u8; COMMITMENT_DIGEST_LEN] {
    // We accept `pedersen_commitment` to encode the API contract — and to
    // give the type-checker something to grip when callers wire this up to
    // `ConfidentialPayload::amount_commitment` — but we deliberately do not
    // hash it into the digest. Mixing the Pedersen point in would force the
    // exiter's witness to carry it as well; the script-level digest is
    // intentionally a function of the opening alone so the on-chain verifier
    // stays minimal. The Pedersen point is bound off-chain.
    let _ = pedersen_commitment;
    commitment_opening_digest(amount, blinding)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256};
    use bitcoin::script::Instruction;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn xonly_key(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        let sk = SecretKey::from_slice(&bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        XOnlyPublicKey::from(pk)
    }

    fn sample_blinding(seed: u8) -> [u8; BLINDING_LEN] {
        let mut b = [0u8; BLINDING_LEN];
        b[0] = 0xab;
        b[BLINDING_LEN - 1] = seed;
        b
    }

    fn sample_pedersen_commitment(seed: u8) -> [u8; PEDERSEN_COMMITMENT_LEN] {
        let mut c = [0u8; PEDERSEN_COMMITMENT_LEN];
        c[0] = 0x02;
        c[1] = seed;
        c
    }

    fn dummy_signature() -> [u8; 64] {
        // Plausible Schnorr-shaped placeholder; CHECKSIG itself isn't exercised
        // by the synthetic stack tests below, only the OPCODES preceding it.
        [0xee; 64]
    }

    // ── opening / digest helpers ───────────────────────────────────

    #[test]
    fn opening_bytes_layout_is_amount_le_then_blinding() {
        let blinding = sample_blinding(0x77);
        let opening = amount_to_opening_bytes(0x1122_3344_5566_7788_u64, &blinding);
        // First 8 bytes: little-endian of 0x1122_3344_5566_7788
        assert_eq!(
            &opening[..8],
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        // Trailing 32 bytes: blinding
        assert_eq!(&opening[8..], &blinding);
    }

    #[test]
    fn digest_changes_when_amount_changes() {
        let blinding = sample_blinding(1);
        let d1 = commitment_opening_digest(1_000, &blinding);
        let d2 = commitment_opening_digest(1_001, &blinding);
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_changes_when_blinding_changes() {
        let b1 = sample_blinding(1);
        let mut b2 = b1;
        b2[0] ^= 0x01;
        let d1 = commitment_opening_digest(42, &b1);
        let d2 = commitment_opening_digest(42, &b2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_is_deterministic() {
        let blinding = sample_blinding(9);
        let a = commitment_opening_digest(7, &blinding);
        let b = commitment_opening_digest(7, &blinding);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_for_published_commitment_ignores_pedersen_byte_pattern() {
        // The Pedersen commitment argument is purely for API hygiene; toggling
        // it must not change the script-level digest.
        let blinding = sample_blinding(2);
        let c1 = sample_pedersen_commitment(0xaa);
        let c2 = sample_pedersen_commitment(0xbb);
        let d1 = digest_for_published_commitment(&c1, 555, &blinding);
        let d2 = digest_for_published_commitment(&c2, 555, &blinding);
        assert_eq!(d1, d2);
    }

    // ── build_confidential_exit_script ─────────────────────────────

    #[test]
    fn script_rejects_zero_csv() {
        let owner = xonly_key(1);
        let digest = [0u8; 32];
        let err = build_confidential_exit_script(&digest, &owner, 0).unwrap_err();
        match err {
            BitcoinError::ScriptError(_) => {}
            other => panic!("expected ScriptError, got {other:?}"),
        }
    }

    #[test]
    fn script_contains_expected_opcodes() {
        let owner = xonly_key(3);
        let digest = commitment_opening_digest(123_456_789, &sample_blinding(4));
        let script = build_confidential_exit_script(&digest, &owner, 144).unwrap();
        let asm = script.to_asm_string();

        for needle in [
            "OP_CSV",
            "OP_DROP",
            "OP_SHA256",
            "OP_EQUALVERIFY",
            "OP_CHECKSIG",
        ] {
            assert!(asm.contains(needle), "ASM must contain {needle}: {asm}");
        }
    }

    #[test]
    fn script_embeds_digest_and_pubkey_pushes() {
        let owner = xonly_key(5);
        let blinding = sample_blinding(6);
        let amount = 9_999u64;
        let digest = commitment_opening_digest(amount, &blinding);
        let script = build_confidential_exit_script(&digest, &owner, 144).unwrap();

        let pushed: Vec<Vec<u8>> = script
            .instructions()
            .filter_map(|ins| match ins {
                Ok(Instruction::PushBytes(b)) => Some(b.as_bytes().to_vec()),
                _ => None,
            })
            .collect();

        // Pushed slices include the CSV value, the digest, and the pubkey.
        assert!(
            pushed.iter().any(|b| b.as_slice() == digest.as_slice()),
            "digest must be pushed in script"
        );
        assert!(
            pushed
                .iter()
                .any(|b| b.as_slice() == owner.serialize().as_slice()),
            "owner xonly pubkey must be pushed in script"
        );
    }

    #[test]
    fn script_op_order_csv_then_sha256_then_checksig() {
        let owner = xonly_key(7);
        let digest = [0u8; 32];
        let script = build_confidential_exit_script(&digest, &owner, 144).unwrap();

        // Find the position of each opcode in the byte stream by walking
        // instructions and recording the offset at each one.
        let mut seen = Vec::new();
        for ins in script.instructions() {
            match ins.unwrap() {
                Instruction::Op(op) => seen.push(op),
                Instruction::PushBytes(_) => {}
            }
        }
        let pos = |op| seen.iter().position(|&o| o == op);
        let p_csv = pos(OP_CSV).expect("OP_CSV present");
        let p_drop = pos(OP_DROP).expect("OP_DROP present");
        let p_sha = pos(OP_SHA256).expect("OP_SHA256 present");
        let p_eqv = pos(OP_EQUALVERIFY).expect("OP_EQUALVERIFY present");
        let p_cs = pos(OP_CHECKSIG).expect("OP_CHECKSIG present");
        assert!(
            p_csv < p_drop && p_drop < p_sha && p_sha < p_eqv && p_eqv < p_cs,
            "expected CSV → DROP → SHA256 → EQUALVERIFY → CHECKSIG order"
        );
    }

    #[test]
    fn script_csv_push_matches_transparent_path_for_same_delay() {
        // Byte-compat goal: for the same `delay`, the CSV-encoded bytes pushed
        // by the confidential script must match the transparent expiry leaf.
        use crate::tapscript::vtxo_expiry_script;
        let owner = xonly_key(9);
        let digest = [0xaa; 32];
        let delay = 144u32;

        let conf_script = build_confidential_exit_script(&digest, &owner, delay).unwrap();
        let trans_script = vtxo_expiry_script(&owner, delay).unwrap();

        let first_push = |s: &ScriptBuf| -> Vec<u8> {
            s.instructions()
                .find_map(|ins| match ins.ok()? {
                    Instruction::PushBytes(b) => Some(b.as_bytes().to_vec()),
                    _ => None,
                })
                .unwrap_or_default()
        };

        assert_eq!(
            first_push(&conf_script),
            first_push(&trans_script),
            "first push (CSV value) must be identical between paths"
        );
    }

    #[test]
    fn different_digests_produce_different_scripts() {
        let owner = xonly_key(11);
        let s1 = build_confidential_exit_script(&[0u8; 32], &owner, 144).unwrap();
        let s2 = build_confidential_exit_script(&[1u8; 32], &owner, 144).unwrap();
        assert_ne!(s1, s2);
    }

    // ── build_confidential_exit_witness ────────────────────────────

    #[test]
    fn witness_has_two_elements() {
        let blinding = sample_blinding(0xcd);
        let sig = dummy_signature();
        let w = build_confidential_exit_witness(42, &blinding, &sig).unwrap();
        assert_eq!(w.len(), 2);
        // Element 0 (bottom of stack) is the signature.
        assert_eq!(w[0].len(), 64);
        // Element 1 (top of stack) is the opening blob.
        assert_eq!(w[1].len(), OPENING_LEN);
    }

    #[test]
    fn witness_top_element_is_opening_bytes() {
        let blinding = sample_blinding(7);
        let amount = 5_000u64;
        let sig = dummy_signature();
        let w = build_confidential_exit_witness(amount, &blinding, &sig).unwrap();
        let expected = amount_to_opening_bytes(amount, &blinding);
        assert_eq!(w[1].as_slice(), expected.as_slice());
    }

    #[test]
    fn witness_rejects_invalid_sig_length() {
        let blinding = sample_blinding(1);
        // 32 bytes is too short
        let bad = [0u8; 32];
        let err = build_confidential_exit_witness(1, &blinding, &bad).unwrap_err();
        assert!(matches!(err, BitcoinError::ScriptError(_)));
    }

    #[test]
    fn witness_accepts_65_byte_sig_with_sighash() {
        let blinding = sample_blinding(1);
        let sig = [0u8; 65];
        let w = build_confidential_exit_witness(1, &blinding, &sig).unwrap();
        assert_eq!(w[0].len(), 65);
    }

    // ── round trip: synthetic VTXO through script + witness ────────

    /// Execute the **commitment-binding portion** of the confidential exit
    /// tapscript against a witness, returning whether the script would accept
    /// up to (but not including) `OP_CHECKSIG` — i.e. the part that does not
    /// require a real signing transaction. This mirrors what
    /// `bitcoin::script::verify` would check for the same opcodes, while
    /// remaining self-contained (no `bitcoinconsensus` dependency, which is
    /// not enabled in the workspace's `bitcoin` feature set).
    ///
    /// Specifically we re-execute the script segment:
    ///
    /// ```text
    /// OP_SHA256 <digest> OP_EQUALVERIFY
    /// ```
    ///
    /// using only the part of the witness that pre-signature execution sees:
    /// the `opening` element (witness item 1, top of stack at script start
    /// after CSV/DROP). CSV is a no-op in this stack-only check (it consumes
    /// nothing and produces nothing — it only fails consensus-side if the tx
    /// sequence is too small), and the trailing `<pubkey> OP_CHECKSIG` is the
    /// signature gate that lives outside this commitment-binding logic.
    ///
    /// This intentionally hand-rolls the OP_SHA256/OP_EQUALVERIFY semantics
    /// because the workspace does not pull in `bitcoinconsensus`. The check
    /// is deliberately scoped to the bytes the on-chain verifier would
    /// re-derive — it is **not** a general script interpreter.
    fn commitment_binding_accepts(
        script: &ScriptBuf,
        witness: &[Vec<u8>],
    ) -> Result<bool, &'static str> {
        // Witness layout: [signature, opening] (push order). Top of stack
        // before script execution is `opening`.
        if witness.len() != 2 {
            return Err("witness must have exactly 2 items");
        }
        let opening = &witness[1];

        // Walk the script and locate the digest pushed between OP_SHA256 and
        // OP_EQUALVERIFY. We trust the script structure produced by
        // `build_confidential_exit_script`.
        let mut found_sha = false;
        let mut digest: Option<Vec<u8>> = None;
        let mut found_eqv_after = false;
        for ins in script.instructions() {
            let ins = ins.map_err(|_| "script instruction parse failed")?;
            match ins {
                Instruction::Op(op) if op == OP_SHA256 => found_sha = true,
                Instruction::PushBytes(b) if found_sha && digest.is_none() => {
                    digest = Some(b.as_bytes().to_vec());
                }
                Instruction::Op(op) if op == OP_EQUALVERIFY && digest.is_some() => {
                    found_eqv_after = true;
                    break;
                }
                _ => {}
            }
        }
        if !found_sha || !found_eqv_after {
            return Err("script structure does not match expected layout");
        }
        let digest = digest.ok_or("no digest push found")?;

        // OP_SHA256 over `opening`, then OP_EQUALVERIFY against `digest`.
        let computed = sha256::Hash::hash(opening).to_byte_array();
        Ok(computed.as_slice() == digest.as_slice())
    }

    #[test]
    fn round_trip_synthetic_vtxo_accepts_correct_opening() {
        // Synthetic confidential VTXO: pick (amount, blinding); derive the
        // published Pedersen commitment placeholder and the script-level
        // digest. Build the script around the digest, build the witness from
        // the opening, then re-check the binding.
        let owner = xonly_key(1);
        let amount = 1_234_567u64;
        let blinding = sample_blinding(0x42);
        let pedersen = sample_pedersen_commitment(0x99);

        let digest = digest_for_published_commitment(&pedersen, amount, &blinding);
        let script = build_confidential_exit_script(&digest, &owner, 144).unwrap();
        let sig = dummy_signature();
        let witness = build_confidential_exit_witness(amount, &blinding, &sig).unwrap();

        assert!(
            commitment_binding_accepts(&script, &witness).unwrap(),
            "script must accept matching opening"
        );
    }

    #[test]
    fn round_trip_rejects_wrong_amount() {
        let owner = xonly_key(2);
        let amount = 1_000u64;
        let blinding = sample_blinding(0x42);
        let pedersen = sample_pedersen_commitment(0x99);

        let digest = digest_for_published_commitment(&pedersen, amount, &blinding);
        let script = build_confidential_exit_script(&digest, &owner, 144).unwrap();
        let sig = dummy_signature();
        // Witness opens to a *different* amount.
        let witness = build_confidential_exit_witness(amount + 1, &blinding, &sig).unwrap();

        assert!(
            !commitment_binding_accepts(&script, &witness).unwrap(),
            "script must reject mismatched amount"
        );
    }

    #[test]
    fn round_trip_rejects_wrong_blinding() {
        let owner = xonly_key(3);
        let amount = 555u64;
        let blinding = sample_blinding(0x10);
        let mut wrong_blinding = blinding;
        wrong_blinding[0] ^= 0xff;
        let pedersen = sample_pedersen_commitment(0x77);

        let digest = digest_for_published_commitment(&pedersen, amount, &blinding);
        let script = build_confidential_exit_script(&digest, &owner, 144).unwrap();
        let sig = dummy_signature();
        let witness = build_confidential_exit_witness(amount, &wrong_blinding, &sig).unwrap();

        assert!(
            !commitment_binding_accepts(&script, &witness).unwrap(),
            "script must reject mismatched blinding"
        );
    }

    #[test]
    fn round_trip_rejects_swapped_amount_blinding() {
        // Sanity check: ensure little-endian amount encoding is what's hashed,
        // not some other byte-order variant. If the ordering is wrong, the
        // digest computed during `build_confidential_exit_script` (via
        // `commitment_opening_digest`) won't match the digest the script
        // would re-derive from the witness opening.
        let owner = xonly_key(4);
        let amount = 0x0102_0304u64;
        let blinding = sample_blinding(0x55);
        let pedersen = sample_pedersen_commitment(0x33);

        let correct_digest = digest_for_published_commitment(&pedersen, amount, &blinding);
        // Construct a deliberately wrong digest by swapping endianness.
        let mut wrong_opening = [0u8; OPENING_LEN];
        wrong_opening[..8].copy_from_slice(&amount.to_be_bytes());
        wrong_opening[8..].copy_from_slice(&blinding);
        let wrong_digest = sha256::Hash::hash(&wrong_opening).to_byte_array();

        assert_ne!(correct_digest, wrong_digest);
        let script = build_confidential_exit_script(&wrong_digest, &owner, 144).unwrap();
        let sig = dummy_signature();
        let witness = build_confidential_exit_witness(amount, &blinding, &sig).unwrap();
        assert!(
            !commitment_binding_accepts(&script, &witness).unwrap(),
            "script with wrongly-encoded digest must reject the canonical witness"
        );
    }

    #[test]
    fn witness_from_opening_matches_three_arg_witness() {
        let blinding = sample_blinding(0x21);
        let amount = 999u64;
        let sig = dummy_signature();
        let opening = amount_to_opening_bytes(amount, &blinding);

        let w_a = build_confidential_exit_witness(amount, &blinding, &sig).unwrap();
        let w_b = build_confidential_exit_witness_from_opening(&opening, &sig).unwrap();
        assert_eq!(w_a, w_b);
    }

    #[test]
    fn dst_constant_is_documented() {
        // We don't currently feed COMMITMENT_OPENING_DST into the digest (see
        // module docs); guard against accidental empty/short tag in case a
        // future ADR bump starts using it for tagged hashing.
        assert!(COMMITMENT_OPENING_DST.starts_with(b"dark-bitcoin/"));
        assert!(COMMITMENT_OPENING_DST.ends_with(b"/v1"));
    }
}
