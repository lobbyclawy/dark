//! Tapscript VTXO tree construction for the Ark protocol.
//!
//! Builds a Taproot output with two leaf scripts:
//! - **Expiry leaf**: `<BIP68_sequence> OP_CSV OP_DROP <user_pubkey> OP_CHECKSIG`
//!   — allows the user to unilaterally exit after a relative timelock.
//! - **Collaborative leaf**: `<owner> OP_CHECKSIGVERIFY <signer> OP_CHECKSIG`
//!   — allows ASP + user to cooperatively spend via script-path.
//!
//! The internal key is the BIP-341 unspendable key (matching the Go SDK).

use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};
use bitcoin::XOnlyPublicKey;

use crate::error::{BitcoinError, BitcoinResult};

// ── BIP68 encoding ─────────────────────────────────────────────
//
// The Go SDK interprets the `boarding_exit_delay` from GetInfo as follows:
//   - If value >= 512: treat as seconds → BIP68 time-based sequence
//   - If value < 512:  treat as blocks  → BIP68 block-based sequence
//
// We replicate this logic so the CSV push in our tapscript matches exactly.

const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;
const SECONDS_MOD: u32 = 1 << SEQUENCE_LOCKTIME_GRANULARITY; // 512

/// Encode a delay value into a BIP68 sequence number, matching the Go SDK's
/// `BIP68Sequence(RelativeLocktime{…})` function.
///
/// - `delay >= 512` → seconds-based (sets bit 22, divides by 512)
/// - `delay < 512`  → block-based (raw value)
pub fn bip68_sequence(delay: u32) -> BitcoinResult<u32> {
    if delay >= SECONDS_MOD {
        // Seconds-based: value must be a multiple of 512
        if !delay.is_multiple_of(SECONDS_MOD) {
            return Err(BitcoinError::ScriptError(format!(
                "BIP68 seconds delay must be a multiple of {SECONDS_MOD}, got {delay}"
            )));
        }
        // blockchain.LockTimeToSequence(true, delay) in Go:
        //   (delay >> granularity) | type_flag
        let encoded = (delay >> SEQUENCE_LOCKTIME_GRANULARITY) | SEQUENCE_LOCKTIME_TYPE_FLAG;
        Ok(encoded)
    } else {
        // Block-based: raw value
        Ok(delay)
    }
}

/// Build the expiry (unilateral exit) tapscript leaf.
///
/// Script: `<BIP68_sequence> OP_CSV OP_DROP <user_pubkey> OP_CHECKSIG`
///
/// The `delay` value follows the Go SDK convention:
/// - `>= 512` → interpreted as **seconds** and BIP68-encoded with the time flag
/// - `< 512`  → interpreted as **blocks** (raw value)
///
/// # Arguments
/// * `user_pubkey` - The VTXO owner's x-only public key.
/// * `delay` - Relative timelock value (seconds if >= 512, blocks otherwise).
///
/// # Errors
/// Returns an error if `delay` is 0 or BIP68 encoding fails.
pub fn vtxo_expiry_script(
    user_pubkey: &XOnlyPublicKey,
    delay: u32,
) -> BitcoinResult<bitcoin::ScriptBuf> {
    if delay == 0 {
        return Err(BitcoinError::ScriptError("delay must be > 0".to_string()));
    }

    let sequence = bip68_sequence(delay)?;

    Ok(Builder::new()
        .push_int(sequence as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(user_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

/// Build the collaborative spend tapscript leaf.
///
/// Script: `<combined_pubkey> OP_CHECKSIG`
///
/// This leaf allows user + ASP to cooperatively spend by producing a
/// MuSig2 signature for the aggregated key. This is the "happy path"
/// script-path fallback; the true happy path is a key-path spend using
/// the internal key directly.
///
/// # Arguments
/// * `combined_pubkey` - MuSig2-aggregated x-only public key of user + ASP.
pub fn vtxo_collaborative_script(combined_pubkey: &XOnlyPublicKey) -> bitcoin::ScriptBuf {
    Builder::new()
        .push_x_only_key(combined_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Two-key collaborative script matching Go's `MultisigClosure{PubKeys: [owner, signer]}`:
/// `<owner_xonly> OP_CHECKSIGVERIFY <signer_xonly> OP_CHECKSIG`
pub fn vtxo_collaborative_script_two_key(
    owner: &XOnlyPublicKey,
    signer: &XOnlyPublicKey,
) -> bitcoin::ScriptBuf {
    use bitcoin::opcodes::all::OP_CHECKSIGVERIFY;
    Builder::new()
        .push_x_only_key(owner)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(signer)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build a complete Taproot VTXO output with expiry + collaborative leaves.
///
/// The resulting [`TaprootSpendInfo`] contains:
/// - **Internal key**: MuSig2 aggregate of `user_pubkey` + `asp_pubkey`
///   (key-path cooperative spend — cheapest spend path).
/// - **Leaf 0 (depth 1)**: Collaborative script (`<agg> OP_CHECKSIG`).
/// - **Leaf 1 (depth 1)**: Expiry script (`<delay> OP_CSV OP_DROP <user> OP_CHECKSIG`).
///
/// Both leaves sit at depth 1 (balanced binary tree), giving equal proof size.
///
/// # Arguments
/// * `user_pubkey` - The VTXO owner's x-only public key.
/// * `asp_pubkey` - The Ark Service Provider's x-only public key.
/// * `csv_delay` - Relative timelock in blocks for the expiry leaf (1..=65535).
///
/// # Errors
/// Returns an error if key aggregation fails or `csv_delay` is invalid.
/// BIP-341 unspendable internal key (same as Go's `UnspendableKey()`):
/// 0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
const UNSPENDABLE_KEY_BYTES: [u8; 33] = [
    0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
    0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a,
    0xc0,
];

/// Build a complete Taproot VTXO output with expiry + collaborative leaves.
///
/// The `delay` parameter follows the Go SDK convention:
/// - `>= 512` → seconds (BIP68 time-based)
/// - `< 512`  → blocks  (BIP68 block-based)
pub fn build_vtxo_taproot(
    user_pubkey: &XOnlyPublicKey,
    asp_pubkey: &XOnlyPublicKey,
    delay: u32,
) -> BitcoinResult<TaprootSpendInfo> {
    // Use BIP-341 unspendable key as internal key (matches Go SDK's UnspendableKey())
    let secp = Secp256k1::verification_only();
    let internal_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&UNSPENDABLE_KEY_BYTES)
        .map_err(|e| BitcoinError::ScriptError(format!("Invalid unspendable key: {e}")))?;
    let internal_key = XOnlyPublicKey::from(internal_pubkey);

    // Leaf 0: CSV exit closure — <BIP68_seq> OP_CSV OP_DROP <user_xonly> OP_CHECKSIG
    let expiry_script = vtxo_expiry_script(user_pubkey, delay)?;
    // Leaf 1: collaborative spend — <user_xonly> OP_CHECKSIGVERIFY <asp_xonly> OP_CHECKSIG
    let collab_script = vtxo_collaborative_script_two_key(user_pubkey, asp_pubkey);

    // Build the taproot tree: two leaves at depth 1 (exit first, then collab — matching Go)
    let taproot_info = TaprootBuilder::new()
        .add_leaf(1, expiry_script)
        .map_err(|e| BitcoinError::ScriptError(format!("Failed to add expiry leaf: {e}")))?
        .add_leaf(1, collab_script)
        .map_err(|e| BitcoinError::ScriptError(format!("Failed to add collaborative leaf: {e}")))?
        .finalize(&secp, internal_key)
        .map_err(|e| {
            BitcoinError::ScriptError(format!("Failed to finalize taproot tree: {e:?}"))
        })?;

    Ok(taproot_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::taproot::LeafVersion;
    use bitcoin::Address;
    use bitcoin::Network;

    /// Helper: deterministic x-only key from a 32-byte secret.
    fn xonly_key(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        let sk = SecretKey::from_slice(&bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        XOnlyPublicKey::from(pk)
    }

    // ── vtxo_expiry_script ─────────────────────────────────────────

    #[test]
    fn expiry_script_contains_csv_and_checksig() {
        let user = xonly_key(1);
        let script = vtxo_expiry_script(&user, 144).unwrap();
        let asm = script.to_asm_string();

        assert!(asm.contains("OP_CSV"), "must contain OP_CSV: {asm}");
        assert!(asm.contains("OP_DROP"), "must contain OP_DROP: {asm}");
        assert!(
            asm.contains("OP_CHECKSIG"),
            "must contain OP_CHECKSIG: {asm}"
        );
    }

    #[test]
    fn expiry_script_rejects_zero_delay() {
        let user = xonly_key(1);
        assert!(vtxo_expiry_script(&user, 0).is_err());
    }

    #[test]
    fn expiry_script_different_delays_differ() {
        let user = xonly_key(1);
        let s1 = vtxo_expiry_script(&user, 144).unwrap();
        let s2 = vtxo_expiry_script(&user, 288).unwrap();
        assert_ne!(s1, s2);
    }

    // ── vtxo_collaborative_script ──────────────────────────────────

    #[test]
    fn collaborative_script_is_single_checksig() {
        let combined = xonly_key(3);
        let script = vtxo_collaborative_script(&combined);
        let asm = script.to_asm_string();

        // Should be exactly: <key> OP_CHECKSIG
        assert!(
            asm.contains("OP_CHECKSIG"),
            "must contain OP_CHECKSIG: {asm}"
        );
        // Should NOT contain OP_CSV or OP_IF
        assert!(!asm.contains("OP_CSV"), "must not contain OP_CSV: {asm}");
        assert!(!asm.contains("OP_IF"), "must not contain OP_IF: {asm}");
    }

    // ── build_vtxo_taproot ─────────────────────────────────────────

    #[test]
    fn build_vtxo_taproot_produces_valid_spend_info() {
        let user = xonly_key(1);
        let asp = xonly_key(2);

        let info = build_vtxo_taproot(&user, &asp, 144).unwrap();

        // Internal key should be the BIP-341 unspendable key (not MuSig2 aggregate)
        let secp = Secp256k1::new();
        let _ = secp; // used for context in surrounding code
        let internal_pubkey =
            bitcoin::secp256k1::PublicKey::from_slice(&UNSPENDABLE_KEY_BYTES).unwrap();
        let expected_internal = XOnlyPublicKey::from(internal_pubkey);
        assert_eq!(info.internal_key(), expected_internal);

        // The output key (tweaked) should differ from the unspendable internal key
        let output_key = info.output_key();
        assert_ne!(
            output_key.to_x_only_public_key().serialize(),
            expected_internal.serialize(),
            "output key must be tweaked"
        );
    }

    #[test]
    fn taproot_tree_has_two_leaves() {
        let user = xonly_key(1);
        let asp = xonly_key(2);

        let info = build_vtxo_taproot(&user, &asp, 144).unwrap();

        // Both scripts should be present in the script map
        let expiry = vtxo_expiry_script(&user, 144).unwrap();
        // Collaborative leaf is now two-key: owner OP_CHECKSIGVERIFY asp OP_CHECKSIG
        let collab = vtxo_collaborative_script_two_key(&user, &asp);

        let has_expiry = info
            .script_map()
            .contains_key(&(expiry, LeafVersion::TapScript));
        let has_collab = info
            .script_map()
            .contains_key(&(collab, LeafVersion::TapScript));

        assert!(has_expiry, "taproot tree must contain expiry leaf");
        assert!(has_collab, "taproot tree must contain collaborative leaf");
    }

    #[test]
    fn taproot_output_key_produces_valid_address() {
        let user = xonly_key(1);
        let asp = xonly_key(2);

        let info = build_vtxo_taproot(&user, &asp, 144).unwrap();
        let output_key = info.output_key();

        // Should produce a valid P2TR address
        let address = Address::p2tr_tweaked(output_key, Network::Regtest);
        let addr_str = address.to_string();
        assert!(
            addr_str.starts_with("bcrt1p"),
            "regtest P2TR should start with bcrt1p: {addr_str}"
        );
    }

    #[test]
    fn taproot_deterministic_output() {
        let user = xonly_key(1);
        let asp = xonly_key(2);

        let info1 = build_vtxo_taproot(&user, &asp, 144).unwrap();
        let info2 = build_vtxo_taproot(&user, &asp, 144).unwrap();

        assert_eq!(
            info1.output_key(),
            info2.output_key(),
            "same inputs must produce same output key"
        );
    }

    #[test]
    fn different_delays_produce_different_outputs() {
        let user = xonly_key(1);
        let asp = xonly_key(2);

        let info_a = build_vtxo_taproot(&user, &asp, 144).unwrap();
        let info_b = build_vtxo_taproot(&user, &asp, 288).unwrap();

        assert_ne!(
            info_a.output_key(),
            info_b.output_key(),
            "different CSV delays must produce different output keys"
        );
    }

    // ── bip68_sequence ─────────────────────────────────────────────

    #[test]
    fn bip68_block_based() {
        // < 512 → block-based, raw value
        assert_eq!(bip68_sequence(144).unwrap(), 144);
        assert_eq!(bip68_sequence(1).unwrap(), 1);
        assert_eq!(bip68_sequence(511).unwrap(), 511);
    }

    #[test]
    fn bip68_seconds_based() {
        // >= 512 → seconds-based, sets bit 22, divides by 512
        // 1024 seconds → 1024/512 = 2, | 0x400000 = 0x400002
        assert_eq!(bip68_sequence(1024).unwrap(), 0x400002);
        // 512 seconds → 512/512 = 1, | 0x400000 = 0x400001
        assert_eq!(bip68_sequence(512).unwrap(), 0x400001);
    }

    #[test]
    fn bip68_seconds_must_be_multiple_of_512() {
        assert!(bip68_sequence(1000).is_err());
        assert!(bip68_sequence(513).is_err());
    }

    #[test]
    fn expiry_script_with_seconds_delay() {
        let user = xonly_key(1);
        // 1024 seconds → BIP68 sequence 0x400002
        let script = vtxo_expiry_script(&user, 1024).unwrap();
        let asm = script.to_asm_string();
        // The pushed value 0x400002 is encoded as CScriptNum little-endian: 02 00 40
        // to_asm_string() renders it as hex bytes "020040"
        assert!(
            asm.contains("020040"),
            "script should push BIP68-encoded value 0x400002 (LE hex 020040): {asm}"
        );
    }
}
