//! Tapscript VTXO tree construction for the Ark protocol.
//!
//! Builds a Taproot output with two leaf scripts:
//! - **Expiry leaf**: `<delay> OP_CSV OP_DROP <user_pubkey> OP_CHECKSIG`
//!   — allows the user to unilaterally exit after a relative timelock.
//! - **Collaborative leaf**: `<agg_pubkey> OP_CHECKSIG`
//!   — allows ASP + user to cooperatively spend via MuSig2 key-path.
//!
//! The internal key is a MuSig2 aggregate of user + ASP keys (enabling
//! key-path cooperative spends without revealing the script tree).

use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};
use bitcoin::XOnlyPublicKey;

use crate::error::{BitcoinError, BitcoinResult};
use crate::tree::aggregate_keys;

/// Build the expiry (unilateral exit) tapscript leaf.
///
/// Script: `<csv_delay> OP_CSV OP_DROP <user_pubkey> OP_CHECKSIG`
///
/// This leaf allows the VTXO owner to claim funds after `csv_delay` blocks
/// have elapsed since the VTXO was confirmed on-chain.
///
/// # Arguments
/// * `user_pubkey` - The VTXO owner's x-only public key.
/// * `csv_delay` - Relative timelock in blocks (1..=65535).
///
/// # Errors
/// Returns an error if `csv_delay` is 0 or exceeds 65535.
pub fn vtxo_expiry_script(
    user_pubkey: &XOnlyPublicKey,
    csv_delay: u16,
) -> BitcoinResult<bitcoin::ScriptBuf> {
    if csv_delay == 0 {
        return Err(BitcoinError::ScriptError(
            "csv_delay must be > 0".to_string(),
        ));
    }

    Ok(Builder::new()
        .push_int(csv_delay as i64)
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
pub fn build_vtxo_taproot(
    user_pubkey: &XOnlyPublicKey,
    asp_pubkey: &XOnlyPublicKey,
    csv_delay: u16,
) -> BitcoinResult<TaprootSpendInfo> {
    // Aggregate user + ASP keys for the internal key
    let internal_key = aggregate_keys(&[*user_pubkey, *asp_pubkey])?;

    // Build leaf scripts
    let expiry_script = vtxo_expiry_script(user_pubkey, csv_delay)?;
    let collab_pubkey = aggregate_keys(&[*user_pubkey, *asp_pubkey])?;
    let collab_script = vtxo_collaborative_script(&collab_pubkey);

    let secp = Secp256k1::verification_only();

    // Build the taproot tree: two leaves at depth 1
    let taproot_info = TaprootBuilder::new()
        .add_leaf(1, collab_script)
        .map_err(|e| BitcoinError::ScriptError(format!("Failed to add collaborative leaf: {e}")))?
        .add_leaf(1, expiry_script)
        .map_err(|e| BitcoinError::ScriptError(format!("Failed to add expiry leaf: {e}")))?
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

        // Internal key should be the MuSig2 aggregate
        let expected_internal = aggregate_keys(&[user, asp]).unwrap();
        assert_eq!(info.internal_key(), expected_internal);

        // The output key (tweaked) should differ from internal key
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
        let collab_key = aggregate_keys(&[user, asp]).unwrap();
        let collab = vtxo_collaborative_script(&collab_key);

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
        let info_b = build_vtxo_taproot(&user, &asp, 1008).unwrap();

        assert_ne!(
            info_a.output_key(),
            info_b.output_key(),
            "different CSV delays must produce different output keys"
        );
    }
}
