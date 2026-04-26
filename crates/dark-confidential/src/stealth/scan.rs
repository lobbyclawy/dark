//! Recipient-side stealth scanning (issue #555).
//!
//! Given the recipient's `scan_priv` and a list of round announcements
//! `(vtxo_id, ephemeral_pk, output_pk)`, decide which VTXOs were paid to
//! this user.
//!
//! # Scheme
//!
//! ```text
//!     shared_point = scan_priv · ephemeral_pk      (= ephemeral_priv · scan_pk)
//!     tweak        = H(shared_point.serialize())
//!     expected_pk  = spend_pk + tweak · G
//!     match        = (expected_pk == output_pk)
//! ```
//!
//! `H` is the BIP-340-style tagged hash with DST
//! `dark-confidential/stealth-tweak/v1`, applied to the 33-byte
//! compressed encoding of the ECDH shared point. Compressed (rather than
//! x-only) serialization keeps the transcript canonical and avoids the
//! parity ambiguity that x-only would force us to disambiguate.
//!
//! # Threat model
//!
//! - **Spend authority.** Matching announcements requires only
//!   `scan_priv`; *spending* a matched VTXO requires `spend_priv`, which
//!   the wallet keeps offline. A compromised scanner cannot move funds.
//! - **Side channels.** The point-equality check is constant-time over
//!   the 33-byte compressed serializations, so a remote scanning oracle
//!   cannot learn near-matches via response timing on the comparison
//!   itself. Upstream `secp256k1` scalar multiplication and hashing are
//!   not strictly constant-time at the C level; we treat the secp256k1
//!   crate as the authoritative side-channel boundary, consistent with
//!   the rest of `dark-confidential`.
//! - **Unspendable announcements.** With negligible probability the
//!   tagged hash produces an invalid scalar (zero or ≥ n). The recipient
//!   simply returns `false`; the funds are unrecoverable but no panic
//!   leaks information.
//!
//! # Concurrent dependencies
//!
//! - Issue #553 (`MetaAddress`) and #554 (sender-side
//!   `derive_one_time_output`) land in parallel. The production scan API
//!   takes raw [`secp256k1`] keys, so it has no compile-time dependency
//!   on those. The round-trip test in this module uses `#[cfg(test)]`
//!   stubs that mirror the agreed transcript; the merge author should
//!   delete them and re-export the real types once #553 / #554 land.
//!   See the `stubs` test sub-module below.

use secp256k1::{
    hashes::{sha256, Hash, HashEngine},
    PublicKey, Scalar, Secp256k1, SecretKey,
};

/// BIP-340-style tagged-hash DST for the stealth tweak. Versioned so a
/// future scheme change mints a new tag rather than reinterpreting v1.
pub const STEALTH_TWEAK_TAG: &[u8] = b"dark-confidential/stealth-tweak/v1";

/// Length of an announcement's VTXO identifier in bytes
/// (`txid || vout_be`, ADR-0002).
pub const VTXO_ID_LEN: usize = 36;

/// A round announcement carrying everything the recipient needs to
/// decide ownership of a single VTXO.
///
/// `vtxo_id` is a borrow of canonical 36-byte ADR-0002 bytes. We borrow
/// rather than own so batch scanning over a streamed buffer doesn't
/// force allocation per announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announcement<'a> {
    pub vtxo_id: &'a [u8; VTXO_ID_LEN],
    pub ephemeral_pk: PublicKey,
    pub output_pk: PublicKey,
}

/// Returns `true` if the announcement was paid to the holder of
/// `scan_priv` / `spend_pk`.
///
/// See the module docs for the transcript and threat model.
pub fn scan_announcement(
    scan_priv: &SecretKey,
    spend_pk: &PublicKey,
    ephemeral_pk: &PublicKey,
    output_pk: &PublicKey,
) -> bool {
    let Some(expected_pk) = derive_expected_output_pk(scan_priv, spend_pk, ephemeral_pk) else {
        return false;
    };
    points_eq_ct(&expected_pk, output_pk)
}

/// Batch helper: returns references to every announcement that belongs
/// to this recipient, preserving input order.
pub fn scan_announcements<'a, 'b>(
    scan_priv: &SecretKey,
    spend_pk: &PublicKey,
    announcements: &'b [Announcement<'a>],
) -> Vec<&'b Announcement<'a>> {
    announcements
        .iter()
        .filter(|ann| scan_announcement(scan_priv, spend_pk, &ann.ephemeral_pk, &ann.output_pk))
        .collect()
}

/// Recompute the recipient's view of the one-time output key.
///
/// Returns `None` if the tagged hash of the ECDH shared point lands on
/// an invalid scalar — a negligible-probability case in which the
/// announcement is simply unspendable.
fn derive_expected_output_pk(
    scan_priv: &SecretKey,
    spend_pk: &PublicKey,
    ephemeral_pk: &PublicKey,
) -> Option<PublicKey> {
    let secp = Secp256k1::new();
    let shared_point = ephemeral_pk
        .mul_tweak(&secp, &Scalar::from(*scan_priv))
        .ok()?;
    let tweak = stealth_tweak_scalar(&shared_point)?;
    spend_pk.add_exp_tweak(&secp, &tweak).ok()
}

/// Hash the compressed shared point under the tweak DST, then map to a
/// secp256k1 [`Scalar`]. The mapping fails only when the hash output is
/// zero or ≥ n, which has cryptographically negligible probability.
fn stealth_tweak_scalar(shared_point: &PublicKey) -> Option<Scalar> {
    let digest = tagged_hash(STEALTH_TWEAK_TAG, &shared_point.serialize());
    Scalar::from_be_bytes(digest).ok()
}

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Constant-time equality on the 33-byte compressed serialization of
/// two secp256k1 points. The serializations themselves are public —
/// we go to constant time only to deny a timing oracle that could
/// distinguish a near-match across a remote scan API.
fn points_eq_ct(a: &PublicKey, b: &PublicKey) -> bool {
    let a_bytes = a.serialize();
    let b_bytes = b.serialize();
    let mut diff = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::SmallRng, RngCore, SeedableRng};
    use secp256k1::Secp256k1;

    /// Local stubs of the sender-side API.
    ///
    /// These are the **only** things in this file that should be deleted
    /// once issues #553 (`MetaAddress`) and #554
    /// (`derive_one_time_output`) land. Replace with the real imports
    /// and keep the round-trip test as-is — it pins the transcript.
    mod stubs {
        use super::super::stealth_tweak_scalar;
        use secp256k1::{PublicKey, Secp256k1, SecretKey};

        /// Stub of the issue #553 type. Real version may include
        /// network/version bytes; for the round-trip we only need the
        /// two pubkeys.
        pub struct MetaAddress {
            pub scan_pk: PublicKey,
            pub spend_pk: PublicKey,
        }

        /// Stub of the issue #554 output type. The real type is
        /// expected to also carry the VTXO id, but we only need the two
        /// pubkeys to drive the recipient-side round trip.
        pub struct StealthOutput {
            pub ephemeral_pk: PublicKey,
            pub output_pk: PublicKey,
        }

        /// Stub of the issue #554 sender derivation. Mirrors the
        /// transcript pinned in `stealth/scan.rs`. Returns `None` only
        /// in the negligible-probability branch where the hash is not a
        /// valid scalar — same contract as the recipient side.
        pub fn derive_one_time_output(
            meta: &MetaAddress,
            ephemeral_priv: &SecretKey,
        ) -> Option<StealthOutput> {
            let secp = Secp256k1::new();
            let ephemeral_pk = PublicKey::from_secret_key(&secp, ephemeral_priv);
            let shared_point = meta
                .scan_pk
                .mul_tweak(&secp, &(*ephemeral_priv).into())
                .ok()?;
            let tweak = stealth_tweak_scalar(&shared_point)?;
            let output_pk = meta.spend_pk.add_exp_tweak(&secp, &tweak).ok()?;
            Some(StealthOutput {
                ephemeral_pk,
                output_pk,
            })
        }
    }

    fn fresh_secret(rng: &mut SmallRng) -> SecretKey {
        loop {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            if let Ok(sk) = SecretKey::from_slice(&buf) {
                return sk;
            }
        }
    }

    fn meta_address(rng: &mut SmallRng) -> (SecretKey, SecretKey, stubs::MetaAddress) {
        let secp = Secp256k1::new();
        let scan_priv = fresh_secret(rng);
        let spend_priv = fresh_secret(rng);
        let meta = stubs::MetaAddress {
            scan_pk: PublicKey::from_secret_key(&secp, &scan_priv),
            spend_pk: PublicKey::from_secret_key(&secp, &spend_priv),
        };
        (scan_priv, spend_priv, meta)
    }

    #[test]
    fn round_trip_sender_derivation_is_recognised_by_recipient() {
        let mut rng = SmallRng::seed_from_u64(0xdeadbeef);
        let (scan_priv, _spend_priv, meta) = meta_address(&mut rng);
        let ephemeral_priv = fresh_secret(&mut rng);

        let output = stubs::derive_one_time_output(&meta, &ephemeral_priv).expect("valid scalar");

        assert!(scan_announcement(
            &scan_priv,
            &meta.spend_pk,
            &output.ephemeral_pk,
            &output.output_pk,
        ));
    }

    #[test]
    fn unrelated_ephemeral_does_not_match() {
        let mut rng = SmallRng::seed_from_u64(42);
        let (scan_priv, _spend_priv, meta) = meta_address(&mut rng);

        let ephemeral_priv = fresh_secret(&mut rng);
        let output = stubs::derive_one_time_output(&meta, &ephemeral_priv).expect("valid scalar");

        let unrelated_ephemeral_priv = fresh_secret(&mut rng);
        let secp = Secp256k1::new();
        let unrelated_ephemeral_pk = PublicKey::from_secret_key(&secp, &unrelated_ephemeral_priv);

        assert!(!scan_announcement(
            &scan_priv,
            &meta.spend_pk,
            &unrelated_ephemeral_pk,
            &output.output_pk,
        ));
    }

    #[test]
    fn announcement_for_other_recipient_is_skipped() {
        let mut rng = SmallRng::seed_from_u64(1234);
        let (alice_scan, _alice_spend, alice) = meta_address(&mut rng);
        let (_bob_scan, _bob_spend, bob) = meta_address(&mut rng);

        let ephemeral_priv = fresh_secret(&mut rng);
        let bob_output =
            stubs::derive_one_time_output(&bob, &ephemeral_priv).expect("valid scalar");

        assert!(!scan_announcement(
            &alice_scan,
            &alice.spend_pk,
            &bob_output.ephemeral_pk,
            &bob_output.output_pk,
        ));
    }

    #[test]
    fn batch_scan_returns_only_owned_announcements() {
        let mut rng = SmallRng::seed_from_u64(2025);
        let (scan_priv, _spend_priv, meta) = meta_address(&mut rng);
        let (_other_scan, _other_spend, other) = meta_address(&mut rng);

        let mut id_buf: Vec<[u8; VTXO_ID_LEN]> = Vec::new();
        let mut owned: Vec<bool> = Vec::new();
        let mut outputs: Vec<stubs::StealthOutput> = Vec::new();

        for i in 0..6u8 {
            let mut id = [0u8; VTXO_ID_LEN];
            id[0] = i;
            id_buf.push(id);
            let mine = i % 2 == 0;
            owned.push(mine);
            let target = if mine { &meta } else { &other };
            let ephemeral_priv = fresh_secret(&mut rng);
            outputs.push(
                stubs::derive_one_time_output(target, &ephemeral_priv).expect("valid scalar"),
            );
        }

        let announcements: Vec<Announcement> = outputs
            .iter()
            .zip(id_buf.iter())
            .map(|(o, id)| Announcement {
                vtxo_id: id,
                ephemeral_pk: o.ephemeral_pk,
                output_pk: o.output_pk,
            })
            .collect();

        let matched = scan_announcements(&scan_priv, &meta.spend_pk, &announcements);
        let matched_ids: Vec<&[u8; VTXO_ID_LEN]> = matched.iter().map(|ann| ann.vtxo_id).collect();
        let expected_ids: Vec<&[u8; VTXO_ID_LEN]> = id_buf
            .iter()
            .zip(owned.iter())
            .filter_map(|(id, mine)| mine.then_some(id))
            .collect();
        assert_eq!(matched_ids, expected_ids);
    }

    #[test]
    fn points_eq_ct_matches_native_equality() {
        let mut rng = SmallRng::seed_from_u64(7);
        let secp = Secp256k1::new();
        let a = PublicKey::from_secret_key(&secp, &fresh_secret(&mut rng));
        let b = PublicKey::from_secret_key(&secp, &fresh_secret(&mut rng));
        assert!(points_eq_ct(&a, &a));
        assert!(!points_eq_ct(&a, &b));
    }
}
