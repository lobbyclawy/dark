//! Per-epoch renewal-message derivation `m_t` (issue #672).
//!
//! The BIP-340 sighash both the user (at boarding pre-signing) and the
//! ASP (during epoch processing) feed to MuSig2 for epoch `t`. By
//! design `m_t` is a function of `(SlotRoot, batch_tree_root, t, n)`
//! only — no per-cohort secrets, no time-of-day inputs — so any party
//! holding the cohort's published metadata recomputes it identically.
//!
//! ```text
//! m_t = tagged_hash(
//!     b"DarkPsarRenewalMsgV1",
//!     slot_root (32 B) || batch_tree_root (32 B) || t (4 B LE u32) || n (4 B LE u32)
//! )
//! ```
//!
//! `batch_tree_root` is the root of the cohort's renewal-output tree,
//! same shape as `crates/dark-core/src/round_tree.rs`. See
//! [`crate::batch_tree::compute_batch_tree_root`] for the canonical
//! reduction from a [`crate::cohort::Cohort`] to that root.

use sha2::{Digest, Sha256};

pub const RENEWAL_MESSAGE_TAG: &[u8] = b"DarkPsarRenewalMsgV1";

/// Derive the per-epoch renewal-message digest `m_t`.
pub fn derive_message_for_epoch(
    slot_root: &[u8; 32],
    batch_tree_root: &[u8; 32],
    t: u32,
    n: u32,
) -> [u8; 32] {
    let tag_hash = Sha256::digest(RENEWAL_MESSAGE_TAG);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(slot_root);
    hasher.update(batch_tree_root);
    hasher.update(t.to_le_bytes());
    hasher.update(n.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch_tree::compute_batch_tree_root;
    use crate::cohort::{CohortMember, HibernationHorizon};
    use crate::slot_tree::SlotRoot;
    use crate::Cohort;

    fn member(seed: u8, slot: u32) -> CohortMember {
        CohortMember {
            user_id: [seed; 32],
            pk_user: [seed.wrapping_add(1); 32],
            slot_index: slot,
        }
    }

    fn cohort(k: u32, n: u32) -> Cohort {
        let members: Vec<_> = (0..k).map(|i| member((i + 1) as u8, i)).collect();
        let horizon = HibernationHorizon::new(n, 256).unwrap();
        Cohort::new([0xab; 32], members, horizon).unwrap()
    }

    // --- Constants ---------------------------------------------------------

    #[test]
    fn pinned_tag_value() {
        assert_eq!(RENEWAL_MESSAGE_TAG, b"DarkPsarRenewalMsgV1");
    }

    // --- Determinism / distinctness ---------------------------------------

    #[test]
    fn determinism() {
        let s = [0x11; 32];
        let b = [0x22; 32];
        assert_eq!(
            derive_message_for_epoch(&s, &b, 7, 12),
            derive_message_for_epoch(&s, &b, 7, 12),
        );
    }

    #[test]
    fn distinct_t_distinct_outputs() {
        let s = [0x11; 32];
        let b = [0x22; 32];
        let n = 12u32;
        let mut seen = std::collections::HashSet::new();
        for t in 1..=n {
            let m = derive_message_for_epoch(&s, &b, t, n);
            assert!(seen.insert(m), "collision at t={t}");
        }
    }

    #[test]
    fn distinct_inputs_distinct_outputs() {
        let s = [0x11; 32];
        let b = [0x22; 32];
        assert_ne!(
            derive_message_for_epoch(&s, &b, 1, 4),
            derive_message_for_epoch(&[0x99; 32], &b, 1, 4),
        );
        assert_ne!(
            derive_message_for_epoch(&s, &b, 1, 4),
            derive_message_for_epoch(&s, &[0xaa; 32], 1, 4),
        );
        // n distinguishes the digest too — different horizon implies
        // different sighash even if (slot_root, batch_tree_root, t) match.
        assert_ne!(
            derive_message_for_epoch(&s, &b, 4, 4),
            derive_message_for_epoch(&s, &b, 4, 12),
        );
    }

    #[test]
    fn t_endianness_is_little() {
        let s = [0u8; 32];
        let b = [0u8; 32];
        assert_ne!(
            derive_message_for_epoch(&s, &b, 1, 12),
            derive_message_for_epoch(&s, &b, 0x0100_0000, 12),
        );
    }

    // --- Golden vectors (issue #672) --------------------------------------
    //
    // Pin the per-epoch message digest for two cohort configurations the
    // paper and tests use as canonical: K=4 / N=4 and K=10 / N=12. Any
    // future change to `RENEWAL_MESSAGE_TAG`, the input encoding, or
    // `compute_batch_tree_root` surfaces here.

    fn golden_messages_for(k: u32, n: u32) -> Vec<String> {
        let c = cohort(k, n);
        let slot_root = SlotRoot::compute(&c.members).0;
        let batch_root = compute_batch_tree_root(&c);
        (1..=n)
            .map(|t| hex::encode(derive_message_for_epoch(&slot_root, &batch_root, t, n)))
            .collect()
    }

    #[test]
    fn golden_messages_k4_n4_pinned() {
        let actual = golden_messages_for(4, 4);
        assert_eq!(actual.len(), 4);
        // Pinned values — regenerated on first run by removing assertions
        // and copying the printed output back.
        let expected = GOLDEN_K4_N4;
        for (t, (got, want)) in actual.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "K=4 N=4 m_t drift at t={}", t + 1);
        }
    }

    #[test]
    fn golden_messages_k10_n12_pinned() {
        let actual = golden_messages_for(10, 12);
        assert_eq!(actual.len(), 12);
        let expected = GOLDEN_K10_N12;
        for (t, (got, want)) in actual.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "K=10 N=12 m_t drift at t={}", t + 1);
        }
    }

    /// Pinned for K=4 / N=4. Order matches `t = 1..=4`.
    const GOLDEN_K4_N4: &[&str] = &[
        "bac97dc1f1c5705030d0bb2164b6b799a8dfbee9654e7223fc140f43cfd1b936",
        "aca57a1470aab91d0ec62b77992df618b2957fdb8f7aa03de4accc1767e20bd3",
        "5210a806f314357e8a33a63b58e1413cb0bacf08ee9c87269600f56becfa4b86",
        "f79d52a01bf2afa4981ce6b335a4695bd4fbc50fdd13dbc4529f0a4c2aabc8f5",
    ];

    /// Pinned for K=10 / N=12. Order matches `t = 1..=12`.
    const GOLDEN_K10_N12: &[&str] = &[
        "a48e422e32b7690d05063e11eed8ee2df872528f52b4ce3a046534fcdaac732b",
        "5baf4d59246928d078c4b6f6b2c2d37fe5cc248fefebfc0ce63c89ea59dbd7a9",
        "54bda9bb866c294ba87ab5bbac28d4a9a790c31a1d3c1f18e4393de289518236",
        "80e3995b8011654a90f92b1d42bfd379ff784b9f2fc500a62c7a85bd0477bb10",
        "f02f443ba4308a18c9b1582889dd14a8a5b0ee51088a62a81a438adb758718a8",
        "76d72cbabd9956a34300a39c4bd53ad79371ac925e8ad85945402b17b19b43da",
        "20245add112cf07c4cf3a7e44a0e425af5d9444ebac24a94a6764373de6ce304",
        "b06dbcba4c6ceaf735bd99f64be1ab276282d85d2d9e3b510256814d66e4ba1f",
        "bfa651540dedab53d0c49edd052097657cf6ef6091700945ca771cf9a9173eea",
        "22a91c1208077a621deff590554532213fd8a22a95b66744f6b305b629a1009d",
        "8cdd0c53c356f2dbdf16ca854d322751436e38171f8665ef7e6d2e80c68c6d7c",
        "b2b78090aad68f80fe0142e32f104e79e1f663cad2e59d7623eb1c7af416269e",
    ];
}
