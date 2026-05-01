//! Batch-tree commitment for PSAR cohorts.
//!
//! The *batch tree* is the per-cohort renewal-output Merkle tree —
//! same shape as [`dark_core::round_tree::RoundTree`], because PSAR
//! sits *above* round-tree (issue #672 technical decision). Each
//! cohort member becomes one leaf; the root is the value that flows
//! into [`crate::message::derive_message_for_epoch`] as
//! `batch_tree_root`.
//!
//! # Phase-4 vs phase-5 amount handling
//!
//! Real renewal outputs carry per-epoch amounts (paper §5). Phase 4
//! does not yet have wallet wiring (#680 lands the demo binary), so
//! the leaves here are synthesised with a fixed
//! [`PHASE4_AMOUNT_PLACEHOLDER_SATS`] amount keyed on `(pk_user,
//! slot_index, cohort_id)`. The structural commitment that results
//! is sufficient for #672–#676 (signing path correctness); phase 5
//! will replace the placeholder with caller-supplied amounts and the
//! pre-image will lengthen accordingly.

use dark_core::round_tree::{leaf_v1_hash, LeafKind, LeafV1, RoundTree};

use crate::cohort::Cohort;

/// Placeholder per-user amount used by [`compute_batch_tree_root`]
/// while phase 4 has no wallet wiring. See module docs.
pub const PHASE4_AMOUNT_PLACEHOLDER_SATS: u64 = 100_000;

/// Compute the batch-tree root for `cohort`.
///
/// Each cohort member contributes one transparent (V1) leaf encoding
/// `(amount = PHASE4_AMOUNT_PLACEHOLDER_SATS, pubkey = m.pk_user,
/// vout = m.slot_index, txid = cohort.id)`. The root is the
/// `RoundTree::root()` value over those leaves with the canonical
/// odd-leaf-promotion rule.
pub fn compute_batch_tree_root(cohort: &Cohort) -> [u8; 32] {
    let cohort_txid = cohort.id;
    let leaf_hashes: Vec<[u8; 32]> = cohort
        .members
        .iter()
        .map(|m| {
            let leaf = LeafV1 {
                amount: PHASE4_AMOUNT_PLACEHOLDER_SATS,
                pubkey: &m.pk_user,
                vout: m.slot_index,
                txid: &cohort_txid,
            };
            leaf_v1_hash(&leaf)
        })
        .collect();
    let kinds = vec![LeafKind::Transparent; leaf_hashes.len()];
    let tree = RoundTree::from_leaf_hashes(leaf_hashes, kinds);
    tree.root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cohort::{CohortMember, HibernationHorizon};

    fn member(seed: u8, slot: u32) -> CohortMember {
        CohortMember {
            user_id: [seed; 32],
            pk_user: [seed.wrapping_add(1); 32],
            slot_index: slot,
        }
    }

    fn cohort(k: u32) -> Cohort {
        let members: Vec<_> = (0..k).map(|i| member((i + 1) as u8, i)).collect();
        let horizon = HibernationHorizon::new(4, 12).unwrap();
        Cohort::new([0xab; 32], members, horizon).unwrap()
    }

    #[test]
    fn determinism() {
        let c = cohort(4);
        assert_eq!(compute_batch_tree_root(&c), compute_batch_tree_root(&c));
    }

    #[test]
    fn distinguishes_distinct_member_sets() {
        let c4 = cohort(4);
        let c5 = cohort(5);
        assert_ne!(compute_batch_tree_root(&c4), compute_batch_tree_root(&c5));
    }

    #[test]
    fn distinguishes_distinct_cohort_ids() {
        let mut c1 = cohort(4);
        let mut c2 = cohort(4);
        c1.id = [0x11; 32];
        c2.id = [0x22; 32];
        assert_ne!(compute_batch_tree_root(&c1), compute_batch_tree_root(&c2));
    }

    #[test]
    fn root_changes_when_member_pubkey_mutates() {
        let mut c = cohort(4);
        let r0 = compute_batch_tree_root(&c);
        c.members[0].pk_user[0] ^= 0x01;
        let r1 = compute_batch_tree_root(&c);
        assert_ne!(r0, r1);
    }

    #[test]
    fn placeholder_amount_is_pinned() {
        // Locking the placeholder catches accidental drift; phase 5 will
        // replace this constant with caller-supplied values.
        assert_eq!(PHASE4_AMOUNT_PLACEHOLDER_SATS, 100_000);
    }
}
