//! Slot allocation Merkle tree (issue #667).
//!
//! Commits a cohort to its slot allocation: every member's
//! `(slot_index, pk_user)` pair is hashed into a leaf, the leaves are
//! combined into a binary Merkle tree, and the root is what the ASP
//! signs in [`SlotAttest`](crate::attest) (#668) and publishes via
//! [`publish`](crate::publish) (#669).
//!
//! # Wire format
//!
//! - Leaf preimage layout (37 B):
//!
//!   ```text
//!   |  0x01 (LEAF_V1_PREFIX) |  4 B slot_index (LE u32) |  32 B pk_user  |
//!   ```
//!
//! - Leaf hash: `tagged_hash(LEAF_V1_TAG, preimage)`
//!   with `LEAF_V1_TAG = b"DarkPsarSlotV1"` per issue #667.
//!
//! - Branch hash: `tagged_hash(BRANCH_TAG, l || r)`
//!   with `BRANCH_TAG = b"DarkPsarBranch"` per issue #667.
//!
//! Tagged hashes follow the BIP-340 construction
//! `SHA256(SHA256(tag) || SHA256(tag) || msg)`. Tree shape mirrors
//! `crates/dark-core/src/round_tree.rs`: pairs combine left-to-right;
//! an unpaired right-most node at any level is promoted unchanged.
//! The empty tree has the zero root `[0u8; 32]`.
//!
//! # Phase-3 scope vs phase-4 batch tree
//!
//! Issue #667 describes the leaf as `(slot_i, pk_{U_i}, tree_path_i)`.
//! `tree_path_i` is the user's commitment to a position in the
//! *batch* tree that phase 4 will land (#672). In phase 3 the batch
//! tree does not exist yet, so the leaf encoding here is locked at
//! `(slot_index, pk_user)`. Phase 4 will introduce a `LeafV2` /
//! `LEAF_V2_PREFIX = 0x02` encoding with `tree_path` appended; the
//! prefix-byte rail keeps the two encodings non-colliding (same
//! pattern as `dark-core`'s `round_tree.rs`).

use sha2::{Digest, Sha256};

use crate::cohort::CohortMember;
use crate::error::PsarError;

/// Leading byte of the V1 (phase-3) leaf preimage.
pub const LEAF_V1_PREFIX: u8 = 0x01;

/// BIP-340 tagged-hash tag for the slot leaf (#667).
pub const LEAF_V1_TAG: &[u8] = b"DarkPsarSlotV1";

/// BIP-340 tagged-hash tag for the slot tree's branch nodes (#667).
pub const BRANCH_TAG: &[u8] = b"DarkPsarBranch";

/// A single slot leaf — the tree-side projection of a [`CohortMember`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Slot {
    pub slot_index: u32,
    pub pk_user: [u8; 32],
}

impl Slot {
    pub fn from_member(m: &CohortMember) -> Self {
        Self {
            slot_index: m.slot_index,
            pk_user: m.pk_user,
        }
    }

    /// Canonical 37-byte leaf preimage.
    pub fn preimage(&self) -> [u8; 37] {
        let mut out = [0u8; 37];
        out[0] = LEAF_V1_PREFIX;
        out[1..5].copy_from_slice(&self.slot_index.to_le_bytes());
        out[5..37].copy_from_slice(&self.pk_user);
        out
    }

    /// 32-byte tagged-hash leaf digest.
    pub fn leaf_hash(&self) -> [u8; 32] {
        tagged_hash(LEAF_V1_TAG, &self.preimage())
    }
}

/// Slot Merkle root. Wraps a 32-byte digest so callers cannot mistake
/// it for an arbitrary hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SlotRoot(pub [u8; 32]);

impl SlotRoot {
    /// Compute the root over the cohort members' slots.
    pub fn compute(members: &[CohortMember]) -> Self {
        let leaves: Vec<[u8; 32]> = members
            .iter()
            .map(|m| Slot::from_member(m).leaf_hash())
            .collect();
        SlotRoot(merkle_root(&leaves))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Which side of the parent the *sibling* sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Sibling is the left child (current node is the right child).
    Left,
    /// Sibling is the right child (current node is the left child).
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    pub side: Side,
}

/// Inclusion proof for a single leaf in the slot Merkle tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotInclusionProof {
    pub leaf_index: u32,
    pub steps: Vec<ProofStep>,
}

impl SlotInclusionProof {
    /// Build the proof for `leaf_index` over the given cohort members.
    pub fn generate(members: &[CohortMember], leaf_index: u32) -> Result<Self, PsarError> {
        let tree = SlotTree::from_members(members);
        tree.inclusion_proof(leaf_index)
    }

    /// `true` iff this proof attests `leaf` is committed in `slot_root`.
    pub fn verify(&self, slot_root: &SlotRoot, leaf: &Slot) -> bool {
        let mut acc = leaf.leaf_hash();
        for step in &self.steps {
            acc = match step.side {
                Side::Left => branch_hash(&step.sibling, &acc),
                Side::Right => branch_hash(&acc, &step.sibling),
            };
        }
        acc == slot_root.0
    }
}

/// In-memory binary Merkle tree over slot leaves.
///
/// Holds every level so inclusion proofs can be generated without
/// re-hashing leaves.
#[derive(Clone, Debug)]
pub struct SlotTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl SlotTree {
    /// Build a tree from `members`. Order is preserved — the leaf at
    /// position `i` corresponds to `members[i]`. Empty member sets
    /// produce a tree with the zero root.
    pub fn from_members(members: &[CohortMember]) -> Self {
        let leaves: Vec<[u8; 32]> = members
            .iter()
            .map(|m| Slot::from_member(m).leaf_hash())
            .collect();
        Self::from_leaf_hashes(leaves)
    }

    /// Build a tree from already-computed leaf hashes. Used by tests
    /// and by callers who have their own [`Slot`] values.
    pub fn from_leaf_hashes(leaf_hashes: Vec<[u8; 32]>) -> Self {
        if leaf_hashes.is_empty() {
            return Self {
                levels: vec![Vec::new()],
            };
        }
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaf_hashes.clone()];
        let mut current = leaf_hashes;
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 2 + 1);
            let mut i = 0;
            while i + 1 < current.len() {
                next.push(branch_hash(&current[i], &current[i + 1]));
                i += 2;
            }
            if !current.len().is_multiple_of(2) {
                next.push(current[current.len() - 1]);
            }
            levels.push(next.clone());
            current = next;
        }
        Self { levels }
    }

    pub fn len(&self) -> u32 {
        self.levels.first().map(|l| l.len()).unwrap_or(0) as u32
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `[0u8; 32]` for the empty tree; otherwise the top-level hash.
    pub fn root(&self) -> SlotRoot {
        let bytes = self
            .levels
            .last()
            .and_then(|l| l.first())
            .copied()
            .unwrap_or([0u8; 32]);
        SlotRoot(bytes)
    }

    pub fn inclusion_proof(&self, leaf_index: u32) -> Result<SlotInclusionProof, PsarError> {
        let k = self.len();
        if leaf_index >= k {
            return Err(PsarError::SlotIndexOutOfRange {
                slot_index: leaf_index,
                k,
            });
        }
        let mut steps = Vec::new();
        let mut idx = leaf_index as usize;
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            // Unpaired right-most node at this level: promoted unchanged.
            // Skip emitting a sibling for it.
            if idx == level.len() - 1 && !level.len().is_multiple_of(2) {
                idx /= 2;
                continue;
            }
            let idx_is_left_child = idx.is_multiple_of(2);
            let sibling_idx = if idx_is_left_child { idx + 1 } else { idx - 1 };
            let side = if idx_is_left_child {
                Side::Right
            } else {
                Side::Left
            };
            steps.push(ProofStep {
                sibling: level[sibling_idx],
                side,
            });
            idx /= 2;
        }
        Ok(SlotInclusionProof { leaf_index, steps })
    }
}

// --- Hash primitives -------------------------------------------------------

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);
    hasher.finalize().into()
}

fn branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    tagged_hash(BRANCH_TAG, &buf)
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut current: Vec<[u8; 32]> = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len() / 2 + 1);
        let mut i = 0;
        while i + 1 < current.len() {
            next.push(branch_hash(&current[i], &current[i + 1]));
            i += 2;
        }
        if !current.len().is_multiple_of(2) {
            next.push(current[current.len() - 1]);
        }
        current = next;
    }
    current[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn member(seed: u8, slot: u32) -> CohortMember {
        CohortMember {
            user_id: [seed; 32],
            pk_user: [seed.wrapping_add(1); 32],
            slot_index: slot,
        }
    }

    fn members(k: u32) -> Vec<CohortMember> {
        (0..k).map(|i| member(i as u8, i)).collect()
    }

    // --- Constants ---------------------------------------------------------

    #[test]
    fn pinned_tag_bytes() {
        assert_eq!(LEAF_V1_PREFIX, 0x01);
        assert_eq!(LEAF_V1_TAG, b"DarkPsarSlotV1");
        assert_eq!(BRANCH_TAG, b"DarkPsarBranch");
    }

    // --- Encoding / determinism -------------------------------------------

    #[test]
    fn leaf_preimage_layout_locked() {
        let s = Slot {
            slot_index: 0x0403_0201,
            pk_user: [0xab; 32],
        };
        let p = s.preimage();
        assert_eq!(p[0], LEAF_V1_PREFIX);
        assert_eq!(&p[1..5], &[0x01, 0x02, 0x03, 0x04]); // LE encoding
        assert_eq!(&p[5..37], &[0xab; 32]);
    }

    #[test]
    fn leaf_hash_is_deterministic() {
        let s = Slot {
            slot_index: 7,
            pk_user: [0x11; 32],
        };
        assert_eq!(s.leaf_hash(), s.leaf_hash());
    }

    #[test]
    fn leaf_hash_changes_with_slot_index() {
        let s1 = Slot {
            slot_index: 0,
            pk_user: [0x11; 32],
        };
        let s2 = Slot {
            slot_index: 1,
            pk_user: [0x11; 32],
        };
        assert_ne!(s1.leaf_hash(), s2.leaf_hash());
    }

    #[test]
    fn leaf_hash_changes_with_pubkey() {
        let s1 = Slot {
            slot_index: 0,
            pk_user: [0x11; 32],
        };
        let s2 = Slot {
            slot_index: 0,
            pk_user: [0x12; 32],
        };
        assert_ne!(s1.leaf_hash(), s2.leaf_hash());
    }

    // --- Tree shape -------------------------------------------------------

    #[test]
    fn empty_tree_has_zero_root() {
        let t = SlotTree::from_members(&[]);
        assert!(t.is_empty());
        assert_eq!(t.root(), SlotRoot([0u8; 32]));
        assert_eq!(SlotRoot::compute(&[]), SlotRoot([0u8; 32]));
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let m = member(1, 0);
        let expected = Slot::from_member(&m).leaf_hash();
        let t = SlotTree::from_members(std::slice::from_ref(&m));
        assert_eq!(t.root(), SlotRoot(expected));
        assert_eq!(
            SlotRoot::compute(std::slice::from_ref(&m)),
            SlotRoot(expected)
        );
    }

    #[test]
    fn two_leaf_root_is_branch_hash() {
        let ms = members(2);
        let h0 = Slot::from_member(&ms[0]).leaf_hash();
        let h1 = Slot::from_member(&ms[1]).leaf_hash();
        let expected = branch_hash(&h0, &h1);
        assert_eq!(SlotRoot::compute(&ms), SlotRoot(expected));
    }

    #[test]
    fn three_leaf_root_promotes_unpaired() {
        // level0: [h0, h1, h2]; level1: [b(h0,h1), h2]; root: b(b(h0,h1), h2)
        let ms = members(3);
        let h: Vec<_> = ms
            .iter()
            .map(|m| Slot::from_member(m).leaf_hash())
            .collect();
        let expected = branch_hash(&branch_hash(&h[0], &h[1]), &h[2]);
        assert_eq!(SlotRoot::compute(&ms), SlotRoot(expected));
    }

    // --- Inclusion-proof round-trip ---------------------------------------

    #[test]
    fn inclusion_proof_round_trip_for_each_k() {
        // K ∈ {1, 2, 3, 4, 7, 16} per issue #667 acceptance.
        for k in [1u32, 2, 3, 4, 7, 16] {
            let ms = members(k);
            let root = SlotRoot::compute(&ms);
            let tree = SlotTree::from_members(&ms);
            for i in 0..k {
                let proof = SlotInclusionProof::generate(&ms, i).expect("generate");
                let leaf = Slot::from_member(&ms[i as usize]);
                assert!(
                    proof.verify(&root, &leaf),
                    "K={k} idx={i}: proof should verify"
                );
                // Tree-side and free-fn-side proofs are equal.
                let proof2 = tree.inclusion_proof(i).expect("tree proof");
                assert_eq!(proof, proof2);
            }
        }
    }

    #[test]
    fn proof_rejects_wrong_leaf() {
        let ms = members(8);
        let root = SlotRoot::compute(&ms);
        let proof = SlotInclusionProof::generate(&ms, 3).unwrap();
        // Leaf with the wrong slot_index for the proof position.
        let bad = Slot {
            slot_index: 0,
            pk_user: ms[3].pk_user,
        };
        assert!(!proof.verify(&root, &bad));
    }

    #[test]
    fn proof_rejects_wrong_root() {
        let ms = members(8);
        let proof = SlotInclusionProof::generate(&ms, 3).unwrap();
        let leaf = Slot::from_member(&ms[3]);
        let wrong_root = SlotRoot([0xff; 32]);
        assert!(!proof.verify(&wrong_root, &leaf));
    }

    #[test]
    fn inclusion_proof_index_out_of_range() {
        let ms = members(4);
        let tree = SlotTree::from_members(&ms);
        assert!(matches!(
            tree.inclusion_proof(4),
            Err(PsarError::SlotIndexOutOfRange {
                slot_index: 4,
                k: 4
            })
        ));
    }

    // --- Mutation-sensitivity property test --------------------------------

    proptest! {
        #[test]
        fn any_byte_mutation_in_proof_step_breaks_verify(
            k in 2u32..=32u32,
            mutate_step_idx in 0usize..32usize,
            mutate_byte_idx in 0usize..32usize,
            xor_byte in 1u8..=255u8,
        ) {
            let ms = members(k);
            let root = SlotRoot::compute(&ms);
            // Pick the middle leaf to ensure the proof has at least one step
            // for K ≥ 2.
            let leaf_index = k / 2;
            let mut proof = SlotInclusionProof::generate(&ms, leaf_index).unwrap();
            prop_assume!(!proof.steps.is_empty());
            let step_idx = mutate_step_idx % proof.steps.len();
            let byte_idx = mutate_byte_idx % 32;
            // Capture original sibling, mutate, verify the mutated proof
            // does not pass.
            let leaf = Slot::from_member(&ms[leaf_index as usize]);
            proof.steps[step_idx].sibling[byte_idx] ^= xor_byte;
            prop_assert!(!proof.verify(&root, &leaf));
        }

        #[test]
        fn pubkey_byte_mutation_changes_leaf_hash(
            byte_idx in 0usize..32usize,
            xor_byte in 1u8..=255u8,
        ) {
            let mut s = Slot {
                slot_index: 9,
                pk_user: [0x33; 32],
            };
            let h_before = s.leaf_hash();
            s.pk_user[byte_idx] ^= xor_byte;
            prop_assert_ne!(h_before, s.leaf_hash());
        }
    }

    // --- Golden vectors ---------------------------------------------------
    //
    // Pin the root for K ∈ {1, 2, 3, 4, 7, 16} so any future change to the
    // leaf encoding, branch tag, or tree shape surfaces immediately. These
    // are computed from the same `members(k)` helper used elsewhere — the
    // generator is deterministic and pinned by the test, so the byte-level
    // values are reproducible.

    fn golden_root_hex(k: u32) -> String {
        hex::encode(SlotRoot::compute(&members(k)).0)
    }

    #[test]
    fn golden_roots_are_pinned_and_distinct() {
        // Distinctness check first: distinct K must produce distinct roots
        // for this generator (since the leaf-set differs by ≥ 1 leaf).
        let ks = [1u32, 2, 3, 4, 7, 16];
        let roots: Vec<String> = ks.iter().map(|&k| golden_root_hex(k)).collect();
        for (i, a) in roots.iter().enumerate() {
            for b in &roots[i + 1..] {
                assert_ne!(a, b, "two different K produced the same root");
            }
        }
        // Pinned hex values — regenerating these is a wire-format change.
        // (Recompute by running this test once with the assertions removed
        // and copying the printed values back here.)
        for (k, expected) in ks.iter().zip(GOLDEN_ROOT_HEX.iter()) {
            assert_eq!(
                golden_root_hex(*k),
                *expected,
                "golden root for K={k} drifted; encoding changed?"
            );
        }
    }

    /// Pinned roots in hex. See `golden_roots_are_pinned_and_distinct`.
    /// Order matches `[1, 2, 3, 4, 7, 16]`.
    const GOLDEN_ROOT_HEX: &[&str] = &[
        "8bc3c85b10c5682eb12435c76c2554c9bcf82a16147e97a8f6b05a77d30ba8b6",
        "8bdc5a940e03a26388fddd6ed283f5d14dda38cb3f32de9f5c20fba3ef5ee519",
        "440a4f373b4fe0f047296ba244c1f87e4987a4cabb28426bffbd723dea8944c4",
        "76cbf8777bddd49296266626893616823e2e8188b4988ae20a156cfbe58cd7df",
        "408d0fbe9e759abedf3305f3c2a1ef529cbd0882c5fc276a9151195fc119788e",
        "83d064216b26370d81f20a47507d2038ff58ff10bbace612ca0263cfcf17fdea",
    ];
}
