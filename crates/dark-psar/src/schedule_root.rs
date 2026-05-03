//! Schedule-commitment Merkle root over the published Λ entries.
//!
//! Each leaf binds a single `(cohort_id, setup_id, t, b, R, π)` tuple.
//! The root is committed as a field of [`crate::SlotAttestUnsigned`], so
//! the ASP's BIP-340 signature on `slot_attest` binds the entire
//! per-cohort schedule. Two signed `slot_attest`s with the same
//! `cohort_id` but different `schedule_root`s constitute publicly
//! verifiable equivocation evidence — the operator has signed two
//! conflicting schedules under the same long-term key.
//!
//! # Why this layer (not VRF uniqueness)
//!
//! ECVRF uniqueness binds `(pk, x) → unique (β, π)`. The wrapper from
//! [`dark_von::wrapper`] uses `α' = x ∥ R` as the VRF input, so two
//! distinct `R, R'` give two distinct VRF inputs and ECVRF uniqueness
//! does not bound them per-slot. The wrapper provides
//! *operator-certified-R* for each slot, not per-slot uniqueness.
//! Per-slot binding is delivered at this layer: the schedule is
//! collated, hashed into a Merkle tree, and the root is signed under
//! the operator's BIP-340 attestation key. Equivocation moves from
//! "two valid VRF proofs on different inputs" (allowed under VRF
//! uniqueness) to "two BIP-340 signatures on conflicting schedule
//! roots" (a Schnorr-key equivocation observable by anyone with both
//! signed `slot_attest`s).
//!
//! # Wire format
//!
//! - Leaf preimage layout (130 B):
//!
//!   ```text
//!   | 0x01 LEAF_V1 | cohort_id (32) | setup_id (32) | t LE u32 (4) | b u8 (1) | R (33) | sha256(π) (32) |
//!   ```
//!
//!   The 81-byte VON proof `π` is hashed (SHA-256) into 32 bytes
//!   inside the preimage to keep the leaf fixed-width and the tree
//!   skim-friendly. Verifiers reconstruct `sha256(π)` from the
//!   published Λ entry, no proof bytes embedded in the leaf preimage.
//! - Leaf hash: `tagged_hash(SCHEDULE_LEAF_TAG, preimage)`
//!   with `SCHEDULE_LEAF_TAG = b"DarkPsarScheduleLeafV1"`.
//! - Branch hash: `tagged_hash(SCHEDULE_BRANCH_TAG, l ∥ r)`
//!   with `SCHEDULE_BRANCH_TAG = b"DarkPsarScheduleBranchV1"`.
//!
//! Tree shape: standard binary Merkle (mirrors [`crate::slot_tree`]) —
//! pairs combine left-to-right; an unpaired right-most node at any
//! level is promoted unchanged. Empty entry list yields the zero root.
//!
//! Leaf order: for `t = 1, …, n` and `b = 1, 2`, leaves are emitted in
//! the order `(t=1, b=1), (t=1, b=2), (t=2, b=1), …`.

use sha2::{Digest, Sha256};

use dark_von_musig2::setup::PublishedSchedule;

/// Leading byte of the V1 schedule-leaf preimage.
pub const LEAF_V1_PREFIX: u8 = 0x01;

/// BIP-340 tagged-hash tag for schedule-tree leaves.
pub const SCHEDULE_LEAF_TAG: &[u8] = b"DarkPsarScheduleLeafV1";

/// BIP-340 tagged-hash tag for schedule-tree branch nodes.
pub const SCHEDULE_BRANCH_TAG: &[u8] = b"DarkPsarScheduleBranchV1";

/// 32-byte schedule-commitment root. Wraps a digest so callers cannot
/// mistake it for any other 32-byte hash in the codebase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScheduleRoot(pub [u8; 32]);

impl ScheduleRoot {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Compute `ScheduleRoot` over the entries of `schedule` for the given
/// `cohort_id`. The leaves are emitted in `(t=1..n, b=1..2)` order.
///
/// The cohort id is folded into every leaf preimage, so two cohorts
/// sharing a `schedule` (same `setup_id`, same horizon) yield distinct
/// roots. This makes per-cohort accountability cheap: a verifier given
/// `(cohort_id, schedule)` can recompute the root in
/// `O(2N · sha256)`.
pub fn compute_schedule_root(
    cohort_id: &[u8; 32],
    schedule: &PublishedSchedule,
) -> Result<ScheduleRoot, ScheduleRootError> {
    if schedule.setup_id.len() != 32 {
        return Err(ScheduleRootError::MalformedSetupId {
            got: schedule.setup_id.len(),
        });
    }
    if schedule.entries.len() != schedule.n as usize {
        return Err(ScheduleRootError::EntryCountMismatch {
            entries: schedule.entries.len(),
            n: schedule.n,
        });
    }
    let mut setup_id_arr = [0u8; 32];
    setup_id_arr.copy_from_slice(&schedule.setup_id);

    let mut leaves = Vec::with_capacity(2 * schedule.entries.len());
    for (idx, entry) in schedule.entries.iter().enumerate() {
        let t = (idx as u32) + 1;
        leaves.push(leaf_hash(
            cohort_id,
            &setup_id_arr,
            t,
            1,
            &entry.r1,
            &entry.proof1,
        )?);
        leaves.push(leaf_hash(
            cohort_id,
            &setup_id_arr,
            t,
            2,
            &entry.r2,
            &entry.proof2,
        )?);
    }
    Ok(ScheduleRoot(merkle_root(&leaves)))
}

/// Construction errors for [`compute_schedule_root`].
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScheduleRootError {
    #[error("malformed setup_id: expected 32 bytes, got {got}")]
    MalformedSetupId { got: usize },
    #[error("entry count {entries} disagrees with n={n}")]
    EntryCountMismatch { entries: usize, n: u32 },
    #[error("malformed r_point: expected 33 bytes, got {got}")]
    MalformedR { got: usize },
    #[error("malformed proof: expected 81 bytes, got {got}")]
    MalformedProof { got: usize },
}

fn leaf_hash(
    cohort_id: &[u8; 32],
    setup_id: &[u8; 32],
    t: u32,
    b: u8,
    r: &[u8],
    proof: &[u8],
) -> Result<[u8; 32], ScheduleRootError> {
    if r.len() != 33 {
        return Err(ScheduleRootError::MalformedR { got: r.len() });
    }
    if proof.len() != 81 {
        return Err(ScheduleRootError::MalformedProof { got: proof.len() });
    }
    let proof_digest: [u8; 32] = Sha256::digest(proof).into();
    let mut preimage = [0u8; 1 + 32 + 32 + 4 + 1 + 33 + 32];
    preimage[0] = LEAF_V1_PREFIX;
    preimage[1..33].copy_from_slice(cohort_id);
    preimage[33..65].copy_from_slice(setup_id);
    preimage[65..69].copy_from_slice(&t.to_le_bytes());
    preimage[69] = b;
    preimage[70..103].copy_from_slice(r);
    preimage[103..135].copy_from_slice(&proof_digest);
    Ok(tagged_hash(SCHEDULE_LEAF_TAG, &preimage))
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            if chunk.len() == 2 {
                let mut concat = [0u8; 64];
                concat[..32].copy_from_slice(&chunk[0]);
                concat[32..].copy_from_slice(&chunk[1]);
                next.push(tagged_hash(SCHEDULE_BRANCH_TAG, &concat));
            } else {
                next.push(chunk[0]);
            }
        }
        layer = next;
    }
    layer[0]
}

fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(msg);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dark_von_musig2::setup::{PublishedEntry, PublishedSchedule};

    fn fake_entry(seed: u8) -> PublishedEntry {
        PublishedEntry {
            r1: vec![seed.wrapping_add(0x10); 33],
            proof1: vec![seed.wrapping_add(0x20); 81],
            r2: vec![seed.wrapping_add(0x30); 33],
            proof2: vec![seed.wrapping_add(0x40); 81],
        }
    }

    fn fake_schedule(n: u32) -> PublishedSchedule {
        PublishedSchedule {
            setup_id: vec![0xc4u8; 32],
            n,
            entries: (0..n as u8).map(fake_entry).collect(),
        }
    }

    #[test]
    fn schedule_root_is_deterministic() {
        let cohort_id = [0xab; 32];
        let s = fake_schedule(4);
        let r1 = compute_schedule_root(&cohort_id, &s).unwrap();
        let r2 = compute_schedule_root(&cohort_id, &s).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn distinct_cohorts_yield_distinct_roots() {
        let s = fake_schedule(4);
        let r_a = compute_schedule_root(&[0x01; 32], &s).unwrap();
        let r_b = compute_schedule_root(&[0x02; 32], &s).unwrap();
        assert_ne!(r_a, r_b);
    }

    #[test]
    fn distinct_setup_ids_yield_distinct_roots() {
        let cohort_id = [0xab; 32];
        let mut s_a = fake_schedule(4);
        s_a.setup_id = vec![0x01; 32];
        let mut s_b = fake_schedule(4);
        s_b.setup_id = vec![0x02; 32];
        let r_a = compute_schedule_root(&cohort_id, &s_a).unwrap();
        let r_b = compute_schedule_root(&cohort_id, &s_b).unwrap();
        assert_ne!(r_a, r_b);
    }

    #[test]
    fn flipping_one_byte_of_a_proof_changes_the_root() {
        let cohort_id = [0xab; 32];
        let mut s = fake_schedule(3);
        let r0 = compute_schedule_root(&cohort_id, &s).unwrap();
        s.entries[1].proof1[0] ^= 0x01;
        let r1 = compute_schedule_root(&cohort_id, &s).unwrap();
        assert_ne!(r0, r1);
    }

    #[test]
    fn flipping_one_byte_of_an_r_changes_the_root() {
        let cohort_id = [0xab; 32];
        let mut s = fake_schedule(3);
        let r0 = compute_schedule_root(&cohort_id, &s).unwrap();
        s.entries[2].r2[5] ^= 0xff;
        let r1 = compute_schedule_root(&cohort_id, &s).unwrap();
        assert_ne!(r0, r1);
    }

    #[test]
    fn rejects_entry_count_mismatch() {
        let mut s = fake_schedule(3);
        s.n = 5;
        let err = compute_schedule_root(&[0; 32], &s).unwrap_err();
        assert!(matches!(
            err,
            ScheduleRootError::EntryCountMismatch { entries: 3, n: 5 }
        ));
    }

    #[test]
    fn rejects_malformed_r_length() {
        let cohort_id = [0; 32];
        let mut s = fake_schedule(2);
        s.entries[0].r1 = vec![0u8; 32]; // 32 instead of 33
        let err = compute_schedule_root(&cohort_id, &s).unwrap_err();
        assert!(matches!(err, ScheduleRootError::MalformedR { got: 32 }));
    }

    #[test]
    fn empty_schedule_n_zero_yields_zero_root() {
        let s = PublishedSchedule {
            setup_id: vec![0u8; 32],
            n: 0,
            entries: Vec::new(),
        };
        let r = compute_schedule_root(&[0; 32], &s).unwrap();
        assert_eq!(r.0, [0u8; 32]);
    }

    #[test]
    fn pinned_tags() {
        assert_eq!(SCHEDULE_LEAF_TAG, b"DarkPsarScheduleLeafV1");
        assert_eq!(SCHEDULE_BRANCH_TAG, b"DarkPsarScheduleBranchV1");
    }
}
