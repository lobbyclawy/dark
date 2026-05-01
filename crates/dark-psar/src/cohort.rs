//! Cohort and horizon types (issue #666).
//!
//! A *cohort* is the set of users boarded together for one PSAR
//! lifecycle: their identities, the slot they occupy in the cohort's
//! Merkle tree (see `slot_tree`, #667), and the horizon `N` of
//! per-epoch renewals they pre-signed.
//!
//! The horizon `N` is a **runtime parameter** carried by
//! [`HibernationHorizon`] and validated against `max_n` at construction
//! time. The type layer does not pin a particular `N`: callers — paper
//! benchmarks at `N ∈ {4, 12, 50}`, integration tests at `N=12`,
//! production at whatever the operator chooses — all flow through the
//! same types.
//!
//! [`BoardingState`] enforces a one-way state machine:
//!
//! ```text
//! Forming → Committed → Active → Concluded
//! ```
//!
//! Any other transition (including same-state transitions) returns
//! [`PsarError::InvalidBoardingState`]. The `Cohort` value owns the
//! state and exposes [`Cohort::transition`] as the only mutator.

use serde::{Deserialize, Serialize};

use crate::error::PsarError;

/// Maximum `max_n` accepted by [`HibernationHorizon::new`].
///
/// Mirrors `dark_von::schedule::MAX_HORIZON` semantically (256 slots);
/// pinning the cap here keeps `dark_psar` independent of the VON crate
/// for the type layer. Callers that want a tighter local cap can
/// always pick a smaller `max_n`.
pub const MAX_HORIZON: u32 = 256;

/// Maximum cohort size accepted by [`Cohort::new`].
///
/// PSAR's design point is `K ∈ {100, 1000, 10000}` (paper §4); we cap
/// at 1<<20 = 1 048 576 to keep the slot-Merkle-tree depth bounded
/// without baking a small constant in. Callers benchmarking larger
/// cohorts can lift this cap in a follow-up.
pub const MAX_COHORT_SIZE: u32 = 1 << 20;

/// A user in the cohort.
///
/// `user_id` is an opaque 32-byte identifier (typically the SHA-256 of
/// a user-provided handle or the operator's row id); `pk_user` is the
/// user's BIP-340 x-only public key as raw bytes (32 B);
/// `slot_index` is the user's position in the cohort's slot tree
/// (#667), constrained to `[0, K)` where `K = members.len()`.
///
/// We avoid pulling in `bitcoin::key::XOnlyPublicKey` here so this
/// crate stays buildable without any of the Bitcoin / `secp256k1`
/// stack — that dependency lands in `slot_tree.rs` (#667) where the
/// hash construction needs it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CohortMember {
    /// 32-byte opaque user identifier.
    pub user_id: [u8; 32],
    /// 32-byte BIP-340 x-only public key.
    pub pk_user: [u8; 32],
    /// Position in the cohort slot tree.
    pub slot_index: u32,
}

/// Hibernation horizon: how many epochs of renewals this cohort has
/// pre-signed.
///
/// `n` is the active horizon (`n ≥ 1`); `max_n` is the per-cohort cap
/// validated against [`MAX_HORIZON`]. Both are runtime values; nothing
/// in the type layer pins a constant `N`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HibernationHorizon {
    pub n: u32,
    pub max_n: u32,
}

impl HibernationHorizon {
    /// Construct a horizon, validating `1 ≤ n ≤ max_n ≤ MAX_HORIZON`.
    pub fn new(n: u32, max_n: u32) -> Result<Self, PsarError> {
        if max_n == 0 || max_n > MAX_HORIZON {
            return Err(PsarError::HorizonOutOfRange {
                n: max_n,
                max_n: MAX_HORIZON,
            });
        }
        if n == 0 || n > max_n {
            return Err(PsarError::HorizonOutOfRange { n, max_n });
        }
        Ok(Self { n, max_n })
    }
}

/// One-way lifecycle of a cohort.
///
/// `Forming` is the only state in which new members can be added.
/// `Committed` is reached once the slot Merkle tree has been built and
/// the [`SlotAttest`](crate) has been published (phase 3, #667–#669).
/// `Active` is reached once every user has handed back their
/// pre-signed material (phase 3, #670–#671). `Concluded` is reached
/// once all `N` epochs have been processed (phase 4, #672–#675).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BoardingState {
    Forming,
    Committed,
    Active,
    Concluded,
}

impl BoardingState {
    /// `true` iff `self → next` is a legal transition.
    fn allows(self, next: BoardingState) -> bool {
        matches!(
            (self, next),
            (BoardingState::Forming, BoardingState::Committed)
                | (BoardingState::Committed, BoardingState::Active)
                | (BoardingState::Active, BoardingState::Concluded)
        )
    }
}

/// A cohort with `K` members boarding for a hibernation horizon of `N`.
///
/// Construction validates the horizon, member-count cap, slot-index
/// uniqueness and range, and `user_id` uniqueness. The slot Merkle root
/// is filled in once the slot tree (#667) commits — until then it is
/// `None` and the state stays `Forming`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cohort {
    /// Caller-supplied 32-byte cohort identifier (typically the SHA-256
    /// of `setup_id || start_height` or similar — bound to a value the
    /// ASP commits to before the cohort starts forming).
    pub id: [u8; 32],
    pub members: Vec<CohortMember>,
    pub horizon: HibernationHorizon,
    /// Filled in by `slot_tree::SlotRoot::compute` (#667) when the
    /// cohort transitions `Forming → Committed`.
    pub slot_root: Option<[u8; 32]>,
    state: BoardingState,
}

impl Cohort {
    /// Build a `Forming` cohort, validating member-set invariants.
    ///
    /// Fails with [`PsarError::EmptyCohort`] on an empty member list,
    /// [`PsarError::TooManyMembers`] above [`MAX_COHORT_SIZE`],
    /// [`PsarError::DuplicateSlotIndex`] / [`PsarError::SlotIndexOutOfRange`]
    /// on slot-index issues, or [`PsarError::DuplicateUserId`] on
    /// repeated `user_id`. The horizon must already be valid (built
    /// via [`HibernationHorizon::new`]).
    pub fn new(
        id: [u8; 32],
        members: Vec<CohortMember>,
        horizon: HibernationHorizon,
    ) -> Result<Self, PsarError> {
        if members.is_empty() {
            return Err(PsarError::EmptyCohort);
        }
        let k = members.len() as u64;
        if k > MAX_COHORT_SIZE as u64 {
            return Err(PsarError::TooManyMembers {
                k: members.len() as u32,
                max_k: MAX_COHORT_SIZE,
            });
        }
        let k_u32 = members.len() as u32;
        // O(K log K) uniqueness via sort-projected indices; we copy
        // 32-byte user_ids out for ordering since CohortMember is
        // borrowed elsewhere.
        let mut slots: Vec<u32> = members.iter().map(|m| m.slot_index).collect();
        slots.sort_unstable();
        for window in slots.windows(2) {
            if window[0] == window[1] {
                return Err(PsarError::DuplicateSlotIndex {
                    slot_index: window[0],
                });
            }
        }
        for &s in &slots {
            if s >= k_u32 {
                return Err(PsarError::SlotIndexOutOfRange {
                    slot_index: s,
                    k: k_u32,
                });
            }
        }
        let mut user_ids: Vec<[u8; 32]> = members.iter().map(|m| m.user_id).collect();
        user_ids.sort_unstable();
        for window in user_ids.windows(2) {
            if window[0] == window[1] {
                return Err(PsarError::DuplicateUserId);
            }
        }
        Ok(Self {
            id,
            members,
            horizon,
            slot_root: None,
            state: BoardingState::Forming,
        })
    }

    /// Number of members `K`.
    pub fn k(&self) -> u32 {
        self.members.len() as u32
    }

    /// Current lifecycle state.
    pub fn state(&self) -> BoardingState {
        self.state
    }

    /// Move to `next`, enforcing the legal transition table.
    pub fn transition(&mut self, next: BoardingState) -> Result<(), PsarError> {
        if !self.state.allows(next) {
            return Err(PsarError::InvalidBoardingState {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }
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

    #[test]
    fn horizon_new_accepts_typical_paper_values() {
        for n in [1u32, 4, 12, 50, 256] {
            let h = HibernationHorizon::new(n, 256).expect("valid horizon");
            assert_eq!(h.n, n);
            assert_eq!(h.max_n, 256);
        }
    }

    #[test]
    fn horizon_new_rejects_zero_n() {
        let err = HibernationHorizon::new(0, 12).unwrap_err();
        assert!(matches!(err, PsarError::HorizonOutOfRange { n: 0, .. }));
    }

    #[test]
    fn horizon_new_rejects_n_above_max_n() {
        let err = HibernationHorizon::new(13, 12).unwrap_err();
        assert!(matches!(
            err,
            PsarError::HorizonOutOfRange { n: 13, max_n: 12 }
        ));
    }

    #[test]
    fn horizon_new_rejects_max_n_above_global_cap() {
        let err = HibernationHorizon::new(1, MAX_HORIZON + 1).unwrap_err();
        assert!(matches!(err, PsarError::HorizonOutOfRange { .. }));
    }

    #[test]
    fn cohort_new_happy_path_two_members() {
        let h = HibernationHorizon::new(4, 12).unwrap();
        let c = Cohort::new([0x11; 32], vec![member(1, 0), member(2, 1)], h).unwrap();
        assert_eq!(c.k(), 2);
        assert_eq!(c.state(), BoardingState::Forming);
        assert!(c.slot_root.is_none());
    }

    #[test]
    fn cohort_new_rejects_empty_member_list() {
        let h = HibernationHorizon::new(1, 12).unwrap();
        assert_eq!(
            Cohort::new([0u8; 32], vec![], h),
            Err(PsarError::EmptyCohort)
        );
    }

    #[test]
    fn cohort_new_rejects_duplicate_slot_index() {
        let h = HibernationHorizon::new(1, 12).unwrap();
        let err = Cohort::new([0u8; 32], vec![member(1, 0), member(2, 0)], h).unwrap_err();
        assert!(matches!(
            err,
            PsarError::DuplicateSlotIndex { slot_index: 0 }
        ));
    }

    #[test]
    fn cohort_new_rejects_slot_index_out_of_range() {
        let h = HibernationHorizon::new(1, 12).unwrap();
        // Two members but slot_index = 2 (must be in [0, 2)).
        let err = Cohort::new([0u8; 32], vec![member(1, 0), member(2, 2)], h).unwrap_err();
        assert!(matches!(
            err,
            PsarError::SlotIndexOutOfRange {
                slot_index: 2,
                k: 2
            }
        ));
    }

    #[test]
    fn cohort_new_rejects_duplicate_user_id() {
        let h = HibernationHorizon::new(1, 12).unwrap();
        // Same user_id, distinct slots — the user-id dedup must still catch it.
        let dup = CohortMember {
            user_id: [9u8; 32],
            pk_user: [10u8; 32],
            slot_index: 1,
        };
        let err = Cohort::new([0u8; 32], vec![member(9, 0), dup], h).unwrap_err();
        assert_eq!(err, PsarError::DuplicateUserId);
    }

    #[test]
    fn boarding_state_legal_transitions_full_cycle() {
        let h = HibernationHorizon::new(1, 12).unwrap();
        let mut c = Cohort::new([0u8; 32], vec![member(1, 0)], h).unwrap();
        for next in [
            BoardingState::Committed,
            BoardingState::Active,
            BoardingState::Concluded,
        ] {
            c.transition(next).expect("legal transition");
            assert_eq!(c.state(), next);
        }
    }

    #[test]
    fn boarding_state_rejects_skip_forming_to_active() {
        let h = HibernationHorizon::new(1, 12).unwrap();
        let mut c = Cohort::new([0u8; 32], vec![member(1, 0)], h).unwrap();
        let err = c.transition(BoardingState::Active).unwrap_err();
        assert_eq!(
            err,
            PsarError::InvalidBoardingState {
                from: BoardingState::Forming,
                to: BoardingState::Active,
            }
        );
    }

    #[test]
    fn boarding_state_rejects_self_transition() {
        let h = HibernationHorizon::new(1, 12).unwrap();
        let mut c = Cohort::new([0u8; 32], vec![member(1, 0)], h).unwrap();
        let err = c.transition(BoardingState::Forming).unwrap_err();
        assert!(matches!(err, PsarError::InvalidBoardingState { .. }));
    }

    #[test]
    fn boarding_state_rejects_backward_transition() {
        let h = HibernationHorizon::new(1, 12).unwrap();
        let mut c = Cohort::new([0u8; 32], vec![member(1, 0)], h).unwrap();
        c.transition(BoardingState::Committed).unwrap();
        let err = c.transition(BoardingState::Forming).unwrap_err();
        assert!(matches!(err, PsarError::InvalidBoardingState { .. }));
    }

    proptest! {
        #[test]
        fn horizon_serde_round_trip(n in 1u32..=256, max_n in 1u32..=256) {
            // Discard generator pairs where n > max_n.
            prop_assume!(n <= max_n);
            let h = HibernationHorizon::new(n, max_n).expect("valid horizon");
            let json = serde_json::to_string(&h).unwrap();
            let parsed: HibernationHorizon = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed, h);
        }

        #[test]
        fn boarding_state_serde_round_trip(s in 0u8..4u8) {
            let state = match s {
                0 => BoardingState::Forming,
                1 => BoardingState::Committed,
                2 => BoardingState::Active,
                _ => BoardingState::Concluded,
            };
            let json = serde_json::to_string(&state).unwrap();
            let parsed: BoardingState = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed, state);
        }
    }
}
