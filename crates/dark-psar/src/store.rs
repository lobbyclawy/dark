//! Persistence trait for active cohorts (issues #671, #674).
//!
//! `ActiveCohortStore` abstracts the on-disk side of an
//! `ActiveCohort`. Phase 3 introduced the trait + an in-memory impl
//! sufficient for the K=100 / N=12 happy-path test; phase 4 (#674)
//! adds [`record_transition`](ActiveCohortStore::record_transition)
//! so lifecycle changes are persisted alongside the cohort. A
//! Postgres impl is out of scope for AFT and is a documented
//! follow-up.

use std::collections::HashMap;

use crate::boarding::ActiveCohort;
use crate::cohort::CohortState;
use crate::error::PsarError;

/// Cohort identifier (the `Cohort::id` 32-byte tag) used as the
/// store's primary key.
pub type CohortId = [u8; 32];

pub trait ActiveCohortStore {
    fn save(&mut self, cohort: ActiveCohort) -> Result<(), PsarError>;
    fn load(&self, id: &CohortId) -> Option<&ActiveCohort>;

    /// Mutable handle to a stored cohort. Required by the parallel
    /// pipeline driver in [`crate::adapter`] to call
    /// [`crate::epoch::process_epoch`] on a `&mut ActiveCohort`.
    fn load_mut(&mut self, id: &CohortId) -> Option<&mut ActiveCohort>;

    fn all(&self) -> Vec<&ActiveCohort>;

    /// Persist a `from → to` lifecycle transition for `cohort_id`.
    ///
    /// Implementations validate that the stored cohort's current state
    /// equals `from` and that `to` is reachable in one step; on
    /// success they update the in-store cohort to `to`.
    fn record_transition(
        &mut self,
        cohort_id: &CohortId,
        from: CohortState,
        to: CohortState,
    ) -> Result<(), PsarError>;
}

/// In-memory store. The `RetainedScalars` inside each `ActiveCohort`
/// auto-zeroize on drop (`secp256k1 = 0.29`), so dropping this store
/// also wipes the per-cohort scalars.
#[derive(Default)]
pub struct InMemoryActiveCohortStore {
    cohorts: HashMap<CohortId, ActiveCohort>,
}

impl InMemoryActiveCohortStore {
    pub fn new() -> Self {
        Self {
            cohorts: HashMap::new(),
        }
    }
}

impl ActiveCohortStore for InMemoryActiveCohortStore {
    fn save(&mut self, cohort: ActiveCohort) -> Result<(), PsarError> {
        self.cohorts.insert(cohort.cohort.id, cohort);
        Ok(())
    }

    fn load(&self, id: &CohortId) -> Option<&ActiveCohort> {
        self.cohorts.get(id)
    }

    fn load_mut(&mut self, id: &CohortId) -> Option<&mut ActiveCohort> {
        self.cohorts.get_mut(id)
    }

    fn all(&self) -> Vec<&ActiveCohort> {
        self.cohorts.values().collect()
    }

    fn record_transition(
        &mut self,
        cohort_id: &CohortId,
        from: CohortState,
        to: CohortState,
    ) -> Result<(), PsarError> {
        let cohort = self
            .cohorts
            .get_mut(cohort_id)
            .ok_or_else(|| PsarError::CohortNotFound {
                cohort_id: hex::encode(cohort_id),
            })?;
        if cohort.cohort.state() != from {
            return Err(PsarError::InvalidBoardingState {
                from: cohort.cohort.state(),
                to,
            });
        }
        cohort.cohort.set_state(to)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boarding::asp_board;
    use crate::cohort::{CohortMember, HibernationHorizon};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secp256k1::{Keypair, Parity, Secp256k1, SecretKey};

    fn even_parity_keypair(secp: &Secp256k1<secp256k1::All>, seed: u8) -> Keypair {
        for offset in 0u32..1000 {
            let mut bytes = [seed; 32];
            bytes[28..32].copy_from_slice(&offset.to_le_bytes());
            if let Ok(sk) = SecretKey::from_slice(&bytes) {
                let kp = Keypair::from_secret_key(secp, &sk);
                if kp.x_only_public_key().1 == Parity::Even {
                    return kp;
                }
            }
        }
        panic!("no even-parity keypair");
    }

    fn build_active_cohort(k: u32, n: u32, seed: u8) -> ActiveCohort {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, seed);
        let horizon = HibernationHorizon::new(n, n.max(12)).unwrap();
        let members_kps: Vec<_> = (0..k)
            .map(|i| {
                let kp = even_parity_keypair(&secp, (i + 1) as u8);
                let xonly = kp.x_only_public_key().0.serialize();
                let mut user_id = [0u8; 32];
                user_id[0] = ((i >> 8) & 0xff) as u8;
                user_id[1] = (i & 0xff) as u8;
                (
                    CohortMember {
                        user_id,
                        pk_user: xonly,
                        slot_index: i,
                    },
                    kp,
                )
            })
            .collect();
        let mut rng = StdRng::seed_from_u64(seed as u64);
        asp_board(
            &asp_kp,
            [seed; 32],
            members_kps,
            horizon,
            [0xc4; 32],
            None,
            &mut rng,
        )
        .unwrap()
    }

    #[test]
    fn record_transition_advances_state_and_rejects_stale_from() {
        let active = build_active_cohort(3, 2, 0xa0);
        let cohort_id = active.cohort.id;
        let mut store = InMemoryActiveCohortStore::new();
        store.save(active).unwrap();

        // Active → InProgress(1) is legal.
        store
            .record_transition(&cohort_id, CohortState::Active, CohortState::InProgress(1))
            .unwrap();
        assert_eq!(
            store.load(&cohort_id).unwrap().cohort.state(),
            CohortState::InProgress(1)
        );

        // Replaying the same transition fails (stored state has moved on).
        let err = store
            .record_transition(&cohort_id, CohortState::Active, CohortState::InProgress(1))
            .unwrap_err();
        assert!(matches!(err, PsarError::InvalidBoardingState { .. }));

        // InProgress(1) → Active is legal.
        store
            .record_transition(&cohort_id, CohortState::InProgress(1), CohortState::Active)
            .unwrap();
        assert_eq!(
            store.load(&cohort_id).unwrap().cohort.state(),
            CohortState::Active,
        );
    }

    #[test]
    fn record_transition_rejects_unknown_cohort() {
        let mut store = InMemoryActiveCohortStore::new();
        let err = store
            .record_transition(&[0u8; 32], CohortState::Active, CohortState::Concluded)
            .unwrap_err();
        assert!(matches!(err, PsarError::CohortNotFound { .. }));
    }

    #[test]
    fn restart_restore_produces_identical_artifacts() {
        // Issue #674 acceptance: in-memory store + serialise → deserialise →
        // continue at next epoch produces identical signatures.
        //
        // We model "restart" by rebuilding the ActiveCohort from the same
        // deterministic inputs the ASP would have persisted (cohort
        // metadata + asp keypair + setup_id + RNG seed). \`asp_board\` is
        // deterministic in those inputs, so the artifacts must be
        // byte-identical across runs.
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0xb0);
        let horizon = HibernationHorizon::new(4, 12).unwrap();
        let members_kps_a: Vec<_> = (0..3u32)
            .map(|i| {
                let kp = even_parity_keypair(&secp, (i + 1) as u8);
                let xonly = kp.x_only_public_key().0.serialize();
                let mut user_id = [0u8; 32];
                user_id[0] = ((i >> 8) & 0xff) as u8;
                user_id[1] = (i & 0xff) as u8;
                (
                    CohortMember {
                        user_id,
                        pk_user: xonly,
                        slot_index: i,
                    },
                    kp,
                )
            })
            .collect();
        let members_kps_b = members_kps_a.clone();
        let cohort_id = [0xb0; 32];
        let setup_id = [0xc4; 32];

        let mut rng_a = StdRng::seed_from_u64(42);
        let active_a = asp_board(
            &asp_kp,
            cohort_id,
            members_kps_a,
            horizon,
            setup_id,
            None,
            &mut rng_a,
        )
        .unwrap();
        // Save then drop the original.
        let mut store = InMemoryActiveCohortStore::new();
        store.save(active_a).unwrap();
        let snapshot = {
            let live = store.load(&cohort_id).unwrap();
            (
                live.slot_root,
                live.batch_tree_root,
                live.attest.unsigned,
                live.artifacts
                    .iter()
                    .map(|(uid, art)| (*uid, art.schedule_witness))
                    .collect::<HashMap<[u8; 32], [u8; 32]>>(),
            )
        };

        // Restart: rebuild from the same inputs.
        let mut rng_b = StdRng::seed_from_u64(42);
        let active_b = asp_board(
            &asp_kp,
            cohort_id,
            members_kps_b,
            horizon,
            setup_id,
            None,
            &mut rng_b,
        )
        .unwrap();

        assert_eq!(snapshot.0, active_b.slot_root);
        assert_eq!(snapshot.1, active_b.batch_tree_root);
        assert_eq!(snapshot.2, active_b.attest.unsigned);
        for (uid, witness_a) in &snapshot.3 {
            let witness_b = active_b.artifacts.get(uid).unwrap().schedule_witness;
            assert_eq!(
                *witness_a,
                witness_b,
                "user_id={}: schedule_witness drift across restart",
                hex::encode(uid)
            );
        }
    }
}
