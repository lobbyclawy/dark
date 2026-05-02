//! Parallel-pipeline driver for PSAR cohorts (issue #678).
//!
//! See `docs/adr/0009-psar-integration.md`. This module owns the
//! ASP-side per-epoch driver for cohorts tagged
//! [`crate::asp_mode::AspMode::Psar`]. Standard cohorts are not
//! visited — the standard-mode round loop in `dark-core` handles them
//! through `dark_bitcoin::signing` exactly as before, which is the
//! parity gate from ADR-0009.
//!
//! ## Driver shape
//!
//! [`Driver`] holds:
//!
//! - An [`AspModeRegistry`] mapping `cohort_id → AspMode`.
//! - An [`ActiveCohortStore`] of in-flight cohorts produced by
//!   [`crate::boarding::asp_board`].
//!
//! Each [`Driver::tick`] call walks every PSAR-tagged cohort and runs
//! [`process_epoch`] for it when (a) the cohort is present in the
//! store, (b) its lifecycle state is [`CohortState::Active`], and
//! (c) the requested epoch `t` is within the cohort's hibernation
//! horizon. Cohorts that fail any of these checks are reported in
//! [`TickReport::skipped`]; cohorts whose `process_epoch` returns an
//! error are reported in [`TickReport::errors`] without aborting the
//! rest of the tick.

use std::collections::HashMap;

use secp256k1::Keypair;

use crate::asp_mode::AspModeRegistry;
use crate::cohort::CohortState;
use crate::epoch::{process_epoch, EpochArtifacts};
use crate::error::PsarError;
use crate::store::{ActiveCohortStore, CohortId};

/// Outcome of one [`Driver::tick`] call across every PSAR cohort.
#[derive(Debug, Default)]
pub struct TickReport {
    /// Per-cohort epoch artifacts produced this tick.
    pub artifacts: HashMap<CohortId, EpochArtifacts>,
    /// Cohort ids skipped because they were absent from the store,
    /// not at `Active`, or had an out-of-range epoch for their horizon.
    pub skipped: Vec<CohortId>,
    /// Cohort ids whose `process_epoch` call returned an error.
    pub errors: Vec<(CohortId, PsarError)>,
}

impl TickReport {
    /// Number of cohorts that produced artifacts this tick.
    pub fn ok_count(&self) -> usize {
        self.artifacts.len()
    }
}

/// PSAR parallel-pipeline driver.
pub struct Driver<S: ActiveCohortStore> {
    registry: AspModeRegistry,
    store: S,
}

impl<S: ActiveCohortStore> Driver<S> {
    pub fn new(registry: AspModeRegistry, store: S) -> Self {
        Self { registry, store }
    }

    pub fn registry(&self) -> &AspModeRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut AspModeRegistry {
        &mut self.registry
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Drive every PSAR-tagged cohort through epoch `t`.
    pub fn tick(&mut self, asp_kp: &Keypair, t: u32) -> TickReport {
        let candidates: Vec<(CohortId, u32)> = self
            .registry
            .psar_cohorts()
            .map(|(id, h)| (id, h.n))
            .collect();

        let mut report = TickReport::default();

        for (cohort_id, n) in candidates {
            if t == 0 || t > n {
                report.skipped.push(cohort_id);
                continue;
            }

            let Some(active) = self.store.load_mut(&cohort_id) else {
                report.skipped.push(cohort_id);
                continue;
            };
            if active.cohort.state() != CohortState::Active {
                report.skipped.push(cohort_id);
                continue;
            }

            match process_epoch(active, asp_kp, t) {
                Ok(arts) => {
                    report.artifacts.insert(cohort_id, arts);
                }
                Err(err) => {
                    report.errors.push((cohort_id, err));
                }
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secp256k1::{schnorr::Signature, Message, Parity, Secp256k1, SecretKey, XOnlyPublicKey};

    use crate::asp_mode::AspMode;
    use crate::boarding::asp_board;
    use crate::cohort::{CohortMember, HibernationHorizon};
    use crate::message::derive_message_for_epoch;
    use crate::store::InMemoryActiveCohortStore;
    use dark_von_musig2::sign::build_key_agg_ctx;

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

    fn lift_xonly_to_even(pk: &XOnlyPublicKey) -> secp256k1::PublicKey {
        let xb = pk.serialize();
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&xb);
        secp256k1::PublicKey::from_slice(&compressed).expect("even-parity lift")
    }

    fn build_active(
        secp: &Secp256k1<secp256k1::All>,
        k: u32,
        n: u32,
        seed: u8,
    ) -> (Keypair, crate::boarding::ActiveCohort) {
        let asp_kp = even_parity_keypair(secp, seed);
        let horizon = HibernationHorizon::new(n, n.max(12)).unwrap();
        let members_kps: Vec<_> = (0..k)
            .map(|i| {
                let kp = even_parity_keypair(secp, (i + 1) as u8);
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
        let active = asp_board(
            &asp_kp,
            [seed; 32],
            members_kps,
            horizon,
            [0xc4; 32],
            None,
            &mut rng,
        )
        .unwrap();
        (asp_kp, active)
    }

    #[test]
    fn tick_with_empty_registry_is_noop() {
        let registry = AspModeRegistry::new();
        let store = InMemoryActiveCohortStore::new();
        let mut driver = Driver::new(registry, store);
        let secp = Secp256k1::new();
        let dummy = even_parity_keypair(&secp, 0xee);
        let report = driver.tick(&dummy, 1);
        assert_eq!(report.ok_count(), 0);
        assert!(report.skipped.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn tick_skips_standard_cohort() {
        let secp = Secp256k1::new();
        let (asp_kp, active) = build_active(&secp, 2, 2, 0xa1);
        let cohort_id = active.cohort.id;

        let mut store = InMemoryActiveCohortStore::new();
        store.save(active).unwrap();
        let mut registry = AspModeRegistry::new();
        registry.insert(cohort_id, AspMode::Standard);

        let mut driver = Driver::new(registry, store);
        let report = driver.tick(&asp_kp, 1);
        assert_eq!(report.ok_count(), 0);
        assert!(report.skipped.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn tick_skips_unregistered_cohort_in_store() {
        // A cohort present in the store but absent from the registry
        // is implicitly Standard and gets skipped.
        let secp = Secp256k1::new();
        let (asp_kp, active) = build_active(&secp, 2, 2, 0xa2);

        let mut store = InMemoryActiveCohortStore::new();
        store.save(active).unwrap();

        let mut driver = Driver::new(AspModeRegistry::new(), store);
        let report = driver.tick(&asp_kp, 1);
        assert_eq!(report.ok_count(), 0);
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn tick_runs_psar_cohort_through_epoch_one() {
        let secp = Secp256k1::new();
        let (asp_kp, active) = build_active(&secp, 2, 4, 0xa3);
        let cohort_id = active.cohort.id;
        let horizon = active.cohort.horizon;

        let mut store = InMemoryActiveCohortStore::new();
        store.save(active).unwrap();
        let mut registry = AspModeRegistry::new();
        registry.insert(cohort_id, AspMode::Psar(horizon));

        let mut driver = Driver::new(registry, store);
        let report = driver.tick(&asp_kp, 1);
        assert_eq!(report.ok_count(), 1);
        let arts = report.artifacts.get(&cohort_id).expect("arts present");
        assert_eq!(arts.epoch, 1);
        assert_eq!(arts.n, horizon.n);
        assert_eq!(arts.signatures.len(), 2);
        assert!(arts.failures.is_empty());

        // Stored cohort is back at Active after the tick (or Concluded
        // when t == n).
        let stored_state = driver.store().load(&cohort_id).unwrap().cohort.state();
        assert_eq!(stored_state, CohortState::Active);
    }

    /// #678 acceptance: a 2-of-2 cohort configured with
    /// `Psar(HibernationHorizon { n: 4, .. })` produces the expected
    /// horizon of pre-signed renewals — i.e., four valid epoch-bound
    /// 2-of-2 BIP-340 aggregates, one per epoch.
    #[test]
    fn psar_2of2_n4_yields_full_horizon_of_renewals() {
        let secp = Secp256k1::new();
        let (asp_kp, active) = build_active(&secp, 2, 4, 0xa4);
        let cohort_id = active.cohort.id;
        let horizon = active.cohort.horizon;
        let asp_xonly = asp_kp.x_only_public_key().0;

        let mut store = InMemoryActiveCohortStore::new();
        store.save(active).unwrap();
        let mut registry = AspModeRegistry::new();
        registry.insert(cohort_id, AspMode::Psar(horizon));

        let mut driver = Driver::new(registry, store);
        let mut all_sigs: Vec<(u32, [u8; 32], [u8; 64])> = Vec::new();

        for t in 1..=horizon.n {
            let report = driver.tick(&asp_kp, t);
            assert!(report.errors.is_empty(), "errors at epoch {t}");
            assert!(report.skipped.is_empty(), "skipped at epoch {t}");
            assert_eq!(report.ok_count(), 1);
            let arts = report.artifacts.get(&cohort_id).expect("arts");
            assert_eq!(arts.signatures.len(), 2);
            for (user_id, sig) in &arts.signatures {
                all_sigs.push((t, *user_id, *sig));
            }
        }
        assert_eq!(
            all_sigs.len(),
            (horizon.n as usize) * 2,
            "K=2 × N=4 = 8 sigs total"
        );

        // Verify every collected sig under its 2-of-2 BIP-340 aggregate
        // pubkey + per-epoch message — the parity gate the issue asks for.
        let asp_full = lift_xonly_to_even(&asp_xonly);
        let active_view = driver.store().load(&cohort_id).unwrap();
        let slot_root = active_view.slot_root.as_bytes();
        let batch_root = active_view.batch_tree_root;
        for (t, user_id, sig_bytes) in &all_sigs {
            let member = active_view
                .cohort
                .members
                .iter()
                .find(|m| m.user_id == *user_id)
                .expect("member");
            let user_xonly = XOnlyPublicKey::from_slice(&member.pk_user).unwrap();
            let user_full = lift_xonly_to_even(&user_xonly);
            let ctx = build_key_agg_ctx(&[asp_full, user_full]).unwrap();
            let agg_xonly = XOnlyPublicKey::from_slice(&ctx.x_only_pubkey()).unwrap();
            let m_t = derive_message_for_epoch(slot_root, &batch_root, *t, horizon.n);
            let msg = Message::from_digest(m_t);
            let sig = Signature::from_slice(sig_bytes).unwrap();
            secp.verify_schnorr(&sig, &msg, &agg_xonly)
                .expect("BIP-340 verify");
        }

        // After exhausting the horizon, the cohort is Concluded and
        // future ticks skip it.
        assert_eq!(
            driver.store().load(&cohort_id).unwrap().cohort.state(),
            CohortState::Concluded
        );
        let next = driver.tick(&asp_kp, 1);
        assert_eq!(next.skipped, vec![cohort_id]);
    }

    #[test]
    fn tick_skips_t_above_horizon() {
        let secp = Secp256k1::new();
        let (asp_kp, active) = build_active(&secp, 2, 2, 0xa5);
        let cohort_id = active.cohort.id;
        let horizon = active.cohort.horizon;
        let mut store = InMemoryActiveCohortStore::new();
        store.save(active).unwrap();
        let mut registry = AspModeRegistry::new();
        registry.insert(cohort_id, AspMode::Psar(horizon));
        let mut driver = Driver::new(registry, store);

        let report = driver.tick(&asp_kp, horizon.n + 5);
        assert_eq!(report.skipped, vec![cohort_id]);
        assert!(report.errors.is_empty());
        assert_eq!(report.ok_count(), 0);
    }

    #[test]
    fn registry_is_independent_of_store() {
        // A cohort tagged Psar but not in the store is skipped
        // (registry can outlive the active cohort).
        let registry = {
            let mut r = AspModeRegistry::new();
            r.insert(
                [0x99; 32],
                AspMode::Psar(HibernationHorizon::new(4, 12).unwrap()),
            );
            r
        };
        let store = InMemoryActiveCohortStore::new();
        let mut driver = Driver::new(registry, store);
        let secp = Secp256k1::new();
        let dummy = even_parity_keypair(&secp, 0xa6);
        let report = driver.tick(&dummy, 1);
        assert_eq!(report.skipped, vec![[0x99; 32]]);
    }
}
