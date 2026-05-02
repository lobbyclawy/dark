//! Per-cohort ASP signing mode and registry (issue #678).
//!
//! See `docs/adr/0009-psar-integration.md` for the design choice — PSAR
//! runs as a parallel pipeline inside `dark-psar` rather than as a
//! per-call branch inside `dark-core::application`.
//!
//! [`AspMode`] tags each cohort with one of:
//!
//! - [`AspMode::Standard`]: handled by the existing standard-mode
//!   round loop in `dark-core` (uses `dark_bitcoin::signing`); PSAR
//!   never visits these cohorts.
//! - [`AspMode::Psar`]: driven by the parallel pipeline in
//!   [`crate::adapter`] (uses `dark_von_musig2`).
//!
//! [`AspModeRegistry`] is a thin `HashMap<CohortId, AspMode>` consumed
//! by [`crate::adapter::Driver`]. The standard round loop does **not**
//! consult the registry — Standard cohorts are simply absent from PSAR
//! processing, which is the parity gate from ADR-0009.

use std::collections::HashMap;

use crate::cohort::HibernationHorizon;
use crate::store::CohortId;

/// Per-cohort signing mode tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AspMode {
    /// Cohort is handled by the standard MuSig2 round loop in
    /// `dark-core`; the PSAR adapter ignores it.
    Standard,
    /// Cohort is driven by the PSAR parallel pipeline with a
    /// hibernation horizon of `n` epochs.
    Psar(HibernationHorizon),
}

impl AspMode {
    /// `true` iff this cohort runs in PSAR mode.
    pub fn is_psar(self) -> bool {
        matches!(self, AspMode::Psar(_))
    }

    /// Hibernation horizon for `Psar` cohorts; `None` for `Standard`.
    pub fn horizon(self) -> Option<HibernationHorizon> {
        match self {
            AspMode::Psar(h) => Some(h),
            AspMode::Standard => None,
        }
    }
}

/// Operator-side registry mapping cohort id → mode.
///
/// Cohorts not present in the registry are treated as
/// [`AspMode::Standard`] by [`AspModeRegistry::dispatch_signing`].
#[derive(Default)]
pub struct AspModeRegistry {
    modes: HashMap<CohortId, AspMode>,
}

impl AspModeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Tag `cohort_id` with `mode`. Replaces any existing entry.
    pub fn insert(&mut self, cohort_id: CohortId, mode: AspMode) {
        self.modes.insert(cohort_id, mode);
    }

    /// Mode dispatch for `cohort_id`.
    ///
    /// Cohorts not present in the registry are reported as
    /// [`AspMode::Standard`]; the standard round loop owns them and
    /// PSAR ignores them.
    pub fn dispatch_signing(&self, cohort_id: &CohortId) -> AspMode {
        self.modes
            .get(cohort_id)
            .copied()
            .unwrap_or(AspMode::Standard)
    }

    /// Iterate every PSAR-tagged cohort id with its horizon.
    pub fn psar_cohorts(&self) -> impl Iterator<Item = (CohortId, HibernationHorizon)> + '_ {
        self.modes.iter().filter_map(|(id, mode)| match mode {
            AspMode::Psar(h) => Some((*id, *h)),
            AspMode::Standard => None,
        })
    }

    pub fn len(&self) -> usize {
        self.modes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u32) -> HibernationHorizon {
        HibernationHorizon::new(n, 12).expect("valid horizon")
    }

    #[test]
    fn empty_registry_dispatches_standard() {
        let r = AspModeRegistry::new();
        assert_eq!(r.dispatch_signing(&[0u8; 32]), AspMode::Standard);
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.psar_cohorts().count(), 0);
    }

    #[test]
    fn insert_and_dispatch_roundtrip() {
        let mut r = AspModeRegistry::new();
        let id = [0xab; 32];
        r.insert(id, AspMode::Psar(h(4)));
        assert_eq!(r.dispatch_signing(&id), AspMode::Psar(h(4)));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn standard_insert_surfaces_via_dispatch() {
        // Explicitly inserted Standard is still Standard (it doesn't
        // appear in psar_cohorts but is reachable via dispatch).
        let mut r = AspModeRegistry::new();
        let id = [0x33; 32];
        r.insert(id, AspMode::Standard);
        assert_eq!(r.dispatch_signing(&id), AspMode::Standard);
        assert_eq!(r.psar_cohorts().count(), 0);
    }

    #[test]
    fn psar_cohorts_filters_standard_entries() {
        let mut r = AspModeRegistry::new();
        r.insert([1u8; 32], AspMode::Psar(h(4)));
        r.insert([2u8; 32], AspMode::Standard);
        r.insert([3u8; 32], AspMode::Psar(h(12)));

        let mut got: Vec<_> = r.psar_cohorts().collect();
        got.sort_by_key(|(id, _)| *id);
        assert_eq!(got, vec![([1u8; 32], h(4)), ([3u8; 32], h(12))]);
    }

    #[test]
    fn insert_replaces_existing_entry() {
        let mut r = AspModeRegistry::new();
        let id = [0x77; 32];
        r.insert(id, AspMode::Standard);
        r.insert(id, AspMode::Psar(h(4)));
        assert_eq!(r.dispatch_signing(&id), AspMode::Psar(h(4)));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn helpers_classify_modes() {
        assert!(AspMode::Psar(h(4)).is_psar());
        assert!(!AspMode::Standard.is_psar());
        assert_eq!(AspMode::Psar(h(4)).horizon(), Some(h(4)));
        assert_eq!(AspMode::Standard.horizon(), None);
    }
}
