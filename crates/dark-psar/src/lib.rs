//! PSAR boarding-and-horizon protocol layer.
//!
//! Phase 3 (#666–#671) lands the structures the ASP and users need to
//! agree on a *cohort* — a set of users boarded together for a horizon
//! of `N` epochs — without baking `N` into the type system. The crate
//! is consumed by phases 4 (per-epoch processing) and 5 (CLI / demo
//! integration); it has no dependency on the rest of the workspace
//! beyond [`dark_von`] and [`dark_von_musig2`] in the boarding modules.
//!
//! Crate-level invariants:
//!
//! - `#![forbid(unsafe_code)]`.
//! - Public functions return `Result<_, PsarError>` per
//!   `docs/conventions/errors.md`.
//! - **No `const N`**. The horizon `N` flows through
//!   [`cohort::HibernationHorizon`] and is validated against a
//!   per-cohort `max_n` cap; nothing in the type layer fixes a
//!   particular `N`.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod asp_mode;
pub mod attest;
pub mod batch_tree;
pub mod boarding;
pub mod cohort;
pub mod epoch;
pub mod error;
pub mod lifecycle;
pub mod message;
#[cfg(feature = "regtest")]
pub mod publish;
pub mod report;
pub mod resurface;
pub mod slot_tree;
pub mod store;

pub use adapter::{Driver, TickReport};
pub use asp_mode::{AspMode, AspModeRegistry};
pub use attest::{SlotAttest, SlotAttestError, SlotAttestUnsigned};
pub use batch_tree::compute_batch_tree_root;
pub use boarding::{asp_board, user_board, ActiveCohort, UserBoardingArtifact};
pub use cohort::{BoardingState, Cohort, CohortMember, CohortState, HibernationHorizon};
pub use epoch::{process_epoch, EpochArtifacts};
pub use error::PsarError;
pub use lifecycle::{next_state, CohortLifecycleEvent};
pub use message::derive_message_for_epoch;
pub use report::{
    run_demo, AggregateReport, BoardingReport, EpochReport, RunReport, TotalsReport, SCHEMA_VERSION,
};
pub use resurface::{user_resurface, ResurfaceArtifact};
pub use slot_tree::{Side, Slot, SlotInclusionProof, SlotRoot, SlotTree};
pub use store::{ActiveCohortStore, CohortId, InMemoryActiveCohortStore};
