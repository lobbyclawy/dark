//! Crate error type.

use thiserror::Error;

use crate::cohort::BoardingState;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PsarError {
    #[error("horizon n={n} is outside [1, {max_n}]")]
    HorizonOutOfRange { n: u32, max_n: u32 },

    #[error("cohort has no members")]
    EmptyCohort,

    #[error("cohort member count {k} exceeds maximum {max_k}")]
    TooManyMembers { k: u32, max_k: u32 },

    #[error("duplicate slot index {slot_index} in cohort")]
    DuplicateSlotIndex { slot_index: u32 },

    #[error("duplicate user id in cohort")]
    DuplicateUserId,

    #[error("slot index {slot_index} is out of range for cohort of size {k}")]
    SlotIndexOutOfRange { slot_index: u32, k: u32 },

    #[error("invalid boarding-state transition from {from:?} to {to:?}")]
    InvalidBoardingState {
        from: BoardingState,
        to: BoardingState,
    },

    #[error("invalid lifecycle event {event:?} for state {state:?}")]
    InvalidLifecycleEvent {
        state: crate::cohort::CohortState,
        event: crate::lifecycle::CohortLifecycleEvent,
    },

    #[error("cohort {cohort_id} not found in store")]
    CohortNotFound { cohort_id: String },

    #[error("user {user_id} produced an invalid partial signature for epoch {epoch}")]
    InvalidUserPartial { user_id: String, epoch: u32 },

    #[error("epoch {epoch} is out of range for cohort horizon n={n}")]
    EpochOutOfRange { epoch: u32, n: u32 },

    #[error("resurface request t_prime={t_prime} > current_epoch={current_epoch}")]
    ResurfaceFromFuture { t_prime: u32, current_epoch: u32 },

    #[error("inclusion proof for slot {slot_index} did not verify against slot_root")]
    InclusionProofInvalid { slot_index: u32 },

    #[error("no signature for user at epoch {epoch}; user may have been evicted")]
    UserSigNotFound { epoch: u32 },

    #[error("schedule entry invalid at epoch {epoch}, slot {slot}")]
    ScheduleInvalid { epoch: u32, slot: u8 },

    #[error("slot {slot_index} commits to a different pubkey than the user's keypair")]
    PubkeyMismatch { slot_index: u32 },

    #[error("slot root in attestation does not match recomputed slot root")]
    SlotRootMismatch,

    #[error("schedule root in attestation does not match recomputed schedule root")]
    ScheduleRootMismatch,

    #[error("attestation signature failed to verify")]
    AttestationVerify,

    #[error("schedule horizon n={schedule_n} disagrees with cohort horizon n={cohort_n}")]
    HorizonDisagrees { schedule_n: u32, cohort_n: u32 },

    #[error("attestation field {field} disagrees with cohort: attest={attest_value}, cohort={cohort_value}")]
    AttestationFieldMismatch {
        field: &'static str,
        attest_value: u32,
        cohort_value: u32,
    },

    #[error("dark-von-musig2 error during boarding")]
    VonMusig2(#[from] dark_von_musig2::VonMusig2Error),

    #[error("user keypair has odd parity; PSAR requires BIP-340 even-parity normalization")]
    OddParity,
}
