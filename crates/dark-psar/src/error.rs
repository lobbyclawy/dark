//! Crate error type.

use thiserror::Error;

use crate::cohort::BoardingState;

#[derive(Debug, Error, PartialEq, Eq)]
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
}
