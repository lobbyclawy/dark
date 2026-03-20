//! Scheduler implementations for dark round triggers.
//!
//! Provides [`SimpleTimeScheduler`] (fixed-interval timer) and
//! [`EsploraBlockScheduler`] (block-height polling via Esplora API).

mod block_scheduler;
mod time_scheduler;

pub use block_scheduler::EsploraBlockScheduler;
pub use time_scheduler::SimpleTimeScheduler;
