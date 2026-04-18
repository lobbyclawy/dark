//! Shared test-support helpers.
//!
//! This module is included by integration tests via `mod support;`. It is
//! not compiled as a standalone test binary — Cargo treats subdirectories
//! containing `mod.rs` as modules rather than test targets.
//!
//! When #505 lands (`crates/dark-testkit`), these helpers migrate there and
//! this module becomes a thin re-export.

#![allow(dead_code)] // individual tests may not use every helper

pub mod poll;
