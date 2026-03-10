pub mod application;
///! arkd-core - Core business logic for Ark protocol
///!
///! This crate implements the core functionality:
///! - Round management and batching
///! - VTXO tree construction
///! - Collaborative/unilateral exits
///! - Boarding transactions
pub mod domain;
pub mod ports;

pub use application::*;
pub use domain::*;
