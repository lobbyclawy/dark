///! arkd-core - Core business logic for Ark protocol
///!
///! This crate implements the core functionality:
///! - Round management and batching
///! - VTXO tree construction
///! - Collaborative/unilateral exits
///! - Boarding transactions

pub mod domain;
pub mod application;
pub mod ports;

pub use domain::*;
pub use application::*;
