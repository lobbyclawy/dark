#![forbid(unsafe_code)]
#![doc = r#"
Confidential primitives for dark.

This crate is the workspace home for Confidential VTXO cryptographic building
blocks, including commitments, range proofs, balance proofs, nullifiers,
stealth addressing, and selective disclosure helpers.

Design goals:
- isolate confidential protocol work from transparent-path crates
- keep cryptographic transcripts explicit and centrally documented
- expose small, auditable APIs for downstream wallet, server, and proof layers

Threat model notes:
- secret material must never influence control flow in ways that create obvious
  side channels at the API level
- serialized cryptographic objects must use canonical encodings
- nullifier, commitment, and proof construction must remain domain separated to
  avoid cross-protocol transcript reuse
"#]

pub mod balance_proof;
pub mod commitment;
pub mod disclosure;
pub mod errors;
pub mod nullifier;
pub mod range_proof;
pub mod stealth;

pub use errors::{ConfidentialError, Result};
