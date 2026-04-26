//! Stealth addressing primitives for Confidential VTXOs.
//!
//! A *stealth meta-address* is the stable, publishable identifier that
//! a recipient shares with senders. It contains two compressed
//! secp256k1 public keys:
//!
//! - **scan public key** — used by senders to derive a one-time output
//!   public key the recipient can detect using the matching scan secret.
//! - **spend public key** — used (with the shared secret) to authorise
//!   spends of received VTXOs.
//!
//! The meta-address itself never appears on-chain or inside VTXO data;
//! a VTXO carries only the derived one-time public key. This module
//! covers the meta-address layer:
//!
//! - [`MetaAddress`] — the publishable type, with bech32m encode/decode
//!   over a network-tagged HRP and an explicit version byte.
//! - [`ScanKey`] / [`SpendKey`] — secret-key wrappers with `Zeroize`
//!   on drop and no `Copy` / `Clone` / `Debug` implementations, so
//!   private material cannot be silently duplicated or logged.
//! - [`StealthNetwork`] — network discriminator, mapped 1:1 to the
//!   bech32m HRP so addresses cannot cross networks.
//!
//! The BIP-32 derivation paths used by [`MetaAddress::from_seed`] live
//! in [`derivation`] — that module is the single source of truth and
//! is where the `m5-dd-paths` ADR (#551) will land.

pub mod derivation;
pub mod keys;
pub mod meta_address;
pub mod network;

pub use keys::{ScanKey, SpendKey};
pub use meta_address::{MetaAddress, StealthSecrets, META_ADDRESS_VERSION_V1};
pub use network::StealthNetwork;
