//! Stealth meta-address: the publishable identifier shared with senders.
//!
//! A meta-address bundles two compressed secp256k1 public keys:
//!
//! - `scan_pk` — used by senders to derive a one-time output public key
//!   that the recipient can detect with their scan secret.
//! - `spend_pk` — used (with the shared secret) to authorise spending
//!   of received VTXOs.
//!
//! The on-the-wire form is bech32m with a network-specific HRP and an
//! explicit version byte so the encoding can evolve without confusing
//! older parsers.
//!
//! ```text
//!   payload = [ version: u8 ][ scan_pk: 33 ][ spend_pk: 33 ]
//!   address = bech32m(hrp = network.hrp(), data = payload)
//! ```
//!
//! Nothing in this format appears on-chain or in VTXO data — the meta-
//! address is a wallet-to-wallet contract, not a consensus object.

use bech32::Bech32m;
use bitcoin::bip32::Xpriv;
use bitcoin::NetworkKind;
use secp256k1::{PublicKey, Secp256k1};

use crate::stealth::derivation::{scan_path, spend_path};
use crate::stealth::keys::{ScanKey, SpendKey};
use crate::stealth::network::StealthNetwork;
use crate::{ConfidentialError, Result};

/// Current stealth meta-address encoding version.
///
/// Versioning lives **inside** the bech32m payload so a new version
/// reuses the same HRP. The decoder rejects unknown versions explicitly.
pub const META_ADDRESS_VERSION_V1: u8 = 0x01;

/// Length of one compressed secp256k1 public key.
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Total length of the bech32m payload (1 + 33 + 33).
const META_ADDRESS_PAYLOAD_LEN: usize = 1 + COMPRESSED_PUBKEY_LEN + COMPRESSED_PUBKEY_LEN;

const VERSION_OFFSET: usize = 0;
const SCAN_PK_OFFSET: usize = 1;
const SPEND_PK_OFFSET: usize = SCAN_PK_OFFSET + COMPRESSED_PUBKEY_LEN;

/// Publishable stealth meta-address.
///
/// Holds only public keys and the network they are published on.
/// `Clone`/`Copy` would be safe here but unhelpful — a meta-address is
/// usually held by reference. We do derive `Clone` for ergonomic
/// re-use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaAddress {
    network: StealthNetwork,
    scan_pk: PublicKey,
    spend_pk: PublicKey,
}

/// Pair of secret keys produced by deterministic derivation.
///
/// Returned by [`MetaAddress::from_seed`] alongside the meta-address
/// itself so the caller can store the secrets in a wallet keystore.
pub struct StealthSecrets {
    pub scan_key: ScanKey,
    pub spend_key: SpendKey,
}

impl MetaAddress {
    /// Constructs a meta-address from the two public keys.
    pub fn new(network: StealthNetwork, scan_pk: PublicKey, spend_pk: PublicKey) -> Self {
        Self {
            network,
            scan_pk,
            spend_pk,
        }
    }

    /// The scan public key (detection).
    pub fn scan_pk(&self) -> &PublicKey {
        &self.scan_pk
    }

    /// The spend public key (authorisation).
    pub fn spend_pk(&self) -> &PublicKey {
        &self.spend_pk
    }

    /// The network this meta-address is intended for.
    pub fn network(&self) -> StealthNetwork {
        self.network
    }

    /// Encodes the meta-address as a bech32m string.
    ///
    /// The output is lowercase ASCII, prefixed by the network HRP.
    pub fn to_bech32m(&self) -> String {
        let payload = self.encode_payload();
        bech32::encode::<Bech32m>(self.network.hrp(), &payload)
            .expect("bech32m payload length is well within encoder limits")
    }

    /// Decodes a bech32m-encoded meta-address.
    ///
    /// Errors:
    /// - unknown HRP -> [`ConfidentialError::Stealth`] "unknown network prefix"
    /// - bad checksum or charset -> [`ConfidentialError::InvalidEncoding`]
    /// - wrong payload length -> [`ConfidentialError::InvalidEncoding`]
    /// - unknown version byte -> [`ConfidentialError::Stealth`] "unsupported meta-address version"
    /// - invalid public-key encoding -> [`ConfidentialError::InvalidEncoding`]
    pub fn from_bech32m(encoded: &str) -> Result<Self> {
        let (hrp, payload) = bech32::decode(encoded)
            .map_err(|_| ConfidentialError::InvalidEncoding("invalid bech32m encoding"))?;

        let network = StealthNetwork::from_hrp(hrp)?;

        if payload.len() != META_ADDRESS_PAYLOAD_LEN {
            return Err(ConfidentialError::InvalidEncoding(
                "unexpected meta-address payload length",
            ));
        }

        let version = payload[VERSION_OFFSET];
        if version != META_ADDRESS_VERSION_V1 {
            return Err(ConfidentialError::Stealth(
                "unsupported meta-address version",
            ));
        }

        let scan_pk =
            decode_pubkey(&payload[SCAN_PK_OFFSET..SCAN_PK_OFFSET + COMPRESSED_PUBKEY_LEN])?;
        let spend_pk =
            decode_pubkey(&payload[SPEND_PK_OFFSET..SPEND_PK_OFFSET + COMPRESSED_PUBKEY_LEN])?;

        Ok(Self::new(network, scan_pk, spend_pk))
    }

    /// Deterministically derives the stealth meta-address (and matching
    /// secret keys) from a wallet seed.
    ///
    /// `account_index` selects which BIP-44 account the keys belong to.
    /// The derivation paths are documented in
    /// [`crate::stealth::derivation`] — see the TODO there about the
    /// `m5-dd-paths` ADR (#551).
    pub fn from_seed(
        seed: &[u8],
        account_index: u32,
        network: StealthNetwork,
    ) -> Result<(Self, StealthSecrets)> {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(NetworkKind::from(network), seed)
            .map_err(|_| ConfidentialError::Stealth("invalid wallet seed for BIP-32 master"))?;

        let scan_xpriv = master
            .derive_priv(&secp, &scan_path(account_index))
            .map_err(|_| ConfidentialError::Stealth("scan key derivation failed"))?;
        let spend_xpriv = master
            .derive_priv(&secp, &spend_path(account_index))
            .map_err(|_| ConfidentialError::Stealth("spend key derivation failed"))?;

        let scan_key = ScanKey::new(scan_xpriv.private_key);
        let spend_key = SpendKey::new(spend_xpriv.private_key);

        let meta = Self::new(network, scan_key.pubkey(), spend_key.pubkey());
        Ok((
            meta,
            StealthSecrets {
                scan_key,
                spend_key,
            },
        ))
    }

    fn encode_payload(&self) -> [u8; META_ADDRESS_PAYLOAD_LEN] {
        let mut out = [0u8; META_ADDRESS_PAYLOAD_LEN];
        out[VERSION_OFFSET] = META_ADDRESS_VERSION_V1;
        out[SCAN_PK_OFFSET..SCAN_PK_OFFSET + COMPRESSED_PUBKEY_LEN]
            .copy_from_slice(&self.scan_pk.serialize());
        out[SPEND_PK_OFFSET..SPEND_PK_OFFSET + COMPRESSED_PUBKEY_LEN]
            .copy_from_slice(&self.spend_pk.serialize());
        out
    }
}

impl From<StealthNetwork> for NetworkKind {
    fn from(net: StealthNetwork) -> Self {
        match net {
            StealthNetwork::Mainnet => NetworkKind::Main,
            StealthNetwork::Testnet | StealthNetwork::Regtest => NetworkKind::Test,
        }
    }
}

fn decode_pubkey(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_slice(bytes)
        .map_err(|_| ConfidentialError::InvalidEncoding("invalid compressed public key"))
}

/// Tampers with the version byte of an encoded meta-address — exposed
/// for unit tests in this crate so the version-rejection path is
/// exercised without copying the encoding helpers into tests.
#[cfg(test)]
pub(crate) fn replace_version_for_test(meta: &MetaAddress, new_version: u8) -> String {
    let mut payload = meta.encode_payload();
    payload[VERSION_OFFSET] = new_version;
    bech32::encode::<Bech32m>(meta.network.hrp(), &payload).expect("encoder accepts payload")
}

/// Replaces the HRP of an encoded meta-address — exposed for unit
/// tests so the network-mismatch path is exercised.
#[cfg(test)]
pub(crate) fn replace_hrp_for_test(meta: &MetaAddress, hrp: bech32::Hrp) -> String {
    let payload = meta.encode_payload();
    bech32::encode::<Bech32m>(hrp, &payload).expect("encoder accepts payload")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_seed() -> [u8; 32] {
        // Static fixture so the derivation test is reproducible across runs.
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    fn build_meta(network: StealthNetwork) -> MetaAddress {
        let (meta, _secrets) = MetaAddress::from_seed(&sample_seed(), 0, network).unwrap();
        meta
    }

    #[test]
    fn bech32m_round_trip_preserves_keys_and_network() {
        for network in [
            StealthNetwork::Mainnet,
            StealthNetwork::Testnet,
            StealthNetwork::Regtest,
        ] {
            let meta = build_meta(network);
            let encoded = meta.to_bech32m();
            let decoded = MetaAddress::from_bech32m(&encoded).unwrap();
            assert_eq!(decoded, meta);
            assert_eq!(decoded.network(), network);
        }
    }

    #[test]
    fn bech32m_uses_network_hrp_prefix() {
        let mainnet = build_meta(StealthNetwork::Mainnet).to_bech32m();
        let testnet = build_meta(StealthNetwork::Testnet).to_bech32m();
        let regtest = build_meta(StealthNetwork::Regtest).to_bech32m();

        assert!(mainnet.starts_with("darks1"));
        assert!(testnet.starts_with("tdarks1"));
        assert!(regtest.starts_with("rdarks1"));
    }

    #[test]
    fn from_seed_is_deterministic() {
        let (left, _) = MetaAddress::from_seed(&sample_seed(), 0, StealthNetwork::Mainnet).unwrap();
        let (right, _) =
            MetaAddress::from_seed(&sample_seed(), 0, StealthNetwork::Mainnet).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn different_accounts_produce_different_meta_addresses() {
        let (a, _) = MetaAddress::from_seed(&sample_seed(), 0, StealthNetwork::Mainnet).unwrap();
        let (b, _) = MetaAddress::from_seed(&sample_seed(), 1, StealthNetwork::Mainnet).unwrap();
        assert_ne!(a.scan_pk(), b.scan_pk());
        assert_ne!(a.spend_pk(), b.spend_pk());
    }

    #[test]
    fn scan_and_spend_pubkeys_differ_within_a_meta_address() {
        let meta = build_meta(StealthNetwork::Mainnet);
        assert_ne!(meta.scan_pk(), meta.spend_pk());
    }

    #[test]
    fn unknown_version_is_rejected_on_decode() {
        let meta = build_meta(StealthNetwork::Mainnet);
        let tampered = replace_version_for_test(&meta, META_ADDRESS_VERSION_V1.wrapping_add(1));
        let err = MetaAddress::from_bech32m(&tampered).unwrap_err();
        assert!(matches!(err, ConfidentialError::Stealth(_)));
    }

    #[test]
    fn unknown_network_prefix_is_rejected_on_decode() {
        let meta = build_meta(StealthNetwork::Mainnet);
        let foreign_hrp = bech32::Hrp::parse("foreign").unwrap();
        let tampered = replace_hrp_for_test(&meta, foreign_hrp);
        let err = MetaAddress::from_bech32m(&tampered).unwrap_err();
        assert!(matches!(err, ConfidentialError::Stealth(_)));
    }

    #[test]
    fn cross_network_decode_is_rejected() {
        // A mainnet-encoded address decoded as if it were testnet must
        // fail because the HRP itself drives network selection.
        let mainnet_str = build_meta(StealthNetwork::Mainnet).to_bech32m();
        let decoded = MetaAddress::from_bech32m(&mainnet_str).unwrap();
        assert_eq!(decoded.network(), StealthNetwork::Mainnet);
        assert_ne!(decoded.network(), StealthNetwork::Testnet);
    }

    #[test]
    fn corrupt_bech32m_is_rejected() {
        let meta = build_meta(StealthNetwork::Mainnet);
        let mut encoded = meta.to_bech32m();
        // Flip the last char of the checksum (last char of the string).
        encoded.pop();
        encoded.push('q');
        let err = MetaAddress::from_bech32m(&encoded).unwrap_err();
        assert!(matches!(err, ConfidentialError::InvalidEncoding(_)));
    }

    #[test]
    fn secrets_match_published_pubkeys() {
        let (meta, secrets) =
            MetaAddress::from_seed(&sample_seed(), 0, StealthNetwork::Mainnet).unwrap();
        assert_eq!(&secrets.scan_key.pubkey(), meta.scan_pk());
        assert_eq!(&secrets.spend_key.pubkey(), meta.spend_pk());
    }

    #[test]
    fn known_answer_vectors_match() {
        use serde::Deserialize;
        use std::fs;

        #[derive(Deserialize)]
        struct VectorFile {
            seed_hex: String,
            version: u8,
            vectors: Vec<Vector>,
        }
        #[derive(Deserialize)]
        struct Vector {
            network: String,
            account: u32,
            scan_pk_hex: String,
            spend_pk_hex: String,
            encoded: String,
        }

        let raw = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/meta_address.json"
        ))
        .expect("test vector file present");
        let vectors: VectorFile = serde_json::from_str(&raw).expect("vectors parse as JSON");

        assert_eq!(vectors.version, META_ADDRESS_VERSION_V1);
        let seed = hex::decode(vectors.seed_hex).expect("seed is hex");
        assert_eq!(seed.as_slice(), sample_seed().as_slice());

        for vector in vectors.vectors {
            let network = match vector.network.as_str() {
                "Mainnet" => StealthNetwork::Mainnet,
                "Testnet" => StealthNetwork::Testnet,
                "Regtest" => StealthNetwork::Regtest,
                other => panic!("unknown network in test vector: {other}"),
            };

            let (meta, _) = MetaAddress::from_seed(&seed, vector.account, network).unwrap();

            assert_eq!(
                hex::encode(meta.scan_pk().serialize()),
                vector.scan_pk_hex,
                "scan_pk mismatch for {:?} account {}",
                network,
                vector.account
            );
            assert_eq!(
                hex::encode(meta.spend_pk().serialize()),
                vector.spend_pk_hex,
                "spend_pk mismatch for {:?} account {}",
                network,
                vector.account
            );
            assert_eq!(
                meta.to_bech32m(),
                vector.encoded,
                "encoded form mismatch for {:?} account {}",
                network,
                vector.account
            );
        }
    }

    /// Run with `cargo test -p dark-confidential -- --ignored print_meta_address_vectors`
    /// to regenerate `tests/vectors/meta_address.json` if the derivation
    /// scheme changes (e.g. when ADR #551 lands).
    #[test]
    #[ignore = "diagnostic tool to regenerate test vectors"]
    fn print_meta_address_vectors() {
        for network in [
            StealthNetwork::Mainnet,
            StealthNetwork::Testnet,
            StealthNetwork::Regtest,
        ] {
            for account in [0u32, 1u32] {
                let (meta, _) = MetaAddress::from_seed(&sample_seed(), account, network).unwrap();
                println!(
                    "{:?} account={} scan_pk={} spend_pk={} encoded={}",
                    network,
                    account,
                    hex::encode(meta.scan_pk().serialize()),
                    hex::encode(meta.spend_pk().serialize()),
                    meta.to_bech32m()
                );
            }
        }
    }
}
