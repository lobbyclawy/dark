//! Single-key wallet for the Ark client SDK.
//!
//! Provides key generation, PSBT signing, and Ark address derivation.
//! This mirrors Go's `client-lib/wallet` single-key wallet.
//!
//! Confidential VTXO support layers a stealth meta-address on top of
//! the transparent keypair. Stealth keys are derived deterministically
//! from a seed via [`MetaAddress::from_seed`] and held inside the
//! wallet so confidential send/receive paths can reach them through
//! the SDK without ever touching raw `SecretKey` bytes.

use std::sync::Arc;

use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use dark_confidential::stealth::{MetaAddress, StealthNetwork, StealthSecrets};

use crate::error::{ClientError, ClientResult};

/// A simple single-key wallet that holds one keypair.
///
/// Used for signing PSBTs, deriving on-chain and off-chain addresses,
/// and generating BIP-322 ownership proofs.
///
/// Wallets may additionally carry a stealth meta-address and the
/// matching scan/spend secrets — populated by
/// [`SingleKeyWallet::derive_confidential_keys_from_seed`] or
/// [`SingleKeyWallet::with_confidential_secrets`]. The presence of
/// confidential secrets is independent from whether the wallet
/// *prefers* confidential outputs by default; that is controlled by
/// [`SingleKeyWallet::set_default_confidential`].
#[derive(Clone)]
pub struct SingleKeyWallet {
    secret_key: SecretKey,
    public_key: PublicKey,
    network: Network,
    /// Public meta-address. May be present without `confidential_secrets`
    /// when the wallet has been restored from a snapshot but its seed
    /// has not yet been re-supplied to rehydrate the secrets.
    confidential_meta: Option<MetaAddress>,
    /// Stealth scan/spend secrets. Held behind an `Arc` because the
    /// underlying [`ScanKey`]/[`SpendKey`] wrappers intentionally do
    /// not implement `Clone`; sharing keeps the no-duplication
    /// invariant intact while still letting the wallet itself be
    /// cloneable.
    ///
    /// [`ScanKey`]: dark_confidential::stealth::ScanKey
    /// [`SpendKey`]: dark_confidential::stealth::SpendKey
    confidential_secrets: Option<Arc<StealthSecrets>>,
    default_confidential: bool,
}

impl SingleKeyWallet {
    /// Generate a new random wallet for `network`.
    pub fn generate(network: Network) -> Self {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = PublicKey::from_private_key(&secp, &PrivateKey::new(secret_key, network));
        Self::from_components(secret_key, public_key, network)
    }

    /// Create a wallet from an existing WIF-encoded private key.
    pub fn from_wif(wif: &str, network: Network) -> ClientResult<Self> {
        let private_key: PrivateKey = wif
            .parse()
            .map_err(|e| ClientError::Wallet(format!("Invalid WIF: {e}")))?;
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        Ok(Self::from_components(
            private_key.inner,
            public_key,
            network,
        ))
    }

    /// Create a wallet from raw 32-byte secret key bytes.
    pub fn from_secret_bytes(bytes: &[u8], network: Network) -> ClientResult<Self> {
        let secret_key = SecretKey::from_slice(bytes)
            .map_err(|e| ClientError::Wallet(format!("Invalid secret key: {e}")))?;
        let secp = Secp256k1::new();
        let private_key = PrivateKey::new(secret_key, network);
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        Ok(Self::from_components(secret_key, public_key, network))
    }

    fn from_components(secret_key: SecretKey, public_key: PublicKey, network: Network) -> Self {
        Self {
            secret_key,
            public_key,
            network,
            confidential_meta: None,
            confidential_secrets: None,
            default_confidential: false,
        }
    }

    /// Return the compressed public key (33 bytes, hex).
    pub fn pubkey_hex(&self) -> String {
        self.public_key.to_string()
    }

    /// Return the x-only (Schnorr) public key (32 bytes).
    pub fn x_only_pubkey(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from(self.public_key.inner)
    }

    /// Return the secp256k1 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Return the secret key (for signing operations).
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Return the network this wallet is configured for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Derive a P2TR (Taproot) on-chain address from the wallet's key.
    pub fn p2tr_address(&self) -> ClientResult<Address> {
        let secp = Secp256k1::new();
        let x_only = self.x_only_pubkey();
        Ok(Address::p2tr(&secp, x_only, None, self.network))
    }

    /// Derive a P2WPKH (SegWit v0) on-chain address.
    pub fn p2wpkh_address(&self) -> ClientResult<Address> {
        let compressed = CompressedPublicKey::try_from(self.public_key)
            .map_err(|e| ClientError::Wallet(format!("Cannot compress pubkey: {e}")))?;
        Ok(Address::p2wpkh(&compressed, self.network))
    }

    /// Return the Ark off-chain address (pubkey-based).
    ///
    /// Format: `ark:<compressed_pubkey_hex>`
    pub fn offchain_address(&self) -> String {
        format!("ark:{}", self.pubkey_hex())
    }

    /// Export the private key as WIF.
    pub fn to_wif(&self) -> String {
        PrivateKey::new(self.secret_key, self.network).to_wif()
    }

    /// Sign a message hash with the wallet's secret key (Schnorr).
    ///
    /// Returns the 64-byte Schnorr signature as hex.
    pub fn sign_schnorr(&self, msg: &[u8; 32]) -> ClientResult<String> {
        let secp = Secp256k1::new();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &self.secret_key);
        let msg = secp256k1::Message::from_digest(*msg);
        let sig = secp.sign_schnorr(&msg, &keypair);
        Ok(hex::encode(sig.serialize()))
    }

    /// Sign a message hash with ECDSA (for legacy compatibility).
    ///
    /// Returns the DER-encoded signature as hex.
    pub fn sign_ecdsa(&self, msg: &[u8; 32]) -> ClientResult<String> {
        let secp = Secp256k1::new();
        let msg = secp256k1::Message::from_digest(*msg);
        let sig = secp.sign_ecdsa(&msg, &self.secret_key);
        Ok(hex::encode(sig.serialize_der()))
    }

    // ── Confidential extensions ──────────────────────────────────────

    /// Hydrate the wallet's stealth keys deterministically from `seed`.
    ///
    /// `account_index` selects which BIP-32 account the stealth keys
    /// belong to — see [`MetaAddress::from_seed`] for the derivation
    /// paths. Calling this twice with the same `(seed, account_index,
    /// stealth_network)` is idempotent: the produced
    /// `(scan_pk, spend_pk)` pair is deterministic, so the second call
    /// overwrites the first with a structurally identical entry.
    ///
    /// The wallet's transparent secret key is left unchanged.
    pub fn derive_confidential_keys_from_seed(
        &mut self,
        seed: &[u8],
        account_index: u32,
        stealth_network: StealthNetwork,
    ) -> ClientResult<&MetaAddress> {
        let (meta, secrets) = MetaAddress::from_seed(seed, account_index, stealth_network)
            .map_err(|err| ClientError::Wallet(format!("stealth derivation failed: {err}")))?;
        self.confidential_meta = Some(meta);
        self.confidential_secrets = Some(Arc::new(secrets));
        Ok(self
            .confidential_meta
            .as_ref()
            .expect("meta-address was just set"))
    }

    /// Attach already-built stealth secrets to the wallet.
    ///
    /// Useful when the secrets have been derived elsewhere (e.g. by a
    /// hardware-wallet shim or an HSM bridge). The accompanying
    /// `meta` MUST match the public keys the secrets derive — callers
    /// are responsible for that invariant; the wallet does not
    /// recompute the pubkeys here.
    pub fn with_confidential_secrets(mut self, meta: MetaAddress, secrets: StealthSecrets) -> Self {
        self.confidential_meta = Some(meta);
        self.confidential_secrets = Some(Arc::new(secrets));
        self
    }

    /// Return the wallet's stealth meta-address, if one has been
    /// derived or restored.
    pub fn confidential_meta_address(&self) -> Option<&MetaAddress> {
        self.confidential_meta.as_ref()
    }

    /// Return the wallet's stealth secrets, if they have been
    /// hydrated. Snapshot-restored wallets that have not yet been
    /// re-derived from the seed will return `None` here even when
    /// [`Self::confidential_meta_address`] is `Some`.
    pub fn confidential_secrets(&self) -> Option<&StealthSecrets> {
        self.confidential_secrets.as_deref()
    }

    /// Whether the wallet should default to confidential outputs when
    /// constructing transactions.
    ///
    /// Defaults to `false` and is intended to be flipped to `true` once
    /// the broader confidential SDK surface lands (issue #576). Toggle
    /// via [`SingleKeyWallet::set_default_confidential`].
    pub fn default_confidential(&self) -> bool {
        self.default_confidential
    }

    /// Set the [`Self::default_confidential`] flag.
    pub fn set_default_confidential(&mut self, default_confidential: bool) {
        self.default_confidential = default_confidential;
    }

    /// Serialize the wallet's persistence-safe public view.
    ///
    /// Stealth secrets are *not* included — see [`WalletSnapshot`] for
    /// the rehydration model.
    pub fn to_snapshot(&self) -> WalletSnapshot {
        WalletSnapshot {
            wif: self.to_wif(),
            network: self.network,
            confidential_meta_address: self.confidential_meta.as_ref().map(MetaAddress::to_bech32m),
            default_confidential: self.default_confidential,
        }
    }

    /// Restore a wallet from a [`WalletSnapshot`].
    ///
    /// The returned wallet does **not** carry any stealth secrets even
    /// when `confidential_meta_address` is set — only the public
    /// meta-address is restored. Pair with
    /// [`SingleKeyWallet::derive_confidential_keys_from_seed`] (or
    /// [`SingleKeyWallet::with_confidential_secrets`]) to rehydrate
    /// the secrets from the wallet's seed.
    pub fn from_snapshot(snapshot: &WalletSnapshot) -> ClientResult<Self> {
        let mut wallet = Self::from_wif(&snapshot.wif, snapshot.network)?;
        wallet.default_confidential = snapshot.default_confidential;
        if let Some(encoded) = &snapshot.confidential_meta_address {
            let meta = MetaAddress::from_bech32m(encoded).map_err(|err| {
                ClientError::Wallet(format!("invalid stealth meta-address in snapshot: {err}"))
            })?;
            wallet.confidential_meta = Some(meta);
        }
        Ok(wallet)
    }
}

impl std::fmt::Debug for SingleKeyWallet {
    /// Hide secret material — only public components and the network
    /// are surfaced. The stealth identity is rendered by the published
    /// meta-address bech32m string, which contains only public keys.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleKeyWallet")
            .field("public_key", &self.public_key.to_string())
            .field("network", &self.network)
            .field(
                "confidential_meta_address",
                &self.confidential_meta.as_ref().map(MetaAddress::to_bech32m),
            )
            .field(
                "has_confidential_secrets",
                &self.confidential_secrets.is_some(),
            )
            .field("default_confidential", &self.default_confidential)
            .finish()
    }
}

/// Serializable, persistence-safe view of a [`SingleKeyWallet`].
///
/// The transparent secret travels as WIF — matching the existing
/// `to_wif`/`from_wif` round-trip already exercised by the wallet
/// tests. Stealth secrets are *not* persisted directly: the
/// [`ScanKey`]/[`SpendKey`] wrappers in `dark-confidential` deliberately
/// withhold byte-level access to keep the bytes from leaking through
/// serializers. Instead, the snapshot records the public meta-address
/// (which carries the scan and spend pubkeys); rehydrating the
/// secrets is done via
/// [`SingleKeyWallet::derive_confidential_keys_from_seed`] from the
/// caller's own seed.
///
/// [`ScanKey`]: dark_confidential::stealth::ScanKey
/// [`SpendKey`]: dark_confidential::stealth::SpendKey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSnapshot {
    /// WIF-encoded transparent secret key.
    pub wif: String,
    /// Bitcoin network this wallet is configured for.
    pub network: Network,
    /// Bech32m-encoded stealth meta-address, when the wallet has one.
    pub confidential_meta_address: Option<String>,
    /// Whether the wallet should default to confidential outputs.
    #[serde(default)]
    pub default_confidential: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }
        seed
    }

    #[test]
    fn test_generate_wallet() {
        let wallet = SingleKeyWallet::generate(Network::Regtest);
        assert!(!wallet.pubkey_hex().is_empty());
        assert_eq!(wallet.network(), Network::Regtest);
    }

    #[test]
    fn test_wallet_roundtrip_wif() {
        let wallet = SingleKeyWallet::generate(Network::Regtest);
        let wif = wallet.to_wif();
        let restored = SingleKeyWallet::from_wif(&wif, Network::Regtest).unwrap();
        assert_eq!(wallet.pubkey_hex(), restored.pubkey_hex());
    }

    #[test]
    fn test_p2tr_address() {
        let wallet = SingleKeyWallet::generate(Network::Regtest);
        let addr = wallet.p2tr_address().unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with("bcrt1p"), "got: {addr_str}");
    }

    #[test]
    fn test_p2wpkh_address() {
        let wallet = SingleKeyWallet::generate(Network::Regtest);
        let addr = wallet.p2wpkh_address().unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with("bcrt1q"), "got: {addr_str}");
    }

    #[test]
    fn test_offchain_address() {
        let wallet = SingleKeyWallet::generate(Network::Regtest);
        let addr = wallet.offchain_address();
        assert!(addr.starts_with("ark:"));
    }

    #[test]
    fn test_sign_schnorr() {
        let wallet = SingleKeyWallet::generate(Network::Regtest);
        let msg = [0xab_u8; 32];
        let sig = wallet.sign_schnorr(&msg).unwrap();
        assert_eq!(sig.len(), 128); // 64 bytes hex
    }

    #[test]
    fn test_sign_ecdsa() {
        let wallet = SingleKeyWallet::generate(Network::Regtest);
        let msg = [0xcd_u8; 32];
        let sig = wallet.sign_ecdsa(&msg).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_from_secret_bytes() {
        let wallet = SingleKeyWallet::generate(Network::Regtest);
        let bytes = wallet.secret_key().secret_bytes();
        let restored = SingleKeyWallet::from_secret_bytes(&bytes, Network::Regtest).unwrap();
        assert_eq!(wallet.pubkey_hex(), restored.pubkey_hex());
    }

    #[test]
    fn fresh_wallet_has_no_confidential_keys_and_defaults_to_transparent() {
        let wallet = SingleKeyWallet::generate(Network::Regtest);
        assert!(wallet.confidential_meta_address().is_none());
        assert!(wallet.confidential_secrets().is_none());
        assert!(!wallet.default_confidential());
    }

    #[test]
    fn deriving_confidential_keys_populates_meta_and_secrets() {
        let mut wallet = SingleKeyWallet::generate(Network::Regtest);
        let meta = wallet
            .derive_confidential_keys_from_seed(&fixture_seed(), 0, StealthNetwork::Regtest)
            .expect("derivation succeeds")
            .clone();

        assert_eq!(wallet.confidential_meta_address(), Some(&meta));
        let secrets = wallet
            .confidential_secrets()
            .expect("secrets present after derivation");
        assert_eq!(secrets.scan_key.pubkey(), *meta.scan_pk());
        assert_eq!(secrets.spend_key.pubkey(), *meta.spend_pk());
    }

    #[test]
    fn deriving_confidential_keys_is_deterministic_for_same_seed() {
        let mut a = SingleKeyWallet::generate(Network::Regtest);
        let mut b = SingleKeyWallet::generate(Network::Regtest);
        a.derive_confidential_keys_from_seed(&fixture_seed(), 0, StealthNetwork::Regtest)
            .unwrap();
        b.derive_confidential_keys_from_seed(&fixture_seed(), 0, StealthNetwork::Regtest)
            .unwrap();

        assert_eq!(a.confidential_meta_address(), b.confidential_meta_address(),);
    }

    #[test]
    fn default_confidential_flag_round_trips_through_setter() {
        let mut wallet = SingleKeyWallet::generate(Network::Regtest);
        assert!(!wallet.default_confidential());
        wallet.set_default_confidential(true);
        assert!(wallet.default_confidential());
    }

    #[test]
    fn snapshot_round_trip_preserves_transparent_key_and_flags() {
        let mut wallet = SingleKeyWallet::generate(Network::Regtest);
        wallet
            .derive_confidential_keys_from_seed(&fixture_seed(), 0, StealthNetwork::Regtest)
            .unwrap();
        wallet.set_default_confidential(true);

        let snapshot = wallet.to_snapshot();
        let restored = SingleKeyWallet::from_snapshot(&snapshot).unwrap();

        assert_eq!(restored.pubkey_hex(), wallet.pubkey_hex());
        assert_eq!(restored.network(), wallet.network());
        assert!(restored.default_confidential());
        assert_eq!(
            restored.confidential_meta_address(),
            wallet.confidential_meta_address(),
        );
    }

    #[test]
    fn snapshot_does_not_carry_stealth_secrets() {
        let mut wallet = SingleKeyWallet::generate(Network::Regtest);
        wallet
            .derive_confidential_keys_from_seed(&fixture_seed(), 0, StealthNetwork::Regtest)
            .unwrap();
        let json = serde_json::to_string(&wallet.to_snapshot()).expect("serialise");
        assert!(
            !json.contains("scan_key") && !json.contains("spend_key"),
            "snapshot must not include stealth-secret field names"
        );

        let snapshot: WalletSnapshot = serde_json::from_str(&json).expect("deserialise");
        let restored = SingleKeyWallet::from_snapshot(&snapshot).unwrap();
        assert!(
            restored.confidential_secrets().is_none(),
            "stealth secrets must require seed re-derivation"
        );
        assert_eq!(
            restored.confidential_meta_address(),
            wallet.confidential_meta_address(),
            "public meta-address still round-trips",
        );
    }

    #[test]
    fn snapshot_round_trip_through_json_preserves_all_public_fields() {
        let mut wallet = SingleKeyWallet::generate(Network::Regtest);
        wallet
            .derive_confidential_keys_from_seed(&fixture_seed(), 0, StealthNetwork::Regtest)
            .unwrap();
        wallet.set_default_confidential(true);

        let snapshot = wallet.to_snapshot();
        let json = serde_json::to_string(&snapshot).expect("serialise");
        let decoded: WalletSnapshot = serde_json::from_str(&json).expect("deserialise");
        let restored = SingleKeyWallet::from_snapshot(&decoded).unwrap();

        assert_eq!(restored.pubkey_hex(), wallet.pubkey_hex());
        assert_eq!(restored.network(), wallet.network());
        assert!(restored.default_confidential());
        assert_eq!(
            restored.confidential_meta_address(),
            wallet.confidential_meta_address(),
        );
    }

    #[test]
    fn legacy_snapshot_without_confidential_fields_decodes() {
        // Snapshots written before this change carry only `wif` and
        // `network`; the new optional fields must default cleanly.
        let json =
            r#"{"wif":"cVbZ8ovhye9AoAHFsqobR3y3i6QFddJfzAEYxQzFa6mQVibyVUE7","network":"regtest"}"#;
        let snapshot: WalletSnapshot = serde_json::from_str(json).expect("legacy parses");
        assert!(snapshot.confidential_meta_address.is_none());
        assert!(!snapshot.default_confidential);
    }

    #[test]
    fn debug_format_hides_secret_key_bytes() {
        let mut wallet = SingleKeyWallet::generate(Network::Regtest);
        wallet
            .derive_confidential_keys_from_seed(&fixture_seed(), 0, StealthNetwork::Regtest)
            .unwrap();
        let rendered = format!("{wallet:?}");
        let secret_hex = hex::encode(wallet.secret_key().secret_bytes());
        assert!(
            !rendered.contains(&secret_hex),
            "Debug must not leak secret bytes: {rendered}"
        );
    }
}
