//! Single-key wallet for the Ark client SDK.
//!
//! Provides key generation, PSBT signing, and Ark address derivation.
//! This mirrors Go's `client-lib/wallet` single-key wallet.

use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, PublicKey, XOnlyPublicKey};

use crate::error::{ClientError, ClientResult};

/// A simple single-key wallet that holds one keypair.
///
/// Used for signing PSBTs, deriving on-chain and off-chain addresses,
/// and generating BIP-322 ownership proofs.
#[derive(Debug, Clone)]
pub struct SingleKeyWallet {
    secret_key: SecretKey,
    public_key: PublicKey,
    network: Network,
}

impl SingleKeyWallet {
    /// Generate a new random wallet for `network`.
    pub fn generate(network: Network) -> Self {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = PublicKey::from_private_key(&secp, &PrivateKey::new(secret_key, network));
        Self {
            secret_key,
            public_key,
            network,
        }
    }

    /// Create a wallet from an existing WIF-encoded private key.
    pub fn from_wif(wif: &str, network: Network) -> ClientResult<Self> {
        let private_key: PrivateKey = wif
            .parse()
            .map_err(|e| ClientError::Wallet(format!("Invalid WIF: {e}")))?;
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        Ok(Self {
            secret_key: private_key.inner,
            public_key,
            network,
        })
    }

    /// Create a wallet from raw 32-byte secret key bytes.
    pub fn from_secret_bytes(bytes: &[u8], network: Network) -> ClientResult<Self> {
        let secret_key = SecretKey::from_slice(bytes)
            .map_err(|e| ClientError::Wallet(format!("Invalid secret key: {e}")))?;
        let secp = Secp256k1::new();
        let private_key = PrivateKey::new(secret_key, network);
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        Ok(Self {
            secret_key,
            public_key,
            network,
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
