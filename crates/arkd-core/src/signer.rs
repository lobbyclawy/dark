//! Local signer — loads ASP key from config and signs locally.

use async_trait::async_trait;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::XOnlyPublicKey;
use tokio::sync::RwLock;

use crate::error::ArkResult;
use crate::ports::SignerService;

/// A local signer that holds a secret key in memory.
///
/// Use [`LocalSigner::from_hex`] to load from a hex-encoded private key
/// (e.g. from config), or [`LocalSigner::random`] for dev/test.
pub struct LocalSigner {
    secret_key: SecretKey,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl LocalSigner {
    /// Create a `LocalSigner` from a hex-encoded 32-byte secret key.
    pub fn from_hex(hex_key: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = hex::decode(hex_key)?;
        let secret_key = SecretKey::from_slice(&bytes)?;
        Ok(Self {
            secret_key,
            secp: Secp256k1::new(),
        })
    }

    /// Generate a random signer (useful for testing / dev mode).
    pub fn random() -> Self {
        use bitcoin::secp256k1::rand::rngs::OsRng;
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut OsRng);
        Self { secret_key, secp }
    }

    /// Return the compressed public key bytes (33 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        bitcoin::secp256k1::PublicKey::from_secret_key(&self.secp, &self.secret_key)
            .serialize()
            .to_vec()
    }
}

#[async_trait]
impl SignerService for LocalSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&self.secp, &self.secret_key);
        let (xonly, _parity) = pk.x_only_public_key();
        Ok(xonly)
    }

    async fn sign_transaction(&self, partial_tx: &str, _extract_raw: bool) -> ArkResult<String> {
        // TODO(#80): Implement real PSBT signing with the secret key.
        // For now, return the transaction as-is (matches MockSigner behaviour)
        // so the rest of the pipeline can be wired up.
        Ok(partial_tx.to_string())
    }
}

/// A wrapper around `dyn SignerService` that allows runtime replacement.
///
/// Used by `SignerManagerService` to hot-swap the active ASP signer
/// without restarting the server. The inner signer is protected by a
/// `RwLock` so reads (signing operations) can proceed concurrently.
pub struct SwappableSigner {
    inner: RwLock<Box<dyn SignerService>>,
}

impl SwappableSigner {
    /// Create a new `SwappableSigner` wrapping the given initial signer.
    pub fn new(signer: Box<dyn SignerService>) -> Self {
        Self {
            inner: RwLock::new(signer),
        }
    }

    /// Replace the active signer with a new one.
    ///
    /// Acquires an exclusive write lock. Any in-flight signing operations
    /// will complete before the swap takes effect.
    pub async fn swap(&self, new_signer: Box<dyn SignerService>) {
        let mut guard = self.inner.write().await;
        *guard = new_signer;
    }
}

#[async_trait]
impl SignerService for SwappableSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        let guard = self.inner.read().await;
        guard.get_pubkey().await
    }

    async fn sign_transaction(&self, partial_tx: &str, extract_raw: bool) -> ArkResult<String> {
        let guard = self.inner.read().await;
        guard.sign_transaction(partial_tx, extract_raw).await
    }
}
