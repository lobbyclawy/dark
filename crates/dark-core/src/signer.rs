//! Local signer — loads ASP key from config and signs locally.

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::XOnlyPublicKey;
use tokio::sync::RwLock;

use crate::error::{ArkError, ArkResult};
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

    async fn sign_transaction(&self, partial_tx: &str, extract_raw: bool) -> ArkResult<String> {
        // Decode PSBT from hex or base64
        let psbt_bytes = hex::decode(partial_tx)
            .or_else(|_| {
                use bitcoin::base64::Engine;
                bitcoin::base64::engine::general_purpose::STANDARD.decode(partial_tx)
            })
            .map_err(|e| ArkError::Internal(format!("Failed to decode PSBT: {e}")))?;

        let mut psbt = Psbt::deserialize(&psbt_bytes)
            .map_err(|e| ArkError::Internal(format!("Failed to parse PSBT: {e}")))?;

        // Build keypair and tweak it for taproot key-path spending
        let keypair = Keypair::from_secret_key(&self.secp, &self.secret_key);
        let tweaked = keypair.tap_tweak(&self.secp, None);
        let signing_keypair = tweaked.to_keypair();

        // Collect prevouts for sighash computation
        let prevouts: Vec<bitcoin::TxOut> = psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                input.witness_utxo.clone().ok_or_else(|| {
                    ArkError::Internal(format!("Missing witness_utxo for input {i}"))
                })
            })
            .collect::<ArkResult<Vec<_>>>()?;

        // Sign each input with taproot key-path spend
        let num_inputs = psbt.inputs.len();
        for idx in 0..num_inputs {
            let sighash = {
                let prevouts_ref = Prevouts::All(&prevouts);
                let mut sighash_cache = SighashCache::new(psbt.unsigned_tx.clone());
                sighash_cache
                    .taproot_key_spend_signature_hash(idx, &prevouts_ref, TapSighashType::Default)
                    .map_err(|e| {
                        ArkError::Internal(format!(
                            "Sighash computation failed for input {idx}: {e}"
                        ))
                    })?
            };

            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = self.secp.sign_schnorr(&msg, &signing_keypair);

            let taproot_sig = bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            };

            psbt.inputs[idx].tap_key_sig = Some(taproot_sig);
        }

        if extract_raw {
            // Finalize the PSBT and extract raw transaction
            for input in &mut psbt.inputs {
                if let Some(sig) = input.tap_key_sig {
                    input.final_script_witness =
                        Some(bitcoin::Witness::from_slice(&[sig.serialize()]));
                    // Clear partial data after finalization
                    input.tap_key_sig = None;
                    input.tap_scripts.clear();
                    input.tap_key_origins.clear();
                }
            }

            let tx = psbt
                .extract_tx()
                .map_err(|e| ArkError::Internal(format!("Failed to extract tx: {e}")))?;
            Ok(hex::encode(bitcoin::consensus::serialize(&tx)))
        } else {
            // Return signed PSBT as hex
            Ok(hex::encode(psbt.serialize()))
        }
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
