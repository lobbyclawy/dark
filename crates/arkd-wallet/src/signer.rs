//! Transaction signing service
//!
//! Handles ECDSA and Schnorr (Taproot) signing for Bitcoin transactions.
//! Supports both key-path and script-path spending for Taproot.

use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::ecdsa::Signature as EcdsaSignature;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use bitcoin::secp256k1::{All, Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighash, TapSighashType};
use bitcoin::{Script, Transaction, TxOut};

use crate::{WalletError, WalletResult};

/// Transaction signer for ECDSA and Schnorr signatures
///
/// Provides signing functionality for:
/// - ECDSA signatures (legacy and SegWit v0)
/// - Schnorr signatures (Taproot key-path spending)
/// - Script-path Taproot spending
pub struct Signer {
    secp: Secp256k1<All>,
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer {
    /// Create a new signer with a fresh secp256k1 context
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Get the secp256k1 context
    pub fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    // =========================================================================
    // ECDSA Signing
    // =========================================================================

    /// Sign a 32-byte message hash with ECDSA
    pub fn sign_ecdsa(
        &self,
        message: &[u8; 32],
        secret_key: &SecretKey,
    ) -> WalletResult<EcdsaSignature> {
        let msg = Message::from_digest(*message);
        Ok(self.secp.sign_ecdsa(&msg, secret_key))
    }

    /// Sign a 32-byte message hash with low-R ECDSA (for smaller signatures)
    pub fn sign_ecdsa_low_r(
        &self,
        message: &[u8; 32],
        secret_key: &SecretKey,
    ) -> WalletResult<EcdsaSignature> {
        let msg = Message::from_digest(*message);
        Ok(self.secp.sign_ecdsa_low_r(&msg, secret_key))
    }

    /// Verify an ECDSA signature
    pub fn verify_ecdsa(
        &self,
        message: &[u8; 32],
        signature: &EcdsaSignature,
        public_key: &PublicKey,
    ) -> WalletResult<bool> {
        let msg = Message::from_digest(*message);
        Ok(self.secp.verify_ecdsa(&msg, signature, public_key).is_ok())
    }

    // =========================================================================
    // Schnorr (Taproot) Signing
    // =========================================================================

    /// Sign a 32-byte message hash with Schnorr
    pub fn sign_schnorr(
        &self,
        message: &[u8; 32],
        keypair: &Keypair,
    ) -> WalletResult<SchnorrSignature> {
        let msg = Message::from_digest(*message);
        Ok(self.secp.sign_schnorr(&msg, keypair))
    }

    /// Sign a 32-byte message hash with Schnorr using auxiliary randomness
    /// This is more secure as it adds additional entropy
    pub fn sign_schnorr_with_aux_rand(
        &self,
        message: &[u8; 32],
        keypair: &Keypair,
        aux_rand: &[u8; 32],
    ) -> WalletResult<SchnorrSignature> {
        let msg = Message::from_digest(*message);
        Ok(self
            .secp
            .sign_schnorr_with_aux_rand(&msg, keypair, aux_rand))
    }

    /// Verify a Schnorr signature
    pub fn verify_schnorr(
        &self,
        message: &[u8; 32],
        signature: &SchnorrSignature,
        public_key: &XOnlyPublicKey,
    ) -> WalletResult<bool> {
        let msg = Message::from_digest(*message);
        Ok(self
            .secp
            .verify_schnorr(signature, &msg, public_key)
            .is_ok())
    }

    // =========================================================================
    // Taproot Transaction Signing
    // =========================================================================

    /// Compute Taproot sighash for key-path spending
    pub fn compute_taproot_key_spend_sighash(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
        sighash_type: TapSighashType,
    ) -> WalletResult<TapSighash> {
        let mut cache = SighashCache::new(tx);
        let prevouts = Prevouts::All(prevouts);

        cache
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .map_err(|e| WalletError::SigningError(format!("Sighash computation failed: {e}")))
    }

    /// Compute Taproot sighash for script-path spending
    pub fn compute_taproot_script_spend_sighash(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
        leaf_hash: bitcoin::TapLeafHash,
        sighash_type: TapSighashType,
    ) -> WalletResult<TapSighash> {
        let mut cache = SighashCache::new(tx);
        let prevouts = Prevouts::All(prevouts);

        cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .map_err(|e| WalletError::SigningError(format!("Sighash computation failed: {e}")))
    }

    /// Sign a Taproot key-path spend
    ///
    /// This is the most common Taproot spending path.
    pub fn sign_taproot_key_spend(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
        keypair: &Keypair,
        sighash_type: TapSighashType,
    ) -> WalletResult<SchnorrSignature> {
        let sighash =
            self.compute_taproot_key_spend_sighash(tx, input_index, prevouts, sighash_type)?;

        let msg = Message::from_digest(sighash.to_byte_array());
        Ok(self.secp.sign_schnorr(&msg, keypair))
    }

    /// Sign a Taproot script-path spend
    ///
    /// Used when spending via a script in the taproot tree.
    pub fn sign_taproot_script_spend(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
        keypair: &Keypair,
        leaf_hash: bitcoin::TapLeafHash,
        sighash_type: TapSighashType,
    ) -> WalletResult<SchnorrSignature> {
        let sighash = self.compute_taproot_script_spend_sighash(
            tx,
            input_index,
            prevouts,
            leaf_hash,
            sighash_type,
        )?;

        let msg = Message::from_digest(sighash.to_byte_array());
        Ok(self.secp.sign_schnorr(&msg, keypair))
    }

    // =========================================================================
    // Key Operations
    // =========================================================================

    /// Generate a new random keypair
    pub fn generate_keypair(&self) -> Keypair {
        Keypair::new(&self.secp, &mut bitcoin::secp256k1::rand::thread_rng())
    }

    /// Create a keypair from a secret key
    pub fn keypair_from_secret(&self, secret: &SecretKey) -> Keypair {
        Keypair::from_secret_key(&self.secp, secret)
    }

    /// Tweak a keypair with a Taproot tweak
    /// Returns the tweaked keypair for key-path spending
    pub fn tweak_keypair(
        &self,
        keypair: &Keypair,
        merkle_root: Option<bitcoin::TapNodeHash>,
    ) -> WalletResult<bitcoin::key::TweakedKeypair> {
        Ok(keypair.tap_tweak(&self.secp, merkle_root))
    }

    /// Compute the Taproot output key from an internal key
    pub fn compute_taproot_output_key(
        &self,
        internal_key: XOnlyPublicKey,
        merkle_root: Option<bitcoin::TapNodeHash>,
    ) -> bitcoin::key::TweakedPublicKey {
        internal_key.tap_tweak(&self.secp, merkle_root).0
    }
}

/// Helper for computing leaf hashes for script-path spending
pub fn compute_leaf_hash(script: &Script) -> bitcoin::TapLeafHash {
    bitcoin::TapLeafHash::from_script(script, bitcoin::taproot::LeafVersion::TapScript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;

    #[test]
    fn test_ecdsa_sign_verify() {
        let signer = Signer::new();
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        let message = [0xab; 32];

        let signature = signer.sign_ecdsa(&message, &secret_key).unwrap();
        let valid = signer
            .verify_ecdsa(&message, &signature, &public_key)
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_ecdsa_low_r() {
        let signer = Signer::new();
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut OsRng);
        let message = [0xcd; 32];

        let sig = signer.sign_ecdsa_low_r(&message, &secret_key).unwrap();
        let bytes = sig.serialize_compact();

        // Low-R signatures should have first byte < 0x80
        assert!(bytes[0] < 0x80, "Signature R value is not low");
    }

    #[test]
    fn test_schnorr_sign_verify() {
        let signer = Signer::new();
        let keypair = signer.generate_keypair();
        let (xonly, _parity) = keypair.x_only_public_key();
        let message = [0xef; 32];

        let signature = signer.sign_schnorr(&message, &keypair).unwrap();
        let valid = signer.verify_schnorr(&message, &signature, &xonly).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_schnorr_with_aux_rand() {
        let signer = Signer::new();
        let keypair = signer.generate_keypair();
        let (xonly, _) = keypair.x_only_public_key();
        let message = [0x11; 32];
        let aux_rand = [0x22; 32];

        let sig = signer
            .sign_schnorr_with_aux_rand(&message, &keypair, &aux_rand)
            .unwrap();
        let valid = signer.verify_schnorr(&message, &sig, &xonly).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_taproot_output_key_computation() {
        let signer = Signer::new();
        let keypair = signer.generate_keypair();
        let internal_key = keypair.x_only_public_key().0;

        // Without merkle root (key-path only)
        let output_key = signer.compute_taproot_output_key(internal_key, None);

        // Output key should be different from internal key due to tweak
        // (TweakedPublicKey wraps XOnlyPublicKey)
        assert_ne!(output_key.to_x_only_public_key(), internal_key);
    }

    #[test]
    fn test_keypair_from_secret() {
        let signer = Signer::new();
        let secp = Secp256k1::new();
        let (secret, _) = secp.generate_keypair(&mut OsRng);

        let keypair = signer.keypair_from_secret(&secret);

        // Verify the public key matches
        let expected = PublicKey::from_secret_key(&secp, &secret);
        assert_eq!(keypair.public_key(), expected);
    }

    #[test]
    fn test_invalid_signature_fails_verification() {
        let signer = Signer::new();
        let keypair1 = signer.generate_keypair();
        let keypair2 = signer.generate_keypair();
        let message = [0x33; 32];

        // Sign with keypair1
        let sig = signer.sign_schnorr(&message, &keypair1).unwrap();

        // Verify with keypair2's public key should fail
        let (wrong_pubkey, _) = keypair2.x_only_public_key();
        let valid = signer
            .verify_schnorr(&message, &sig, &wrong_pubkey)
            .unwrap();

        assert!(!valid);
    }
}
