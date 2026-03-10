//! Transaction signing service

use crate::{WalletError, WalletResult};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

/// Transaction signer
///
/// Handles ECDSA and Schnorr signing for Bitcoin transactions.
pub struct Signer {
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer {
    /// Create a new signer
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Sign a message hash with ECDSA
    pub fn sign_ecdsa(
        &self,
        message: &[u8; 32],
        secret_key: &SecretKey,
    ) -> WalletResult<bitcoin::secp256k1::ecdsa::Signature> {
        let msg = Message::from_digest(*message);
        Ok(self.secp.sign_ecdsa(&msg, secret_key))
    }

    /// Sign a message hash with Schnorr (for Taproot)
    pub fn sign_schnorr(
        &self,
        message: &[u8; 32],
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> WalletResult<bitcoin::secp256k1::schnorr::Signature> {
        let msg = Message::from_digest(*message);
        Ok(self.secp.sign_schnorr(&msg, keypair))
    }

    /// Verify an ECDSA signature
    pub fn verify_ecdsa(
        &self,
        message: &[u8; 32],
        signature: &bitcoin::secp256k1::ecdsa::Signature,
        public_key: &bitcoin::secp256k1::PublicKey,
    ) -> WalletResult<bool> {
        let msg = Message::from_digest(*message);
        Ok(self.secp.verify_ecdsa(&msg, signature, public_key).is_ok())
    }
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
        let message = [0u8; 32];

        let signature = signer.sign_ecdsa(&message, &secret_key).unwrap();
        let valid = signer
            .verify_ecdsa(&message, &signature, &public_key)
            .unwrap();

        assert!(valid);
    }
}
