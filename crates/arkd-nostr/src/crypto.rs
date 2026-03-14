//! Cryptographic primitives for Nostr: Schnorr signing and NIP-04 encryption.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::types::NostrEvent;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Error type for crypto operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Invalid hex: {0}")]
    InvalidHex(String),
}

/// Nostr keypair for signing events.
pub struct NostrKeypair {
    secret_key: SecretKey,
    public_key: XOnlyPublicKey,
}

impl NostrKeypair {
    /// Create a keypair from a hex-encoded secret key.
    pub fn from_hex(secret_key_hex: &str) -> Result<Self, CryptoError> {
        let bytes =
            hex::decode(secret_key_hex).map_err(|e| CryptoError::InvalidHex(e.to_string()))?;
        let secret_key = SecretKey::from_slice(&bytes)
            .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
        let secp = Secp256k1::new();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let (public_key, _parity) = keypair.x_only_public_key();
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Get the x-only public key as hex.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.public_key.serialize())
    }

    /// Sign a message hash with BIP-340 Schnorr signature.
    pub fn sign(&self, message_hash: &[u8; 32]) -> Result<String, CryptoError> {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(*message_hash);
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &self.secret_key);
        let sig = secp.sign_schnorr(&msg, &keypair);
        Ok(hex::encode(sig.serialize()))
    }

    /// Compute NIP-04 shared secret for encryption/decryption.
    /// Uses ECDH: shared_point = their_pubkey * our_secret_key
    pub fn compute_shared_secret(
        &self,
        recipient_pubkey_hex: &str,
    ) -> Result<[u8; 32], CryptoError> {
        let recipient_bytes = hex::decode(recipient_pubkey_hex)
            .map_err(|e| CryptoError::InvalidHex(e.to_string()))?;

        // Convert x-only pubkey to full pubkey (assume even Y)
        let mut full_pubkey = vec![0x02]; // even Y prefix
        full_pubkey.extend_from_slice(&recipient_bytes);

        let recipient_pubkey = PublicKey::from_slice(&full_pubkey)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        // ECDH multiplication
        let secp = Secp256k1::new();
        let shared_point = recipient_pubkey
            .mul_tweak(&secp, &self.secret_key.into())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Use the x-coordinate of the shared point as the shared secret
        let shared_x = &shared_point.serialize()[1..33]; // skip prefix, take x
        let mut result = [0u8; 32];
        result.copy_from_slice(shared_x);
        Ok(result)
    }
}

/// Compute NIP-01 event ID (SHA-256 of serialized event data).
///
/// The serialization format is:
/// [0, pubkey, created_at, kind, tags, content]
///
/// Tags must be properly serialized as a JSON array of arrays.
pub fn compute_event_id(event: &NostrEvent) -> String {
    // Build the serialization array as per NIP-01
    let serialized = serde_json::json!([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content
    ]);

    let json_string =
        serde_json::to_string(&serialized).expect("JSON serialization should not fail");

    let mut hasher = Sha256::new();
    hasher.update(json_string.as_bytes());
    hex::encode(hasher.finalize())
}

/// Sign a Nostr event in place, setting the id and sig fields.
pub fn sign_event(event: &mut NostrEvent, keypair: &NostrKeypair) -> Result<(), CryptoError> {
    // Compute event ID
    event.id = compute_event_id(event);

    // Sign the event ID
    let id_bytes = hex::decode(&event.id).map_err(|e| CryptoError::InvalidHex(e.to_string()))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&id_bytes);

    event.sig = keypair.sign(&hash)?;
    Ok(())
}

/// NIP-04 encrypt a message.
///
/// Returns: base64(ciphertext)?iv=base64(iv)
pub fn nip04_encrypt(plaintext: &str, shared_secret: &[u8; 32]) -> Result<String, CryptoError> {
    // Generate random 16-byte IV
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Pad plaintext to block size
    let plaintext_bytes = plaintext.as_bytes();
    let padded_len = ((plaintext_bytes.len() / 16) + 1) * 16;
    let mut buffer = vec![0u8; padded_len];

    // Encrypt with AES-256-CBC
    let cipher = Aes256CbcEnc::new(shared_secret.into(), &iv.into());
    let ciphertext = cipher
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext_bytes, &mut buffer)
        .map_err(|e| CryptoError::EncryptionFailed(format!("{:?}", e)))?;

    // Format: base64(ciphertext)?iv=base64(iv)
    let encoded_ciphertext = BASE64.encode(ciphertext);
    let encoded_iv = BASE64.encode(iv);

    Ok(format!("{}?iv={}", encoded_ciphertext, encoded_iv))
}

/// NIP-04 decrypt a message.
///
/// Input format: base64(ciphertext)?iv=base64(iv)
pub fn nip04_decrypt(encrypted: &str, shared_secret: &[u8; 32]) -> Result<String, CryptoError> {
    // Parse the encrypted format
    let parts: Vec<&str> = encrypted.split("?iv=").collect();
    if parts.len() != 2 {
        return Err(CryptoError::DecryptionFailed(
            "Invalid NIP-04 format: expected 'ciphertext?iv=iv'".to_string(),
        ));
    }

    let ciphertext = BASE64
        .decode(parts[0])
        .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid base64 ciphertext: {}", e)))?;
    let iv = BASE64
        .decode(parts[1])
        .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid base64 IV: {}", e)))?;

    if iv.len() != 16 {
        return Err(CryptoError::DecryptionFailed(format!(
            "Invalid IV length: expected 16, got {}",
            iv.len()
        )));
    }

    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(&iv);

    // Decrypt with AES-256-CBC
    let cipher = Aes256CbcDec::new(shared_secret.into(), &iv_arr.into());
    let mut buffer = ciphertext.clone();

    let plaintext = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| CryptoError::DecryptionFailed(format!("{:?}", e)))?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid UTF-8: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test keypair with known values
    const TEST_PRIVKEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn test_keypair_from_hex() {
        let keypair = NostrKeypair::from_hex(TEST_PRIVKEY).unwrap();
        // Public key for privkey=1 is well-known
        assert_eq!(keypair.pubkey_hex().len(), 64);
    }

    #[test]
    fn test_compute_event_id_deterministic() {
        let event = NostrEvent::unsigned("abc123", 1000, 1, vec![], "hello");
        let id1 = compute_event_id(&event);
        let id2 = compute_event_id(&event);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_compute_event_id_with_tags() {
        let event = NostrEvent::unsigned(
            "abc123",
            1000,
            4,
            vec![vec!["p".to_string(), "recipient_pubkey".to_string()]],
            "encrypted_content",
        );
        let id = compute_event_id(&event);
        assert_eq!(id.len(), 64);

        // Different tags → different ID
        let event2 = NostrEvent::unsigned(
            "abc123",
            1000,
            4,
            vec![vec!["p".to_string(), "different_pubkey".to_string()]],
            "encrypted_content",
        );
        let id2 = compute_event_id(&event2);
        assert_ne!(id, id2);
    }

    #[test]
    fn test_sign_event() {
        let keypair = NostrKeypair::from_hex(TEST_PRIVKEY).unwrap();
        let mut event =
            NostrEvent::unsigned(keypair.pubkey_hex(), 1234567890, 1, vec![], "Test message");

        sign_event(&mut event, &keypair).unwrap();

        assert!(!event.id.is_empty());
        assert!(!event.sig.is_empty());
        assert_eq!(event.sig.len(), 128); // 64 bytes = 128 hex chars
    }

    #[test]
    fn test_nip04_encrypt_decrypt_roundtrip() {
        // Use a simple shared secret for testing
        let shared_secret: [u8; 32] = [0x42; 32];
        let plaintext = "Hello, NIP-04!";

        let encrypted = nip04_encrypt(plaintext, &shared_secret).unwrap();
        assert!(encrypted.contains("?iv="));

        let decrypted = nip04_decrypt(&encrypted, &shared_secret).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nip04_different_messages_different_ciphertext() {
        let shared_secret: [u8; 32] = [0x42; 32];

        let enc1 = nip04_encrypt("message1", &shared_secret).unwrap();
        let enc2 = nip04_encrypt("message2", &shared_secret).unwrap();

        // Different messages → different ciphertext (even with same key)
        // Also, IV is random, so same message twice gives different results
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_nip04_invalid_format() {
        let shared_secret: [u8; 32] = [0x42; 32];

        // Missing IV separator
        let result = nip04_decrypt("invalidciphertext", &shared_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_invalid_hex() {
        let result = NostrKeypair::from_hex("not_valid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_invalid_key_length() {
        let result = NostrKeypair::from_hex("0011223344"); // Too short
        assert!(result.is_err());
    }
}
