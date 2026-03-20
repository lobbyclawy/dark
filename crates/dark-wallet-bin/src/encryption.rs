//! AES-256-GCM seed encryption at rest with PBKDF2 key derivation.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Number of PBKDF2 iterations for key derivation.
const PBKDF2_ITERATIONS: u32 = 600_000;
/// Salt length in bytes.
const SALT_LEN: usize = 32;
/// Nonce length for AES-256-GCM (96 bits).
const NONCE_LEN: usize = 12;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: wrong password or corrupted data")]
    Decrypt,
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Encrypted seed stored on disk.
#[derive(Serialize, Deserialize)]
pub struct EncryptedSeed {
    /// PBKDF2 salt (hex).
    pub salt: String,
    /// AES-GCM nonce (hex).
    pub nonce: String,
    /// Ciphertext (hex).
    pub ciphertext: String,
}

/// Derive a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256.
fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypt a seed phrase with a password.
pub fn encrypt_seed(seed_phrase: &str, password: &str) -> Result<EncryptedSeed, EncryptionError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password.as_bytes(), &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, seed_phrase.as_bytes())
        .map_err(|e| EncryptionError::Encrypt(e.to_string()))?;

    Ok(EncryptedSeed {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Decrypt a seed phrase with a password.
pub fn decrypt_seed(encrypted: &EncryptedSeed, password: &str) -> Result<String, EncryptionError> {
    let salt = hex::decode(&encrypted.salt).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;
    let nonce_bytes =
        hex::decode(&encrypted.nonce).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;
    let ciphertext =
        hex::decode(&encrypted.ciphertext).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;

    let key = derive_key(password.as_bytes(), &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| EncryptionError::Decrypt)?;

    String::from_utf8(plaintext).map_err(|e| EncryptionError::Encrypt(e.to_string()))
}

/// Save encrypted seed to a file.
pub fn save_encrypted_seed(
    path: &std::path::Path,
    encrypted: &EncryptedSeed,
) -> Result<(), EncryptionError> {
    let json = serde_json::to_string_pretty(encrypted)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load encrypted seed from a file.
pub fn load_encrypted_seed(path: &std::path::Path) -> Result<EncryptedSeed, EncryptionError> {
    let json = std::fs::read_to_string(path)?;
    let encrypted: EncryptedSeed = serde_json::from_str(&json)?;
    Ok(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "test-password-123";

        let encrypted = encrypt_seed(seed, password).unwrap();
        let decrypted = decrypt_seed(&encrypted, password).unwrap();
        assert_eq!(decrypted, seed);
    }

    #[test]
    fn test_wrong_password_fails() {
        let seed = "test seed phrase";
        let encrypted = encrypt_seed(seed, "correct").unwrap();
        let result = decrypt_seed(&encrypted, "wrong");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EncryptionError::Decrypt));
    }

    #[test]
    fn test_encrypt_produces_unique_ciphertext() {
        let seed = "same seed same password";
        let password = "pw";
        let e1 = encrypt_seed(seed, password).unwrap();
        let e2 = encrypt_seed(seed, password).unwrap();
        // Different salt and nonce each time → different ciphertext
        assert_ne!(e1.ciphertext, e2.ciphertext);
        assert_ne!(e1.salt, e2.salt);
        assert_ne!(e1.nonce, e2.nonce);
        // Both still decrypt correctly
        assert_eq!(decrypt_seed(&e1, password).unwrap(), seed);
        assert_eq!(decrypt_seed(&e2, password).unwrap(), seed);
    }

    #[test]
    fn test_empty_seed_roundtrip() {
        let encrypted = encrypt_seed("", "pw").unwrap();
        assert_eq!(decrypt_seed(&encrypted, "pw").unwrap(), "");
    }

    #[test]
    fn test_empty_password_roundtrip() {
        let seed = "some seed";
        let encrypted = encrypt_seed(seed, "").unwrap();
        assert_eq!(decrypt_seed(&encrypted, "").unwrap(), seed);
        // Wrong password still fails
        assert!(decrypt_seed(&encrypted, "x").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let encrypted = encrypt_seed("my seed", "pw").unwrap();
        let mut tampered = encrypted;
        // Flip a byte in the ciphertext hex
        let mut ct_bytes = hex::decode(&tampered.ciphertext).unwrap();
        ct_bytes[0] ^= 0xff;
        tampered.ciphertext = hex::encode(ct_bytes);
        assert!(decrypt_seed(&tampered, "pw").is_err());
    }

    #[test]
    fn test_tampered_nonce_fails() {
        let encrypted = encrypt_seed("my seed", "pw").unwrap();
        let mut tampered = encrypted;
        let mut nonce_bytes = hex::decode(&tampered.nonce).unwrap();
        nonce_bytes[0] ^= 0xff;
        tampered.nonce = hex::encode(nonce_bytes);
        assert!(decrypt_seed(&tampered, "pw").is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let encrypted = encrypt_seed("my seed phrase", "password").unwrap();
        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedSeed = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decrypt_seed(&deserialized, "password").unwrap(),
            "my seed phrase"
        );
    }

    #[test]
    fn test_save_load_roundtrip() {
        let encrypted = encrypt_seed("file roundtrip seed", "secret").unwrap();
        let dir = std::env::temp_dir();
        let path = dir.join("dark_test_encrypted_seed.json");
        save_encrypted_seed(&path, &encrypted).unwrap();
        let loaded = load_encrypted_seed(&path).unwrap();
        assert_eq!(
            decrypt_seed(&loaded, "secret").unwrap(),
            "file roundtrip seed"
        );
        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_unicode_seed_roundtrip() {
        let seed = "🔑 abandon abandon abandon 日本語";
        let encrypted = encrypt_seed(seed, "pw").unwrap();
        assert_eq!(decrypt_seed(&encrypted, "pw").unwrap(), seed);
    }
}
