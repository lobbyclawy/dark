//! Note store — in-memory bearer note registry.
//!
//! A note is a 32-byte random preimage + 4-byte big-endian uint32 value,
//! encoded as `"arknote" + base58(preimage || value)` — compatible with
//! the Go ark-lib `note` package format.
//!
//! Notes are single-use: `redeem` marks them consumed and returns the amount.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::secp256k1::rand::RngCore;
use tokio::sync::Mutex;

const NOTE_HRP: &str = "arknote";
const PREIMAGE_SIZE: usize = 32;

/// Entry in the note store: (preimage_bytes, amount_sats).
type NoteEntry = ([u8; PREIMAGE_SIZE], u64);

/// Thread-safe in-memory note store.
#[derive(Clone, Default)]
pub struct NoteStore {
    /// preimage hex → (preimage_bytes, amount_sats)
    inner: Arc<Mutex<HashMap<String, NoteEntry>>>,
}

impl NoteStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create `quantity` notes each worth `amount` sats.
    /// Returns encoded note strings.
    pub async fn create(&self, amount: u32, quantity: u32) -> Vec<String> {
        let mut store = self.inner.lock().await;
        let mut notes = Vec::with_capacity(quantity as usize);
        for _ in 0..quantity {
            let mut preimage = [0u8; PREIMAGE_SIZE];
            bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut preimage);
            let key = hex::encode(preimage);
            store.insert(key, (preimage, amount as u64));
            notes.push(encode_note(&preimage, amount));
        }
        notes
    }

    /// Attempt to redeem a note string.
    /// Returns `Ok(amount_sats)` on success, `Err` if invalid or already redeemed.
    pub async fn redeem(&self, note_str: &str) -> Result<u64, String> {
        let (preimage, _decoded_amount) = decode_note(note_str)?;
        let key = hex::encode(preimage);
        let mut store = self.inner.lock().await;
        match store.remove(&key) {
            Some((_, stored_amount)) => Ok(stored_amount),
            None => Err(format!("note not found or already redeemed: {}", &key[..8])),
        }
    }
}

/// Encode a note as `"arknote" + base58(preimage || big_endian(value))`.
fn encode_note(preimage: &[u8; PREIMAGE_SIZE], value: u32) -> String {
    let mut buf = Vec::with_capacity(PREIMAGE_SIZE + 4);
    buf.extend_from_slice(preimage);
    buf.extend_from_slice(&value.to_be_bytes());
    format!("{}{}", NOTE_HRP, bitcoin::base58::encode(&buf))
}

/// Decode a note string back to (preimage, value).
fn decode_note(s: &str) -> Result<([u8; PREIMAGE_SIZE], u32), String> {
    let encoded = s
        .strip_prefix(NOTE_HRP)
        .ok_or_else(|| format!("missing '{}' prefix", NOTE_HRP))?;
    let decoded =
        bitcoin::base58::decode(encoded).map_err(|e| format!("base58 decode failed: {e}"))?;
    if decoded.len() != PREIMAGE_SIZE + 4 {
        return Err(format!(
            "invalid note length: expected {}, got {}",
            PREIMAGE_SIZE + 4,
            decoded.len()
        ));
    }
    let mut preimage = [0u8; PREIMAGE_SIZE];
    preimage.copy_from_slice(&decoded[..PREIMAGE_SIZE]);
    let value = u32::from_be_bytes(decoded[PREIMAGE_SIZE..].try_into().unwrap());
    Ok((preimage, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip() {
        let store = NoteStore::new();
        let notes = store.create(21_000, 1).await;
        assert_eq!(notes.len(), 1);
        assert!(notes[0].starts_with(NOTE_HRP));

        let amount = store.redeem(&notes[0]).await.unwrap();
        assert_eq!(amount, 21_000);

        // second redeem should fail
        assert!(store.redeem(&notes[0]).await.is_err());
    }

    #[tokio::test]
    async fn invalid_note() {
        let store = NoteStore::new();
        assert!(store.redeem("arknoteBADDATA").await.is_err());
        assert!(store.redeem("notanote").await.is_err());
    }
}
