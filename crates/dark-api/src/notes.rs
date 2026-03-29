//! Note store — in-memory bearer note registry.
//!
//! A note is a 32-byte random preimage + 4-byte big-endian uint32 value,
//! encoded as `"arknote" + base58(preimage || value)` — compatible with
//! the Go ark-lib `note` package format.
//!
//! Notes support two-phase redemption: `redeem_pending` moves a note to
//! "pending" state (keyed by round ID), `confirm_pending` finalizes it,
//! and `rollback_pending` returns it to available. Legacy `redeem` still
//! works for contexts that don't need two-phase semantics.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::secp256k1::rand::RngCore;
use tokio::sync::Mutex;

const NOTE_HRP: &str = "arknote";
const PREIMAGE_SIZE: usize = 32;

/// Entry in the note store: (preimage_bytes, amount_sats).
type NoteEntry = ([u8; PREIMAGE_SIZE], u64);

/// A pending redemption entry: the note data and optionally the outpoint txid
/// (for notes redeemed via `try_redeem_by_outpoint_pending`).
#[derive(Clone)]
struct PendingEntry {
    key: String,
    entry: NoteEntry,
    /// If redeemed via outpoint, store the outpoint txid for later confirmation.
    outpoint_txid: Option<String>,
}

/// Thread-safe in-memory note store.
#[derive(Clone, Default)]
pub struct NoteStore {
    /// preimage hex → (preimage_bytes, amount_sats)
    inner: Arc<Mutex<HashMap<String, NoteEntry>>>,
    /// Set of outpoint txid hashes for already-redeemed notes.
    /// Used by `try_redeem_by_outpoint` to distinguish "never was a note" from "already redeemed".
    redeemed_outpoints: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Pending redemptions: round_id → list of pending entries.
    /// Notes here have been removed from `inner` but not yet permanently consumed.
    pending: Arc<Mutex<HashMap<String, Vec<PendingEntry>>>>,
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

    /// Attempt to redeem a note string (immediate / permanent).
    /// Returns `Ok(amount_sats)` on success, `Err` if invalid or already redeemed.
    pub async fn redeem(&self, note_str: &str) -> Result<u64, String> {
        let (preimage, _decoded_amount) = decode_note(note_str)?;
        let key = hex::encode(preimage);

        // Lock order: pending → inner (consistent across all methods).
        let pending = self.pending.lock().await;
        for entries in pending.values() {
            if entries.iter().any(|e| e.key == key) {
                return Err(format!("note not found or already redeemed: {}", &key[..8]));
            }
        }
        drop(pending);

        let mut store = self.inner.lock().await;
        match store.remove(&key) {
            Some((_, stored_amount)) => Ok(stored_amount),
            None => Err(format!("note not found or already redeemed: {}", &key[..8])),
        }
    }

    /// Redeem a note string in pending mode: removes it from the available pool
    /// and associates it with `round_id`. The note can later be confirmed
    /// (permanently consumed) or rolled back (returned to available).
    ///
    /// Returns `Ok(amount_sats)` on success.
    pub async fn redeem_pending(&self, note_str: &str, round_id: &str) -> Result<u64, String> {
        let (preimage, _decoded_amount) = decode_note(note_str)?;
        let key = hex::encode(preimage);

        // Lock order: pending → inner (consistent across all methods).
        let mut pending = self.pending.lock().await;
        for entries in pending.values() {
            if entries.iter().any(|e| e.key == key) {
                return Err(format!("note not found or already redeemed: {}", &key[..8]));
            }
        }

        let mut store = self.inner.lock().await;
        match store.remove(&key) {
            Some(entry) => {
                let amount = entry.1;
                pending
                    .entry(round_id.to_string())
                    .or_default()
                    .push(PendingEntry {
                        key,
                        entry,
                        outpoint_txid: None,
                    });
                Ok(amount)
            }
            None => Err(format!("note not found or already redeemed: {}", &key[..8])),
        }
    }

    /// Confirm all pending note redemptions for a given round.
    /// Notes are permanently consumed and their outpoints (if any) are added
    /// to the redeemed set.
    pub async fn confirm_pending(&self, round_id: &str) {
        let mut pending = self.pending.lock().await;
        if let Some(entries) = pending.remove(round_id) {
            let mut redeemed = self.redeemed_outpoints.lock().await;
            for entry in entries {
                if let Some(outpoint) = entry.outpoint_txid {
                    redeemed.insert(outpoint);
                }
            }
        }
    }

    /// Roll back all pending note redemptions for a given round.
    /// Notes are returned to the available pool so they can be redeemed again.
    pub async fn rollback_pending(&self, round_id: &str) {
        let mut pending = self.pending.lock().await;
        if let Some(entries) = pending.remove(round_id) {
            let mut store = self.inner.lock().await;
            for entry in entries {
                store.insert(entry.key, entry.entry);
            }
        }
    }

    /// Move pending entries from one key to another.
    /// Used to re-key temporary pending keys to the actual round_id.
    pub async fn rekey_pending(&self, old_key: &str, new_key: &str) {
        if old_key == new_key {
            return;
        }
        let mut pending = self.pending.lock().await;
        if let Some(entries) = pending.remove(old_key) {
            pending
                .entry(new_key.to_string())
                .or_default()
                .extend(entries);
        }
    }

    /// Try to redeem a note by its preimage hash (the PSBT outpoint txid).
    ///
    /// When the Go SDK uses `RegisterIntent` with note inputs, the outpoint
    /// txid is `SHA256(preimage)`. This method scans the store for a matching
    /// note and redeems it.
    ///
    /// Returns `Ok(Some(amount))` if redeemed, `Ok(None)` if no match,
    /// or `Err` if the note was already redeemed.
    pub async fn try_redeem_by_outpoint(
        &self,
        outpoint_txid_hex: &str,
    ) -> Result<Option<u64>, String> {
        use bitcoin::hashes::{sha256, Hash};

        // Check if this outpoint was already redeemed
        {
            let redeemed = self.redeemed_outpoints.lock().await;
            if redeemed.contains(outpoint_txid_hex) {
                return Err(format!(
                    "note already redeemed (outpoint {}…)",
                    &outpoint_txid_hex[..8.min(outpoint_txid_hex.len())]
                ));
            }
        }

        // Also check pending — a note in pending state is not available
        {
            let pending = self.pending.lock().await;
            for entries in pending.values() {
                if entries
                    .iter()
                    .any(|e| e.outpoint_txid.as_deref() == Some(outpoint_txid_hex))
                {
                    return Err(format!(
                        "note already redeemed (outpoint {}…)",
                        &outpoint_txid_hex[..8.min(outpoint_txid_hex.len())]
                    ));
                }
            }
        }

        let mut store = self.inner.lock().await;
        let mut matching_key = None;
        for (key, (preimage, _)) in store.iter() {
            let hash = sha256::Hash::hash(preimage);
            let hash_hex = hex::encode(hash.as_byte_array());
            // Bitcoin txids are displayed in reverse byte order
            let hash_reversed: String = hash
                .as_byte_array()
                .iter()
                .rev()
                .map(|b| format!("{:02x}", b))
                .collect();
            if hash_hex == outpoint_txid_hex || hash_reversed == outpoint_txid_hex {
                matching_key = Some(key.clone());
                break;
            }
        }

        match matching_key {
            Some(key) => match store.remove(&key) {
                Some((_, amount)) => {
                    // Track redeemed outpoints so future lookups return Err
                    let mut redeemed = self.redeemed_outpoints.lock().await;
                    redeemed.insert(outpoint_txid_hex.to_string());
                    Ok(Some(amount))
                }
                None => Err(format!("note already redeemed: {}", &key[..8])),
            },
            None => Ok(None),
        }
    }

    /// Pending variant of `try_redeem_by_outpoint`: moves the note to pending
    /// state associated with `round_id` instead of permanently consuming it.
    ///
    /// Returns `Ok(Some(amount))` if redeemed, `Ok(None)` if no match,
    /// or `Err` if the note was already redeemed.
    pub async fn try_redeem_by_outpoint_pending(
        &self,
        outpoint_txid_hex: &str,
        round_id: &str,
    ) -> Result<Option<u64>, String> {
        use bitcoin::hashes::{sha256, Hash};

        // Check if this outpoint was already redeemed (permanently)
        {
            let redeemed = self.redeemed_outpoints.lock().await;
            if redeemed.contains(outpoint_txid_hex) {
                return Err(format!(
                    "note already redeemed (outpoint {}…)",
                    &outpoint_txid_hex[..8.min(outpoint_txid_hex.len())]
                ));
            }
        }

        // Lock order: pending → inner (consistent across all methods).
        let mut pending = self.pending.lock().await;
        for entries in pending.values() {
            if entries
                .iter()
                .any(|e| e.outpoint_txid.as_deref() == Some(outpoint_txid_hex))
            {
                return Err(format!(
                    "note already redeemed (outpoint {}…)",
                    &outpoint_txid_hex[..8.min(outpoint_txid_hex.len())]
                ));
            }
        }

        let mut store = self.inner.lock().await;
        let mut matching_key = None;
        for (key, (preimage, _)) in store.iter() {
            let hash = sha256::Hash::hash(preimage);
            let hash_hex = hex::encode(hash.as_byte_array());
            let hash_reversed: String = hash
                .as_byte_array()
                .iter()
                .rev()
                .map(|b| format!("{:02x}", b))
                .collect();
            if hash_hex == outpoint_txid_hex || hash_reversed == outpoint_txid_hex {
                matching_key = Some(key.clone());
                break;
            }
        }

        match matching_key {
            Some(key) => match store.remove(&key) {
                Some(entry) => {
                    let amount = entry.1;
                    pending
                        .entry(round_id.to_string())
                        .or_default()
                        .push(PendingEntry {
                            key,
                            entry,
                            outpoint_txid: Some(outpoint_txid_hex.to_string()),
                        });
                    Ok(Some(amount))
                }
                None => Err(format!("note already redeemed: {}", &key[..8])),
            },
            None => Ok(None),
        }
    }
}

/// Public decode helper so callers can validate note format without redeeming.
pub fn decode_note_public(s: &str) -> Result<([u8; PREIMAGE_SIZE], u32), String> {
    decode_note(s)
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
