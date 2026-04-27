//! Local cache of owned confidential VTXOs (issue #574).
//!
//! For every confidential VTXO this wallet owns we keep the opening
//! tuple `(vtxo_id, amount, blinding, one_time_sk)` plus a small
//! [`ScopeMetadata`] block locally. Balance and send flows read from
//! this cache; restore (#560) and the live stealth scanner (#558) feed
//! into it.
//!
//! ## On-disk shape
//!
//! Persistence is provided by [`EncryptedFileOwnedVtxoStore`]. It
//! reuses the same AES-256-GCM + PBKDF2-HMAC-SHA256 stack that
//! [`dark-wallet-bin`](../../dark-wallet-bin/src/encryption.rs)
//! uses for the seed at rest — same iteration count, same salt and
//! nonce widths, same JSON envelope shape (`salt` / `nonce` /
//! `ciphertext`, all hex-encoded). The plaintext payload is the
//! JSON serialisation of `OwnedVtxosSnapshot`.
//!
//! ## Mutation safety
//!
//! Every mutation rewrites the whole file via `atomic_write`:
//! create-and-write `<path>.tmp`, then `rename` into place. This
//! gives us crash atomicity at filesystem granularity — a
//! mid-write crash leaves either the prior snapshot or the new one,
//! never a torn file.
//!
//! ## Memory hygiene
//!
//! [`OwnedConfidentialVtxo`] does not derive `Clone`; secrets stay
//! in one place unless [`OwnedConfidentialVtxo::cloned`] is called
//! deliberately. The secret fields are erased on drop via
//! [`Zeroize`]/[`ZeroizeOnDrop`] (see [`SecretBytes`]). The
//! decrypted JSON buffer used during a load is also wiped before
//! we return.
//!
//! ## Scope and stubs
//!
//! Issue #574 lists #571 and #573 as concurrent dependencies. To
//! keep this module independently buildable, [`OwnedConfidentialVtxo`]
//! holds the secret fields as 32-byte arrays rather than typed
//! `secp256k1::Scalar` / `secp256k1::SecretKey`. The conversion
//! helpers ([`OwnedConfidentialVtxo::blinding_scalar`] and
//! [`OwnedConfidentialVtxo::one_time_secret_key`]) are zero-cost
//! and validate the bytes lie in the curve subgroup.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use secp256k1::{Scalar, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PBKDF2 iterations — matches `dark-wallet-bin::encryption`.
const PBKDF2_ITERATIONS: u32 = 600_000;
/// PBKDF2 salt width in bytes — matches `dark-wallet-bin::encryption`.
const SALT_LEN: usize = 32;
/// AES-256-GCM nonce width in bytes (96-bit, the standard width).
const NONCE_LEN: usize = 12;
/// Suffix used for the temp file in `atomic_write`.
const TMP_SUFFIX: &str = ".tmp";

/// 32-byte secret that erases itself on drop.
///
/// Used as the in-memory home for `blinding` and `one_time_sk`.
/// Holding the bytes directly (rather than a typed
/// `secp256k1::Scalar` / `SecretKey`) lets us derive [`Zeroize`]
/// trivially and keeps the cache free of curve-subgroup
/// validation until the value is actually consumed.
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretBytes(#[serde(with = "hex_array_32")] pub [u8; 32]);

impl SecretBytes {
    /// Borrow the inner bytes. Callers must not retain the slice
    /// past the lifetime of the [`SecretBytes`].
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    /// Redacts the inner bytes; we never want secrets in logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

mod hex_array_32 {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(d)?;
        let decoded = hex::decode(&raw).map_err(D::Error::custom)?;
        decoded
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

/// Small public anchoring block for an owned VTXO — round id and
/// the round height it was emitted at. Keeps balance/UI flows from
/// having to round-trip the full [`crate::types::Vtxo`] just to
/// label a row.
///
/// Public-by-design: contains no secret material.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeMetadata {
    /// Round identifier the VTXO was emitted in.
    pub round_id: String,
    /// Round height (per the operator's announcement stream).
    pub round_height: u64,
    /// Wallet account index this VTXO was discovered under.
    pub account_index: u32,
}

/// A single owned confidential VTXO row in the local cache.
///
/// Carries everything balance and send flows need: the public
/// `vtxo_id`, the cleartext `amount`, the secret `blinding` (so the
/// Pedersen opening can be re-derived), and the `one_time_sk` that
/// authorises the spend. [`ScopeMetadata`] is a public sidecar.
///
/// **Not `Clone`-able by design**. Use [`Self::cloned`] when a
/// duplicate is genuinely required (e.g. test fixtures, transfer
/// to a worker thread).
#[derive(Debug, Serialize, Deserialize)]
pub struct OwnedConfidentialVtxo {
    /// Public identifier of the VTXO (matches the `vtxo_id` carried
    /// on round announcements).
    pub vtxo_id: String,
    /// VTXO amount in satoshis.
    pub amount: u64,
    /// Pedersen blinding factor, secret. Erased on drop.
    pub blinding: SecretBytes,
    /// One-time spend key, secret. Erased on drop.
    pub one_time_sk: SecretBytes,
    /// Public anchoring metadata.
    pub scope_metadata: ScopeMetadata,
}

impl OwnedConfidentialVtxo {
    /// Construct an owned-VTXO row from raw secret bytes.
    pub fn new(
        vtxo_id: impl Into<String>,
        amount: u64,
        blinding: [u8; 32],
        one_time_sk: [u8; 32],
        scope_metadata: ScopeMetadata,
    ) -> Self {
        Self {
            vtxo_id: vtxo_id.into(),
            amount,
            blinding: SecretBytes(blinding),
            one_time_sk: SecretBytes(one_time_sk),
            scope_metadata,
        }
    }

    /// Explicit deep copy. Only call when a duplicate is genuinely
    /// required — secrets get re-materialised in memory.
    pub fn cloned(&self) -> Self {
        Self {
            vtxo_id: self.vtxo_id.clone(),
            amount: self.amount,
            blinding: SecretBytes(self.blinding.0),
            one_time_sk: SecretBytes(self.one_time_sk.0),
            scope_metadata: self.scope_metadata.clone(),
        }
    }

    /// Try to interpret `blinding` as a curve scalar. Fails if the
    /// bytes lie outside the secp256k1 group order.
    pub fn blinding_scalar(&self) -> Result<Scalar, OwnedVtxoError> {
        Scalar::from_be_bytes(self.blinding.0)
            .map_err(|_| OwnedVtxoError::InvalidSecret("blinding"))
    }

    /// Try to interpret `one_time_sk` as a [`SecretKey`]. Fails if
    /// the bytes are zero or out of range.
    pub fn one_time_secret_key(&self) -> Result<SecretKey, OwnedVtxoError> {
        SecretKey::from_slice(&self.one_time_sk.0)
            .map_err(|_| OwnedVtxoError::InvalidSecret("one_time_sk"))
    }
}

/// Errors returned by the owned-VTXO store.
#[derive(Debug, Error)]
pub enum OwnedVtxoError {
    /// Tried to insert a row whose `vtxo_id` is already in the store.
    #[error("vtxo {0} already present in the store")]
    DuplicateVtxo(String),

    /// Tried to remove a row whose `vtxo_id` is not present.
    #[error("vtxo {0} not present in the store")]
    UnknownVtxo(String),

    /// Cached secret bytes do not encode a valid curve element.
    /// Indicates the cache file was tampered with or written by a
    /// future format we do not understand.
    #[error("cached secret field `{0}` is not a valid curve element")]
    InvalidSecret(&'static str),

    /// Decryption failed — wrong passphrase, tampered ciphertext,
    /// or wrong key-derivation parameters.
    #[error("decryption failed: wrong passphrase or corrupted file")]
    Decrypt,

    /// On-disk envelope is structurally invalid (bad JSON, bad hex,
    /// bad sizes). Distinct from [`Self::Decrypt`] so callers can
    /// surface a clearer message: tampering rather than wrong key.
    #[error("on-disk file is corrupted: {0}")]
    Corrupted(String),

    /// Filesystem I/O error during read / write / rename.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON encode of the plaintext snapshot failed — should be
    /// unreachable in practice (the snapshot is owned data with
    /// no funky `Serialize` impls).
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// AES-GCM encryption failed — should be unreachable; AES-GCM
    /// only fails encryption when the cipher is mis-keyed.
    #[error("encryption failed: {0}")]
    Encrypt(String),
}

/// Storage abstraction over owned confidential VTXO rows.
///
/// The trait is intentionally narrow: callers do not need
/// pagination or query predicates beyond `find_by_id`, and adding
/// surface here forces every backend to implement it.
pub trait OwnedVtxoStore {
    /// Insert a fresh row. Errors if `vtxo.vtxo_id` already exists.
    fn insert(&self, vtxo: OwnedConfidentialVtxo) -> Result<(), OwnedVtxoError>;

    /// Remove the row with the given id. Errors if absent.
    fn remove(&self, vtxo_id: &str) -> Result<(), OwnedVtxoError>;

    /// All rows currently held, deep-cloned. The order is stable
    /// (sorted by `vtxo_id`) so callers can compare snapshots.
    fn list(&self) -> Vec<OwnedConfidentialVtxo>;

    /// Look up a single row by id. Returns a [`OwnedConfidentialVtxo::cloned`]
    /// copy so the caller can hold the secret without locking the
    /// store.
    fn find_by_id(&self, vtxo_id: &str) -> Option<OwnedConfidentialVtxo>;

    /// Sum of `amount` across all rows. Convenience for balance UI.
    fn total_amount(&self) -> u64;
}

/// In-memory [`OwnedVtxoStore`]. Useful for tests and for wallets
/// that accept the trade-off of losing the cache on shutdown.
#[derive(Default)]
pub struct InMemoryOwnedVtxoStore {
    rows: Mutex<BTreeMap<String, OwnedConfidentialVtxo>>,
}

impl InMemoryOwnedVtxoStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl OwnedVtxoStore for InMemoryOwnedVtxoStore {
    fn insert(&self, vtxo: OwnedConfidentialVtxo) -> Result<(), OwnedVtxoError> {
        let mut rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        if rows.contains_key(&vtxo.vtxo_id) {
            return Err(OwnedVtxoError::DuplicateVtxo(vtxo.vtxo_id));
        }
        rows.insert(vtxo.vtxo_id.clone(), vtxo);
        Ok(())
    }

    fn remove(&self, vtxo_id: &str) -> Result<(), OwnedVtxoError> {
        let mut rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        rows.remove(vtxo_id)
            .map(|_| ())
            .ok_or_else(|| OwnedVtxoError::UnknownVtxo(vtxo_id.to_string()))
    }

    fn list(&self) -> Vec<OwnedConfidentialVtxo> {
        let rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        rows.values().map(OwnedConfidentialVtxo::cloned).collect()
    }

    fn find_by_id(&self, vtxo_id: &str) -> Option<OwnedConfidentialVtxo> {
        let rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        rows.get(vtxo_id).map(OwnedConfidentialVtxo::cloned)
    }

    fn total_amount(&self) -> u64 {
        let rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        rows.values().map(|v| v.amount).sum()
    }
}

/// Plaintext snapshot — the value we encrypt and write to disk.
///
/// Versioned via `format_version` so we can evolve the format
/// (e.g. add fields) without breaking old caches.
#[derive(Debug, Default, Serialize, Deserialize)]
struct OwnedVtxosSnapshot {
    /// Snapshot format tag; currently always `1`.
    format_version: u32,
    /// All rows.
    vtxos: Vec<OwnedConfidentialVtxo>,
}

impl OwnedVtxosSnapshot {
    const CURRENT_VERSION: u32 = 1;

    fn from_rows(rows: &BTreeMap<String, OwnedConfidentialVtxo>) -> Self {
        Self {
            format_version: Self::CURRENT_VERSION,
            vtxos: rows.values().map(OwnedConfidentialVtxo::cloned).collect(),
        }
    }
}

/// Encrypted JSON envelope written to disk. Hex-encoded fields keep
/// the file ASCII-clean and grep-able for ops; the envelope shape
/// matches `dark-wallet-bin::encryption::EncryptedSeed`.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedEnvelope {
    /// PBKDF2 salt (hex).
    salt: String,
    /// AES-GCM nonce (hex).
    nonce: String,
    /// Ciphertext over the JSON-encoded snapshot (hex).
    ciphertext: String,
    /// Format tag for the *envelope* (vs. the snapshot inside).
    /// Bumping this signals an encryption-stack change; bumping
    /// `format_version` inside the snapshot signals a payload change.
    envelope_version: u32,
}

impl EncryptedEnvelope {
    const CURRENT_VERSION: u32 = 1;
}

/// File-backed [`OwnedVtxoStore`] encrypted at rest with a
/// passphrase.
///
/// Mutations rewrite the entire file atomically (write-tmp +
/// rename). The passphrase is copied into the store on
/// [`Self::open`] and held in plaintext for the lifetime of the
/// instance; callers should drop the store as soon as they are
/// done with it and must not retain their own copy of the
/// passphrase any longer than necessary.
pub struct EncryptedFileOwnedVtxoStore {
    path: PathBuf,
    passphrase: String,
    rows: Mutex<BTreeMap<String, OwnedConfidentialVtxo>>,
}

impl std::fmt::Debug for EncryptedFileOwnedVtxoStore {
    /// Redacts the passphrase. Lock-free; we only show the path
    /// and a row count read from the mutex when uncontended.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let row_count = self
            .rows
            .try_lock()
            .map(|rows| rows.len() as isize)
            .unwrap_or(-1);
        f.debug_struct("EncryptedFileOwnedVtxoStore")
            .field("path", &self.path)
            .field("rows", &row_count)
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

impl EncryptedFileOwnedVtxoStore {
    /// Open or create a store at `path`.
    ///
    /// If the file does not exist, an empty store is created in
    /// memory; the file itself is not written until the first
    /// mutation. If the file exists, it is decrypted with
    /// `passphrase` — an incorrect passphrase or a corrupted file
    /// returns the appropriate [`OwnedVtxoError`].
    ///
    /// The caller is responsible for not retaining the
    /// `passphrase` slice elsewhere; this constructor copies it.
    pub fn open(path: impl Into<PathBuf>, passphrase: &str) -> Result<Self, OwnedVtxoError> {
        let path = path.into();
        let rows = if path.exists() {
            load_rows(&path, passphrase)?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            passphrase: passphrase.to_string(),
            rows: Mutex::new(rows),
        })
    }

    /// Persist the current in-memory state to disk. Called from
    /// every mutation to keep the file in sync.
    fn flush(&self, rows: &BTreeMap<String, OwnedConfidentialVtxo>) -> Result<(), OwnedVtxoError> {
        let snapshot = OwnedVtxosSnapshot::from_rows(rows);
        let mut plaintext = serde_json::to_vec(&snapshot)?;
        let envelope = encrypt_envelope(&plaintext, &self.passphrase)?;
        plaintext.zeroize();
        let json = serde_json::to_vec_pretty(&envelope)?;
        atomic_write(&self.path, &json)?;
        Ok(())
    }
}

impl OwnedVtxoStore for EncryptedFileOwnedVtxoStore {
    fn insert(&self, vtxo: OwnedConfidentialVtxo) -> Result<(), OwnedVtxoError> {
        let mut rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        if rows.contains_key(&vtxo.vtxo_id) {
            return Err(OwnedVtxoError::DuplicateVtxo(vtxo.vtxo_id));
        }
        rows.insert(vtxo.vtxo_id.clone(), vtxo);
        self.flush(&rows)
    }

    fn remove(&self, vtxo_id: &str) -> Result<(), OwnedVtxoError> {
        let mut rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        if rows.remove(vtxo_id).is_none() {
            return Err(OwnedVtxoError::UnknownVtxo(vtxo_id.to_string()));
        }
        self.flush(&rows)
    }

    fn list(&self) -> Vec<OwnedConfidentialVtxo> {
        let rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        rows.values().map(OwnedConfidentialVtxo::cloned).collect()
    }

    fn find_by_id(&self, vtxo_id: &str) -> Option<OwnedConfidentialVtxo> {
        let rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        rows.get(vtxo_id).map(OwnedConfidentialVtxo::cloned)
    }

    fn total_amount(&self) -> u64 {
        let rows = self.rows.lock().expect("owned-vtxo cache mutex poisoned");
        rows.values().map(|v| v.amount).sum()
    }
}

// ── Persistence helpers ────────────────────────────────────────────

/// Read & decrypt the file at `path`.
fn load_rows(
    path: &Path,
    passphrase: &str,
) -> Result<BTreeMap<String, OwnedConfidentialVtxo>, OwnedVtxoError> {
    let bytes = fs::read(path)?;
    let envelope: EncryptedEnvelope = serde_json::from_slice(&bytes)
        .map_err(|e| OwnedVtxoError::Corrupted(format!("envelope parse failed: {e}")))?;
    if envelope.envelope_version != EncryptedEnvelope::CURRENT_VERSION {
        return Err(OwnedVtxoError::Corrupted(format!(
            "unsupported envelope version: {}",
            envelope.envelope_version
        )));
    }
    let mut plaintext = decrypt_envelope(&envelope, passphrase)?;
    let snapshot: OwnedVtxosSnapshot = serde_json::from_slice(&plaintext)
        .map_err(|e| OwnedVtxoError::Corrupted(format!("snapshot parse failed: {e}")))?;
    plaintext.zeroize();

    if snapshot.format_version != OwnedVtxosSnapshot::CURRENT_VERSION {
        return Err(OwnedVtxoError::Corrupted(format!(
            "unsupported snapshot version: {}",
            snapshot.format_version
        )));
    }

    let mut rows = BTreeMap::new();
    for vtxo in snapshot.vtxos {
        rows.insert(vtxo.vtxo_id.clone(), vtxo);
    }
    Ok(rows)
}

/// Write `bytes` to `path` atomically: write to `<path>.tmp`, then
/// `rename` over `path`. POSIX `rename(2)` is atomic for files on
/// the same filesystem, which is the only guarantee the wallet
/// needs (cache files always live next to their final location).
fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = tmp_path(path);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }

    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Build the temp-file companion to `path`: same parent, same
/// stem, with [`TMP_SUFFIX`] appended.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(TMP_SUFFIX);
    path.with_file_name(name)
}

// ── Encryption helpers ─────────────────────────────────────────────

fn encrypt_envelope(
    plaintext: &[u8],
    passphrase: &str,
) -> Result<EncryptedEnvelope, OwnedVtxoError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(passphrase.as_bytes(), &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| OwnedVtxoError::Encrypt(e.to_string()))?;
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| OwnedVtxoError::Encrypt(e.to_string()))?;

    Ok(EncryptedEnvelope {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        envelope_version: EncryptedEnvelope::CURRENT_VERSION,
    })
}

fn decrypt_envelope(
    envelope: &EncryptedEnvelope,
    passphrase: &str,
) -> Result<Vec<u8>, OwnedVtxoError> {
    let salt = hex::decode(&envelope.salt)
        .map_err(|e| OwnedVtxoError::Corrupted(format!("salt hex: {e}")))?;
    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|e| OwnedVtxoError::Corrupted(format!("nonce hex: {e}")))?;
    let ciphertext = hex::decode(&envelope.ciphertext)
        .map_err(|e| OwnedVtxoError::Corrupted(format!("ciphertext hex: {e}")))?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(OwnedVtxoError::Corrupted(format!(
            "nonce must be {NONCE_LEN} bytes, got {}",
            nonce_bytes.len()
        )));
    }

    let mut key = derive_key(passphrase.as_bytes(), &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| OwnedVtxoError::Encrypt(e.to_string()))?;
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| OwnedVtxoError::Decrypt)
}

/// PBKDF2-HMAC-SHA256 → 32-byte key. Mirrors
/// `dark-wallet-bin::encryption::derive_key`.
fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    fn sample_scope() -> ScopeMetadata {
        ScopeMetadata {
            round_id: "round-001".into(),
            round_height: 7,
            account_index: 0,
        }
    }

    fn sample_vtxo(id: &str, amount: u64, blinding_byte: u8, sk_byte: u8) -> OwnedConfidentialVtxo {
        let mut blinding = [0u8; 32];
        blinding[31] = blinding_byte;
        let mut sk = [0u8; 32];
        sk[31] = sk_byte;
        OwnedConfidentialVtxo::new(id, amount, blinding, sk, sample_scope())
    }

    fn temp_cache_path() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("owned_vtxos.enc");
        (dir, path)
    }

    // ── In-memory store ────────────────────────────────────────────

    #[test]
    fn in_memory_insert_list_remove_round_trip() {
        let store = InMemoryOwnedVtxoStore::new();
        store.insert(sample_vtxo("a", 100, 1, 2)).unwrap();
        store.insert(sample_vtxo("b", 250, 3, 4)).unwrap();

        let listed: Vec<_> = store.list().into_iter().map(|v| v.vtxo_id).collect();
        assert_eq!(listed, vec!["a", "b"], "list is sorted by vtxo_id");
        assert_eq!(store.total_amount(), 350);

        let row = store.find_by_id("a").expect("a present");
        assert_eq!(row.amount, 100);
        assert_eq!(row.blinding.as_bytes()[31], 1);

        store.remove("a").unwrap();
        assert!(store.find_by_id("a").is_none());
        assert_eq!(store.total_amount(), 250);
    }

    #[test]
    fn in_memory_rejects_duplicate_vtxo() {
        let store = InMemoryOwnedVtxoStore::new();
        store.insert(sample_vtxo("a", 100, 1, 2)).unwrap();

        let err = store.insert(sample_vtxo("a", 999, 9, 9)).unwrap_err();
        assert!(matches!(err, OwnedVtxoError::DuplicateVtxo(id) if id == "a"));
        assert_eq!(store.total_amount(), 100, "duplicate did not mutate state");
    }

    #[test]
    fn in_memory_remove_unknown_vtxo_errors() {
        let store = InMemoryOwnedVtxoStore::new();
        let err = store.remove("missing").unwrap_err();
        assert!(matches!(err, OwnedVtxoError::UnknownVtxo(id) if id == "missing"));
    }

    // ── Encrypted file-backed store ────────────────────────────────

    #[test]
    fn encrypted_round_trip_persists_across_reopen() {
        let (_dir, path) = temp_cache_path();
        let passphrase = "correct-horse-battery-staple";

        {
            let store = EncryptedFileOwnedVtxoStore::open(&path, passphrase).unwrap();
            store.insert(sample_vtxo("vtxo-a", 1_000, 11, 22)).unwrap();
            store.insert(sample_vtxo("vtxo-b", 2_000, 33, 44)).unwrap();
        }

        // Reopen with the same passphrase and verify state matches.
        let reopened = EncryptedFileOwnedVtxoStore::open(&path, passphrase).unwrap();
        assert_eq!(reopened.total_amount(), 3_000);

        let restored = reopened
            .find_by_id("vtxo-a")
            .expect("vtxo-a survives reload");
        assert_eq!(restored.amount, 1_000);
        assert_eq!(restored.blinding.as_bytes()[31], 11);
        assert_eq!(restored.one_time_sk.as_bytes()[31], 22);
        assert_eq!(restored.scope_metadata.round_id, "round-001");
    }

    #[test]
    fn encrypted_remove_persists_across_reopen() {
        let (_dir, path) = temp_cache_path();
        let pw = "pw";

        let store = EncryptedFileOwnedVtxoStore::open(&path, pw).unwrap();
        store.insert(sample_vtxo("a", 100, 1, 2)).unwrap();
        store.insert(sample_vtxo("b", 200, 3, 4)).unwrap();
        store.remove("a").unwrap();
        drop(store);

        let reopened = EncryptedFileOwnedVtxoStore::open(&path, pw).unwrap();
        assert_eq!(reopened.list().len(), 1);
        assert!(reopened.find_by_id("a").is_none());
        assert!(reopened.find_by_id("b").is_some());
    }

    #[test]
    fn wrong_passphrase_fails_to_decrypt() {
        let (_dir, path) = temp_cache_path();
        {
            let store = EncryptedFileOwnedVtxoStore::open(&path, "right").unwrap();
            store.insert(sample_vtxo("a", 100, 1, 2)).unwrap();
        }

        let err = EncryptedFileOwnedVtxoStore::open(&path, "wrong").unwrap_err();
        assert!(
            matches!(err, OwnedVtxoError::Decrypt),
            "wrong passphrase must surface as Decrypt, got: {err:?}"
        );
    }

    #[test]
    fn corrupted_envelope_fails_with_clear_error() {
        let (_dir, path) = temp_cache_path();
        let pw = "pw";
        {
            let store = EncryptedFileOwnedVtxoStore::open(&path, pw).unwrap();
            store.insert(sample_vtxo("a", 100, 1, 2)).unwrap();
        }

        // Truncate the file mid-envelope.
        let mut bytes = fs::read(&path).unwrap();
        bytes.truncate(bytes.len() / 2);
        fs::write(&path, bytes).unwrap();

        let err = EncryptedFileOwnedVtxoStore::open(&path, pw).unwrap_err();
        assert!(
            matches!(err, OwnedVtxoError::Corrupted(_)),
            "truncated file must surface as Corrupted, got: {err:?}"
        );
    }

    #[test]
    fn tampered_ciphertext_fails_with_decrypt_error() {
        let (_dir, path) = temp_cache_path();
        let pw = "pw";
        {
            let store = EncryptedFileOwnedVtxoStore::open(&path, pw).unwrap();
            store.insert(sample_vtxo("a", 100, 1, 2)).unwrap();
        }

        // Flip a byte inside the ciphertext field. The envelope is
        // still well-formed JSON, so this exercises the AEAD-fail
        // path rather than the JSON-parse path.
        let raw = fs::read_to_string(&path).unwrap();
        let mut envelope: EncryptedEnvelope = serde_json::from_str(&raw).unwrap();
        let mut ct = hex::decode(&envelope.ciphertext).unwrap();
        ct[0] ^= 0xff;
        envelope.ciphertext = hex::encode(ct);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let err = EncryptedFileOwnedVtxoStore::open(&path, pw).unwrap_err();
        assert!(
            matches!(err, OwnedVtxoError::Decrypt),
            "tampered ciphertext must surface as Decrypt, got: {err:?}"
        );
    }

    #[test]
    fn on_disk_bytes_contain_no_plaintext_amount() {
        let (_dir, path) = temp_cache_path();
        let secret_amount: u64 = 0xDEAD_BEEF_CAFE_BABE;

        let store = EncryptedFileOwnedVtxoStore::open(&path, "pw").unwrap();
        store
            .insert(sample_vtxo("witness", secret_amount, 7, 8))
            .unwrap();
        drop(store);

        let bytes = fs::read(&path).unwrap();
        let needle = secret_amount.to_le_bytes();
        assert!(
            bytes.windows(needle.len()).all(|w| w != needle),
            "on-disk bytes must not contain the plaintext amount"
        );
        let needle_be = secret_amount.to_be_bytes();
        assert!(
            bytes.windows(needle_be.len()).all(|w| w != needle_be),
            "on-disk bytes must not contain the plaintext amount (BE)"
        );
        // The decimal rendering of the amount must also be absent.
        let decimal = secret_amount.to_string();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(&decimal),
            "on-disk bytes must not contain the plaintext amount (decimal)"
        );
    }

    #[test]
    fn atomic_write_leaves_no_tmp_file_on_success() {
        let (_dir, path) = temp_cache_path();
        let store = EncryptedFileOwnedVtxoStore::open(&path, "pw").unwrap();
        store.insert(sample_vtxo("a", 1, 1, 1)).unwrap();

        assert!(path.exists(), "final cache file written");
        assert!(!tmp_path(&path).exists(), "temp file cleaned up");
    }

    #[test]
    fn open_on_missing_file_yields_empty_store() {
        let (_dir, path) = temp_cache_path();
        let store = EncryptedFileOwnedVtxoStore::open(&path, "pw").unwrap();
        assert!(store.list().is_empty());
        assert_eq!(store.total_amount(), 0);
        assert!(!path.exists(), "no file is written until first mutation");
    }

    // ── Type-level guards ──────────────────────────────────────────

    #[test]
    fn cloned_produces_independent_secret_bytes() {
        let original = sample_vtxo("x", 5, 9, 10);
        let copy = original.cloned();
        assert_eq!(copy.blinding.as_bytes(), original.blinding.as_bytes());
        assert_eq!(copy.one_time_sk.as_bytes(), original.one_time_sk.as_bytes());

        // Drop the copy; the original must still be intact.
        drop(copy);
        assert_eq!(original.blinding.as_bytes()[31], 9);
    }

    #[test]
    fn secret_bytes_debug_redacts_inner_value() {
        let secret = SecretBytes([0xAB; 32]);
        let printed = format!("{secret:?}");
        assert!(!printed.contains("AB"), "Debug must redact bytes");
        assert!(printed.contains("redacted"));
    }
}
