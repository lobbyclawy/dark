//! Virtual Transaction Output (VTXO) domain model
//!
//! Aligned with Go dark: `github.com/ark-network/ark/internal/core/domain/vtxo.go`
//!
//! # Confidential VTXO support (issue #530)
//!
//! A `Vtxo` can be either:
//! - **Transparent**: the historical model with a plaintext `amount: u64`.
//! - **Confidential**: the amount is hidden behind a Pedersen commitment plus
//!   a range proof, with metadata for stealth/ECDH delivery (#525, #529, ADR-0002).
//!
//! Discrimination is exposed via [`VtxoVersion`] and [`Vtxo::version`]. The
//! confidential payload lives in an `Option<ConfidentialPayload>` field which
//! is `#[serde(skip_serializing_if = "Option::is_none")]` — that keeps the
//! transparent JSON wire format **bit-identical** to the pre-change encoding,
//! per the issue's parity gate (vendored Go arkd E2E suite).
//!
//! # Design notes
//!
//! The task description for #530 narrowed scope to a `Confidential` variant
//! carrying four payload fields:
//! - 33-byte Pedersen commitment (compressed secp256k1 point, per #524/#525)
//! - opaque range-proof byte blob (variable length, per #525)
//! - 32-byte nullifier (HMAC-SHA256 output, per ADR-0002)
//! - 33-byte ephemeral compressed secp256k1 pubkey (for ECDH per #529)
//!
//! A `tag-field` style was preferred over a top-level `enum Vtxo { ... }`
//! because the existing `Vtxo` struct has 16+ shared fields (outpoint, status
//! flags, expiry, commitment chain, asset list) that apply equally to both
//! variants. A side-by-side enum would force every shared field through both
//! arms with no semantic gain. The optional payload + version helper pattern
//! keeps shared call sites unchanged while still letting variant-aware code
//! pattern-match exhaustively on `vtxo.version()`.

use bitcoin::{OutPoint, XOnlyPublicKey};
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Outpoint identifying a VTXO (matches Go's `domain.Outpoint`)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VtxoOutpoint {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
}

impl VtxoOutpoint {
    /// Create from components
    pub fn new(txid: String, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Parse from "txid:vout" string format
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            let vout = parts[1].parse::<u32>().ok()?;
            Some(Self {
                txid: parts[0].to_string(),
                vout,
            })
        } else {
            None
        }
    }

    /// Convert from bitcoin OutPoint
    pub fn from_outpoint(outpoint: OutPoint) -> Self {
        Self {
            txid: outpoint.txid.to_string(),
            vout: outpoint.vout,
        }
    }
}

impl std::fmt::Display for VtxoOutpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

// -----------------------------------------------------------------------------
// Confidential variant (issue #530)
// -----------------------------------------------------------------------------

/// Length in bytes of a Pedersen commitment (compressed secp256k1 point).
pub const PEDERSEN_COMMITMENT_LEN: usize = 33;

/// Length in bytes of a confidential nullifier (HMAC-SHA256 output, ADR-0002).
pub const NULLIFIER_LEN: usize = 32;

/// Length in bytes of an ephemeral compressed secp256k1 pubkey (for ECDH).
pub const EPHEMERAL_PUBKEY_LEN: usize = 33;

/// Confidential VTXO payload (issue #530).
///
/// All bytes are stored in canonical, fixed-width form so that downstream
/// serialization layers (#531 protobuf, #532 Postgres, #533 SQLite) can move
/// them as opaque blobs without re-parsing. The range proof is variable-length
/// and opaque per the #525 design — `dark-core` does not validate it; that is
/// the verifier's job in `dark-confidential`.
///
/// # Field invariants (not enforced at construction time)
/// - `amount_commitment`: must be a valid compressed secp256k1 point. Validity
///   is checked by callers that need it (e.g. when computing balance proofs).
/// - `range_proof`: opaque blob. May be empty during early protocol stages.
/// - `nullifier`: any 32 bytes. Domain separation and key derivation live in
///   `dark-confidential::nullifier` (ADR-0002).
/// - `ephemeral_pubkey`: must be a valid compressed secp256k1 point used as
///   the ECDH ephemeral published with the VTXO (#529 — encryption format
///   still being designed, but the field placeholder belongs here).
///
/// `dark-core` deliberately does not depend on `dark-confidential`; this keeps
/// the core domain model decoupled from the heavy zk crate. Cryptographic
/// helpers live in `dark-confidential` and consume these byte slices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPayload {
    /// 33-byte Pedersen commitment (compressed secp256k1 point) hiding the amount.
    #[serde(with = "serde_byte_array_33")]
    pub amount_commitment: [u8; PEDERSEN_COMMITMENT_LEN],

    /// Opaque range-proof bytes (#525). Variable length, may be empty.
    #[serde(default, with = "serde_bytes_compat")]
    pub range_proof: Vec<u8>,

    /// 32-byte nullifier per ADR-0002 (`HMAC-SHA256(sk, dst || ver || vtxo_id)`).
    #[serde(with = "serde_byte_array_32")]
    pub nullifier: [u8; NULLIFIER_LEN],

    /// 33-byte ephemeral compressed secp256k1 pubkey used for ECDH (#529).
    #[serde(with = "serde_byte_array_33")]
    pub ephemeral_pubkey: [u8; EPHEMERAL_PUBKEY_LEN],
}

impl ConfidentialPayload {
    /// Construct a confidential payload from raw byte components.
    pub fn new(
        amount_commitment: [u8; PEDERSEN_COMMITMENT_LEN],
        range_proof: Vec<u8>,
        nullifier: [u8; NULLIFIER_LEN],
        ephemeral_pubkey: [u8; EPHEMERAL_PUBKEY_LEN],
    ) -> Self {
        Self {
            amount_commitment,
            range_proof,
            nullifier,
            ephemeral_pubkey,
        }
    }
}

/// Discriminates between transparent and confidential VTXOs.
///
/// Returned by [`Vtxo::version`] so callers can pattern-match exhaustively
/// without poking at internal fields. Marked `#[non_exhaustive]` is **not**
/// used here — `dark-core` consumers do depend on exhaustiveness audits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VtxoVersion {
    /// Plaintext-amount VTXO (the historical wire format).
    Transparent,
    /// Pedersen-commitment VTXO with confidential payload (#530).
    Confidential,
}

/// Either a plaintext amount (transparent) or a 33-byte Pedersen commitment
/// (confidential). Returned by [`Vtxo::amount_or_commitment`] so call sites
/// can branch without unwrapping nested options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountOrCommitment<'a> {
    /// Plaintext amount in satoshis.
    Amount(u64),
    /// Compressed-secp256k1 Pedersen commitment over the hidden amount.
    Commitment(&'a [u8; PEDERSEN_COMMITMENT_LEN]),
}

// -----------------------------------------------------------------------------
// Vtxo
// -----------------------------------------------------------------------------

/// A Virtual Transaction Output (VTXO) — matches Go's `domain.Vtxo`
///
/// Key differences from the old Rust model:
/// - Uses `VtxoOutpoint` as identity (not UUID)
/// - `expires_at` is a unix timestamp; `expires_at_block` is a block height
/// - Tracks `commitment_txids` chain (not a single round_id)
/// - Status is represented by boolean flags (Spent/Unrolled/Swept)
///
/// # Confidential variant (#530)
///
/// When [`Vtxo::confidential`] is `Some`, this VTXO is in the *confidential*
/// variant: the `amount` field is unused/zero on the wire and the canonical
/// amount lives behind the Pedersen commitment in
/// [`ConfidentialPayload::amount_commitment`]. When `confidential` is `None`,
/// this is a *transparent* VTXO and `amount` carries the plaintext satoshi
/// value as before.
///
/// The `confidential` field is `#[serde(skip_serializing_if = "Option::is_none")]`
/// so transparent-variant JSON wire bytes are bit-identical to the pre-change
/// encoding (per the issue's parity gate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vtxo {
    /// The outpoint identifying this VTXO in the transaction tree
    pub outpoint: VtxoOutpoint,
    /// The amount in satoshis (transparent variant only; zero for confidential)
    pub amount: u64,
    /// Owner's public key (hex-encoded, Schnorr/x-only)
    pub pubkey: String,
    /// Chain of commitment transaction IDs
    pub commitment_txids: Vec<String>,
    /// The root (original) commitment txid
    pub root_commitment_txid: String,
    /// Commitment txid that settled this VTXO
    pub settled_by: String,
    /// Forfeit or checkpoint txid that spent this VTXO
    pub spent_by: String,
    /// The Ark transaction ID that spent this VTXO
    pub ark_txid: String,
    /// Whether this VTXO has been spent
    pub spent: bool,
    /// Whether this VTXO's tree branch has been unrolled (published on-chain)
    pub unrolled: bool,
    /// Whether this VTXO has been swept by the ASP
    pub swept: bool,
    /// Whether this VTXO is preconfirmed (not yet in a finalized round)
    pub preconfirmed: bool,
    /// Unix timestamp when this VTXO expires (time-based expiry)
    pub expires_at: i64,
    /// Block height at which this VTXO expires (block-based expiry, 0 = unused)
    #[serde(default)]
    pub expires_at_block: u32,
    /// Unix timestamp when this VTXO was created
    pub created_at: i64,
    /// Asset amounts carried by this VTXO (asset_id → amount)
    #[serde(default)]
    pub assets: Vec<(String, u64)>,
    /// Confidential variant payload (Pedersen commitment + range proof + nullifier
    /// + ECDH ephemeral pubkey). `None` means this is a transparent VTXO.
    ///
    /// `skip_serializing_if = "Option::is_none"` keeps the transparent wire
    /// bytes bit-identical to the pre-#530 encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidential: Option<ConfidentialPayload>,
}

impl Vtxo {
    /// Create a new transparent VTXO with a plaintext amount.
    pub fn new(outpoint: VtxoOutpoint, amount: u64, pubkey: String) -> Self {
        let now = Utc::now().timestamp();
        Self {
            outpoint,
            amount,
            pubkey,
            commitment_txids: Vec::new(),
            root_commitment_txid: String::new(),
            settled_by: String::new(),
            spent_by: String::new(),
            ark_txid: String::new(),
            spent: false,
            unrolled: false,
            swept: false,
            preconfirmed: false,
            expires_at: 0,
            expires_at_block: 0,
            created_at: now,
            assets: Vec::new(),
            confidential: None,
        }
    }

    /// Create a new confidential VTXO. The plaintext `amount` field is set to
    /// zero on the wire; callers that need to learn the amount must decrypt
    /// the memo (#529) and verify the Pedersen commitment.
    pub fn new_confidential(
        outpoint: VtxoOutpoint,
        pubkey: String,
        payload: ConfidentialPayload,
    ) -> Self {
        let mut v = Self::new(outpoint, 0, pubkey);
        v.confidential = Some(payload);
        v
    }

    // -------------------------------------------------------------------------
    // Variant discrimination (#530)
    // -------------------------------------------------------------------------

    /// Returns the discriminant of this VTXO.
    ///
    /// Use this in `match` blocks instead of poking at internal fields, so
    /// that a future variant addition surfaces as a compile error at every
    /// call site.
    pub fn version(&self) -> VtxoVersion {
        if self.confidential.is_some() {
            VtxoVersion::Confidential
        } else {
            VtxoVersion::Transparent
        }
    }

    /// `true` iff this VTXO is in the confidential variant.
    pub fn is_confidential(&self) -> bool {
        self.confidential.is_some()
    }

    /// `true` iff this VTXO is in the transparent variant.
    pub fn is_transparent(&self) -> bool {
        self.confidential.is_none()
    }

    /// Returns the plaintext amount (transparent) or the Pedersen commitment
    /// (confidential), in a single discriminated wrapper.
    ///
    /// Callers wanting the actual numeric amount on a confidential VTXO must
    /// decrypt the memo and recompute it; `dark-core` cannot reveal it.
    pub fn amount_or_commitment(&self) -> AmountOrCommitment<'_> {
        match &self.confidential {
            Some(payload) => AmountOrCommitment::Commitment(&payload.amount_commitment),
            None => AmountOrCommitment::Amount(self.amount),
        }
    }

    /// Returns the Pedersen commitment bytes if this is a confidential VTXO.
    pub fn pedersen_commitment(&self) -> Option<&[u8; PEDERSEN_COMMITMENT_LEN]> {
        self.confidential.as_ref().map(|p| &p.amount_commitment)
    }

    /// Returns the range-proof bytes if this is a confidential VTXO.
    pub fn range_proof(&self) -> Option<&[u8]> {
        self.confidential.as_ref().map(|p| p.range_proof.as_slice())
    }

    /// Returns the 32-byte nullifier if this is a confidential VTXO.
    pub fn nullifier(&self) -> Option<&[u8; NULLIFIER_LEN]> {
        self.confidential.as_ref().map(|p| &p.nullifier)
    }

    /// Returns the 33-byte ephemeral ECDH pubkey if this is a confidential VTXO.
    pub fn ephemeral_pubkey(&self) -> Option<&[u8; EPHEMERAL_PUBKEY_LEN]> {
        self.confidential.as_ref().map(|p| &p.ephemeral_pubkey)
    }

    // -------------------------------------------------------------------------
    // Existing behaviour (unchanged for transparent path)
    // -------------------------------------------------------------------------

    /// Check if this VTXO is a "note" (no commitment chain)
    pub fn is_note(&self) -> bool {
        self.commitment_txids.is_empty() && self.root_commitment_txid.is_empty()
    }

    /// Check if this VTXO needs a connector when spent in a new round.
    ///
    /// Returns true for:
    /// - Round-based VTXOs (have commitment_txids) that aren't swept
    /// - Preconfirmed VTXOs (have ark_txid) regardless of swept status,
    ///   because the server's time-based sweep is a bookkeeping detail
    ///   that doesn't remove the need for a forfeit connector
    ///
    /// Returns false for notes (no commitment chain and no ark_txid).
    pub fn needs_connector(&self) -> bool {
        // Swept VTXOs never need connectors — the server already
        // reclaimed the funds. The Go SDK's vtxosToForfeit() also
        // excludes swept VTXOs, so the connector count must match.
        if self.swept {
            return false;
        }
        // Preconfirmed VTXOs with an ark_txid need a connector for
        // their forfeit path (via checkpoint mechanism).
        if !self.ark_txid.is_empty() {
            return true;
        }
        !self.is_note()
    }

    /// Generate a note URI for this VTXO using the given prefix.
    ///
    /// Only meaningful when `is_note()` returns true.
    pub fn note_uri(&self, prefix: &str) -> String {
        format!("{}:{}", prefix, self.outpoint)
    }

    /// Check if this VTXO requires a forfeit transaction to be spent
    pub fn requires_forfeit(&self) -> bool {
        !self.swept && !self.is_note()
    }

    /// Check if this VTXO is spendable
    pub fn is_spendable(&self) -> bool {
        !self.spent && !self.swept && !self.unrolled
    }

    /// Check if this VTXO is expired at the given unix timestamp
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        self.expires_at > 0 && now_unix >= self.expires_at
    }

    /// Check if this VTXO is expired at the given block height
    pub fn is_expired_at_block(&self, current_height: u32) -> bool {
        self.expires_at_block > 0 && current_height >= self.expires_at_block
    }

    /// Get the owner's public key as XOnlyPublicKey
    pub fn tap_key(&self) -> Option<XOnlyPublicKey> {
        let bytes = hex::decode(&self.pubkey).ok()?;
        XOnlyPublicKey::from_slice(&bytes).ok()
    }
}

/// A receiver for VTXO outputs (matches Go's `domain.Receiver`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receiver {
    /// Amount in satoshis
    pub amount: u64,
    /// On-chain destination address
    pub onchain_address: String,
    /// Off-chain public key
    pub pubkey: String,
}

impl Receiver {
    /// Check if this is an on-chain receiver
    pub fn is_onchain(&self) -> bool {
        !self.onchain_address.is_empty()
    }

    /// Create an on-chain receiver
    pub fn onchain(amount: u64, address: String) -> Self {
        Self {
            amount,
            onchain_address: address,
            pubkey: String::new(),
        }
    }

    /// Create an off-chain receiver
    pub fn offchain(amount: u64, pubkey: String) -> Self {
        Self {
            amount,
            onchain_address: String::new(),
            pubkey,
        }
    }
}

/// Legacy type alias
pub type VtxoId = VtxoOutpoint;

// -----------------------------------------------------------------------------
// Serde helpers for fixed-size byte arrays.
//
// `serde` derives a tuple-style sequence for `[u8; N]` by default (one element
// per byte). For commitment / nullifier / ephemeral pubkey we want compact
// canonical forms: hex-encoded strings in JSON (human-readable, copy-pastable
// in test vectors), and raw byte sequences in binary formats. The custom
// (de)serializers below give us a single hex string in JSON without pulling
// in `serde_bytes` or `serde-big-array` (the latter would also be needed for
// `[u8; 33]` if we relied on serde's default array support, which only covers
// `[T; 0..=32]` until const-generic support is universally available).
// -----------------------------------------------------------------------------

mod serde_byte_array_32 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(bytes))
        } else {
            s.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let human = d.is_human_readable();
        if human {
            let s = String::deserialize(d)?;
            let v = hex::decode(&s).map_err(D::Error::custom)?;
            v.try_into()
                .map_err(|_| D::Error::custom("expected 32 bytes"))
        } else {
            let v = <Vec<u8>>::deserialize(d)?;
            v.try_into()
                .map_err(|_| D::Error::custom("expected 32 bytes"))
        }
    }
}

mod serde_byte_array_33 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(bytes))
        } else {
            s.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        let human = d.is_human_readable();
        if human {
            let s = String::deserialize(d)?;
            let v = hex::decode(&s).map_err(D::Error::custom)?;
            v.try_into()
                .map_err(|_| D::Error::custom("expected 33 bytes"))
        } else {
            let v = <Vec<u8>>::deserialize(d)?;
            v.try_into()
                .map_err(|_| D::Error::custom("expected 33 bytes"))
        }
    }
}

/// Variable-length byte blob serialized as hex in JSON, raw bytes otherwise.
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(bytes))
        } else {
            s.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let human = d.is_human_readable();
        if human {
            let s = String::deserialize(d)?;
            hex::decode(&s).map_err(serde::de::Error::custom)
        } else {
            <Vec<u8>>::deserialize(d)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtxo_outpoint_parse() {
        let op = VtxoOutpoint::from_string("abc123:5").unwrap();
        assert_eq!(op.txid, "abc123");
        assert_eq!(op.vout, 5);
        assert!(VtxoOutpoint::from_string("invalid").is_none());
    }

    #[test]
    fn test_vtxo_creation() {
        let op = VtxoOutpoint::new("txid123".to_string(), 0);
        let vtxo = Vtxo::new(op.clone(), 100_000, "deadbeef".to_string());
        assert_eq!(vtxo.outpoint, op);
        assert!(vtxo.is_spendable());
    }

    #[test]
    fn test_vtxo_expiry() {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            50_000,
            "pub".to_string(),
        );
        vtxo.expires_at = 1000;
        assert!(!vtxo.is_expired_at(999));
        assert!(vtxo.is_expired_at(1000));
    }

    #[test]
    fn test_receiver() {
        let onchain = Receiver::onchain(100_000, "bc1q...".to_string());
        assert!(onchain.is_onchain());
        let offchain = Receiver::offchain(50_000, "deadbeef".to_string());
        assert!(!offchain.is_onchain());
    }

    #[test]
    fn test_vtxo_outpoint_display() {
        let op = VtxoOutpoint::new("abc123".to_string(), 42);
        assert_eq!(op.to_string(), "abc123:42");
    }

    #[test]
    fn test_vtxo_outpoint_from_string_edge_cases() {
        // Missing vout
        assert!(VtxoOutpoint::from_string("abc123").is_none());
        // Non-numeric vout
        assert!(VtxoOutpoint::from_string("abc123:xyz").is_none());
        // Empty string
        assert!(VtxoOutpoint::from_string("").is_none());
        // Multiple colons
        assert!(VtxoOutpoint::from_string("a:b:c").is_none());
        // Valid
        assert!(VtxoOutpoint::from_string("txid:0").is_some());
    }

    #[test]
    fn test_vtxo_spendable_states() {
        let op = VtxoOutpoint::new("tx".to_string(), 0);

        // Fresh = spendable
        let vtxo = Vtxo::new(op.clone(), 1000, "pk".to_string());
        assert!(vtxo.is_spendable());

        // Spent = not spendable
        let mut vtxo = Vtxo::new(op.clone(), 1000, "pk".to_string());
        vtxo.spent = true;
        assert!(!vtxo.is_spendable());

        // Swept = not spendable
        let mut vtxo = Vtxo::new(op.clone(), 1000, "pk".to_string());
        vtxo.swept = true;
        assert!(!vtxo.is_spendable());

        // Unrolled = not spendable
        let mut vtxo = Vtxo::new(op, 1000, "pk".to_string());
        vtxo.unrolled = true;
        assert!(!vtxo.is_spendable());
    }

    #[test]
    fn test_vtxo_zero_expiry_never_expires() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            "pk".to_string(),
        );
        // expires_at = 0 means never expires
        assert!(!vtxo.is_expired_at(0));
        assert!(!vtxo.is_expired_at(i64::MAX));
    }

    #[test]
    fn test_vtxo_requires_forfeit_swept() {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            "pk".to_string(),
        );
        vtxo.commitment_txids = vec!["c1".to_string()];
        vtxo.root_commitment_txid = "c1".to_string();
        vtxo.swept = true;

        // Swept VTXOs don't require forfeit even with commitments
        assert!(!vtxo.requires_forfeit());
    }

    #[test]
    fn test_vtxo_tap_key_invalid_hex() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            "not_hex".to_string(),
        );
        assert!(vtxo.tap_key().is_none());
    }

    #[test]
    fn test_vtxo_tap_key_valid() {
        let valid_pk_hex = "0202020202020202020202020202020202020202020202020202020202020202";
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            valid_pk_hex.to_string(),
        );
        assert!(vtxo.tap_key().is_some());
    }

    #[test]
    fn test_vtxo_preconfirmed_flag() {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            "pk".to_string(),
        );
        assert!(!vtxo.preconfirmed);
        vtxo.preconfirmed = true;
        assert!(vtxo.preconfirmed);
        // Preconfirmed VTXOs are still spendable
        assert!(vtxo.is_spendable());
    }

    #[test]
    fn test_vtxo_outpoint_from_bitcoin_outpoint() {
        use bitcoin::hashes::Hash;
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [0xab; 32],
            )),
            vout: 7,
        };
        let vtxo_op = VtxoOutpoint::from_outpoint(outpoint);
        assert_eq!(vtxo_op.vout, 7);
        assert!(!vtxo_op.txid.is_empty());
    }

    // -----------------------------------------------------------------------
    // Notes system tests (#56)
    // -----------------------------------------------------------------------

    #[test]
    fn test_vtxo_is_note_default_false() {
        // A freshly created VTXO with no commitment chain is technically a note
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            50_000,
            "pk".to_string(),
        );
        // New VTXOs have empty commitment_txids and root_commitment_txid → is_note() == true
        assert!(vtxo.is_note());

        // Once a commitment chain is set, it's no longer a note
        let mut vtxo_with_chain = vtxo.clone();
        vtxo_with_chain.commitment_txids = vec!["commit_tx_1".to_string()];
        vtxo_with_chain.root_commitment_txid = "commit_tx_1".to_string();
        assert!(!vtxo_with_chain.is_note());
    }

    #[test]
    fn test_vtxo_note_uri_format() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("abc123".to_string(), 7),
            100_000,
            "deadbeef".to_string(),
        );
        let uri = vtxo.note_uri("ark-note");
        assert_eq!(uri, "ark-note:abc123:7");
    }

    #[test]
    fn test_vtxo_note_flag_roundtrip() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx_rt".to_string(), 3),
            25_000,
            "cafebabe".to_string(),
        );
        // Serialize → deserialize roundtrip
        let json = serde_json::to_string(&vtxo).expect("serialize");
        let restored: Vtxo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(vtxo, restored);
        // Note status preserved
        assert_eq!(vtxo.is_note(), restored.is_note());
    }

    #[test]
    fn test_note_validation_note_vtxo_skips_round() {
        // A note VTXO (no commitment chain) should NOT require forfeit
        let note = Vtxo::new(
            VtxoOutpoint::new("note_tx".to_string(), 0),
            10_000,
            "pk_note".to_string(),
        );
        assert!(note.is_note());
        assert!(!note.requires_forfeit(), "notes should skip forfeit/round");

        // A regular VTXO with commitment chain DOES require forfeit
        let mut regular = note.clone();
        regular.commitment_txids = vec!["c1".to_string()];
        regular.root_commitment_txid = "c1".to_string();
        assert!(!regular.is_note());
        assert!(regular.requires_forfeit(), "regular VTXOs require forfeit");
    }

    // -----------------------------------------------------------------------
    // Confidential variant tests (#530)
    // -----------------------------------------------------------------------

    fn make_payload(seed: u8) -> ConfidentialPayload {
        ConfidentialPayload::new(
            [seed; PEDERSEN_COMMITMENT_LEN],
            vec![seed; 64], // arbitrary range-proof blob
            [seed.wrapping_add(1); NULLIFIER_LEN],
            [seed.wrapping_add(2); EPHEMERAL_PUBKEY_LEN],
        )
    }

    #[test]
    fn test_vtxo_default_is_transparent() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            1000,
            "pk".to_string(),
        );
        assert_eq!(vtxo.version(), VtxoVersion::Transparent);
        assert!(vtxo.is_transparent());
        assert!(!vtxo.is_confidential());
        assert!(vtxo.confidential.is_none());
        assert!(vtxo.pedersen_commitment().is_none());
        assert!(vtxo.range_proof().is_none());
        assert!(vtxo.nullifier().is_none());
        assert!(vtxo.ephemeral_pubkey().is_none());
    }

    #[test]
    fn test_vtxo_new_confidential() {
        let payload = make_payload(7);
        let vtxo = Vtxo::new_confidential(
            VtxoOutpoint::new("tx_conf".to_string(), 1),
            "pk".to_string(),
            payload.clone(),
        );
        assert_eq!(vtxo.version(), VtxoVersion::Confidential);
        assert!(vtxo.is_confidential());
        assert!(!vtxo.is_transparent());
        // Plaintext amount must be zero on the wire for confidential VTXOs.
        assert_eq!(vtxo.amount, 0);
        assert_eq!(vtxo.pedersen_commitment(), Some(&payload.amount_commitment));
        assert_eq!(vtxo.range_proof(), Some(payload.range_proof.as_slice()));
        assert_eq!(vtxo.nullifier(), Some(&payload.nullifier));
        assert_eq!(vtxo.ephemeral_pubkey(), Some(&payload.ephemeral_pubkey));
    }

    #[test]
    fn test_amount_or_commitment_dispatch() {
        // Transparent: returns the plaintext amount.
        let t = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            42_000,
            "pk".to_string(),
        );
        match t.amount_or_commitment() {
            AmountOrCommitment::Amount(a) => assert_eq!(a, 42_000),
            AmountOrCommitment::Commitment(_) => panic!("expected Amount"),
        }

        // Confidential: returns the Pedersen commitment.
        let payload = make_payload(0xab);
        let c = Vtxo::new_confidential(
            VtxoOutpoint::new("tx".to_string(), 1),
            "pk".to_string(),
            payload.clone(),
        );
        match c.amount_or_commitment() {
            AmountOrCommitment::Amount(_) => panic!("expected Commitment"),
            AmountOrCommitment::Commitment(bytes) => {
                assert_eq!(bytes, &payload.amount_commitment);
            }
        }
    }

    #[test]
    fn test_vtxo_version_dispatch_is_exhaustive() {
        // This match must cover every VtxoVersion arm. If a new variant is
        // added without updating this site, the compiler refuses to build.
        let vtxo = Vtxo::new(VtxoOutpoint::new("tx".to_string(), 0), 1, "pk".to_string());
        let label = match vtxo.version() {
            VtxoVersion::Transparent => "transparent",
            VtxoVersion::Confidential => "confidential",
        };
        assert_eq!(label, "transparent");
    }

    #[test]
    fn test_confidential_payload_round_trip_json() {
        let payload = make_payload(0x42);
        let json = serde_json::to_string(&payload).expect("serialize");
        let restored: ConfidentialPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(payload, restored);
        // Sanity: the JSON contains the hex-encoded fields (compact form).
        assert!(
            json.contains(&hex::encode(payload.amount_commitment)),
            "amount_commitment hex must appear in JSON: {json}"
        );
        assert!(json.contains(&hex::encode(payload.nullifier)));
        assert!(json.contains(&hex::encode(payload.ephemeral_pubkey)));
    }

    #[test]
    fn test_confidential_vtxo_round_trip_json() {
        let payload = make_payload(0x11);
        let mut vtxo = Vtxo::new_confidential(
            VtxoOutpoint::new("tx_conf".to_string(), 2),
            "deadbeef".to_string(),
            payload,
        );
        vtxo.expires_at = 1_700_000_000;
        vtxo.commitment_txids = vec!["c1".into(), "c2".into()];
        vtxo.root_commitment_txid = "c1".into();

        let json = serde_json::to_string(&vtxo).expect("serialize");
        let restored: Vtxo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(vtxo, restored);
        assert_eq!(restored.version(), VtxoVersion::Confidential);
        assert_eq!(restored.confidential, vtxo.confidential);
    }

    #[test]
    fn test_transparent_vtxo_wire_format_is_unchanged() {
        // The transparent JSON wire format must NOT include the `confidential`
        // key when payload is None (parity gate with Go arkd E2E).
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            42_000,
            "deadbeef".to_string(),
        );
        let json = serde_json::to_string(&vtxo).expect("serialize");
        assert!(
            !json.contains("confidential"),
            "transparent VTXO must not emit `confidential` field in JSON: {json}"
        );
        // And it must round-trip cleanly.
        let restored: Vtxo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(vtxo, restored);
        assert_eq!(restored.version(), VtxoVersion::Transparent);
    }

    #[test]
    fn test_legacy_json_without_confidential_field_deserializes() {
        // A pre-#530 JSON blob (no `confidential` key at all) must still
        // deserialize, defaulting to the transparent variant.
        let legacy = r#"{
            "outpoint": {"txid": "tx", "vout": 0},
            "amount": 1000,
            "pubkey": "deadbeef",
            "commitment_txids": [],
            "root_commitment_txid": "",
            "settled_by": "",
            "spent_by": "",
            "ark_txid": "",
            "spent": false,
            "unrolled": false,
            "swept": false,
            "preconfirmed": false,
            "expires_at": 0,
            "created_at": 0
        }"#;
        let vtxo: Vtxo = serde_json::from_str(legacy).expect("legacy JSON must parse");
        assert!(vtxo.is_transparent());
        assert_eq!(vtxo.amount, 1000);
        assert_eq!(vtxo.version(), VtxoVersion::Transparent);
    }

    #[test]
    fn test_confidential_payload_byte_field_widths() {
        let payload = make_payload(0);
        assert_eq!(payload.amount_commitment.len(), PEDERSEN_COMMITMENT_LEN);
        assert_eq!(payload.amount_commitment.len(), 33);
        assert_eq!(payload.nullifier.len(), NULLIFIER_LEN);
        assert_eq!(payload.nullifier.len(), 32);
        assert_eq!(payload.ephemeral_pubkey.len(), EPHEMERAL_PUBKEY_LEN);
        assert_eq!(payload.ephemeral_pubkey.len(), 33);
    }

    #[test]
    fn test_confidential_payload_rejects_wrong_length_hex() {
        // 33-byte amount_commitment encoded as 31 bytes of hex must error out.
        let bad = serde_json::json!({
            "amount_commitment": "00".repeat(31),
            "range_proof": "",
            "nullifier": "00".repeat(32),
            "ephemeral_pubkey": "00".repeat(33),
        })
        .to_string();
        let err = serde_json::from_str::<ConfidentialPayload>(&bad).unwrap_err();
        assert!(
            err.to_string().contains("33"),
            "error should mention the expected length: {err}"
        );

        // 32-byte nullifier encoded as 33 bytes must error out too.
        let bad = serde_json::json!({
            "amount_commitment": "00".repeat(33),
            "range_proof": "",
            "nullifier": "00".repeat(33),
            "ephemeral_pubkey": "00".repeat(33),
        })
        .to_string();
        let err = serde_json::from_str::<ConfidentialPayload>(&bad).unwrap_err();
        assert!(err.to_string().contains("32"), "{err}");
    }

    #[test]
    fn test_vtxo_helper_accessors_on_transparent_return_none() {
        let v = Vtxo::new(VtxoOutpoint::new("tx".to_string(), 0), 1, "pk".to_string());
        assert!(v.pedersen_commitment().is_none());
        assert!(v.range_proof().is_none());
        assert!(v.nullifier().is_none());
        assert!(v.ephemeral_pubkey().is_none());
    }

    #[test]
    fn test_confidential_payload_empty_range_proof_round_trip() {
        // Range proof blob may legally be empty during early protocol phases.
        let payload = ConfidentialPayload::new(
            [1u8; PEDERSEN_COMMITMENT_LEN],
            Vec::new(),
            [2u8; NULLIFIER_LEN],
            [3u8; EPHEMERAL_PUBKEY_LEN],
        );
        let json = serde_json::to_string(&payload).unwrap();
        let restored: ConfidentialPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, restored);
        assert!(restored.range_proof.is_empty());
    }

    #[test]
    fn test_confidential_payload_large_range_proof_round_trip() {
        // Range proofs can be hundreds of bytes (~672 for a single bulletproof,
        // larger for aggregations). Make sure the variable-length blob path
        // round-trips at non-trivial sizes.
        let big = vec![0xcd; 4096];
        let payload = ConfidentialPayload::new(
            [9u8; PEDERSEN_COMMITMENT_LEN],
            big.clone(),
            [8u8; NULLIFIER_LEN],
            [7u8; EPHEMERAL_PUBKEY_LEN],
        );
        let json = serde_json::to_string(&payload).unwrap();
        let restored: ConfidentialPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.range_proof, big);
    }

    #[test]
    fn test_confidential_vtxo_preserves_existing_helpers() {
        // Confidential VTXOs must still answer is_note / requires_forfeit /
        // is_spendable correctly — the variant only changes the amount field.
        let payload = make_payload(0);
        let mut vtxo = Vtxo::new_confidential(
            VtxoOutpoint::new("tx".to_string(), 0),
            "pk".to_string(),
            payload,
        );
        // No commitment chain → still a note.
        assert!(vtxo.is_note());
        assert!(!vtxo.requires_forfeit());
        assert!(vtxo.is_spendable());

        vtxo.commitment_txids = vec!["c1".into()];
        vtxo.root_commitment_txid = "c1".into();
        assert!(!vtxo.is_note());
        assert!(vtxo.requires_forfeit());
    }
}
