//! Single-VTXO selective reveal with commitment opening.
//!
//! # Use case
//!
//! A wallet wishes to share, with one specific third party, a verifiable
//! opening of a single VTXO it owns: the amount, the blinding factor, and
//! optional metadata (exit delay, memo). The recipient can confirm the
//! opening recomputes the on-chain Pedersen commitment, and that the
//! disclosure was constructed for *this* outpoint under *this* owner
//! pubkey — not lifted from another VTXO with the same amount and
//! blinding.
//!
//! # Construction
//!
//! A [`SelectiveReveal`] carries:
//! - the [`VtxoOutpoint`](super::super::vtxo) of the disclosed VTXO,
//! - a [`PedersenOpening`] that recomputes the commitment,
//! - a [`DisclosedFields`] bag of optional metadata the wallet chose to
//!   include (e.g. `exit_delay_blocks`, a freeform `memo`),
//! - a 32-byte `transcript_hash` tying everything together.
//!
//! The `transcript_hash` is a BIP-340-style tagged SHA-256 over the
//! domain separator [`SELECTIVE_REVEAL_DST`] and a length-prefixed,
//! canonical encoding of:
//!
//! 1. the outpoint (`txid || vout_be`),
//! 2. the expected commitment (33-byte compressed point),
//! 3. the VTXO owner pubkey (33-byte compressed point),
//! 4. the disclosed fields (length-prefixed, see [`DisclosedFields`]).
//!
//! The opening (`amount`, `blinding`) is **not** mixed into the
//! transcript: the Pedersen commitment cryptographically binds them
//! already, and re-binding them would just expand the transcript surface
//! without strengthening verification.
//!
//! # Privacy
//!
//! See the parent module [`crate::disclosure`]. Revealing one VTXO does
//! not reveal sibling VTXOs, the round graph, or any other wallet state.
//!
//! # Threat model
//!
//! - The opening's `blinding` scalar is secret material in the prover
//!   environment; once embedded in a [`SelectiveReveal`] the wallet has
//!   *chosen* to publish it to the disclosure recipient. We do not
//!   zeroize the field on the public type — by the time it lives there
//!   the wallet has accepted disclosure.
//! - Cross-VTXO replay (presenting reveal-for-A as a reveal-for-B with
//!   matching amount and blinding) is rejected because the transcript
//!   binds the commitment bytes; B's commitment hashes differently.
//! - Tampering with the opening's amount is rejected because the
//!   commitment recomputation no longer matches `expected_commitment`.
//! - Tampering with the disclosed fields is rejected because the
//!   transcript hash no longer matches.
//! - The verifier's `vtxo_pubkey` argument is trusted-input: the caller
//!   must have an out-of-band reason to believe a particular pubkey owns
//!   the disclosed outpoint (e.g. on-chain script reconstruction). The
//!   transcript binds it so a wallet cannot construct a single reveal
//!   that satisfies multiple owners.

use secp256k1::{
    hashes::{sha256, Hash, HashEngine},
    PublicKey,
};

use crate::{
    commitment::PedersenCommitment, disclosure::PedersenOpening, ConfidentialError, Result,
};

/// Domain separator for the selective-reveal transcript.
///
/// Versioned `v1`. A new primitive (different field set, different
/// hash, etc.) MUST mint a new DST rather than reinterpret this one.
///
/// TODO(#563): replace with the wire-tag the disclosure-types ADR
/// assigns once it lands. The fallback below matches the spec hint
/// from #565's task description.
pub const SELECTIVE_REVEAL_DST: &[u8] = b"dark-disclosure/selective-reveal/v1";

/// Metadata fields the prover voluntarily includes in a disclosure.
///
/// Each field is `Option`: `None` means "not disclosed", `Some(_)` means
/// "the prover commits to this exact value as part of this reveal". A
/// verifier sees only what the prover chose to include; absent fields
/// reveal nothing.
///
/// The `(amount, blinding)` opening is **not** here — it lives in the
/// [`SelectiveReveal::opening`] field and is mandatory for any verifiable
/// disclosure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisclosedFields {
    /// Unilateral-exit CSV delay (blocks), if disclosed.
    pub exit_delay_blocks: Option<u32>,
    /// Free-form memo, if disclosed.
    pub memo: Option<Vec<u8>>,
}

impl DisclosedFields {
    /// Empty disclosure — only the opening is shared, no metadata.
    pub const fn none() -> Self {
        Self {
            exit_delay_blocks: None,
            memo: None,
        }
    }

    pub fn with_exit_delay(mut self, blocks: u32) -> Self {
        self.exit_delay_blocks = Some(blocks);
        self
    }

    pub fn with_memo(mut self, memo: Vec<u8>) -> Self {
        self.memo = Some(memo);
        self
    }

    /// Canonical encoding for the transcript hash.
    ///
    /// Layout:
    /// - 1 byte: presence bitmap (`0x01 = exit_delay`, `0x02 = memo`)
    /// - if `exit_delay_blocks` is set: 4 bytes big-endian
    /// - if `memo` is set: 4-byte big-endian length || raw bytes
    ///
    /// Length prefixes prevent two distinct field sets from hashing to
    /// the same byte stream (canonical encoding requirement).
    fn canonical_encode(&self) -> Vec<u8> {
        const FLAG_EXIT_DELAY: u8 = 0x01;
        const FLAG_MEMO: u8 = 0x02;

        let mut presence: u8 = 0;
        if self.exit_delay_blocks.is_some() {
            presence |= FLAG_EXIT_DELAY;
        }
        if self.memo.is_some() {
            presence |= FLAG_MEMO;
        }

        let memo_len = self.memo.as_ref().map(|m| m.len()).unwrap_or(0);
        let mut out = Vec::with_capacity(1 + 4 + 4 + memo_len);
        out.push(presence);
        if let Some(blocks) = self.exit_delay_blocks {
            out.extend_from_slice(&blocks.to_be_bytes());
        }
        if let Some(memo) = &self.memo {
            out.extend_from_slice(&(memo.len() as u32).to_be_bytes());
            out.extend_from_slice(memo);
        }
        out
    }
}

/// Canonical 36-byte VTXO outpoint encoding (`txid || vout_be`).
///
/// Mirrors [`crate::nullifier::encode_vtxo_id`] so disclosure transcripts
/// share a common identity layout with nullifier derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VtxoOutpoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl VtxoOutpoint {
    pub const fn new(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }

    pub fn to_bytes(&self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..32].copy_from_slice(&self.txid);
        out[32..].copy_from_slice(&self.vout.to_be_bytes());
        out
    }
}

impl From<bitcoin::OutPoint> for VtxoOutpoint {
    fn from(outpoint: bitcoin::OutPoint) -> Self {
        Self {
            txid: *outpoint.txid.as_ref(),
            vout: outpoint.vout,
        }
    }
}

/// A single-VTXO selective reveal bundle.
///
/// Constructed by [`prove_selective_reveal`], checked by
/// [`verify_selective_reveal`]. The struct is `pub` and inspectable so
/// recipients can render the disclosed information; the transcript hash
/// is what gives that information cryptographic weight.
///
/// This type does **not** derive `Clone`: the `opening` carries secret
/// blinding data (until intentionally shared), and accidental
/// duplication makes zeroization harder. Callers that genuinely need a
/// duplicate should construct a new value explicitly.
#[derive(Debug)]
pub struct SelectiveReveal {
    /// Outpoint of the disclosed VTXO.
    pub vtxo_outpoint: VtxoOutpoint,
    /// `(amount, blinding)` opening of the VTXO's Pedersen commitment.
    pub opening: PedersenOpening,
    /// Optional metadata the prover voluntarily included.
    pub disclosed_fields: DisclosedFields,
    /// Tagged-hash transcript binding outpoint, commitment, pubkey, and
    /// disclosed fields. See module docs for the canonical layout.
    pub transcript_hash: [u8; 32],
}

/// Build a selective-reveal bundle for a VTXO the wallet owns.
///
/// `expected_commitment` is recomputed from `opening` to bind the
/// transcript to the on-chain commitment without trusting any
/// independently-supplied bytes — the caller cannot accidentally bind a
/// stale commitment to a fresh opening.
///
/// `vtxo_pubkey` is the VTXO's owner pubkey, included in the transcript
/// so a single reveal cannot be re-attributed to a different owner.
///
/// Returns `Err(ConfidentialError::InvalidInput)` if the opening's
/// blinding scalar is malformed for Pedersen commitment construction.
pub fn prove_selective_reveal(
    vtxo_outpoint: VtxoOutpoint,
    opening: PedersenOpening,
    vtxo_pubkey: &PublicKey,
    disclosed_fields: DisclosedFields,
) -> Result<SelectiveReveal> {
    let commitment = opening.commit()?;
    let transcript_hash =
        compute_transcript_hash(&vtxo_outpoint, &commitment, vtxo_pubkey, &disclosed_fields);
    Ok(SelectiveReveal {
        vtxo_outpoint,
        opening,
        disclosed_fields,
        transcript_hash,
    })
}

/// Verify a selective-reveal bundle against the on-chain commitment and
/// the (independently-trusted) owner pubkey.
///
/// Returns `Ok(())` iff:
/// 1. `commit(reveal.opening) == *expected_commitment`, and
/// 2. `reveal.transcript_hash` matches the canonical hash recomputed
///    from `(reveal.vtxo_outpoint, expected_commitment, vtxo_pubkey,
///    reveal.disclosed_fields)`.
///
/// Failures are surfaced as [`ConfidentialError::Disclosure`] with a
/// stable message identifying the failed check.
pub fn verify_selective_reveal(
    reveal: &SelectiveReveal,
    expected_commitment: &PedersenCommitment,
    vtxo_pubkey: &PublicKey,
) -> Result<()> {
    let recomputed = reveal.opening.commit()?;
    if &recomputed != expected_commitment {
        return Err(ConfidentialError::Disclosure(
            "opening does not match expected commitment",
        ));
    }
    let expected_hash = compute_transcript_hash(
        &reveal.vtxo_outpoint,
        expected_commitment,
        vtxo_pubkey,
        &reveal.disclosed_fields,
    );
    if expected_hash != reveal.transcript_hash {
        return Err(ConfidentialError::Disclosure(
            "transcript hash does not bind reveal to outpoint and pubkey",
        ));
    }
    Ok(())
}

fn compute_transcript_hash(
    outpoint: &VtxoOutpoint,
    commitment: &PedersenCommitment,
    vtxo_pubkey: &PublicKey,
    disclosed_fields: &DisclosedFields,
) -> [u8; 32] {
    // BIP-340-style tagged hash: SHA-256(tag || tag || message), where
    // `tag = SHA-256(DST)`. Each field is fixed-width except disclosed
    // fields, which carry their own internal length prefixes — so the
    // concatenation is unambiguously parseable.
    let tag = sha256::Hash::hash(SELECTIVE_REVEAL_DST).to_byte_array();
    let fields_bytes = disclosed_fields.canonical_encode();
    let mut engine = sha256::Hash::engine();
    engine.input(&tag);
    engine.input(&tag);
    engine.input(&outpoint.to_bytes());
    engine.input(&commitment.to_bytes());
    engine.input(&vtxo_pubkey.serialize());
    engine.input(&fields_bytes);
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Scalar, Secp256k1, SecretKey};

    fn scalar_from_u64(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_be_bytes(bytes).unwrap()
    }

    fn pubkey_from_seed(seed: u8) -> PublicKey {
        let mut sk = [seed.max(1); 32];
        sk[31] = seed.max(1);
        let secret = SecretKey::from_slice(&sk).unwrap();
        PublicKey::from_secret_key(&Secp256k1::new(), &secret)
    }

    fn outpoint_from_seed(seed: u8) -> VtxoOutpoint {
        VtxoOutpoint::new([seed; 32], seed as u32)
    }

    /// Convenience: construct a fresh `(opening, commitment)` pair.
    fn fresh_opening(amount: u64, blinding_lo: u64) -> (PedersenOpening, PedersenCommitment) {
        let opening = PedersenOpening::new(amount, scalar_from_u64(blinding_lo));
        let commitment = opening.commit().unwrap();
        (opening, commitment)
    }

    #[test]
    fn round_trip_prove_verify() {
        let (opening, commitment) = fresh_opening(42_000, 0xdead_beef);
        let pubkey = pubkey_from_seed(7);
        let outpoint = outpoint_from_seed(7);

        let reveal = prove_selective_reveal(
            outpoint,
            opening,
            &pubkey,
            DisclosedFields::none()
                .with_exit_delay(144)
                .with_memo(b"invoice 0042".to_vec()),
        )
        .unwrap();

        assert!(verify_selective_reveal(&reveal, &commitment, &pubkey).is_ok());
    }

    #[test]
    fn round_trip_with_no_disclosed_fields() {
        // `DisclosedFields::none()` is the smallest viable disclosure:
        // only the opening is revealed; no metadata is signed.
        let (opening, commitment) = fresh_opening(1, 1);
        let pubkey = pubkey_from_seed(1);
        let outpoint = outpoint_from_seed(1);

        let reveal =
            prove_selective_reveal(outpoint, opening, &pubkey, DisclosedFields::none()).unwrap();
        assert!(verify_selective_reveal(&reveal, &commitment, &pubkey).is_ok());
    }

    #[test]
    fn tampered_amount_fails_verification() {
        let (opening, commitment) = fresh_opening(1_000, 0x100);
        let pubkey = pubkey_from_seed(2);
        let outpoint = outpoint_from_seed(2);

        let mut reveal =
            prove_selective_reveal(outpoint, opening, &pubkey, DisclosedFields::none()).unwrap();
        // Mutate the amount in the opening; the commitment recomputation
        // now diverges from the stored expected commitment.
        reveal.opening.amount = reveal.opening.amount.wrapping_add(1);

        let err = verify_selective_reveal(&reveal, &commitment, &pubkey).unwrap_err();
        assert!(matches!(err, ConfidentialError::Disclosure(msg) if msg.contains("opening")));
    }

    #[test]
    fn tampered_blinding_fails_verification() {
        let (opening, commitment) = fresh_opening(500, 0x200);
        let pubkey = pubkey_from_seed(3);
        let outpoint = outpoint_from_seed(3);

        let mut reveal =
            prove_selective_reveal(outpoint, opening, &pubkey, DisclosedFields::none()).unwrap();
        reveal.opening.blinding = scalar_from_u64(0x999);

        let err = verify_selective_reveal(&reveal, &commitment, &pubkey).unwrap_err();
        assert!(matches!(err, ConfidentialError::Disclosure(_)));
    }

    #[test]
    fn tampered_transcript_hash_fails_verification() {
        let (opening, commitment) = fresh_opening(1_000, 0x300);
        let pubkey = pubkey_from_seed(4);
        let outpoint = outpoint_from_seed(4);

        let mut reveal =
            prove_selective_reveal(outpoint, opening, &pubkey, DisclosedFields::none()).unwrap();
        reveal.transcript_hash[0] ^= 0x01;

        let err = verify_selective_reveal(&reveal, &commitment, &pubkey).unwrap_err();
        assert!(matches!(err, ConfidentialError::Disclosure(msg) if msg.contains("transcript")));
    }

    #[test]
    fn tampered_disclosed_fields_fails_verification() {
        let (opening, commitment) = fresh_opening(1_000, 0x400);
        let pubkey = pubkey_from_seed(5);
        let outpoint = outpoint_from_seed(5);

        let reveal = prove_selective_reveal(
            outpoint,
            opening,
            &pubkey,
            DisclosedFields::none().with_memo(b"original".to_vec()),
        )
        .unwrap();

        // Mutate the memo without recomputing the transcript hash — the
        // stored hash now binds the *original* memo, so verification fails.
        let mut tampered = SelectiveReveal {
            vtxo_outpoint: reveal.vtxo_outpoint,
            opening: PedersenOpening::new(reveal.opening.amount, reveal.opening.blinding),
            disclosed_fields: DisclosedFields::none().with_memo(b"replaced".to_vec()),
            transcript_hash: reveal.transcript_hash,
        };
        // Sanity: the disclosed_fields really did change.
        assert_ne!(tampered.disclosed_fields.memo, Some(b"original".to_vec()));

        let err = verify_selective_reveal(&tampered, &commitment, &pubkey).unwrap_err();
        assert!(matches!(err, ConfidentialError::Disclosure(msg) if msg.contains("transcript")));

        // Restoring the original memo makes verification pass again,
        // confirming the transcript binding is what flagged the tamper.
        tampered.disclosed_fields = DisclosedFields::none().with_memo(b"original".to_vec());
        assert!(verify_selective_reveal(&tampered, &commitment, &pubkey).is_ok());
    }

    #[test]
    fn cross_vtxo_replay_is_rejected() {
        // Build two distinct VTXOs that share the same `(amount, blinding)`
        // — i.e. the same Pedersen commitment bytes — but live at
        // different outpoints. A reveal for outpoint A must not verify
        // for outpoint B, even though the commitments are identical.
        let (opening_a, commitment_a) = fresh_opening(7_777, 0x500);
        let pubkey = pubkey_from_seed(6);
        let outpoint_a = outpoint_from_seed(0xa);
        let outpoint_b = outpoint_from_seed(0xb);

        let reveal_a =
            prove_selective_reveal(outpoint_a, opening_a, &pubkey, DisclosedFields::none())
                .unwrap();

        // Replay attempt: present the proof under outpoint B's identity
        // (same commitment — verifier supplies its `expected_commitment`
        // for the VTXO at outpoint B, which happens to equal A's).
        let replay = SelectiveReveal {
            vtxo_outpoint: outpoint_b,
            opening: PedersenOpening::new(reveal_a.opening.amount, reveal_a.opening.blinding),
            disclosed_fields: DisclosedFields::none(),
            transcript_hash: reveal_a.transcript_hash,
        };
        let err = verify_selective_reveal(&replay, &commitment_a, &pubkey).unwrap_err();
        assert!(matches!(err, ConfidentialError::Disclosure(_)));
    }

    #[test]
    fn cross_vtxo_replay_with_distinct_commitments_is_rejected() {
        // Independent VTXOs at distinct outpoints with distinct openings.
        // A reveal for VTXO A presented against VTXO B's commitment must
        // fail — both because the opening doesn't match B's commitment,
        // and because the transcript binds A's commitment bytes.
        let (opening_a, _commitment_a) = fresh_opening(100, 0x601);
        let (_opening_b, commitment_b) = fresh_opening(200, 0x602);
        let pubkey = pubkey_from_seed(7);

        let reveal_a = prove_selective_reveal(
            outpoint_from_seed(0xc),
            opening_a,
            &pubkey,
            DisclosedFields::none(),
        )
        .unwrap();

        let err = verify_selective_reveal(&reveal_a, &commitment_b, &pubkey).unwrap_err();
        assert!(matches!(err, ConfidentialError::Disclosure(_)));
    }

    #[test]
    fn wrong_pubkey_fails_verification() {
        let (opening, commitment) = fresh_opening(2_500, 0x700);
        let pubkey = pubkey_from_seed(8);
        let other_pubkey = pubkey_from_seed(9);
        let outpoint = outpoint_from_seed(8);

        let reveal =
            prove_selective_reveal(outpoint, opening, &pubkey, DisclosedFields::none()).unwrap();

        // Pubkey is mixed into the transcript — a verifier supplying a
        // different pubkey rebuilds a different hash.
        let err = verify_selective_reveal(&reveal, &commitment, &other_pubkey).unwrap_err();
        assert!(matches!(err, ConfidentialError::Disclosure(_)));
    }

    #[test]
    fn disclosed_fields_canonical_encoding_is_unambiguous() {
        // Two field sets that differ only in *which* field is set must
        // produce different byte streams (no presence bitmap collision).
        let only_delay = DisclosedFields::none().with_exit_delay(0);
        let only_memo = DisclosedFields::none().with_memo(Vec::new());
        assert_ne!(only_delay.canonical_encode(), only_memo.canonical_encode());

        // Memo length is part of the encoding, so two distinct memo
        // payloads of different lengths cannot collide.
        let memo_a = DisclosedFields::none().with_memo(b"a".to_vec());
        let memo_ab = DisclosedFields::none().with_memo(b"ab".to_vec());
        assert_ne!(memo_a.canonical_encode(), memo_ab.canonical_encode());
    }

    #[test]
    fn transcript_hash_is_deterministic() {
        let (opening, _) = fresh_opening(500, 0x800);
        let pubkey = pubkey_from_seed(10);
        let outpoint = outpoint_from_seed(10);
        let fields = DisclosedFields::none().with_exit_delay(42);

        let r1 =
            prove_selective_reveal(outpoint, opening.cloned(), &pubkey, fields.clone()).unwrap();
        let r2 = prove_selective_reveal(outpoint, opening, &pubkey, fields).unwrap();
        assert_eq!(r1.transcript_hash, r2.transcript_hash);
    }

    #[test]
    fn dst_string_matches_spec() {
        // Lock the wire-tag so unintentional rewording shows up as a
        // failing test rather than a silent transcript-hash drift.
        assert_eq!(SELECTIVE_REVEAL_DST, b"dark-disclosure/selective-reveal/v1");
    }

    #[test]
    fn vtxo_outpoint_from_bitcoin_outpoint_round_trip() {
        use bitcoin::{
            hashes::{sha256d, Hash as _},
            OutPoint, Txid,
        };
        let txid_bytes = [0xab; 32];
        let outpoint = OutPoint::new(
            Txid::from_raw_hash(sha256d::Hash::from_byte_array(txid_bytes)),
            7,
        );
        let v: VtxoOutpoint = outpoint.into();
        assert_eq!(v.txid, txid_bytes);
        assert_eq!(v.vout, 7);
    }
}
