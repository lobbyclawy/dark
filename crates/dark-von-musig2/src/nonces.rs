//! Public-nonce wire types.
//!
//! `PubNonce` and `AggNonce` are 66-byte wire blobs (`R₁_compressed || R₂_compressed`)
//! matching BIP-327 §"Public nonce encoding". Compatible with `musig2 = "0.3.1"`'s
//! `PubNonce::to_bytes()` / `AggNonce::to_bytes()` byte layout.

use secp256k1::PublicKey;

use crate::bip327::internal::generator;
use crate::error::Bip327Error;

/// One signer's public-nonce contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubNonce {
    pub r1: PublicKey,
    pub r2: PublicKey,
}

impl PubNonce {
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        out[..33].copy_from_slice(&self.r1.serialize());
        out[33..].copy_from_slice(&self.r2.serialize());
        out
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Bip327Error> {
        if bytes.len() != 66 {
            return Err(Bip327Error::MalformedPubNonce);
        }
        let r1 = PublicKey::from_slice(&bytes[..33]).map_err(|_| Bip327Error::MalformedPubNonce)?;
        let r2 = PublicKey::from_slice(&bytes[33..]).map_err(|_| Bip327Error::MalformedPubNonce)?;
        Ok(PubNonce { r1, r2 })
    }
}

/// Aggregated public nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggNonce {
    pub r1: PublicKey,
    pub r2: PublicKey,
}

impl AggNonce {
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        out[..33].copy_from_slice(&self.r1.serialize());
        out[33..].copy_from_slice(&self.r2.serialize());
        out
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Bip327Error> {
        if bytes.len() != 66 {
            return Err(Bip327Error::MalformedAggNonce);
        }
        let r1 = PublicKey::from_slice(&bytes[..33]).map_err(|_| Bip327Error::MalformedAggNonce)?;
        let r2 = PublicKey::from_slice(&bytes[33..]).map_err(|_| Bip327Error::MalformedAggNonce)?;
        Ok(AggNonce { r1, r2 })
    }

    /// Sum a set of [`PubNonce`] contributions per BIP-327 §"Nonce Aggregation".
    ///
    /// If a per-coordinate sum lands at the point at infinity, substitute the
    /// generator `G` per BIP-327's `cbytes_ext` rule. This closes the DoS where
    /// a malicious participant negates the operator's published `R_op,b` to
    /// force `combine` to fail.
    ///
    /// Limitation: `secp256k1 = 0.29`'s `PublicKey` cannot represent infinity,
    /// so for `> 2` signers an intermediate sum that lands at infinity would
    /// trigger the substitution even though the spec only requires it for the
    /// final sum. This is acceptable for the 2-of-2 path exercised by phase-2
    /// tests; full N-of-N spec compliance requires modeling `AggNonce` as
    /// `Option<PublicKey>` and is tracked as a follow-up.
    pub fn sum(pub_nonces: &[PubNonce]) -> Result<Self, Bip327Error> {
        if pub_nonces.is_empty() {
            return Err(Bip327Error::MalformedPubNonce);
        }
        let g = generator();
        let mut r1 = pub_nonces[0].r1;
        let mut r2 = pub_nonces[0].r2;
        for n in &pub_nonces[1..] {
            r1 = match r1.combine(&n.r1) {
                Ok(p) => p,
                Err(_) => *g,
            };
            r2 = match r2.combine(&n.r2) {
                Ok(p) => p,
                Err(_) => *g,
            };
        }
        Ok(AggNonce { r1, r2 })
    }
}
