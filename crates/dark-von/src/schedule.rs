//! Deterministic VON schedule generation.
//!
//! `Schedule::generate(sk, setup_id, n)` produces, for `t ∈ [1, n]` and
//! `b ∈ {1, 2}`, the public points and proofs `{(R_{t,b}, π_{t,b})}`
//! and the matching retained secret scalars `{r_{t,b}}`. The public
//! half is what the operator publishes at setup; the secret half is
//! what the operator retains.
//!
//! Per ADR-0007's downstream constraint on this issue:
//! - `PublicSchedule` serialises via [`PublicSchedule::to_bytes`] /
//!   [`PublicSchedule::from_bytes`] using a fixed binary layout
//!   (no derive(Serialize)).
//! - `SecretSchedule` exposes [`SecretSchedule::to_bytes_dangerous`]
//!   only behind the `dangerous-export` Cargo feature.
//!
//! The wire layout is:
//!
//! ```text
//! PublicSchedule:
//!     setup_id (32 B) || n (4 B BE u32)
//!     for t in 1..=n:
//!         R_{t,1} (33 B) || π_{t,1} (81 B)
//!         R_{t,2} (33 B) || π_{t,2} (81 B)
//!     -- total = 36 + 228 * n bytes
//!
//! SecretSchedule (dangerous-export only):
//!     setup_id (32 B) || n (4 B BE u32)
//!     for t in 1..=n:
//!         r_{t,1} (32 B BE) || r_{t,2} (32 B BE)
//!     -- total = 36 + 64 * n bytes
//! ```

use secp256k1::{PublicKey, SecretKey};
#[cfg(feature = "dangerous-export")]
use zeroize::Zeroizing;

use crate::ecvrf::{Proof, PROOF_LEN};
use crate::error::VonError;
use crate::hash::h_nonce;
use crate::wrapper;

/// Maximum schedule horizon. Caps the cohort lifetime; deployments that
/// need longer horizons must override this constant in a subsequent ADR
/// (and re-run #658's benchmarks at the new ceiling).
pub const MAX_HORIZON: u32 = 256;

/// Per-`(t, b)` public schedule entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicEntry {
    pub r_point: PublicKey,
    pub proof: Proof,
}

const PUBLIC_ENTRY_LEN: usize = 33 + PROOF_LEN; // 33 + 81 = 114
const PUBLIC_HEADER_LEN: usize = 32 + 4; // setup_id + n
#[cfg(feature = "dangerous-export")]
const SECRET_HEADER_LEN: usize = 32 + 4;

/// Public schedule: published by the operator at setup time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicSchedule {
    pub setup_id: [u8; 32],
    pub n: u32,
    /// Entries indexed as `[t-1] = (entry_b1, entry_b2)`.
    pub entries: Vec<(PublicEntry, PublicEntry)>,
}

impl PublicSchedule {
    /// Get `(R, π)` for the requested `(t, b)`.
    /// `t ∈ [1, n]`, `b ∈ {1, 2}`.
    pub fn entry(&self, t: u32, b: u8) -> Option<&PublicEntry> {
        if t == 0 || t > self.n {
            return None;
        }
        let pair = self.entries.get((t - 1) as usize)?;
        match b {
            1 => Some(&pair.0),
            2 => Some(&pair.1),
            _ => None,
        }
    }

    /// Total byte length of [`Self::to_bytes`].
    pub fn byte_len(&self) -> usize {
        PUBLIC_HEADER_LEN + 2 * PUBLIC_ENTRY_LEN * self.n as usize
    }

    /// Serialise to the canonical wire format documented in this module.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_len());
        out.extend_from_slice(&self.setup_id);
        out.extend_from_slice(&self.n.to_be_bytes());
        for (e1, e2) in &self.entries {
            write_public_entry(&mut out, e1);
            write_public_entry(&mut out, e2);
        }
        out
    }

    /// Parse from the canonical wire format. Validates length and
    /// every embedded point/proof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VonError> {
        if bytes.len() < PUBLIC_HEADER_LEN {
            return Err(VonError::MalformedSchedule(
                "public schedule shorter than header",
            ));
        }
        let mut setup_id = [0u8; 32];
        setup_id.copy_from_slice(&bytes[..32]);
        let n = u32::from_be_bytes(bytes[32..36].try_into().unwrap());
        if n == 0 {
            return Err(VonError::HorizonZero { n });
        }
        if n > MAX_HORIZON {
            return Err(VonError::HorizonTooLarge {
                n,
                max: MAX_HORIZON,
            });
        }
        let expected = PUBLIC_HEADER_LEN + 2 * PUBLIC_ENTRY_LEN * n as usize;
        if bytes.len() != expected {
            return Err(VonError::MalformedSchedule(
                "public schedule length mismatch",
            ));
        }
        let mut entries = Vec::with_capacity(n as usize);
        let mut cursor = PUBLIC_HEADER_LEN;
        for _ in 0..n {
            let e1 = read_public_entry(&bytes[cursor..cursor + PUBLIC_ENTRY_LEN])?;
            cursor += PUBLIC_ENTRY_LEN;
            let e2 = read_public_entry(&bytes[cursor..cursor + PUBLIC_ENTRY_LEN])?;
            cursor += PUBLIC_ENTRY_LEN;
            entries.push((e1, e2));
        }
        Ok(PublicSchedule {
            setup_id,
            n,
            entries,
        })
    }
}

fn write_public_entry(out: &mut Vec<u8>, e: &PublicEntry) {
    out.extend_from_slice(&e.r_point.serialize());
    out.extend_from_slice(&e.proof.to_bytes());
}

fn read_public_entry(bytes: &[u8]) -> Result<PublicEntry, VonError> {
    let r_point = PublicKey::from_slice(&bytes[..33])
        .map_err(|_| VonError::MalformedSchedule("invalid R point"))?;
    let proof = Proof::from_slice(&bytes[33..])
        .map_err(|_| VonError::MalformedSchedule("invalid proof bytes"))?;
    Ok(PublicEntry { r_point, proof })
}

/// Secret schedule: retained by the operator. Serialise only via the
/// `dangerous-export`-gated method.
#[derive(Clone, Debug)]
pub struct SecretSchedule {
    pub setup_id: [u8; 32],
    pub n: u32,
    pub entries: Vec<(SecretKey, SecretKey)>,
}

impl SecretSchedule {
    pub fn r(&self, t: u32, b: u8) -> Option<&SecretKey> {
        if t == 0 || t > self.n {
            return None;
        }
        let pair = self.entries.get((t - 1) as usize)?;
        match b {
            1 => Some(&pair.0),
            2 => Some(&pair.1),
            _ => None,
        }
    }
}

#[cfg(feature = "dangerous-export")]
impl SecretSchedule {
    /// Export raw bytes. Gated behind `dangerous-export` Cargo feature.
    /// Each `r_{t,b}` is a 32-byte BE scalar. Returns `Zeroizing<Vec<u8>>` so
    /// the buffer wipes on drop and per-scalar transient stack copies are
    /// also zeroized.
    pub fn to_bytes_dangerous(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(SECRET_HEADER_LEN + 64 * self.n as usize));
        out.extend_from_slice(&self.setup_id);
        out.extend_from_slice(&self.n.to_be_bytes());
        for (r1, r2) in &self.entries {
            let s1 = Zeroizing::new(r1.secret_bytes());
            let s2 = Zeroizing::new(r2.secret_bytes());
            out.extend_from_slice(&*s1);
            out.extend_from_slice(&*s2);
        }
        out
    }

    pub fn from_bytes_dangerous(bytes: &[u8]) -> Result<Self, VonError> {
        if bytes.len() < SECRET_HEADER_LEN {
            return Err(VonError::MalformedSchedule(
                "secret schedule shorter than header",
            ));
        }
        let mut setup_id = [0u8; 32];
        setup_id.copy_from_slice(&bytes[..32]);
        let n = u32::from_be_bytes(bytes[32..36].try_into().unwrap());
        if n == 0 {
            return Err(VonError::HorizonZero { n });
        }
        if n > MAX_HORIZON {
            return Err(VonError::HorizonTooLarge {
                n,
                max: MAX_HORIZON,
            });
        }
        let expected = SECRET_HEADER_LEN + 64 * n as usize;
        if bytes.len() != expected {
            return Err(VonError::MalformedSchedule(
                "secret schedule length mismatch",
            ));
        }
        let mut entries = Vec::with_capacity(n as usize);
        let mut cursor = SECRET_HEADER_LEN;
        for _ in 0..n {
            let r1 = SecretKey::from_slice(&bytes[cursor..cursor + 32])
                .map_err(|_| VonError::MalformedSchedule("invalid r scalar"))?;
            cursor += 32;
            let r2 = SecretKey::from_slice(&bytes[cursor..cursor + 32])
                .map_err(|_| VonError::MalformedSchedule("invalid r scalar"))?;
            cursor += 32;
            entries.push((r1, r2));
        }
        Ok(SecretSchedule {
            setup_id,
            n,
            entries,
        })
    }
}

/// Generate the public + secret schedule for a horizon of `n` slots.
pub fn generate(
    sk: &SecretKey,
    setup_id: &[u8; 32],
    n: u32,
) -> Result<(PublicSchedule, SecretSchedule), VonError> {
    if n == 0 {
        return Err(VonError::HorizonZero { n });
    }
    if n > MAX_HORIZON {
        return Err(VonError::HorizonTooLarge {
            n,
            max: MAX_HORIZON,
        });
    }
    let mut public_entries = Vec::with_capacity(n as usize);
    let mut secret_entries = Vec::with_capacity(n as usize);
    for t in 1..=n {
        let x_b1 = h_nonce(setup_id, t, 1);
        let x_b2 = h_nonce(setup_id, t, 2);
        let n_b1 = wrapper::nonce(sk, &x_b1)?;
        let n_b2 = wrapper::nonce(sk, &x_b2)?;
        public_entries.push((
            PublicEntry {
                r_point: n_b1.r_point,
                proof: n_b1.proof,
            },
            PublicEntry {
                r_point: n_b2.r_point,
                proof: n_b2.proof,
            },
        ));
        secret_entries.push((n_b1.r, n_b2.r));
    }
    Ok((
        PublicSchedule {
            setup_id: *setup_id,
            n,
            entries: public_entries,
        },
        SecretSchedule {
            setup_id: *setup_id,
            n,
            entries: secret_entries,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecvrf;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn round_trip_horizons() {
        let mut rng = StdRng::seed_from_u64(0xbabe_face);
        let kp = ecvrf::keygen(&mut rng);
        let setup_id = [0xa1u8; 32];
        for n in [1u32, 4, 12, 50, 256] {
            let (public, secret) = generate(&kp.secret, &setup_id, n).expect("generate");
            assert_eq!(public.n, n);
            assert_eq!(secret.n, n);
            assert_eq!(public.entries.len(), n as usize);
            for t in 1..=n {
                for b in [1u8, 2u8] {
                    let entry = public.entry(t, b).expect("entry");
                    let r = secret.r(t, b).expect("r");
                    let r_g = PublicKey::from_secret_key(crate::internal::secp(), r);
                    assert_eq!(r_g, entry.r_point, "r·G != R at (t={t}, b={b})");
                    let x = h_nonce(&setup_id, t, b);
                    wrapper::verify(&kp.public, &x, &entry.r_point, &entry.proof)
                        .unwrap_or_else(|_| panic!("verify failed at (t={t}, b={b})"));
                }
            }
        }
    }

    #[test]
    fn horizon_zero_rejected() {
        let sk = SecretKey::from_slice(&[0x12u8; 32]).unwrap();
        let result = generate(&sk, &[0u8; 32], 0);
        assert!(matches!(result, Err(VonError::HorizonZero { n: 0 })));
    }

    #[test]
    fn horizon_too_large_rejected() {
        let sk = SecretKey::from_slice(&[0x12u8; 32]).unwrap();
        let result = generate(&sk, &[0u8; 32], MAX_HORIZON + 1);
        assert!(matches!(
            result,
            Err(VonError::HorizonTooLarge {
                n,
                max: MAX_HORIZON,
            }) if n == MAX_HORIZON + 1
        ));
    }

    #[test]
    fn public_schedule_byte_round_trip() {
        let sk = SecretKey::from_slice(&[0x21u8; 32]).unwrap();
        let setup_id = [0xb2u8; 32];
        let (public, _secret) = generate(&sk, &setup_id, 12).unwrap();
        let bytes = public.to_bytes();
        assert_eq!(bytes.len(), public.byte_len());
        assert_eq!(bytes.len(), 36 + 2 * 114 * 12);
        let public2 = PublicSchedule::from_bytes(&bytes).unwrap();
        assert_eq!(public, public2);
    }

    #[test]
    fn deterministic_generation() {
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let setup_id = [0x99u8; 32];
        let (p1, _) = generate(&sk, &setup_id, 4).unwrap();
        let (p2, _) = generate(&sk, &setup_id, 4).unwrap();
        assert_eq!(p1.to_bytes(), p2.to_bytes());
    }

    #[test]
    fn distinct_setup_ids_distinct_schedules() {
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let (p_a, _) = generate(&sk, &[0xa1u8; 32], 4).unwrap();
        let (p_b, _) = generate(&sk, &[0xb2u8; 32], 4).unwrap();
        assert_ne!(p_a.to_bytes(), p_b.to_bytes());
    }

    #[test]
    fn malformed_public_schedule_truncated() {
        assert!(matches!(
            PublicSchedule::from_bytes(&[0u8; 10]),
            Err(VonError::MalformedSchedule(_))
        ));
    }

    #[test]
    fn malformed_public_schedule_zero_n() {
        let mut bytes = vec![0u8; 36];
        // n = 0
        assert!(matches!(
            PublicSchedule::from_bytes(&bytes),
            Err(VonError::HorizonZero { n: 0 })
        ));
        // n above MAX_HORIZON
        bytes[32..36].copy_from_slice(&(MAX_HORIZON + 1).to_be_bytes());
        assert!(matches!(
            PublicSchedule::from_bytes(&bytes),
            Err(VonError::HorizonTooLarge { .. })
        ));
    }

    #[test]
    fn entry_lookup_out_of_bounds() {
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let (public, secret) = generate(&sk, &[0u8; 32], 4).unwrap();
        assert!(public.entry(0, 1).is_none());
        assert!(public.entry(5, 1).is_none());
        assert!(public.entry(1, 0).is_none());
        assert!(public.entry(1, 3).is_none());
        assert!(secret.r(0, 1).is_none());
        assert!(secret.r(5, 1).is_none());
        assert!(secret.r(1, 3).is_none());
    }
}

#[cfg(all(test, feature = "dangerous-export"))]
mod tests_dangerous_export {
    use super::*;

    #[test]
    fn secret_schedule_byte_round_trip() {
        let sk = SecretKey::from_slice(&[0x21u8; 32]).unwrap();
        let (_, secret) = generate(&sk, &[0xb2u8; 32], 12).unwrap();
        let bytes = secret.to_bytes_dangerous();
        assert_eq!(bytes.len(), 36 + 64 * 12);
        let secret2 = SecretSchedule::from_bytes_dangerous(&bytes).unwrap();
        assert_eq!(secret.setup_id, secret2.setup_id);
        assert_eq!(secret.n, secret2.n);
        for (a, b) in secret.entries.iter().zip(secret2.entries.iter()) {
            assert_eq!(a.0.secret_bytes(), b.0.secret_bytes());
            assert_eq!(a.1.secret_bytes(), b.1.secret_bytes());
        }
    }
}
