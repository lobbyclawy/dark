//! MuSig2 key aggregation for Taproot VTXO trees.
//!
//! Implements BIP-327 MuSig2 key aggregation using the `musig2` crate,
//! replacing the previous SHA256-based placeholder. The aggregated key
//! is used as the Taproot internal key for cooperative spending paths.

use bitcoin::XOnlyPublicKey;

use crate::error::{BitcoinError, BitcoinResult};

/// Aggregate multiple public keys into a single MuSig2 combined key.
///
/// Uses BIP-327 key aggregation to produce a single public key that
/// requires cooperation from all participants to sign. The resulting
/// key is suitable for use as a Taproot internal key.
///
/// # Arguments
/// * `pubkeys` - Slice of x-only public keys to aggregate. Must contain
///   at least 2 keys. Keys are sorted lexicographically before aggregation
///   to ensure deterministic output regardless of input order.
///
/// # Returns
/// The aggregated x-only public key.
///
/// # Errors
/// Returns an error if fewer than 2 keys are provided, or if key
/// aggregation fails (e.g., keys sum to the point at infinity).
pub fn aggregate_keys(pubkeys: &[XOnlyPublicKey]) -> BitcoinResult<XOnlyPublicKey> {
    if pubkeys.len() < 2 {
        return Err(BitcoinError::ScriptError(
            "MuSig2 key aggregation requires at least 2 public keys".to_string(),
        ));
    }

    // Convert bitcoin 0.32 XOnlyPublicKey -> musig2's secp256k1::PublicKey
    // by serializing to bytes and re-parsing with the musig2-compatible secp256k1.
    // XOnlyPublicKey is 32 bytes; prepend 0x02 to make a compressed pubkey.
    let mut musig_pubkeys: Vec<musig2::secp256k1::PublicKey> = pubkeys
        .iter()
        .map(|xonly| {
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed[1..].copy_from_slice(&xonly.serialize());
            musig2::secp256k1::PublicKey::from_slice(&compressed).map_err(|e| {
                BitcoinError::ScriptError(format!("Invalid public key for MuSig2: {}", e))
            })
        })
        .collect::<BitcoinResult<Vec<_>>>()?;

    // Sort for deterministic aggregation (BIP-327 recommends sorted keys)
    musig_pubkeys.sort();

    let key_agg_ctx = musig2::KeyAggContext::new(musig_pubkeys)
        .map_err(|e| BitcoinError::ScriptError(format!("MuSig2 key aggregation failed: {}", e)))?;

    // Get the aggregated public key as x-only (for Taproot)
    let agg_pubkey: musig2::secp256k1::XOnlyPublicKey = key_agg_ctx.aggregated_pubkey();

    // Convert back to bitcoin 0.32 XOnlyPublicKey via serialized bytes
    let agg_bytes = agg_pubkey.serialize();
    XOnlyPublicKey::from_slice(&agg_bytes)
        .map_err(|e| BitcoinError::ScriptError(format!("Invalid aggregated key: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    /// Helper: generate a deterministic XOnlyPublicKey from a 32-byte secret.
    fn test_xonly_key(secret_bytes: [u8; 32]) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        XOnlyPublicKey::from(pk)
    }

    #[test]
    fn aggregate_two_keys_produces_valid_output() {
        let key1 = test_xonly_key([1u8; 32]);
        let key2 = test_xonly_key([2u8; 32]);

        let agg = aggregate_keys(&[key1, key2]).expect("should aggregate 2 keys");

        // Aggregated key must differ from both inputs
        assert_ne!(agg, key1);
        assert_ne!(agg, key2);
    }

    #[test]
    fn aggregation_is_deterministic() {
        let key1 = test_xonly_key([1u8; 32]);
        let key2 = test_xonly_key([2u8; 32]);

        let agg_a = aggregate_keys(&[key1, key2]).unwrap();
        let agg_b = aggregate_keys(&[key1, key2]).unwrap();
        let agg_c = aggregate_keys(&[key2, key1]).unwrap();

        assert_eq!(agg_a, agg_b, "same order must be deterministic");
        assert_eq!(agg_a, agg_c, "reversed order must match (keys are sorted)");
    }

    #[test]
    fn same_key_twice_is_valid() {
        let key = test_xonly_key([1u8; 32]);
        let result = aggregate_keys(&[key, key]);
        assert!(result.is_ok(), "MuSig2 allows duplicate keys");
    }

    #[test]
    fn many_keys_aggregation() {
        let keys: Vec<XOnlyPublicKey> = (1u8..=10)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i;
                test_xonly_key(bytes)
            })
            .collect();

        let agg = aggregate_keys(&keys).expect("should aggregate 10 keys");

        // Verify round-trip serialization
        let bytes = agg.serialize();
        assert_eq!(bytes.len(), 32);
        let reparsed = XOnlyPublicKey::from_slice(&bytes).unwrap();
        assert_eq!(agg, reparsed);
    }

    #[test]
    fn rejects_single_key() {
        let key = test_xonly_key([1u8; 32]);
        let err = aggregate_keys(&[key]).unwrap_err();
        assert!(
            err.to_string().contains("at least 2"),
            "error should mention minimum: {}",
            err
        );
    }

    #[test]
    fn rejects_empty_keys() {
        let err = aggregate_keys(&[]).unwrap_err();
        assert!(err.to_string().contains("at least 2"));
    }

    #[test]
    fn aggregated_key_round_trips_as_xonly() {
        let key1 = test_xonly_key([3u8; 32]);
        let key2 = test_xonly_key([4u8; 32]);

        let agg = aggregate_keys(&[key1, key2]).unwrap();
        let bytes = agg.serialize();
        assert_eq!(bytes.len(), 32);
        assert_eq!(XOnlyPublicKey::from_slice(&bytes).unwrap(), agg);
    }
}
