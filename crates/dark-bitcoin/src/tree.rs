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
/// **Important:** This function accepts 33-byte compressed keys (with their
/// original 02/03 parity prefix) and passes them to the MuSig2 key
/// aggregation as-is. This matches the Go reference implementation
/// (`btcec/musig2.AggregateKeys`) which also uses full compressed keys.
/// Using the original parity is critical: BIP-327 aggregation coefficients
/// are computed from the serialized compressed keys, so normalizing all
/// keys to 0x02 would produce a different aggregate key than Go.
///
/// # Arguments
/// * `compressed_keys` - Slice of 33-byte compressed public keys.
///   Must contain at least 2 keys. Keys are sorted lexicographically
///   before aggregation to ensure deterministic output.
///
/// # Returns
/// The aggregated x-only public key.
///
/// # Errors
/// Returns an error if fewer than 2 keys are provided, or if key
/// aggregation fails (e.g., keys sum to the point at infinity).
pub fn aggregate_keys(compressed_keys: &[[u8; 33]]) -> BitcoinResult<XOnlyPublicKey> {
    if compressed_keys.len() < 2 {
        return Err(BitcoinError::ScriptError(
            "MuSig2 key aggregation requires at least 2 public keys".to_string(),
        ));
    }

    // Parse 33-byte compressed keys into musig2's secp256k1::PublicKey,
    // preserving the original parity (02/03 prefix).
    let mut musig_pubkeys: Vec<musig2::secp256k1::PublicKey> = compressed_keys
        .iter()
        .map(|compressed| {
            musig2::secp256k1::PublicKey::from_slice(compressed).map_err(|e| {
                BitcoinError::ScriptError(format!("Invalid public key for MuSig2: {}", e))
            })
        })
        .collect::<BitcoinResult<Vec<_>>>()?;

    // Sort for deterministic aggregation (BIP-327 recommends sorted keys).
    // Go's btcec sorts by SerializeCompressed() — our sort does the same.
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

    /// Helper: generate a deterministic compressed key from a 32-byte secret.
    fn test_compressed_key(secret_bytes: [u8; 32]) -> [u8; 33] {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        pk.serialize()
    }

    #[test]
    fn aggregate_two_keys_produces_valid_output() {
        let key1 = test_compressed_key([1u8; 32]);
        let key2 = test_compressed_key([2u8; 32]);

        let agg = aggregate_keys(&[key1, key2]).expect("should aggregate 2 keys");

        // Aggregated key should be a valid x-only key
        assert_eq!(agg.serialize().len(), 32);
    }

    #[test]
    fn aggregation_is_deterministic() {
        let key1 = test_compressed_key([1u8; 32]);
        let key2 = test_compressed_key([2u8; 32]);

        let agg_a = aggregate_keys(&[key1, key2]).unwrap();
        let agg_b = aggregate_keys(&[key1, key2]).unwrap();
        let agg_c = aggregate_keys(&[key2, key1]).unwrap();

        assert_eq!(agg_a, agg_b, "same order must be deterministic");
        assert_eq!(agg_a, agg_c, "reversed order must match (keys are sorted)");
    }

    #[test]
    fn same_key_twice_is_valid() {
        let key = test_compressed_key([1u8; 32]);
        let result = aggregate_keys(&[key, key]);
        assert!(result.is_ok(), "MuSig2 allows duplicate keys");
    }

    #[test]
    fn many_keys_aggregation() {
        let keys: Vec<[u8; 33]> = (1u8..=10)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i;
                test_compressed_key(bytes)
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
        let key = test_compressed_key([1u8; 32]);
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
        let key1 = test_compressed_key([3u8; 32]);
        let key2 = test_compressed_key([4u8; 32]);

        let agg = aggregate_keys(&[key1, key2]).unwrap();
        let bytes = agg.serialize();
        assert_eq!(bytes.len(), 32);
        assert_eq!(XOnlyPublicKey::from_slice(&bytes).unwrap(), agg);
    }
}
