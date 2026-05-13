//! Informational compatibility check against `vrf = 0.2.4`.
//!
//! ADR-0006 calls out Witnet's `vrf` crate as the only crates.io package
//! exposing a secp256k1 ECVRF surface, but it is pinned to a different
//! ciphersuite (`SECP256K1_SHA256_TAI`) and to pre-RFC draft conventions.
//!
//! The vectors here were generated from the upstream example program
//! `examples/generate_secp256k1.rs` in `vrf = 0.2.4`, using message
//! `b"sample"` and secret keys `1..=8`. The test is `#[ignore]` because it is
//! informational, not a gate on our own ciphersuite. It documents the exact
//! incompatibility we expect:
//!
//! - public keys match for the same secret keys,
//! - the upstream proof parses as an 81-byte `(Gamma || c || s)` tuple,
//! - our ciphersuite intentionally produces different `beta` / `pi`, and
//! - our verifier rejects the upstream proof/hash pair.

use std::fs;
use std::path::PathBuf;

use dark_von::ecvrf::{prove, verify, Proof};
use dark_von::EcvrfError;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::Deserialize;

const VECTOR_PATH: &str = "tests/data/witnet_v0_2_4_secp256k1_tai.json";

#[derive(Debug, Deserialize)]
struct VectorFile {
    source: String,
    source_suite: String,
    source_message: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    #[serde(rename = "priv")]
    priv_: String,
    #[serde(rename = "pub")]
    pub_: String,
    message: String,
    pi: String,
    hash: String,
}

#[test]
#[ignore = "informational cross-implementation fixture; not part of the required conformance gate"]
fn witnet_vectors_are_documented_as_incompatible() {
    let file = load_file();
    assert_eq!(file.source, "vrf 0.2.4 example/generate_secp256k1.rs");
    assert_eq!(file.source_suite, "SECP256K1_SHA256_TAI");
    assert_eq!(file.source_message, "sample");
    assert_eq!(
        file.vectors.len(),
        8,
        "fixture should stay small and reviewable"
    );

    let secp = Secp256k1::new();
    for (i, vector) in file.vectors.iter().enumerate() {
        let sk = decimal_secret_key(&vector.priv_);
        let pk = PublicKey::from_secret_key(&secp, &sk);
        assert_eq!(
            hex::encode(pk.serialize()),
            vector.pub_,
            "vector {i}: pk drift"
        );

        let alpha = hex::decode(&vector.message).expect("message hex");
        let upstream_pi_bytes = hex::decode(&vector.pi).expect("proof hex");
        let upstream_beta_vec = hex::decode(&vector.hash).expect("hash hex");
        let upstream_proof = Proof::from_slice(&upstream_pi_bytes).expect("proof shape");
        let upstream_beta: [u8; 32] = upstream_beta_vec.try_into().expect("32-byte hash");

        let (our_beta, our_proof) = prove(&sk, &alpha).expect("prove ok");

        assert_ne!(
            our_proof.to_bytes().as_slice(),
            upstream_pi_bytes.as_slice(),
            "vector {i}: proof unexpectedly matched Witnet suite"
        );
        assert_ne!(
            our_beta.as_slice(),
            upstream_beta.as_slice(),
            "vector {i}: beta unexpectedly matched Witnet suite"
        );

        let err = verify(&pk, &alpha, &upstream_beta, &upstream_proof)
            .expect_err("Witnet vector should not verify under DARK suite");
        assert!(
            matches!(
                err,
                EcvrfError::VerificationEquationFailed
                    | EcvrfError::ChallengeMismatch
                    | EcvrfError::OutputMismatch
            ),
            "vector {i}: unexpected error: {err}"
        );
    }
}

fn load_file() -> VectorFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTOR_PATH);
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "missing cross-implementation fixture {} ({err})",
            path.display()
        )
    });
    serde_json::from_str(&raw).expect("fixture JSON parses")
}

fn decimal_secret_key(value: &str) -> SecretKey {
    let scalar = value.parse::<u128>().expect("small decimal scalar");
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&scalar.to_be_bytes());
    SecretKey::from_slice(&bytes).expect("scalar in range")
}
