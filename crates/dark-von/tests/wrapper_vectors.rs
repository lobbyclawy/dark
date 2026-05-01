//! VON wrapper test vectors (#656).
//!
//! Five-case coverage per the issue's acceptance criteria:
//!
//! 1. Round-trip: `wrapper::nonce` then `wrapper::verify` succeeds.
//! 2. Malformed-proof rejection: tampered `π` rejects.
//! 3. Wrong-pk rejection: a different `pk_VON` rejects.
//! 4. Wrong-input rejection: a different `x` rejects (mutated `setup_id`,
//!    mutated `t`, mutated `b`).
//! 5. Domain separation: distinct `(t, b)` pairs across a small grid
//!    produce pairwise-distinct `R`.
//!
//! Pinned positive vectors live in `tests/data/von_wrapper_vectors.json`
//! and the regenerator is the `#[ignore]` `emit_vectors` test.

use std::fs;
use std::path::PathBuf;

use dark_von::ecvrf::{Proof, PROOF_LEN};
use dark_von::hash::{h_nonce, H_NONCE_TAG};
use dark_von::wrapper::{nonce, verify, R_DERIVATION_TAG};
use dark_von::VonError;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

const VECTOR_PATH: &str = "tests/data/von_wrapper_vectors.json";

const SK_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Grid of (setup_id, t, b) triples covering small/large t, both b values,
/// and two distinct setup_ids. Twelve vectors total.
const INPUTS: &[(&str, u32, u8)] = &[
    // setup_id (32 B hex), t, b
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        1,
        1,
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        1,
        2,
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        2,
        1,
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        2,
        2,
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        12,
        1,
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        12,
        2,
    ),
    (
        "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef",
        1,
        1,
    ),
    (
        "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef",
        1,
        2,
    ),
    (
        "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef",
        50,
        1,
    ),
    (
        "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef",
        50,
        2,
    ),
    (
        "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef",
        256,
        1,
    ),
    (
        "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef",
        256,
        2,
    ),
];

#[derive(Debug, Serialize, Deserialize)]
struct VectorFile {
    sk: String,
    h_nonce_tag: String,
    r_derivation_tag: String,
    proof_len: usize,
    vectors: Vec<Vector>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Vector {
    index: usize,
    setup_id: String,
    t: u32,
    b: u8,
    h_nonce: String,
    r: String,
    r_point: String,
    proof: String,
}

#[test]
fn vectors_round_trip() {
    let file = load_file();
    let secp = Secp256k1::new();
    let sk_bytes: [u8; 32] = decode_array(&file.sk);
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);

    assert_eq!(file.h_nonce_tag.as_bytes(), H_NONCE_TAG);
    assert_eq!(file.r_derivation_tag.as_bytes(), R_DERIVATION_TAG);
    assert_eq!(file.proof_len, PROOF_LEN);
    assert_eq!(file.vectors.len(), INPUTS.len());

    for (i, (vec, (setup_hex, t, b))) in file.vectors.iter().zip(INPUTS.iter()).enumerate() {
        assert_eq!(vec.index, i);
        let setup: [u8; 32] = decode_array(setup_hex);
        let x = h_nonce(&setup, *t, *b);
        assert_eq!(hex::encode(x), vec.h_nonce, "vector {i}: h_nonce drift");

        let n = nonce(&sk, &x).expect("nonce ok");
        assert_eq!(
            hex::encode(n.r.secret_bytes()),
            vec.r,
            "vector {i}: r drift"
        );
        assert_eq!(
            hex::encode(n.r_point.serialize()),
            vec.r_point,
            "vector {i}: R drift"
        );
        assert_eq!(
            hex::encode(n.proof.to_bytes()),
            vec.proof,
            "vector {i}: proof drift"
        );

        // Case 1: positive round-trip.
        verify(&pk, &x, &n.r_point, &n.proof).expect("vector {i}: verify ok");

        // Case 2: malformed proof (tamper byte in s).
        let mut tampered = n.proof.to_bytes();
        tampered[80] ^= 0x01;
        let pi_bad = Proof::from_slice(&tampered).expect("still parseable");
        assert!(matches!(
            verify(&pk, &x, &n.r_point, &pi_bad),
            Err(VonError::WrongPublicKey)
        ));

        // Case 3: wrong-pk rejection.
        let other_sk = SecretKey::from_slice(&[0xaau8; 32]).unwrap();
        let other_pk = PublicKey::from_secret_key(&secp, &other_sk);
        assert!(matches!(
            verify(&other_pk, &x, &n.r_point, &n.proof),
            Err(VonError::WrongPublicKey)
        ));

        // Case 4: wrong-input rejection (mutate b).
        let x_mut = h_nonce(&setup, *t, b ^ 1);
        assert!(matches!(
            verify(&pk, &x_mut, &n.r_point, &n.proof),
            Err(VonError::WrongPublicKey)
        ));

        // Case 4b: mutated t.
        let x_mut_t = h_nonce(&setup, t.wrapping_add(1), *b);
        assert!(matches!(
            verify(&pk, &x_mut_t, &n.r_point, &n.proof),
            Err(VonError::WrongPublicKey)
        ));

        // Case 4c: mutated setup_id.
        let mut setup_mut = setup;
        setup_mut[0] ^= 0x01;
        let x_mut_setup = h_nonce(&setup_mut, *t, *b);
        assert!(matches!(
            verify(&pk, &x_mut_setup, &n.r_point, &n.proof),
            Err(VonError::WrongPublicKey)
        ));
    }
}

#[test]
fn domain_separation_grid() {
    // Case 5: distinct (t, b) ⇒ distinct R points.
    let sk_bytes: [u8; 32] = decode_array(SK_HEX);
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();
    let setup = [0xa5u8; 32];

    let mut points = Vec::new();
    for t in 1..=8u32 {
        for b in [1u8, 2u8] {
            let x = h_nonce(&setup, t, b);
            let n = nonce(&sk, &x).unwrap();
            points.push(((t, b), n.r_point));
        }
    }

    for i in 0..points.len() {
        for j in (i + 1)..points.len() {
            assert_ne!(
                points[i].1, points[j].1,
                "R collision between {:?} and {:?}",
                points[i].0, points[j].0
            );
        }
    }
}

#[test]
#[ignore = "regenerator; run with `--ignored` to refresh tests/data/von_wrapper_vectors.json"]
fn emit_vectors() {
    let secp = Secp256k1::new();
    let sk_bytes: [u8; 32] = decode_array(SK_HEX);
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();
    let _pk = PublicKey::from_secret_key(&secp, &sk);

    let mut vectors = Vec::with_capacity(INPUTS.len());
    for (i, (setup_hex, t, b)) in INPUTS.iter().enumerate() {
        let setup: [u8; 32] = decode_array(setup_hex);
        let x = h_nonce(&setup, *t, *b);
        let n = nonce(&sk, &x).expect("nonce ok");
        vectors.push(Vector {
            index: i,
            setup_id: (*setup_hex).to_string(),
            t: *t,
            b: *b,
            h_nonce: hex::encode(x),
            r: hex::encode(n.r.secret_bytes()),
            r_point: hex::encode(n.r_point.serialize()),
            proof: hex::encode(n.proof.to_bytes()),
        });
    }

    let file = VectorFile {
        sk: SK_HEX.to_string(),
        h_nonce_tag: String::from_utf8(H_NONCE_TAG.to_vec()).expect("ascii"),
        r_derivation_tag: String::from_utf8(R_DERIVATION_TAG.to_vec()).expect("ascii"),
        proof_len: PROOF_LEN,
        vectors,
    };
    let json = serde_json::to_string_pretty(&file).expect("json");
    let path = vectors_path();
    fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
    fs::write(&path, json).expect("write");
    println!("wrote {} vectors to {}", INPUTS.len(), path.display());
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTOR_PATH)
}

fn load_file() -> VectorFile {
    let path = vectors_path();
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "missing vector file {} ({}). Regenerate with `cargo test -p dark-von \
             --test wrapper_vectors -- emit_vectors --ignored --nocapture`.",
            path.display(),
            err
        )
    });
    serde_json::from_str(&raw).expect("vector JSON parses")
}

fn decode_array(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("valid hex");
    bytes.try_into().expect("32 bytes")
}
