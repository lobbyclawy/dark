//! Byte-exact vector generator for ADR-0003 (confidential VTXO memo format v1).
//!
//! Run with `cargo run --release` from this crate's directory; pipe stdout to
//! `docs/adr/vectors/0003-memo-vectors.json`.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use serde_json::{json, Value};
use sha2::Sha256;

const VERSION_V1: u8 = 0x01;
const KDF_INFO: &[u8] = b"dark-confidential/memo/v1";

const PLAINTEXT_LEN: usize = 72;
const AAD_LEN: usize = 67;
const WIRE_LEN: usize = 134;

#[derive(Clone)]
struct Plaintext {
    amount: u64,
    blinding: [u8; 32],
    one_time_spend_tag: [u8; 32],
}

impl Plaintext {
    fn encode(&self) -> [u8; PLAINTEXT_LEN] {
        let mut buf = [0u8; PLAINTEXT_LEN];
        buf[..8].copy_from_slice(&self.amount.to_le_bytes());
        buf[8..40].copy_from_slice(&self.blinding);
        buf[40..72].copy_from_slice(&self.one_time_spend_tag);
        buf
    }

    fn decode(buf: &[u8]) -> Self {
        assert_eq!(buf.len(), PLAINTEXT_LEN);
        let amount = u64::from_le_bytes(buf[..8].try_into().unwrap());
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&buf[8..40]);
        let mut one_time_spend_tag = [0u8; 32];
        one_time_spend_tag.copy_from_slice(&buf[40..72]);
        Self {
            amount,
            blinding,
            one_time_spend_tag,
        }
    }
}

fn ecdh(secp: &Secp256k1<secp256k1::All>, sk: &SecretKey, pk: &PublicKey) -> [u8; 33] {
    let scalar = Scalar::from_be_bytes(sk.secret_bytes()).expect("non-zero scalar");
    pk.mul_tweak(secp, &scalar).expect("ecdh").serialize()
}

fn hkdf_44(salt: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 44];
    hk.expand(KDF_INFO, &mut okm).unwrap();
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    (key, nonce)
}

fn aad_for(version: u8, ephemeral_pk: &[u8; 33], one_time_pk: &[u8; 33]) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[0] = version;
    aad[1..34].copy_from_slice(ephemeral_pk);
    aad[34..67].copy_from_slice(one_time_pk);
    aad
}

fn encrypt(
    ephemeral_sk: &SecretKey,
    scan_pk: &PublicKey,
    one_time_pk: &[u8; 33],
    plaintext: &Plaintext,
) -> Vec<u8> {
    let secp = Secp256k1::new();
    let ephemeral_pk = PublicKey::from_secret_key(&secp, ephemeral_sk).serialize();
    let shared_bytes = ecdh(&secp, ephemeral_sk, scan_pk);
    let (key, nonce) = hkdf_44(&ephemeral_pk, &shared_bytes);
    let aad = aad_for(VERSION_V1, &ephemeral_pk, one_time_pk);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext.encode(),
                aad: &aad,
            },
        )
        .expect("encrypt");
    let mut wire = Vec::with_capacity(WIRE_LEN);
    wire.push(VERSION_V1);
    wire.extend_from_slice(&ephemeral_pk);
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ct);
    assert_eq!(wire.len(), WIRE_LEN);
    wire
}

fn decrypt(
    wire: &[u8],
    scan_sk: &SecretKey,
    one_time_pk: &[u8; 33],
) -> Result<Plaintext, &'static str> {
    if wire.len() != WIRE_LEN {
        return Err("wrong wire length");
    }
    let version = wire[0];
    if version != VERSION_V1 {
        return Err("unknown version");
    }
    let mut ephemeral_pk_bytes = [0u8; 33];
    ephemeral_pk_bytes.copy_from_slice(&wire[1..34]);
    let mut wire_nonce = [0u8; 12];
    wire_nonce.copy_from_slice(&wire[34..46]);
    let ct = &wire[46..];

    let secp = Secp256k1::new();
    let ephemeral_pk = PublicKey::from_slice(&ephemeral_pk_bytes).map_err(|_| "bad eph pk")?;
    let shared_bytes = ecdh(&secp, scan_sk, &ephemeral_pk);
    let (key, _derived_nonce) = hkdf_44(&ephemeral_pk_bytes, &shared_bytes);
    let aad = aad_for(version, &ephemeral_pk_bytes, one_time_pk);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let pt_bytes = cipher
        .decrypt(
            Nonce::from_slice(&wire_nonce),
            Payload { msg: ct, aad: &aad },
        )
        .map_err(|_| "aead tag")?;
    Ok(Plaintext::decode(&pt_bytes))
}

fn sk_from_hex(s: &str) -> SecretKey {
    SecretKey::from_slice(&hex::decode(s).unwrap()).unwrap()
}

fn pk_from_sk_hex(secp: &Secp256k1<secp256k1::All>, s: &str) -> [u8; 33] {
    PublicKey::from_secret_key(secp, &sk_from_hex(s)).serialize()
}

fn fixed32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn fixed32_hex(byte: u8) -> String {
    hex::encode(fixed32(byte))
}

struct VectorInput {
    name: &'static str,
    description: &'static str,
    ephemeral_sk_hex: &'static str,
    scan_sk_hex: &'static str,
    one_time_sk_hex: &'static str,
    amount: u64,
    blinding: [u8; 32],
    one_time_spend_tag: [u8; 32],
}

fn build_vector(input: &VectorInput) -> Value {
    let secp = Secp256k1::new();
    let ephemeral_sk = sk_from_hex(input.ephemeral_sk_hex);
    let scan_sk = sk_from_hex(input.scan_sk_hex);

    let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
    let scan_pk_bytes = scan_pk.serialize();
    let ephemeral_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk).serialize();
    let one_time_pk = pk_from_sk_hex(&secp, input.one_time_sk_hex);

    let plaintext = Plaintext {
        amount: input.amount,
        blinding: input.blinding,
        one_time_spend_tag: input.one_time_spend_tag,
    };
    let pt_bytes = plaintext.encode();

    let shared_bytes = ecdh(&secp, &ephemeral_sk, &scan_pk);
    let (key, nonce) = hkdf_44(&ephemeral_pk, &shared_bytes);
    let aad = aad_for(VERSION_V1, &ephemeral_pk, &one_time_pk);
    let wire = encrypt(&ephemeral_sk, &scan_pk, &one_time_pk, &plaintext);

    let pt_back = decrypt(&wire, &scan_sk, &one_time_pk).expect("round-trip");
    assert_eq!(pt_back.amount, plaintext.amount);
    assert_eq!(pt_back.blinding, plaintext.blinding);
    assert_eq!(pt_back.one_time_spend_tag, plaintext.one_time_spend_tag);

    let mut hkdf_output = Vec::with_capacity(44);
    hkdf_output.extend_from_slice(&key);
    hkdf_output.extend_from_slice(&nonce);

    json!({
        "name": input.name,
        "description": input.description,
        "input": {
            "ephemeral_sk_hex": input.ephemeral_sk_hex,
            "scan_sk_hex": input.scan_sk_hex,
            "one_time_sk_hex": input.one_time_sk_hex,
            "scan_pk_hex": hex::encode(scan_pk_bytes),
            "one_time_pk_hex": hex::encode(one_time_pk),
            "version_byte_hex": format!("{:02x}", VERSION_V1),
            "plaintext": {
                "amount": input.amount,
                "amount_le_hex": hex::encode(input.amount.to_le_bytes()),
                "blinding_hex": hex::encode(input.blinding),
                "one_time_spend_tag_hex": hex::encode(input.one_time_spend_tag),
                "encoded_72_hex": hex::encode(pt_bytes),
            }
        },
        "intermediate": {
            "ephemeral_pk_hex": hex::encode(ephemeral_pk),
            "ecdh_shared_point_compressed_hex": hex::encode(shared_bytes),
            "hkdf_salt_hex": hex::encode(ephemeral_pk),
            "hkdf_ikm_hex": hex::encode(shared_bytes),
            "hkdf_info_ascii": std::str::from_utf8(KDF_INFO).unwrap(),
            "hkdf_output_44_hex": hex::encode(&hkdf_output),
            "aead_key_hex": hex::encode(key),
            "aead_nonce_hex": hex::encode(nonce),
            "aad_hex": hex::encode(aad),
        },
        "output": {
            "memo_wire_hex": hex::encode(&wire),
            "memo_wire_len_bytes": wire.len(),
        }
    })
}

fn negative_scenarios(positive_a: &Value) -> Value {
    let wire_hex = positive_a["output"]["memo_wire_hex"].as_str().unwrap();
    let scan_sk = sk_from_hex(positive_a["input"]["scan_sk_hex"].as_str().unwrap());
    let one_time_pk_hex = positive_a["input"]["one_time_pk_hex"].as_str().unwrap();
    let one_time_pk = {
        let v = hex::decode(one_time_pk_hex).unwrap();
        let mut a = [0u8; 33];
        a.copy_from_slice(&v);
        a
    };

    let wrong_scan_sk_hex = "0000000000000000000000000000000000000000000000000000000000000099";
    let wrong_sk = sk_from_hex(wrong_scan_sk_hex);
    let d = decrypt(&hex::decode(wire_hex).unwrap(), &wrong_sk, &one_time_pk);

    let mut flipped_otpk = one_time_pk;
    flipped_otpk[1] ^= 0x01;
    let e = decrypt(&hex::decode(wire_hex).unwrap(), &scan_sk, &flipped_otpk);

    let mut version_mut = hex::decode(wire_hex).unwrap();
    version_mut[0] = 0x02;
    let f = decrypt(&version_mut, &scan_sk, &one_time_pk);

    let mut tag_flip = hex::decode(wire_hex).unwrap();
    let last = tag_flip.len() - 1;
    tag_flip[last] ^= 0x01;
    let g = decrypt(&tag_flip, &scan_sk, &one_time_pk);

    json!({
        "D_wrong_recipient_scan_sk": {
            "description": "Decrypt vector A's memo with a different scan_sk → AEAD tag verification fails (recipient cannot derive the AEAD key).",
            "wrong_scan_sk_hex": wrong_scan_sk_hex,
            "expected_error": format!("{:?}", d.err().unwrap()),
        },
        "E_aad_one_time_pk_flipped": {
            "description": "Recipient runs decrypt with a one_time_pk where byte 1 (first byte of the x-coordinate) is XOR'd with 0x01 → AAD differs, AEAD tag verification fails. Demonstrates that an operator cannot graft a valid memo onto a different VTXO.",
            "expected_error": format!("{:?}", e.err().unwrap()),
        },
        "F_version_byte_mutated": {
            "description": "Wire mutated to version=0x02; parser rejects on unknown version. Even if parsing accepted v2, AAD includes the version byte so AEAD tag verification would also fail.",
            "expected_error": format!("{:?}", f.err().unwrap()),
        },
        "G_aead_tag_flipped": {
            "description": "Last byte of the wire (inside Poly1305 tag) flipped → AEAD tag verification fails.",
            "expected_error": format!("{:?}", g.err().unwrap()),
        }
    })
}

fn main() {
    let inputs: [VectorInput; 3] = [
        VectorInput {
            name: "A_basic",
            description: "Canonical happy-path vector: small amount, distinct fixed-byte fillers for blinding and spend tag.",
            ephemeral_sk_hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            scan_sk_hex:      "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
            one_time_sk_hex:  "2020202020202020202020202020202020202020202020202020202020202020",
            amount: 21_000_000,
            blinding: fixed32(0x11),
            one_time_spend_tag: fixed32(0x22),
        },
        VectorInput {
            name: "B_zero_amount",
            description: "Corner case: amount = 0 with all-zero blinding. Tests that a zero plaintext encrypts and round-trips correctly.",
            ephemeral_sk_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            scan_sk_hex:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            one_time_sk_hex:  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            amount: 0,
            blinding: fixed32(0x00),
            one_time_spend_tag: fixed32(0x33),
        },
        VectorInput {
            name: "C_max_amount",
            description: "Corner case: amount = u64::MAX with all-0xff blinding. Exercises the upper bound of the amount field.",
            ephemeral_sk_hex: "0000000000000000000000000000000000000000000000000000000000000001",
            scan_sk_hex:      "0000000000000000000000000000000000000000000000000000000000000002",
            one_time_sk_hex:  "0000000000000000000000000000000000000000000000000000000000000003",
            amount: u64::MAX,
            blinding: fixed32(0xff),
            one_time_spend_tag: fixed32(0x44),
        },
    ];

    let vectors: Vec<Value> = inputs.iter().map(build_vector).collect();
    let neg = negative_scenarios(&vectors[0]);

    let out = json!({
        "schema_version": 1,
        "spec": "ADR-0003 confidential VTXO memo format v1",
        "constants": {
            "version_byte_v1_hex": format!("{:02x}", VERSION_V1),
            "kdf_info_ascii": std::str::from_utf8(KDF_INFO).unwrap(),
            "kdf_info_hex": hex::encode(KDF_INFO),
        },
        "wire_layout_bytes": {
            "version_byte": 1,
            "ephemeral_pk_compressed": 33,
            "nonce": 12,
            "ciphertext_with_poly1305_tag": 88,
            "total": WIRE_LEN,
        },
        "plaintext_layout_bytes": {
            "amount_u64_le": 8,
            "blinding": 32,
            "one_time_spend_tag": 32,
            "total": PLAINTEXT_LEN,
        },
        "aad_layout_bytes": {
            "version_byte": 1,
            "ephemeral_pk_compressed": 33,
            "one_time_pk_compressed": 33,
            "total": AAD_LEN,
        },
        "kdf": {
            "function": "HKDF-SHA256",
            "salt": "ephemeral_pk (33 bytes, compressed secp256k1 point)",
            "ikm":  "ECDH shared point (33 bytes, compressed secp256k1 point)",
            "info": "dark-confidential/memo/v1",
            "output_layout": "32-byte aead_key || 12-byte nonce",
        },
        "aead": {
            "function": "ChaCha20-Poly1305 (RFC 8439)",
            "key_bytes": 32,
            "nonce_bytes": 12,
            "tag_bytes": 16,
        },
        "vectors": vectors,
        "negative_scenarios_built_from_vector_A": neg,
        "_constants_for_cross_check": {
            "fixed32_0x11_hex": fixed32_hex(0x11),
            "fixed32_0xff_hex": fixed32_hex(0xff),
        }
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
