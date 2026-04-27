//! Confidential transaction builder (issue #572).
//!
//! Top-level wallet-side API for assembling a confidential transaction from
//! a set of owned inputs and stealth outputs, returning a fully-formed
//! [`ConfidentialTransaction`] that the operator's validator
//! ([`dark_core::confidential_tx_validation::validate_confidential_transaction`])
//! will accept.
//!
//! # Pipeline
//!
//! Per the issue text:
//!
//! 1. Compute a nullifier for each input via [`compute_nullifier`].
//! 2. Derive a fresh blinding for each output (issue #573 stub —
//!    `derive_output_blinding`).
//! 3. Derive a stealth one-time key per recipient with
//!    [`derive_one_time_output`].
//! 4. Build Pedersen balance commitments and value commitments for each
//!    output, plus a per-output Back-Maxwell range proof.
//! 5. Build the Schnorr balance proof over the excess point.
//! 6. Encrypt each output's memo (currently empty by default) under the
//!    ECDH shared secret per ADR-0003 (#536 stub).
//! 7. Bind the canonical transaction hash and return the assembled struct.
//!
//! # What is *not* in this module
//!
//! - **Wire encoding.** This builder produces the in-memory
//!   [`dark_core::confidential_tx_validation::ConfidentialTransaction`]
//!   the validator consumes; the gRPC handler (#542) is responsible for
//!   converting that to and from the proto type.
//! - **Aggregated range proofs.** v1 ships per-output Back-Maxwell proofs.
//!   Aggregation is a follow-up once #525 / FU-BP land.
//! - **Operator-initiated paths.** The `is_operator_initiated` flag on the
//!   validator's context is a server-side concept; wallets never set it.
//!
//! # Stubbed dependencies
//!
//! - [`OwnedVtxo`] is a local type until #574 lands the canonical wallet
//!   VTXO struct; the field set matches what the issue spec calls out so
//!   the integrator can map 1:1.
//! - `derive_output_blinding` is a deterministic SHA-256-based KDF
//!   marked `TODO(#573)`; the real derivation will share #571's seed
//!   schedule.
//! - `encrypt_memo` is a domain-separated keystream cipher marked
//!   `TODO(#536)`; the real construction in ADR-0003 will be
//!   ChaCha20-Poly1305 with an explicit AEAD tag.

use rand::{CryptoRng, RngCore};
use secp256k1::hashes::{sha256, Hash, HashEngine};
use secp256k1::{PublicKey, Scalar, SecretKey};

use dark_confidential::balance_proof::prove_balance;
use dark_confidential::commitment::PedersenCommitment;
use dark_confidential::nullifier::{compute_nullifier, encode_vtxo_id, NULLIFIER_LEN};
use dark_confidential::range_proof::{prove_range, RangeProof, ValueCommitment};
use dark_confidential::stealth::{derive_one_time_output, MetaAddress, StealthOutput};
use dark_confidential::ConfidentialError;

use crate::error::{ClientError, ClientResult};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version emitted by this builder. Pinned to v1 per ADR-0004 / #537.
pub const SCHEMA_VERSION: u32 = 1;

/// Domain separator for the per-output blinding KDF (#573 stub).
///
/// The real derivation will live in `dark-confidential` and tie into the
/// wallet-seed schedule from #571. This builder hashes
/// `(seed || index)` under the DST as a placeholder so transactions are
/// deterministic across rebuilds within a test.
const BLINDING_KDF_DST: &[u8] = b"dark-client/blinding/v0-stub";

/// Domain separator for the per-output memo encryption keystream (#536
/// stub). ADR-0003 will replace this with ChaCha20-Poly1305 + per-output
/// nonce.
const MEMO_KEY_DST: &[u8] = b"dark-client/memo-key/v0-stub";

/// Domain separator for the canonical transaction-hash transcript bound
/// into the balance proof.
const TX_HASH_DST: &[u8] = b"dark-client/tx-hash/v1";

// ---------------------------------------------------------------------------
// OwnedVtxo (#574 stub)
// ---------------------------------------------------------------------------

/// Wallet-side view of a confidential VTXO that the holder controls.
///
/// This struct is a local stub for the canonical type from issue #574.
/// The field set matches the issue spec so the eventual integrator can
/// translate one-for-one when #574 lands.
#[derive(Debug, Clone)]
pub struct OwnedVtxo {
    /// Canonical 36-byte ID `(txid || vout_be)` per ADR-0002.
    pub vtxo_id: [u8; 36],
    /// Plaintext satoshi amount.
    pub amount: u64,
    /// Blinding factor that produced the on-chain Pedersen commitment.
    pub blinding: Scalar,
    /// One-time spend secret for this VTXO. The same key derives the
    /// nullifier (ADR-0002) and authorises the spend.
    pub one_time_sk: SecretKey,
    /// Owner's scan public key. Used by the round-tree builder for
    /// re-attribution and not by the validator; carried here so the
    /// caller does not have to thread it separately.
    pub scan_pk_for_owner: PublicKey,
}

// ---------------------------------------------------------------------------
// Output type returned to callers
// ---------------------------------------------------------------------------

/// A confidential transaction ready to submit, in the validator's domain
/// shape.
///
/// Re-exported from `dark-core` so callers can use one type whether they
/// are submitting via the gRPC client or unit-testing against the
/// in-process validator.
pub use dark_core::confidential_tx_validation::{ConfidentialOutput, ConfidentialTransaction};

// ---------------------------------------------------------------------------
// Public builder
// ---------------------------------------------------------------------------

/// Wallet seed bytes used to derive deterministic per-output blindings.
///
/// Held by reference at the API boundary so callers can keep the seed in
/// a zeroizing wrapper of their choice.
pub type WalletSeed = [u8; 32];

/// Build a confidential transaction.
///
/// `inputs` must already balance against `outputs + fee`; the builder
/// rejects under-funded sets explicitly with
/// [`ClientError::InsufficientFunds`] so the error is visible to wallet
/// UIs without consulting a balance proof. Over-funded sets — where the
/// surplus would silently inflate the fee — are also rejected:
/// the wallet caller is expected to introduce a change output to the
/// sender's own meta-address. Producing change is a wallet-policy
/// concern and lives outside this builder.
///
/// Ephemeral key randomness for the stealth-output ECDH derivation is
/// taken from `rng`. Production callers must pass a CSPRNG (`OsRng` is
/// canonical); tests pass a seeded `StdRng` for golden vectors.
pub fn create_confidential_tx<R: RngCore + CryptoRng>(
    inputs: &[OwnedVtxo],
    outputs: &[(MetaAddress, u64)],
    fee: u64,
    seed: &WalletSeed,
    rng: &mut R,
) -> ClientResult<ConfidentialTransaction> {
    if inputs.is_empty() {
        return Err(ClientError::Validation(
            "confidential tx requires at least one input".into(),
        ));
    }
    if outputs.is_empty() {
        return Err(ClientError::Validation(
            "confidential tx requires at least one output".into(),
        ));
    }

    let total_in = sum_amounts(inputs.iter().map(|i| i.amount))?;
    let total_out_plus_fee = sum_amounts(outputs.iter().map(|(_, v)| *v))?
        .checked_add(fee)
        .ok_or_else(|| ClientError::Validation("output sum + fee overflowed u64".into()))?;
    if total_in < total_out_plus_fee {
        return Err(ClientError::InsufficientFunds {
            available: total_in,
            required: total_out_plus_fee,
        });
    }
    if total_in > total_out_plus_fee {
        return Err(ClientError::Validation(format!(
            "inputs ({total_in}) exceed outputs+fee ({total_out_plus_fee}); add a change output"
        )));
    }

    let nullifiers = compute_input_nullifiers(inputs);
    let outputs_with_secrets = build_outputs(outputs, seed, rng)?;
    let tx_hash = compute_tx_hash(&nullifiers, &outputs_with_secrets, fee);

    let input_blindings: Vec<Scalar> = inputs.iter().map(|i| i.blinding).collect();
    let output_blindings: Vec<Scalar> = outputs_with_secrets.iter().map(|o| o.blinding).collect();
    let balance_proof = prove_balance(&input_blindings, &output_blindings, fee, &tx_hash)
        .map_err(map_confidential_error)?;

    Ok(ConfidentialTransaction {
        schema_version: SCHEMA_VERSION,
        nullifiers,
        outputs: outputs_with_secrets
            .into_iter()
            .map(BuiltOutput::into_validator_output)
            .collect(),
        balance_proof,
        fee_amount: fee,
        tx_hash,
    })
}

// ---------------------------------------------------------------------------
// Internal pipeline
// ---------------------------------------------------------------------------

/// One output, fully built but still carrying its blinding so the caller
/// can feed it to [`prove_balance`].
struct BuiltOutput {
    blinding: Scalar,
    balance_commitment: PedersenCommitment,
    value_commitment: ValueCommitment,
    range_proof: RangeProof,
    owner_pubkey: [u8; 33],
    ephemeral_pubkey: [u8; 33],
    encrypted_memo: Vec<u8>,
}

impl BuiltOutput {
    fn into_validator_output(self) -> ConfidentialOutput {
        ConfidentialOutput {
            balance_commitment: self.balance_commitment,
            value_commitment: self.value_commitment,
            range_proof: Some(self.range_proof),
            owner_pubkey: self.owner_pubkey,
            ephemeral_pubkey: Some(self.ephemeral_pubkey),
            encrypted_memo: self.encrypted_memo,
        }
    }
}

fn compute_input_nullifiers(inputs: &[OwnedVtxo]) -> Vec<[u8; NULLIFIER_LEN]> {
    inputs
        .iter()
        .map(|i| compute_nullifier(&i.one_time_sk, &i.vtxo_id))
        .collect()
}

fn build_outputs<R: RngCore + CryptoRng>(
    outputs: &[(MetaAddress, u64)],
    seed: &WalletSeed,
    rng: &mut R,
) -> ClientResult<Vec<BuiltOutput>> {
    outputs
        .iter()
        .enumerate()
        .map(|(index, (meta_addr, amount))| build_one_output(index, meta_addr, *amount, seed, rng))
        .collect()
}

fn build_one_output<R: RngCore + CryptoRng>(
    index: usize,
    meta_addr: &MetaAddress,
    amount: u64,
    seed: &WalletSeed,
    rng: &mut R,
) -> ClientResult<BuiltOutput> {
    let blinding = derive_output_blinding(seed, index)?;
    let balance_commitment =
        PedersenCommitment::commit(amount, &blinding).map_err(map_confidential_error)?;
    let (range_proof, value_commitment) =
        prove_range(amount, &blinding).map_err(map_confidential_error)?;

    let stealth = derive_one_time_output(meta_addr, rng).map_err(map_confidential_error)?;
    let StealthOutput {
        ephemeral_pk,
        one_time_pk,
        shared_secret,
    } = stealth;

    let encrypted_memo = encrypt_memo(&shared_secret, &[]);

    Ok(BuiltOutput {
        blinding,
        balance_commitment,
        value_commitment,
        range_proof,
        owner_pubkey: one_time_pk.serialize(),
        ephemeral_pubkey: ephemeral_pk.serialize(),
        encrypted_memo,
    })
}

/// Derive a per-output blinding from the wallet seed and output index.
///
/// **`TODO(#573)`** — placeholder KDF. The real derivation lives in
/// `dark-confidential` once #573 lands; it will share the BIP-32 schedule
/// the wallet uses for spend keys and the per-VTXO scope chosen by ADR-0001.
/// Until then we hash `(seed || u32_be(index))` under a versioned DST so
/// transactions remain deterministic across rebuilds within a test.
fn derive_output_blinding(seed: &WalletSeed, index: usize) -> ClientResult<Scalar> {
    let index_u32: u32 = index
        .try_into()
        .map_err(|_| ClientError::Validation("output index exceeds u32 range".into()))?;
    for counter in 0u8..=u8::MAX {
        let mut engine = sha256::Hash::engine();
        engine.input(BLINDING_KDF_DST);
        engine.input(&[0x00]);
        engine.input(seed);
        engine.input(&index_u32.to_be_bytes());
        engine.input(&[counter]);
        let digest = sha256::Hash::from_engine(engine).to_byte_array();
        if let Ok(scalar) = Scalar::from_be_bytes(digest) {
            // Reject the zero scalar — Pedersen and balance proof both
            // require non-zero blindings — by going around the loop.
            if scalar.to_be_bytes() != [0u8; 32] {
                return Ok(scalar);
            }
        }
    }
    Err(ClientError::Internal(
        "blinding KDF exhausted counter (cryptographically impossible)".into(),
    ))
}

/// Encrypt `plaintext` under a memo key derived from `shared_secret`.
///
/// **`TODO(#536)`** — placeholder. ADR-0003 will replace this with
/// ChaCha20-Poly1305: a versioned per-output nonce, an explicit AEAD tag,
/// and bound additional-data covering the output's commitment. Until that
/// lands the construction is a domain-separated SHA-256 keystream XOR'd
/// over the plaintext — the validator only checks the ciphertext length,
/// and golden-vector test parity comes from #555 on the recipient side.
fn encrypt_memo(shared_secret: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    if plaintext.is_empty() {
        return Vec::new();
    }
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut counter: u32 = 0;
    let mut offset = 0;
    while offset < plaintext.len() {
        let mut engine = sha256::Hash::engine();
        engine.input(MEMO_KEY_DST);
        engine.input(&[0x00]);
        engine.input(shared_secret);
        engine.input(&counter.to_be_bytes());
        let block = sha256::Hash::from_engine(engine).to_byte_array();
        for byte in block.iter() {
            if offset >= plaintext.len() {
                break;
            }
            ciphertext.push(plaintext[offset] ^ byte);
            offset += 1;
        }
        counter = counter.wrapping_add(1);
    }
    ciphertext
}

/// Compute the canonical transaction-hash transcript that the balance
/// proof binds to.
///
/// The hash mixes every nullifier, every output's owner pubkey,
/// ephemeral pubkey, value-commitment serialisation, and the fee. Any
/// post-hoc tamper of these fields flips the hash, which flips the
/// balance-proof challenge, which makes the proof reject. Output range
/// proofs are not hashed — they are bound to the value commitments
/// directly via the homomorphic identity.
fn compute_tx_hash(
    nullifiers: &[[u8; NULLIFIER_LEN]],
    outputs: &[BuiltOutput],
    fee: u64,
) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(TX_HASH_DST);
    engine.input(&[0x00]);
    engine.input(&(nullifiers.len() as u32).to_be_bytes());
    for nullifier in nullifiers {
        engine.input(nullifier);
    }
    engine.input(&(outputs.len() as u32).to_be_bytes());
    for output in outputs {
        engine.input(&output.owner_pubkey);
        engine.input(&output.ephemeral_pubkey);
        engine.input(&output.balance_commitment.to_bytes());
        engine.input(&output.value_commitment.to_bytes());
    }
    engine.input(&fee.to_be_bytes());
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn sum_amounts<I: IntoIterator<Item = u64>>(amounts: I) -> ClientResult<u64> {
    let mut sum: u64 = 0;
    for amount in amounts {
        sum = sum
            .checked_add(amount)
            .ok_or_else(|| ClientError::Validation("amount sum overflowed u64".into()))?;
    }
    Ok(sum)
}

fn map_confidential_error(err: ConfidentialError) -> ClientError {
    ClientError::Internal(format!("dark-confidential primitive failed: {err}"))
}

// ---------------------------------------------------------------------------
// Helpers reused by tests / external callers building OwnedVtxo
// ---------------------------------------------------------------------------

/// Build the canonical 36-byte `vtxo_id` from `(txid, vout)` per ADR-0002.
///
/// Re-exported so callers do not have to depend on `dark_confidential`
/// for the layout. Identical bytes to
/// [`dark_confidential::nullifier::encode_vtxo_id`].
pub fn build_vtxo_id(txid: &[u8; 32], vout: u32) -> [u8; 36] {
    encode_vtxo_id(txid, vout)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{HashMap, HashSet};

    use async_trait::async_trait;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secp256k1::{Secp256k1, SecretKey};
    use tokio::sync::Mutex;

    use dark_confidential::stealth::StealthNetwork;
    use dark_core::confidential_tx_validation::{
        validate_confidential_transaction, FeeMinimumProvider, InputVtxoResolver,
        ValidationContext, ValidationError,
    };
    use dark_core::error::{ArkError, ArkResult};
    use dark_core::ports::NullifierSink;

    // ---- Test fixtures ----------------------------------------------------

    /// In-memory nullifier sink that records inserts.
    #[derive(Default)]
    struct MockSink {
        seen: Mutex<HashSet<[u8; 32]>>,
    }

    #[async_trait]
    impl NullifierSink for MockSink {
        async fn batch_insert(
            &self,
            nullifiers: &[[u8; 32]],
            _round_id: Option<&str>,
        ) -> ArkResult<Vec<bool>> {
            let mut guard = self.seen.lock().await;
            Ok(nullifiers.iter().map(|n| guard.insert(*n)).collect())
        }

        async fn contains(&self, nullifier: &[u8; 32]) -> bool {
            self.seen.lock().await.contains(nullifier)
        }
    }

    /// Resolver that maps each input nullifier to the input's
    /// balance-side commitment, computed from the corresponding
    /// [`OwnedVtxo`].
    struct OwnedInputResolver {
        map: HashMap<[u8; 32], PedersenCommitment>,
    }

    impl OwnedInputResolver {
        fn for_inputs(inputs: &[OwnedVtxo]) -> ArkResult<Self> {
            let mut map = HashMap::with_capacity(inputs.len());
            for input in inputs {
                let nullifier = compute_nullifier(&input.one_time_sk, &input.vtxo_id);
                let commitment = PedersenCommitment::commit(input.amount, &input.blinding)
                    .map_err(|e| ArkError::Internal(format!("commit failed: {e}")))?;
                map.insert(nullifier, commitment);
            }
            Ok(Self { map })
        }
    }

    #[async_trait]
    impl InputVtxoResolver for OwnedInputResolver {
        async fn resolve(&self, n: &[u8; 32]) -> Option<PedersenCommitment> {
            self.map.get(n).cloned()
        }
    }

    /// Fee provider with a fixed minimum and `u64::MAX` cap.
    struct StaticFeeProvider {
        min: u64,
    }

    #[async_trait]
    impl FeeMinimumProvider for StaticFeeProvider {
        async fn minimum_fee(&self, _num_inputs: usize, _num_outputs: usize) -> u64 {
            self.min
        }
        async fn fee_cap(&self) -> u64 {
            u64::MAX
        }
    }

    /// Build an OwnedVtxo deterministically from a seed byte. The
    /// blinding mirrors what the wallet would compute for an *input*
    /// (i.e. an incoming-VTXO blinding chosen at creation time, not the
    /// builder-derived output blinding).
    fn owned_vtxo(seed: u8, amount: u64, blinding_seed: u64) -> OwnedVtxo {
        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = seed;
        if sk_bytes == [0u8; 32] {
            sk_bytes[31] = 1;
        }
        let one_time_sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let scan_sk = {
            let mut bytes = [0u8; 32];
            bytes[30] = seed;
            bytes[31] = 0xa5;
            SecretKey::from_slice(&bytes).unwrap()
        };
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);

        let mut txid = [0u8; 32];
        txid[0] = seed;
        let vtxo_id = build_vtxo_id(&txid, seed as u32);

        OwnedVtxo {
            vtxo_id,
            amount,
            blinding: scalar_from_u64(blinding_seed),
            one_time_sk,
            scan_pk_for_owner: scan_pk,
        }
    }

    fn scalar_from_u64(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_be_bytes(bytes).unwrap()
    }

    fn meta_address(scan_seed: u8, spend_seed: u8) -> MetaAddress {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[scan_seed; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[spend_seed; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
        MetaAddress::new(StealthNetwork::Regtest, scan_pk, spend_pk)
    }

    fn validation_ctx<'a>(
        sink: &'a MockSink,
        resolver: &'a OwnedInputResolver,
        fee_provider: &'a StaticFeeProvider,
    ) -> ValidationContext<'a> {
        ValidationContext {
            nullifier_sink: sink,
            input_resolver: resolver,
            fee_provider,
            aggregated_range_proof: None,
            is_operator_initiated: false,
            round_id: Some("test-round"),
        }
    }

    // ---- Round-trip with the real validator -------------------------------

    #[tokio::test]
    async fn round_trip_through_validator() {
        // Inputs: 100 + 50 = 150. Outputs: 90 + 50 = 140. Fee: 10.
        let inputs = vec![
            owned_vtxo(0x11, 100, 0xaaaa_1111),
            owned_vtxo(0x22, 50, 0xbbbb_2222),
        ];
        let outputs = vec![
            (meta_address(0x33, 0x44), 90u64),
            (meta_address(0x55, 0x66), 50u64),
        ];
        let fee = 10u64;
        let seed = [0x77u8; 32];
        let mut rng = StdRng::seed_from_u64(0xc0ffee);

        let tx = create_confidential_tx(&inputs, &outputs, fee, &seed, &mut rng)
            .expect("builder must produce a valid tx");
        assert_eq!(tx.fee_amount, fee);
        assert_eq!(tx.nullifiers.len(), inputs.len());
        assert_eq!(tx.outputs.len(), outputs.len());

        let sink = MockSink::default();
        let resolver = OwnedInputResolver::for_inputs(&inputs).unwrap();
        let fee_provider = StaticFeeProvider { min: 0 };
        let ctx = validation_ctx(&sink, &resolver, &fee_provider);

        let validated = validate_confidential_transaction(&tx, &ctx)
            .await
            .expect("validator must accept builder output");
        assert_eq!(validated.fee_amount, fee);
        assert_eq!(validated.spent_nullifiers.len(), inputs.len());
        assert_eq!(validated.outputs.len(), outputs.len());
    }

    // ---- Tampering: bumping an output amount must trip validation ---------

    #[tokio::test]
    async fn tampered_output_amount_rejected() {
        let inputs = vec![
            owned_vtxo(0x12, 100, 0xaaaa_3333),
            owned_vtxo(0x34, 50, 0xbbbb_4444),
        ];
        let outputs = vec![
            (meta_address(0x56, 0x78), 90u64),
            (meta_address(0x9a, 0xbc), 50u64),
        ];
        let fee = 10u64;
        let seed = [0x88u8; 32];
        let mut rng = StdRng::seed_from_u64(0xfeed_face);

        let mut tx = create_confidential_tx(&inputs, &outputs, fee, &seed, &mut rng).unwrap();

        // Tamper: rebuild output[0]'s commitment under a different
        // (amount, blinding) pair so the homomorphic identity no longer
        // holds. A fresh range proof bound to the new commitment keeps
        // step 2 of the validator passing — the failure must surface
        // from the balance-proof verifier (step 3).
        let bad_amount = 91u64;
        let bad_blinding = scalar_from_u64(0xdead_beef);
        let bad_balance = PedersenCommitment::commit(bad_amount, &bad_blinding).unwrap();
        let (bad_range_proof, bad_value_commitment) =
            prove_range(bad_amount, &bad_blinding).unwrap();
        tx.outputs[0].balance_commitment = bad_balance;
        tx.outputs[0].value_commitment = bad_value_commitment;
        tx.outputs[0].range_proof = Some(bad_range_proof);

        let sink = MockSink::default();
        let resolver = OwnedInputResolver::for_inputs(&inputs).unwrap();
        let fee_provider = StaticFeeProvider { min: 0 };
        let ctx = validation_ctx(&sink, &resolver, &fee_provider);

        let err = validate_confidential_transaction(&tx, &ctx)
            .await
            .expect_err("validator must reject tampered output");
        assert!(matches!(err, ValidationError::InvalidBalanceProof));
    }

    // ---- Insufficient inputs surface as a typed wallet error --------------

    #[test]
    fn insufficient_inputs_returns_typed_error() {
        let inputs = vec![owned_vtxo(0x01, 50, 0xaaaa_5555)];
        let outputs = vec![(meta_address(0x02, 0x03), 100u64)];
        let fee = 10u64;
        let seed = [0x99u8; 32];
        let mut rng = StdRng::seed_from_u64(0x1234);

        let err = create_confidential_tx(&inputs, &outputs, fee, &seed, &mut rng).unwrap_err();
        match err {
            ClientError::InsufficientFunds {
                available,
                required,
            } => {
                assert_eq!(available, 50);
                assert_eq!(required, 110);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    // ---- Over-funded inputs reject so wallets explicitly add change -------

    #[test]
    fn unbalanced_inputs_demand_change_output() {
        let inputs = vec![
            owned_vtxo(0x21, 100, 0xaaaa_7777),
            owned_vtxo(0x22, 50, 0xbbbb_8888),
        ];
        // Inputs total 150, outputs+fee total 100. The remaining 50 sats
        // would silently inflate the fee unless the wallet adds change.
        let outputs = vec![(meta_address(0x23, 0x24), 90u64)];
        let fee = 10u64;
        let seed = [0xaau8; 32];
        let mut rng = StdRng::seed_from_u64(0x5678);

        let err = create_confidential_tx(&inputs, &outputs, fee, &seed, &mut rng).unwrap_err();
        match err {
            ClientError::Validation(msg) => assert!(msg.contains("change")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // ---- No inputs / no outputs rejected upfront --------------------------

    #[test]
    fn empty_inputs_rejected() {
        let outputs = vec![(meta_address(0x31, 0x32), 10u64)];
        let mut rng = StdRng::seed_from_u64(0);
        let err = create_confidential_tx(&[], &outputs, 0, &[0u8; 32], &mut rng).unwrap_err();
        assert!(matches!(err, ClientError::Validation(_)));
    }

    #[test]
    fn empty_outputs_rejected() {
        let inputs = vec![owned_vtxo(0x41, 100, 0xaaaa_9999)];
        let mut rng = StdRng::seed_from_u64(0);
        let err = create_confidential_tx(&inputs, &[], 100, &[0u8; 32], &mut rng).unwrap_err();
        assert!(matches!(err, ClientError::Validation(_)));
    }

    // ---- Determinism (same seed + RNG) ------------------------------------

    #[test]
    fn deterministic_when_rng_seed_matches() {
        let inputs = vec![
            owned_vtxo(0x51, 100, 0xaaaa_aaaa),
            owned_vtxo(0x52, 50, 0xbbbb_bbbb),
        ];
        let outputs = vec![
            (meta_address(0x61, 0x62), 90u64),
            (meta_address(0x63, 0x64), 50u64),
        ];
        let fee = 10u64;
        let seed = [0xcdu8; 32];

        let mut rng_a = StdRng::seed_from_u64(0xabcd);
        let mut rng_b = StdRng::seed_from_u64(0xabcd);
        let tx_a = create_confidential_tx(&inputs, &outputs, fee, &seed, &mut rng_a).unwrap();
        let tx_b = create_confidential_tx(&inputs, &outputs, fee, &seed, &mut rng_b).unwrap();

        // Same seed, same wallet seed, same inputs/outputs ⇒ identical
        // tx_hash. (Range-proof bytes are also deterministic given the
        // RNG seed, because `OsRng` is the only non-determinism in the
        // primitive layer and we override it here.)
        assert_eq!(tx_a.tx_hash, tx_b.tx_hash);
        assert_eq!(tx_a.nullifiers, tx_b.nullifiers);
    }

    // ---- Memo encryption stub: empty-in => empty-out ----------------------

    #[test]
    fn empty_memo_stays_empty() {
        let key = [0xabu8; 32];
        assert_eq!(encrypt_memo(&key, &[]), Vec::<u8>::new());
    }

    #[test]
    fn memo_keystream_is_invertible() {
        // The placeholder keystream cipher is its own inverse: applying
        // it twice reproduces the plaintext. Pin this here so callers
        // aren't surprised by the ADR-0003 swap-in.
        let key = [0x33u8; 32];
        let plaintext = b"hello, dark";
        let ciphertext = encrypt_memo(&key, plaintext);
        assert_ne!(ciphertext, plaintext);
        let recovered = encrypt_memo(&key, &ciphertext);
        assert_eq!(recovered, plaintext);
    }

    // ---- Sanity: nullifier set is the issue's spec --------------------------

    #[test]
    fn nullifiers_match_adr_0002_per_input() {
        let inputs = vec![
            owned_vtxo(0x71, 100, 0xaaaa_eeee),
            owned_vtxo(0x72, 50, 0xbbbb_ffff),
        ];
        let outputs = vec![(meta_address(0x81, 0x82), 140u64)];
        let mut rng = StdRng::seed_from_u64(0xdead);
        let tx = create_confidential_tx(&inputs, &outputs, 10, &[0u8; 32], &mut rng).unwrap();

        for (input, nullifier) in inputs.iter().zip(tx.nullifiers.iter()) {
            assert_eq!(
                *nullifier,
                compute_nullifier(&input.one_time_sk, &input.vtxo_id)
            );
        }
    }
}
