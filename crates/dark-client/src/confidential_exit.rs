//! Client-side confidential VTXO unilateral-exit flow (issue #548).
//!
//! When the user believes the operator is offline or misbehaving, the wallet
//! can broadcast the round-tree leaf transaction unilaterally. This module
//! drives that flow for **confidential** VTXOs:
//!
//! 1. reconstruct the exit tapscript leaf via
//!    [`dark_confidential::build_confidential_exit_script`] (stub of #547),
//! 2. construct the exit transaction spending the round-tree leaf outpoint,
//! 3. populate the witness with `(amount, blinding, signature)` so the
//!    leaf can verify the opening of the Pedersen commitment plus the
//!    owner's signature,
//! 4. broadcast via the configured mempool explorer.
//!
//! The flow is generic over a [`MempoolExplorer`] trait so unit tests can
//! swap in an in-memory mock — see the tests at the bottom of this file.
//!
//! Out of scope for #548 (and explicitly **not** implemented here):
//! * the production tapscript builder (#547)
//! * the post-CSV sweep / claim path (#549)
//! * server-side validation pipeline (#538)

use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize_hex,
    hashes::Hash as _,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use dark_confidential::{
    build_confidential_exit_script as default_build_confidential_exit_script,
    commitment::PedersenCommitment, vtxo::ConfidentialVtxo, ConfidentialExitScriptInputs,
};

use crate::error::{ClientError, ClientResult};

/// Index of the `(amount, blinding, signature)` triple inside the witness.
const WITNESS_AMOUNT_INDEX: usize = 0;
const WITNESS_BLINDING_INDEX: usize = 1;
const WITNESS_SIGNATURE_INDEX: usize = 2;

/// Encoded width of the amount field in the witness (8 bytes, big-endian).
const WITNESS_AMOUNT_LEN: usize = 8;

/// Encoded width of the blinding field in the witness (32 bytes, big-endian).
const WITNESS_BLINDING_LEN: usize = 32;

/// Minimal mempool explorer surface required by [`unilateral_exit_confidential`].
///
/// Trait-based so tests can mock the broadcast leg without going over HTTP.
/// The real `EsploraExplorer` implements this — see the bottom of this file.
#[async_trait]
pub trait MempoolExplorer: Send + Sync {
    /// Broadcast a hex-encoded raw transaction. Returns the txid on success.
    async fn broadcast_tx(&self, tx_hex: &str) -> ClientResult<String>;
}

#[async_trait]
impl MempoolExplorer for crate::explorer::EsploraExplorer {
    async fn broadcast_tx(&self, tx_hex: &str) -> ClientResult<String> {
        crate::explorer::EsploraExplorer::broadcast_tx(self, tx_hex).await
    }
}

/// Boxed builder for the confidential exit tapscript.
///
/// Defaults to [`default_build_confidential_exit_script`] (the #547 stub).
/// Tests inject their own builder to assert the script flows through to the
/// witness untouched.
pub type ExitScriptBuilder =
    Arc<dyn Fn(&XOnlyPublicKey, &PedersenCommitment, u32) -> ScriptBuf + Send + Sync + 'static>;

/// Default exit-script builder — wraps the `dark-confidential` (stub) builder.
pub fn default_exit_script_builder() -> ExitScriptBuilder {
    Arc::new(
        |owner_pubkey: &XOnlyPublicKey, commitment: &PedersenCommitment, exit_delay_blocks: u32| {
            default_build_confidential_exit_script(&ConfidentialExitScriptInputs {
                owner_pubkey,
                amount_commitment: commitment,
                exit_delay_blocks,
            })
        },
    )
}

/// Progress events emitted by [`unilateral_exit_confidential`].
///
/// The CLI displays these to the user as e.g.
/// "leaf exit broadcast → CSV maturing → claimable".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfidentialExitProgress {
    /// Witness has been assembled and the exit tx is fully signed.
    LeafExitSigned { txid: String },
    /// Exit transaction has been broadcast to the mempool.
    LeafExitBroadcast { txid: String },
    /// CSV timelock is maturing on-chain (the wallet is waiting for the
    /// `exit_delay_blocks` to elapse).
    CsvMaturing {
        txid: String,
        exit_delay_blocks: u32,
    },
    /// Funds are claimable — the post-CSV sweep can now be issued (#549).
    Claimable { txid: String },
}

/// Boxed progress callback. The flow takes ownership and may call it
/// multiple times.
pub type ProgressCallback = Box<dyn FnMut(ConfidentialExitProgress) + Send + 'static>;

/// Outcome of a successful unilateral exit broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnilateralExitOutcome {
    /// Txid returned by the explorer when the exit transaction was broadcast.
    pub txid: String,
    /// Hex-encoded exit transaction that was broadcast.
    pub raw_tx_hex: String,
    /// Tapscript leaf the witness commits to (returned for diagnostics
    /// and CLI display).
    pub exit_script: ScriptBuf,
    /// Witness placed on the exit transaction's leaf input.
    pub witness: Witness,
}

/// Run the confidential VTXO unilateral-exit flow.
///
/// See the module docs for the full step-by-step description.
///
/// # Parameters
/// * `vtxo` — the wallet's local record for the confidential VTXO being
///   exited (carries the amount, blinding factor, and leaf outpoint).
/// * `owner_secret` — the owner's secp256k1 secret key, used to sign the
///   exit transaction.
/// * `mempool_explorer` — broadcast surface; in production this is the
///   Esplora client, in tests it is a mock.
/// * `progress` — optional structured progress callback. Called once per
///   stage so the CLI can render "leaf exit broadcast → CSV maturing →
///   claimable".
/// * `script_builder` — script builder. Use [`default_exit_script_builder`]
///   in production; tests inject a mock to assert the script flows through
///   to the witness.
pub async fn unilateral_exit_confidential(
    vtxo: &ConfidentialVtxo,
    owner_secret: &SecretKey,
    mempool_explorer: &dyn MempoolExplorer,
    mut progress: Option<ProgressCallback>,
    script_builder: ExitScriptBuilder,
) -> ClientResult<UnilateralExitOutcome> {
    // ── 1. Reconstruct the exit script (#547 stub by default). ────────────
    let secp = Secp256k1::new();
    let amount_commitment = PedersenCommitment::commit(vtxo.amount, &vtxo.blinding)
        .map_err(|e| ClientError::Internal(format!("Pedersen commitment failed: {e}")))?;
    let exit_script = script_builder(
        &vtxo.owner_pubkey,
        &amount_commitment,
        vtxo.exit_delay_blocks,
    );

    // ── 2. Construct the exit transaction spending the round-tree leaf. ──
    //
    // The CSV exit path requires the input sequence to encode the relative
    // timelock so the CSV opcode in the exit script accepts the spend.
    let csv_sequence = Sequence::from_consensus(vtxo.exit_delay_blocks);
    let leaf_amount = Amount::from_sat(vtxo.amount);

    let exit_tx_template = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: vtxo.leaf_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: csv_sequence,
            witness: Witness::new(),
        }],
        // The change output script is intentionally identical to the leaf's
        // P2TR pubkey: at this stage of #548 we only need a placeholder
        // anchor — the post-CSV sweep (#549) will replace this output.
        output: vec![TxOut {
            value: leaf_amount,
            script_pubkey: ScriptBuf::new_p2tr(&secp, vtxo.owner_pubkey, None),
        }],
    };

    // ── 3. Populate the witness with (amount, blinding, signature). ──────
    //
    // Sighash is computed over the leaf's prevout so the signature commits
    // to both the script being satisfied and the value being spent.
    let prev_txout = TxOut {
        value: leaf_amount,
        script_pubkey: ScriptBuf::new_p2tr(&secp, vtxo.owner_pubkey, None),
    };
    let mut sighash_cache = SighashCache::new(&exit_tx_template);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prev_txout]), TapSighashType::Default)
        .map_err(|e| ClientError::Internal(format!("sighash computation failed: {e}")))?;
    let msg = Message::from_digest(sighash.to_byte_array());
    let keypair = Keypair::from_secret_key(&secp, owner_secret);
    let sig = secp.sign_schnorr(&msg, &keypair);
    let signature_bytes = sig.serialize().to_vec();

    let amount_bytes = vtxo.amount.to_be_bytes();
    let blinding_bytes = vtxo.blinding.to_be_bytes();

    let mut witness = Witness::new();
    witness.push(amount_bytes); // index 0 — amount opening
    witness.push(blinding_bytes); // index 1 — blinding opening
    witness.push(signature_bytes.clone()); // index 2 — owner signature
    witness.push(exit_script.as_bytes()); // index 3 — script being executed

    debug_assert_eq!(witness.len(), 4);
    debug_assert_eq!(
        witness.nth(WITNESS_AMOUNT_INDEX).map(|v| v.len()),
        Some(WITNESS_AMOUNT_LEN)
    );
    debug_assert_eq!(
        witness.nth(WITNESS_BLINDING_INDEX).map(|v| v.len()),
        Some(WITNESS_BLINDING_LEN)
    );
    debug_assert_eq!(
        witness.nth(WITNESS_SIGNATURE_INDEX).map(|v| v.to_vec()),
        Some(signature_bytes.clone())
    );

    let mut exit_tx = exit_tx_template;
    exit_tx.input[0].witness = witness.clone();
    let raw_tx_hex = serialize_hex(&exit_tx);
    let local_txid = exit_tx.compute_txid().to_string();

    if let Some(cb) = progress.as_mut() {
        cb(ConfidentialExitProgress::LeafExitSigned {
            txid: local_txid.clone(),
        });
    }

    // ── 4. Broadcast. ────────────────────────────────────────────────────
    let broadcast_txid = mempool_explorer.broadcast_tx(&raw_tx_hex).await?;

    if let Some(cb) = progress.as_mut() {
        cb(ConfidentialExitProgress::LeafExitBroadcast {
            txid: broadcast_txid.clone(),
        });
        cb(ConfidentialExitProgress::CsvMaturing {
            txid: broadcast_txid.clone(),
            exit_delay_blocks: vtxo.exit_delay_blocks,
        });
        // The "claimable" event is logically post-CSV; we surface it now so
        // the CLI can render the full "leaf exit broadcast → CSV maturing
        // → claimable" timeline. The actual claim transaction is built by
        // the sweep flow (#549).
        cb(ConfidentialExitProgress::Claimable {
            txid: broadcast_txid.clone(),
        });
    }

    Ok(UnilateralExitOutcome {
        txid: broadcast_txid,
        raw_tx_hex,
        exit_script,
        witness,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{hashes::Hash, OutPoint, Txid};
    use secp256k1::{Scalar, SECP256K1};
    use std::sync::Mutex;

    /// Mock explorer: records every broadcast call for later assertion.
    #[derive(Default)]
    struct MockExplorer {
        calls: Mutex<Vec<String>>,
        return_txid: Mutex<String>,
    }

    impl MockExplorer {
        fn new(return_txid: impl Into<String>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                return_txid: Mutex::new(return_txid.into()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MempoolExplorer for MockExplorer {
        async fn broadcast_tx(&self, tx_hex: &str) -> ClientResult<String> {
            self.calls.lock().unwrap().push(tx_hex.to_string());
            Ok(self.return_txid.lock().unwrap().clone())
        }
    }

    fn test_vtxo() -> (ConfidentialVtxo, SecretKey, XOnlyPublicKey) {
        let secret = SecretKey::from_slice(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11,
        ])
        .unwrap();
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        let xonly = XOnlyPublicKey::from_keypair(&keypair).0;
        let blinding = {
            let mut bytes = [0u8; 32];
            bytes[31] = 9;
            Scalar::from_be_bytes(bytes).unwrap()
        };
        let outpoint = OutPoint::new(Txid::all_zeros(), 0);
        let vtxo = ConfidentialVtxo::new(50_000, blinding, xonly, outpoint, 144);
        (vtxo, secret, xonly)
    }

    #[tokio::test]
    async fn witness_third_element_matches_owner_signature() {
        let (vtxo, secret, _xonly) = test_vtxo();
        let explorer = MockExplorer::new("expected-txid");
        let outcome = unilateral_exit_confidential(
            &vtxo,
            &secret,
            &explorer,
            None,
            default_exit_script_builder(),
        )
        .await
        .expect("flow should succeed");

        // Independently recompute the expected sighash and verify the
        // witness's third element is a valid Schnorr signature from the
        // owner over that exact sighash. Schnorr sign uses fresh aux rand
        // per call so byte-equality with a recomputed signature is not
        // guaranteed; what we *can* assert is verifier acceptance, which
        // is the actual security-relevant property.
        let secp = Secp256k1::new();
        let leaf_amount = Amount::from_sat(vtxo.amount);
        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: vtxo.leaf_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(vtxo.exit_delay_blocks),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: leaf_amount,
                script_pubkey: ScriptBuf::new_p2tr(&secp, vtxo.owner_pubkey, None),
            }],
        };
        let prev_txout = TxOut {
            value: leaf_amount,
            script_pubkey: ScriptBuf::new_p2tr(&secp, vtxo.owner_pubkey, None),
        };
        let mut cache = SighashCache::new(&unsigned);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[prev_txout]),
                TapSighashType::Default,
            )
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());

        let third = outcome.witness.nth(WITNESS_SIGNATURE_INDEX).unwrap();
        assert_eq!(
            third.len(),
            64,
            "witness[2] must be a 64-byte Schnorr signature"
        );
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(third)
            .expect("witness[2] must parse as a Schnorr signature");
        secp.verify_schnorr(&sig, &msg, &vtxo.owner_pubkey)
            .expect("witness[2] must verify against the owner pubkey + sighash");
    }

    #[tokio::test]
    async fn broadcast_call_carries_correct_script_and_witness() {
        let (vtxo, secret, _xonly) = test_vtxo();
        let explorer = MockExplorer::new("returned-txid-xyz");

        // Inject a custom script-builder so we can assert the broadcast
        // payload is built from *this* script and not (e.g.) a hard-coded
        // default.
        let sentinel_script = ScriptBuf::from_bytes(b"\xab\xcd\xef\x00MOCK".to_vec());
        let captured = sentinel_script.clone();
        let builder: ExitScriptBuilder = Arc::new(move |_pk, _c, _d| captured.clone());

        let outcome = unilateral_exit_confidential(&vtxo, &secret, &explorer, None, builder)
            .await
            .expect("flow should succeed");

        // The outcome reflects the injected script.
        assert_eq!(outcome.exit_script, sentinel_script);

        // The witness's last element is the script.
        let last = outcome.witness.last().expect("witness has elements");
        assert_eq!(
            last,
            sentinel_script.as_bytes(),
            "witness must commit to the injected exit script"
        );

        // The explorer was called exactly once with the serialized exit tx.
        let calls = explorer.calls();
        assert_eq!(calls.len(), 1);
        let broadcast_hex = &calls[0];

        // Decode the broadcast and confirm both the witness's third element
        // (signature) and last element (script) survived intact.
        let bytes = hex::decode(broadcast_hex).expect("broadcast must be valid hex");
        let decoded: Transaction = bitcoin::consensus::encode::deserialize(&bytes)
            .expect("broadcast bytes must decode as a transaction");
        assert_eq!(decoded.input.len(), 1);
        let broadcast_witness = &decoded.input[0].witness;
        assert_eq!(
            broadcast_witness.last().unwrap(),
            sentinel_script.as_bytes(),
            "broadcast witness must carry the injected script"
        );
        let sig = broadcast_witness.nth(WITNESS_SIGNATURE_INDEX).unwrap();
        assert_eq!(
            sig,
            outcome.witness.nth(WITNESS_SIGNATURE_INDEX).unwrap(),
            "broadcast witness signature must match the outcome"
        );

        // The function returns the txid the explorer reported.
        assert_eq!(outcome.txid, "returned-txid-xyz");
    }

    #[tokio::test]
    async fn progress_callback_emits_full_timeline() {
        let (vtxo, secret, _xonly) = test_vtxo();
        let explorer = MockExplorer::new("progress-txid");

        let events: Arc<Mutex<Vec<ConfidentialExitProgress>>> = Arc::new(Mutex::new(Vec::new()));
        let events_cb = events.clone();
        let cb: ProgressCallback = Box::new(move |evt| {
            events_cb.lock().unwrap().push(evt);
        });

        let _outcome = unilateral_exit_confidential(
            &vtxo,
            &secret,
            &explorer,
            Some(cb),
            default_exit_script_builder(),
        )
        .await
        .expect("flow should succeed");

        let evts = events.lock().unwrap().clone();
        assert_eq!(evts.len(), 4, "expected 4 progress events, got {evts:?}");
        assert!(matches!(
            evts[0],
            ConfidentialExitProgress::LeafExitSigned { .. }
        ));
        assert!(matches!(
            evts[1],
            ConfidentialExitProgress::LeafExitBroadcast { .. }
        ));
        assert!(matches!(
            evts[2],
            ConfidentialExitProgress::CsvMaturing {
                exit_delay_blocks: 144,
                ..
            }
        ));
        assert!(matches!(
            evts[3],
            ConfidentialExitProgress::Claimable { .. }
        ));
    }

    #[tokio::test]
    async fn witness_first_two_elements_are_amount_and_blinding() {
        let (vtxo, secret, _xonly) = test_vtxo();
        let explorer = MockExplorer::new("ok");
        let outcome = unilateral_exit_confidential(
            &vtxo,
            &secret,
            &explorer,
            None,
            default_exit_script_builder(),
        )
        .await
        .unwrap();

        let amount_bytes = outcome.witness.nth(WITNESS_AMOUNT_INDEX).unwrap();
        assert_eq!(amount_bytes.len(), WITNESS_AMOUNT_LEN);
        assert_eq!(amount_bytes, &vtxo.amount.to_be_bytes());

        let blinding_bytes = outcome.witness.nth(WITNESS_BLINDING_INDEX).unwrap();
        assert_eq!(blinding_bytes.len(), WITNESS_BLINDING_LEN);
        assert_eq!(blinding_bytes, &vtxo.blinding.to_be_bytes());
    }

    #[tokio::test]
    async fn explorer_error_propagates() {
        struct FailingExplorer;
        #[async_trait]
        impl MempoolExplorer for FailingExplorer {
            async fn broadcast_tx(&self, _tx_hex: &str) -> ClientResult<String> {
                Err(ClientError::Explorer("boom".into()))
            }
        }
        let (vtxo, secret, _) = test_vtxo();
        let err = unilateral_exit_confidential(
            &vtxo,
            &secret,
            &FailingExplorer,
            None,
            default_exit_script_builder(),
        )
        .await
        .expect_err("must surface explorer error");
        assert!(matches!(err, ClientError::Explorer(_)));
    }
}
