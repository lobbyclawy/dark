//! `TxBuilder` trait implementation for `dark_bitcoin::LocalTxBuilder`.
//!
//! Bridges the standalone `LocalTxBuilder` from `dark-bitcoin` to the
//! `TxBuilder` trait defined in `dark-core::ports`.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::consensus::deserialize;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::taproot::ControlBlock;
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};
use tracing::warn;

use crate::domain::{FlatTxTree, Intent, TxTreeNode, Vtxo, VtxoOutpoint};
use crate::error::{ArkError, ArkResult};
use crate::ports::{
    BoardingInput, CommitmentTxResult, SignedBoardingInput, SweepInput, SweepableOutput, TxBuilder,
    ValidForfeitTx,
};

use dark_bitcoin::tx_builder::{BoardingUtxo, IntentInput, LocalTxBuilder, ReceiverInput};

#[async_trait]
impl TxBuilder for LocalTxBuilder {
    async fn build_commitment_tx(
        &self,
        signer_pubkey: &XOnlyPublicKey,
        intents: &[Intent],
        boarding_inputs: &[BoardingInput],
    ) -> ArkResult<CommitmentTxResult> {
        // Convert domain types to dark-bitcoin input types
        let intent_inputs: Vec<IntentInput> = intents
            .iter()
            .map(|i| IntentInput {
                id: i.id.clone(),
                receivers: i
                    .receivers
                    .iter()
                    .map(|r| ReceiverInput {
                        pubkey: r.pubkey.clone(),
                        onchain_address: r.onchain_address.clone(),
                        amount: r.amount,
                    })
                    .collect(),
                cosigners_public_keys: i.cosigners_public_keys.clone(),
            })
            .collect();

        let boarding_utxos: Vec<BoardingUtxo> = boarding_inputs
            .iter()
            .map(|b| BoardingUtxo {
                txid: b.outpoint.txid.clone(),
                vout: b.outpoint.vout,
                amount: b.amount,
            })
            .collect();

        let result = self
            .build(signer_pubkey, &intent_inputs, &boarding_utxos)
            .map_err(ArkError::Internal)?;

        // Convert TreeNode -> TxTreeNode
        let convert_tree = |nodes: Vec<dark_bitcoin::tx_builder::TreeNode>| -> FlatTxTree {
            nodes
                .into_iter()
                .map(|n| TxTreeNode {
                    txid: n.txid,
                    tx: n.tx,
                    children: n.children,
                })
                .collect()
        };

        Ok(CommitmentTxResult {
            commitment_tx: result.commitment_tx,
            vtxo_tree: convert_tree(result.vtxo_tree),
            connector_address: result.connector_address,
            connectors: convert_tree(result.connectors),
        })
    }

    async fn verify_forfeit_txs(
        &self,
        vtxos: &[Vtxo],
        connectors: &FlatTxTree,
        txs: &[String],
    ) -> ArkResult<Vec<ValidForfeitTx>> {
        verify_forfeit_txs_impl(vtxos, connectors, txs)
    }

    async fn build_sweep_tx(&self, inputs: &[SweepInput]) -> ArkResult<(String, String)> {
        if inputs.is_empty() {
            return Err(ArkError::Internal("no sweep inputs provided".into()));
        }

        let csv_delay = self.csv_delay;

        // Build transaction inputs from SweepInputs
        let mut tx_inputs = Vec::with_capacity(inputs.len());
        let mut total_amount: u64 = 0;

        for si in inputs {
            let txid = Txid::from_str(&si.txid)
                .map_err(|e| ArkError::Internal(format!("invalid sweep input txid: {e}")))?;

            tx_inputs.push(TxIn {
                previous_output: OutPoint {
                    txid,
                    vout: si.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(csv_delay as u32),
                witness: Witness::default(),
            });

            total_amount = total_amount
                .checked_add(si.amount)
                .ok_or_else(|| ArkError::Internal("sweep amount overflow".into()))?;
        }

        // Fee estimate: 300 sats per input
        let fee = 300u64 * inputs.len() as u64;
        let output_amount = total_amount
            .checked_sub(fee)
            .ok_or_else(|| ArkError::Internal("sweep inputs too small to cover fees".into()))?;

        // Sweep output: P2TR to the ASP key (same pattern used in connector outputs).
        // LocalTxBuilder doesn't store asp_pubkey, so we derive it from the first
        // input's tapscripts (the expiry leaf encodes the user pubkey, but for
        // sweep the ASP is spending to itself). Use an unspendable internal key
        // as a safe default — the ASP will replace the output address before signing.
        //
        // For now, use a deterministic "nothing up my sleeve" key (all-ones x-only).
        let nums_bytes = [
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02,
        ];
        let sweep_key = XOnlyPublicKey::from_slice(&nums_bytes)
            .map_err(|e| ArkError::Internal(format!("failed to create sweep key: {e}")))?;
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let (tweaked_sweep, _) = sweep_key.tap_tweak(&secp, None);
        let sweep_script = ScriptBuf::new_p2tr_tweaked(tweaked_sweep);

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: sweep_script,
            }],
        };

        let unsigned_txid = tx.compute_txid().to_string();

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .map_err(|e| ArkError::Internal(format!("failed to create sweep PSBT: {e}")))?;

        // Populate witness_utxo for each input so the signer can compute
        // taproot sighashes.  The VTXO output script is P2TR derived from the
        // owner's x-only public key.
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        for (i, si) in inputs.iter().enumerate() {
            if si.pubkey.is_empty() {
                continue; // connector outputs — path currently unreachable
            }
            let pubkey_bytes = hex::decode(&si.pubkey)
                .map_err(|e| ArkError::Internal(format!("invalid sweep input pubkey hex: {e}")))?;
            let xonly = XOnlyPublicKey::from_slice(&pubkey_bytes).map_err(|e| {
                ArkError::Internal(format!("invalid sweep input x-only pubkey: {e}"))
            })?;
            let script_pubkey = ScriptBuf::new_p2tr(&secp, xonly, None);
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: Amount::from_sat(si.amount),
                script_pubkey,
            });
        }

        let psbt_hex = hex::encode(psbt.serialize());

        Ok((unsigned_txid, psbt_hex))
    }

    async fn get_sweepable_batch_outputs(
        &self,
        _vtxo_tree: &FlatTxTree,
    ) -> ArkResult<Option<SweepableOutput>> {
        // TODO(#167): scan VTXO tree for outputs past their CSV expiry
        // that can be swept back to the ASP.
        Ok(None)
    }

    async fn finalize_and_extract(&self, tx: &str) -> ArkResult<String> {
        self.finalize_and_extract(tx).map_err(ArkError::Internal)
    }

    async fn verify_vtxo_tapscript_sigs(
        &self,
        _tx: &str,
        _must_include_signer: bool,
    ) -> ArkResult<bool> {
        // TODO(#171): deserialize PSBT and verify taproot script-spend
        // signatures for each VTXO input. If must_include_signer is true,
        // check that the ASP's key contributed a signature.
        Ok(true)
    }

    async fn verify_boarding_tapscript_sigs(
        &self,
        _signed_tx: &str,
        _commitment_tx: &str,
    ) -> ArkResult<HashMap<u32, SignedBoardingInput>> {
        // TODO(#171): compare signed boarding tx against commitment tx,
        // extract per-input taproot script-spend signatures and leaf scripts.
        Ok(HashMap::new())
    }
}

/// Build a set of known connector outpoints from the connector tree.
///
/// Each connector tree node has a txid and a set of output indices. We try to
/// parse the `tx` field (hex-encoded raw transaction) to discover the output
/// count. If that fails (e.g. base64-encoded PSBT), we fall back to the
/// `children` map keys plus output index 0 as a reasonable default.
fn collect_connector_outpoints(connectors: &FlatTxTree) -> HashSet<String> {
    let mut set = HashSet::new();
    for node in connectors {
        let mut found = false;
        if let Ok(raw) = hex::decode(&node.tx) {
            if let Ok(tx) = deserialize::<Transaction>(&raw) {
                for vout in 0..tx.output.len() as u32 {
                    set.insert(format!("{}:{}", node.txid, vout));
                }
                found = true;
            }
        }
        if !found {
            // Fallback: register children keys + output 0
            set.insert(format!("{}:{}", node.txid, 0));
            for &vout in node.children.keys() {
                set.insert(format!("{}:{}", node.txid, vout));
            }
        }
    }
    set
}

/// Core forfeit transaction verification logic.
///
/// For each hex-encoded signed forfeit transaction:
/// 1. Deserialize the raw transaction from hex.
/// 2. Verify it has exactly 2 inputs (VTXO at index 0, connector at index 1).
/// 3. Verify input 0 references a known VTXO from the provided list.
/// 4. Verify input 1 references a known connector from the connector tree.
/// 5. Validate the witness structure on input 0:
///    - Key-path spend: witness has exactly 1 element (64-or-65-byte Schnorr sig).
///    - Script-path spend: witness has ≥2 elements; last element is a valid
///      control block that, combined with the leaf script, verifies against the
///      VTXO's P2TR output key.
/// 6. Return a `ValidForfeitTx` for each transaction that passes.
///
/// Transactions that fail verification are logged and skipped (not returned).
fn verify_forfeit_txs_impl(
    vtxos: &[Vtxo],
    connectors: &FlatTxTree,
    txs: &[String],
) -> ArkResult<Vec<ValidForfeitTx>> {
    // Build lookup maps
    let vtxo_map: HashMap<String, &Vtxo> = vtxos
        .iter()
        .map(|v| (format!("{}:{}", v.outpoint.txid, v.outpoint.vout), v))
        .collect();

    let connector_outpoints = collect_connector_outpoints(connectors);

    let mut valid = Vec::new();

    for (idx, tx_hex) in txs.iter().enumerate() {
        match verify_single_forfeit(tx_hex, &vtxo_map, &connector_outpoints) {
            Ok(vf) => valid.push(vf),
            Err(e) => {
                warn!(
                    forfeit_index = idx,
                    error = %e,
                    "Forfeit tx verification failed, skipping"
                );
            }
        }
    }

    Ok(valid)
}

/// Verify a single forfeit transaction.
fn verify_single_forfeit(
    tx_hex: &str,
    vtxo_map: &HashMap<String, &Vtxo>,
    connector_outpoints: &HashSet<String>,
) -> Result<ValidForfeitTx, ArkError> {
    // Step 1: Decode hex → raw bytes → Transaction
    let raw_bytes = hex::decode(tx_hex)
        .map_err(|e| ArkError::Internal(format!("Invalid forfeit tx hex: {e}")))?;

    let tx: Transaction = deserialize(&raw_bytes)
        .map_err(|e| ArkError::Internal(format!("Failed to deserialize forfeit tx: {e}")))?;

    // Step 2: Must have exactly 2 inputs
    if tx.input.len() != 2 {
        return Err(ArkError::Internal(format!(
            "Forfeit tx must have exactly 2 inputs, got {}",
            tx.input.len()
        )));
    }

    // Step 3: Input 0 must reference a known VTXO
    let vtxo_outpoint = &tx.input[0].previous_output;
    let vtxo_key = format!("{}:{}", vtxo_outpoint.txid, vtxo_outpoint.vout);

    let vtxo = vtxo_map.get(&vtxo_key).ok_or_else(|| {
        ArkError::Internal(format!(
            "Forfeit tx input 0 references unknown VTXO: {vtxo_key}"
        ))
    })?;

    // Step 4: Input 1 must reference a known connector
    let connector_outpoint = &tx.input[1].previous_output;
    let connector_key = format!("{}:{}", connector_outpoint.txid, connector_outpoint.vout);

    if !connector_outpoints.contains(&connector_key) {
        return Err(ArkError::Internal(format!(
            "Forfeit tx input 1 references unknown connector: {connector_key}"
        )));
    }

    // Step 5: Validate witness structure on input 0 (the VTXO input)
    let witness = &tx.input[0].witness;
    if witness.is_empty() {
        return Err(ArkError::Internal(
            "Forfeit tx VTXO input has empty witness".to_string(),
        ));
    }

    validate_taproot_witness(witness, vtxo)?;

    // Step 6: Must have at least 1 output
    if tx.output.is_empty() {
        return Err(ArkError::Internal("Forfeit tx has no outputs".to_string()));
    }

    Ok(ValidForfeitTx {
        tx: tx_hex.to_string(),
        connector: VtxoOutpoint {
            txid: connector_outpoint.txid.to_string(),
            vout: connector_outpoint.vout,
        },
    })
}

/// Validate a taproot witness against a VTXO's expected output key.
///
/// Two valid witness shapes:
/// - **Key-path spend**: `[signature]` — 1 element, 64 or 65 bytes (Schnorr sig,
///   optionally with sighash type byte).
/// - **Script-path spend**: `[...script_args, leaf_script, control_block]` — ≥2
///   elements; the last element is a control block. We verify the control block
///   + leaf script produce the expected output key from the VTXO.
fn validate_taproot_witness(witness: &bitcoin::Witness, vtxo: &Vtxo) -> Result<(), ArkError> {
    let items: Vec<&[u8]> = witness.iter().collect();

    if items.len() == 1 {
        // Key-path spend: single Schnorr signature (64 bytes, or 65 with sighash byte)
        let sig_len = items[0].len();
        if sig_len != 64 && sig_len != 65 {
            return Err(ArkError::Internal(format!(
                "Key-path witness has invalid signature length: {sig_len} (expected 64 or 65)"
            )));
        }
        // Key-path spend is structurally valid — full sig verification would
        // require computing the sighash with prevouts, which is out of scope
        // for structural validation.
        return Ok(());
    }

    // Script-path spend: last element is the control block, second-to-last is leaf script
    if items.len() < 2 {
        return Err(ArkError::Internal(
            "Script-path witness must have at least 2 elements".to_string(),
        ));
    }

    let control_block_bytes = items[items.len() - 1];
    let leaf_script_bytes = items[items.len() - 2];

    // Parse the control block
    let control_block = ControlBlock::decode(control_block_bytes).map_err(|e| {
        ArkError::Internal(format!("Invalid control block in forfeit witness: {e}"))
    })?;

    // Get the VTXO's expected output key
    let vtxo_pubkey = vtxo.tap_key().ok_or_else(|| {
        ArkError::Internal(format!(
            "Cannot parse VTXO pubkey '{}' as x-only public key",
            vtxo.pubkey
        ))
    })?;

    // Verify the control block: the control block + leaf script must produce
    // the expected output key (the VTXO's taproot key).
    let leaf_script = bitcoin::ScriptBuf::from(leaf_script_bytes.to_vec());

    let verified = control_block.verify_taproot_commitment(
        &bitcoin::secp256k1::Secp256k1::verification_only(),
        vtxo_pubkey,
        &leaf_script,
    );

    if !verified {
        return Err(ArkError::Internal(
            "Control block does not verify against VTXO taproot output key".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::taproot::TaprootBuilder;
    use bitcoin::{absolute, transaction, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Txid, Witness};

    fn test_keypair() -> (Keypair, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut bitcoin::secp256k1::rand::thread_rng());
        let (xonly, _) = kp.x_only_public_key();
        (kp, xonly)
    }

    fn dummy_outpoint(index: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([index; 32]),
            vout: 0,
        }
    }

    fn make_vtxo(txid_byte: u8, pubkey: &XOnlyPublicKey) -> Vtxo {
        let txid = Txid::from_byte_array([txid_byte; 32]);
        Vtxo::new(
            VtxoOutpoint::new(txid.to_string(), 0),
            100_000,
            hex::encode(pubkey.serialize()),
        )
    }

    fn make_connector_tree(txid_byte: u8) -> FlatTxTree {
        let connector_txid = Txid::from_byte_array([txid_byte; 32]);
        // Build a minimal valid transaction for the connector
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let tx_hex = hex::encode(serialize(&tx));
        vec![TxTreeNode {
            txid: connector_txid.to_string(),
            tx: tx_hex,
            children: HashMap::new(),
        }]
    }

    /// Build a forfeit tx with key-path spend witness on input 0.
    fn build_forfeit_with_keypath(
        vtxo_outpoint: OutPoint,
        connector_outpoint: OutPoint,
        asp_pubkey: &XOnlyPublicKey,
    ) -> Transaction {
        let asp_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(*asp_pubkey),
        );
        let mut tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: vtxo_outpoint,
                    witness: Witness::default(),
                    ..Default::default()
                },
                TxIn {
                    previous_output: connector_outpoint,
                    witness: Witness::default(),
                    ..Default::default()
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: asp_script,
            }],
        };
        // Add a dummy 64-byte Schnorr signature as key-path witness
        let dummy_sig = vec![0x42u8; 64];
        tx.input[0].witness.push(dummy_sig);
        tx
    }

    #[test]
    fn test_verify_forfeit_valid_keypath() {
        let (_kp, vtxo_pk) = test_keypair();
        let (_asp_kp, asp_pk) = test_keypair();

        let vtxo_out = dummy_outpoint(1);
        let conn_out = dummy_outpoint(2);

        let vtxo = make_vtxo(1, &vtxo_pk);
        let connectors = make_connector_tree(2);

        let tx = build_forfeit_with_keypath(vtxo_out, conn_out, &asp_pk);
        let tx_hex = hex::encode(serialize(&tx));

        let result = verify_forfeit_txs_impl(&[vtxo], &connectors, &[tx_hex]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].connector.vout, 0);
    }

    #[test]
    fn test_verify_forfeit_unknown_vtxo() {
        let (_kp, vtxo_pk) = test_keypair();
        let (_asp_kp, asp_pk) = test_keypair();

        let vtxo_out = dummy_outpoint(1);
        let conn_out = dummy_outpoint(2);

        // VTXO with a different txid byte — won't match input 0
        let vtxo = make_vtxo(99, &vtxo_pk);
        let connectors = make_connector_tree(2);

        let tx = build_forfeit_with_keypath(vtxo_out, conn_out, &asp_pk);
        let tx_hex = hex::encode(serialize(&tx));

        let result = verify_forfeit_txs_impl(&[vtxo], &connectors, &[tx_hex]).unwrap();
        assert_eq!(result.len(), 0, "Should reject unknown VTXO");
    }

    #[test]
    fn test_verify_forfeit_unknown_connector() {
        let (_kp, vtxo_pk) = test_keypair();
        let (_asp_kp, asp_pk) = test_keypair();

        let vtxo_out = dummy_outpoint(1);
        let conn_out = dummy_outpoint(2);

        let vtxo = make_vtxo(1, &vtxo_pk);
        // Connector tree with a different txid byte — won't match input 1
        let connectors = make_connector_tree(99);

        let tx = build_forfeit_with_keypath(vtxo_out, conn_out, &asp_pk);
        let tx_hex = hex::encode(serialize(&tx));

        let result = verify_forfeit_txs_impl(&[vtxo], &connectors, &[tx_hex]).unwrap();
        assert_eq!(result.len(), 0, "Should reject unknown connector");
    }

    #[test]
    fn test_verify_forfeit_empty_witness() {
        let (_kp, vtxo_pk) = test_keypair();
        let (_asp_kp, asp_pk) = test_keypair();

        let vtxo_out = dummy_outpoint(1);
        let conn_out = dummy_outpoint(2);

        let vtxo = make_vtxo(1, &vtxo_pk);
        let connectors = make_connector_tree(2);

        // Build tx with empty witness
        let asp_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(asp_pk),
        );
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: vtxo_out,
                    witness: Witness::default(), // empty
                    ..Default::default()
                },
                TxIn {
                    previous_output: conn_out,
                    witness: Witness::default(),
                    ..Default::default()
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: asp_script,
            }],
        };
        let tx_hex = hex::encode(serialize(&tx));

        let result = verify_forfeit_txs_impl(&[vtxo], &connectors, &[tx_hex]).unwrap();
        assert_eq!(result.len(), 0, "Should reject empty witness");
    }

    #[test]
    fn test_verify_forfeit_wrong_input_count() {
        let (_kp, vtxo_pk) = test_keypair();

        let vtxo = make_vtxo(1, &vtxo_pk);
        let connectors = make_connector_tree(2);

        // Build tx with only 1 input
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: dummy_outpoint(1),
                witness: {
                    let mut w = Witness::default();
                    w.push(vec![0x42u8; 64]);
                    w
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let tx_hex = hex::encode(serialize(&tx));

        let result = verify_forfeit_txs_impl(&[vtxo], &connectors, &[tx_hex]).unwrap();
        assert_eq!(result.len(), 0, "Should reject tx with wrong input count");
    }

    #[test]
    fn test_verify_forfeit_invalid_hex() {
        let (_kp, vtxo_pk) = test_keypair();

        let vtxo = make_vtxo(1, &vtxo_pk);
        let connectors = make_connector_tree(2);

        let result =
            verify_forfeit_txs_impl(&[vtxo], &connectors, &["not_valid_hex!!".to_string()])
                .unwrap();
        assert_eq!(result.len(), 0, "Should reject invalid hex");
    }

    #[test]
    fn test_verify_forfeit_script_path_spend() {
        let secp = Secp256k1::new();
        let (_kp, internal_key) = test_keypair();
        let (_asp_kp, asp_pk) = test_keypair();

        // Build a taproot output with a script path
        let leaf_script = ScriptBuf::from_bytes(vec![
            0x20, // OP_PUSHBYTES_32
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0xac, // OP_CHECKSIG
        ]);

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf_script.clone())
            .expect("add leaf")
            .finalize(&secp, internal_key)
            .expect("finalize taproot");

        let output_key = taproot_spend_info.output_key();

        // The VTXO pubkey must match the taproot output key
        let vtxo_txid = Txid::from_byte_array([1; 32]);
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new(vtxo_txid.to_string(), 0),
            100_000,
            hex::encode(output_key.serialize()),
        );
        vtxo.commitment_txids = vec!["c1".to_string()];
        vtxo.root_commitment_txid = "c1".to_string();

        let connectors = make_connector_tree(2);

        // Build control block for the leaf
        let control_block = taproot_spend_info
            .control_block(&(
                leaf_script.clone(),
                bitcoin::taproot::LeafVersion::TapScript,
            ))
            .expect("control block");

        // Build forfeit tx with script-path witness
        let asp_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(asp_pk),
        );
        let mut tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: vtxo_txid,
                        vout: 0,
                    },
                    witness: Witness::default(),
                    ..Default::default()
                },
                TxIn {
                    previous_output: dummy_outpoint(2),
                    witness: Witness::default(),
                    ..Default::default()
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: asp_script,
            }],
        };

        // Witness: [dummy_sig, leaf_script, control_block]
        tx.input[0].witness.push(vec![0x42u8; 64]); // dummy signature
        tx.input[0].witness.push(leaf_script.as_bytes());
        tx.input[0].witness.push(control_block.serialize());

        let tx_hex = hex::encode(serialize(&tx));

        let result = verify_forfeit_txs_impl(&[vtxo], &connectors, &[tx_hex]).unwrap();
        assert_eq!(result.len(), 1, "Script-path spend should verify");
    }

    #[test]
    fn test_verify_forfeit_bad_control_block() {
        let secp = Secp256k1::new();
        let (_kp, internal_key) = test_keypair();
        let (_asp_kp, asp_pk) = test_keypair();
        let (_other_kp, other_key) = test_keypair();

        // Build a taproot output with internal_key
        let leaf_script = ScriptBuf::from_bytes(vec![
            0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0xac,
        ]);

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf_script.clone())
            .expect("add leaf")
            .finalize(&secp, internal_key)
            .expect("finalize taproot");

        let output_key = taproot_spend_info.output_key();

        let vtxo_txid = Txid::from_byte_array([1; 32]);
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new(vtxo_txid.to_string(), 0),
            100_000,
            hex::encode(output_key.serialize()),
        );
        vtxo.commitment_txids = vec!["c1".to_string()];
        vtxo.root_commitment_txid = "c1".to_string();

        let connectors = make_connector_tree(2);

        // Build a DIFFERENT taproot tree with other_key to get a mismatched control block
        let other_spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf_script.clone())
            .expect("add leaf")
            .finalize(&secp, other_key)
            .expect("finalize taproot");

        let bad_control_block = other_spend_info
            .control_block(&(
                leaf_script.clone(),
                bitcoin::taproot::LeafVersion::TapScript,
            ))
            .expect("control block");

        let asp_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(asp_pk),
        );
        let mut tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: vtxo_txid,
                        vout: 0,
                    },
                    witness: Witness::default(),
                    ..Default::default()
                },
                TxIn {
                    previous_output: dummy_outpoint(2),
                    witness: Witness::default(),
                    ..Default::default()
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: asp_script,
            }],
        };

        // Witness with mismatched control block
        tx.input[0].witness.push(vec![0x42u8; 64]);
        tx.input[0].witness.push(leaf_script.as_bytes());
        tx.input[0].witness.push(bad_control_block.serialize());

        let tx_hex = hex::encode(serialize(&tx));

        let result = verify_forfeit_txs_impl(&[vtxo], &connectors, &[tx_hex]).unwrap();
        assert_eq!(
            result.len(),
            0,
            "Bad control block should fail verification"
        );
    }

    #[test]
    fn test_verify_multiple_forfeits_mixed() {
        let (_kp, vtxo_pk) = test_keypair();
        let (_asp_kp, asp_pk) = test_keypair();

        let vtxo1 = make_vtxo(1, &vtxo_pk);
        let vtxo2 = make_vtxo(3, &vtxo_pk);

        let connectors = make_connector_tree(2);

        // Valid forfeit for vtxo1
        let tx1 = build_forfeit_with_keypath(dummy_outpoint(1), dummy_outpoint(2), &asp_pk);
        let tx1_hex = hex::encode(serialize(&tx1));

        // Invalid: references unknown VTXO (byte 99)
        let tx2 = build_forfeit_with_keypath(dummy_outpoint(99), dummy_outpoint(2), &asp_pk);
        let tx2_hex = hex::encode(serialize(&tx2));

        // Valid forfeit for vtxo2
        let tx3 = build_forfeit_with_keypath(dummy_outpoint(3), dummy_outpoint(2), &asp_pk);
        let tx3_hex = hex::encode(serialize(&tx3));

        let result =
            verify_forfeit_txs_impl(&[vtxo1, vtxo2], &connectors, &[tx1_hex, tx2_hex, tx3_hex])
                .unwrap();

        assert_eq!(result.len(), 2, "Should accept 2 valid, skip 1 invalid");
    }
}
