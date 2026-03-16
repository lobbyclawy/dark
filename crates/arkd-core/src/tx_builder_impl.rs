//! `TxBuilder` trait implementation for `arkd_bitcoin::LocalTxBuilder`.
//!
//! Bridges the standalone `LocalTxBuilder` from `arkd-bitcoin` to the
//! `TxBuilder` trait defined in `arkd-core::ports`.

use std::collections::HashMap;

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

use crate::domain::{FlatTxTree, Intent, TxTreeNode, Vtxo};
use crate::error::{ArkError, ArkResult};
use crate::ports::{
    BoardingInput, CommitmentTxResult, SignedBoardingInput, SweepInput, SweepableOutput, TxBuilder,
    ValidForfeitTx,
};

use arkd_bitcoin::tx_builder::{BoardingUtxo, IntentInput, LocalTxBuilder, ReceiverInput};

#[async_trait]
impl TxBuilder for LocalTxBuilder {
    async fn build_commitment_tx(
        &self,
        signer_pubkey: &XOnlyPublicKey,
        intents: &[Intent],
        boarding_inputs: &[BoardingInput],
    ) -> ArkResult<CommitmentTxResult> {
        // Convert domain types to arkd-bitcoin input types
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
        let convert_tree = |nodes: Vec<arkd_bitcoin::tx_builder::TreeNode>| -> FlatTxTree {
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
        _vtxos: &[Vtxo],
        _connectors: &FlatTxTree,
        _txs: &[String],
    ) -> ArkResult<Vec<ValidForfeitTx>> {
        // Stub: forfeit verification not yet implemented
        Ok(Vec::new())
    }

    async fn build_sweep_tx(&self, _inputs: &[SweepInput]) -> ArkResult<(String, String)> {
        // TODO(#167): implement real sweep transaction construction
        // This will aggregate expired VTXO outputs into a single sweep tx
        // that returns funds to the ASP wallet.
        Err(ArkError::Internal(
            "build_sweep_tx not yet implemented".into(),
        ))
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
