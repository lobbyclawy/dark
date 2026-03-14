//! `TxBuilder` trait implementation for `arkd_bitcoin::LocalTxBuilder`.
//!
//! Bridges the standalone `LocalTxBuilder` from `arkd-bitcoin` to the
//! `TxBuilder` trait defined in `arkd-core::ports`.

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

use crate::domain::{FlatTxTree, Intent, TxTreeNode, Vtxo};
use crate::error::{ArkError, ArkResult};
use crate::ports::{BoardingInput, CommitmentTxResult, TxBuilder, ValidForfeitTx};

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
}
