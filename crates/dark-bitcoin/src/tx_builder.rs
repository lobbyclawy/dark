//! Local transaction builder for VTXO tree construction.
//!
//! Builds real Bitcoin PSBTs for commitment transactions, VTXO trees,
//! and connector trees using the `bitcoin` crate's PSBT support.
//!
//! The [`LocalTxBuilder`] struct provides the core logic. The `TxBuilder`
//! trait implementation (from `dark-core::ports`) is provided in `dark-core`
//! since `dark-bitcoin` cannot depend on `dark-core` (it's the other way).

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::TweakedPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, XOnlyPublicKey,
};

#[cfg(test)]
use crate::tapscript::build_vtxo_taproot;

/// Default CSV delay for VTXO expiry leaves (in blocks).
/// ~1 day at 10-min blocks.
const DEFAULT_CSV_DELAY: u16 = 144;

/// Radix (fan-out) of the VTXO tree. Each internal node has up to this
/// many children outputs.
const VTXO_TREE_RADIX: usize = 2;

/// Dust threshold for connector outputs (satoshis).
const CONNECTOR_DUST: u64 = 546;

/// Estimated fee for tree-internal transactions (conservative, in sats).
/// TODO: compute dynamically from fee rate once wallet integration lands.
const TREE_TX_FEE: u64 = 300;

/// A node in a flattened transaction tree (mirrors `dark-core::domain::TxTreeNode`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TreeNode {
    /// Transaction ID
    pub txid: String,
    /// Hex-encoded serialized PSBT (or raw transaction for tree nodes)
    pub tx: String,
    /// Maps output index → child txid
    pub children: HashMap<u32, String>,
}

/// Input descriptor for a receiver in the VTXO tree.
#[derive(Debug, Clone)]
pub struct ReceiverInput {
    /// Receiver public key (hex-encoded x-only, empty for on-chain)
    pub pubkey: String,
    /// On-chain address (empty for off-chain)
    pub onchain_address: String,
    /// Amount in satoshis
    pub amount: u64,
}

/// Input descriptor for a commitment intent.
#[derive(Debug, Clone)]
pub struct IntentInput {
    /// Intent identifier
    pub id: String,
    /// Receivers for this intent
    pub receivers: Vec<ReceiverInput>,
}

/// Boarding input descriptor.
#[derive(Debug, Clone)]
pub struct BoardingUtxo {
    /// Outpoint txid (hex)
    pub txid: String,
    /// Outpoint vout
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
}

/// Result of building a commitment transaction.
#[derive(Debug, Clone)]
pub struct CommitmentResult {
    /// Hex-encoded unsigned PSBT for the commitment transaction
    pub commitment_tx: String,
    /// VTXO tree nodes (each node's `tx` field is a hex-encoded PSBT)
    pub vtxo_tree: Vec<TreeNode>,
    /// Connector address (bech32m P2TR)
    pub connector_address: String,
    /// Connector tree nodes
    pub connectors: Vec<TreeNode>,
}

/// Local transaction builder for Bitcoin-based Ark rounds.
///
/// Produces real Bitcoin PSBTs: the commitment transaction, VTXO tree,
/// and connector tree all contain valid Bitcoin transactions.
#[derive(Debug, Clone)]
pub struct LocalTxBuilder {
    /// Bitcoin network
    pub network: Network,
    /// CSV delay for VTXO expiry leaves
    pub csv_delay: u16,
}

impl LocalTxBuilder {
    /// Create a new `LocalTxBuilder`.
    pub fn new(network: impl Into<String>) -> Self {
        let net_str: String = network.into();
        let network = match net_str.as_str() {
            "mainnet" | "bitcoin" => Network::Bitcoin,
            "testnet" | "testnet3" => Network::Testnet,
            "signet" => Network::Signet,
            _ => Network::Regtest,
        };
        Self {
            network,
            csv_delay: DEFAULT_CSV_DELAY,
        }
    }

    /// Create a builder with a specific CSV delay.
    pub fn with_csv_delay(mut self, delay: u16) -> Self {
        self.csv_delay = delay;
        self
    }

    /// Build a commitment transaction from intents and boarding inputs.
    ///
    /// The commitment tx is an unsigned PSBT with:
    /// - **Inputs**: boarding UTXOs (to be signed externally)
    /// - **Outputs**: VTXO tree root (P2TR), connector output (P2TR), change
    ///
    /// Returns an error string if no intents or boarding inputs are provided.
    pub fn build(
        &self,
        asp_pubkey: &XOnlyPublicKey,
        intents: &[IntentInput],
        boarding_inputs: &[BoardingUtxo],
    ) -> Result<CommitmentResult, String> {
        if intents.is_empty() && boarding_inputs.is_empty() {
            return Err("No intents or boarding inputs provided".to_string());
        }

        // Collect all receivers across all intents, separating on-chain
        // (collaborative exit) receivers from off-chain (VTXO) receivers.
        let all_receivers: Vec<&ReceiverInput> =
            intents.iter().flat_map(|i| i.receivers.iter()).collect();

        let offchain_receivers: Vec<&ReceiverInput> = all_receivers
            .iter()
            .filter(|r| r.onchain_address.is_empty())
            .copied()
            .collect();
        let onchain_receivers: Vec<&ReceiverInput> = all_receivers
            .iter()
            .filter(|r| !r.onchain_address.is_empty())
            .copied()
            .collect();

        let offchain_amount: u64 = offchain_receivers.iter().map(|r| r.amount).sum();
        let onchain_amount: u64 = onchain_receivers.iter().map(|r| r.amount).sum();
        let total_receiver_amount: u64 = offchain_amount + onchain_amount;
        let total_boarding: u64 = boarding_inputs.iter().map(|b| b.amount).sum();

        // Build VTXO tree leaf outputs only for off-chain receivers
        let vtxo_leaf_outputs = self
            .build_vtxo_leaf_outputs(asp_pubkey, &offchain_receivers)
            .map_err(|e| format!("Failed to build VTXO outputs: {e}"))?;

        // Build on-chain (collaborative exit) outputs
        let onchain_outputs: Vec<TxOut> = onchain_receivers
            .iter()
            .map(|r| {
                let addr = Address::from_str(&r.onchain_address)
                    .map_err(|e| format!("Invalid address '{}': {e}", r.onchain_address))?
                    .require_network(self.network)
                    .map_err(|e| format!("Address network mismatch: {e}"))?;
                Ok(TxOut {
                    value: Amount::from_sat(r.amount),
                    script_pubkey: addr.script_pubkey(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        // Connector output: P2TR to ASP key (trivially spendable by ASP)
        let connector_script =
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(*asp_pubkey));
        let connector_address = Address::from_script(&connector_script, self.network)
            .map_err(|e| format!("Failed to derive connector address: {e}"))?
            .to_string();

        // Build the commitment transaction
        let inputs: Vec<TxIn> = boarding_inputs
            .iter()
            .map(|b| {
                let txid =
                    Txid::from_str(&b.txid).unwrap_or_else(|_| Txid::from_byte_array([0u8; 32]));
                TxIn {
                    previous_output: OutPoint { txid, vout: b.vout },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                }
            })
            .collect();

        // Outputs: [vtxo_tree_root, onchain_exits..., connector, change (if any)]
        let mut outputs = Vec::new();

        // Output 0: VTXO tree root amount (only for off-chain receivers)
        if offchain_amount > 0 {
            let vtxo_root_script = if !vtxo_leaf_outputs.is_empty() {
                if vtxo_leaf_outputs.len() == 1 {
                    vtxo_leaf_outputs[0].0.clone()
                } else {
                    connector_script.clone()
                }
            } else {
                connector_script.clone()
            };
            outputs.push(TxOut {
                value: Amount::from_sat(offchain_amount),
                script_pubkey: vtxo_root_script,
            });
        }

        // On-chain (collaborative exit) outputs: added directly to commitment tx
        // so the Go SDK's validateOnchainReceiver can find them.
        outputs.extend(onchain_outputs);

        // Connector output (only if budget allows)
        let budget_after_receivers =
            total_boarding.saturating_sub(total_receiver_amount + TREE_TX_FEE);
        let connector_amount = if budget_after_receivers >= CONNECTOR_DUST {
            CONNECTOR_DUST
        } else {
            0
        };
        if connector_amount > 0 {
            outputs.push(TxOut {
                value: Amount::from_sat(connector_amount),
                script_pubkey: connector_script.clone(),
            });
        }

        // Change output (remaining budget after all outputs + fee)
        let total_out = total_receiver_amount + connector_amount;
        if total_boarding > total_out + TREE_TX_FEE {
            let change = total_boarding - total_out - TREE_TX_FEE;
            if change > CONNECTOR_DUST {
                outputs.push(TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: connector_script.clone(),
                });
            }
        }

        // Commitment tx uses version 2 (not 3) because it spends from regular
        // on-chain UTXOs. Only vtxo tree txs use version 3 (BIP-431).
        let commitment_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        // Wrap in PSBT and populate witness_utxo for each boarding input
        let psbt = Psbt::from_unsigned_tx(commitment_tx.clone())
            .map_err(|e| format!("Failed to create PSBT: {e}"))?;

        // NOTE: witness_utxo is intentionally NOT set here.
        // The Go client's wallet.SignTransaction will populate it from esplora
        // with the correct script_pubkey for each boarding input.
        // Setting a dummy here would cause sighash mismatches.

        let commitment_psbt_hex = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
        };

        let commitment_txid = commitment_tx.compute_txid();

        // Build the VTXO tree (series of PSBTs from root → leaves)
        // Only off-chain receivers go into the VTXO tree; on-chain outputs
        // are already direct outputs of the commitment tx.
        // Track the output index for the VTXO root.
        // Layout: [vtxo_root (if any), onchain_exits..., connector, change]
        let vtxo_root_vout: u32 = 0;
        let vtxo_tree = if offchain_amount > 0 {
            self.build_vtxo_tree_from_commitment(
                asp_pubkey,
                &offchain_receivers,
                &vtxo_leaf_outputs,
                commitment_txid,
                vtxo_root_vout,
                offchain_amount,
            )
        } else {
            Vec::new()
        };

        // Connector output follows vtxo root + on-chain outputs
        let connector_vout =
            if offchain_amount > 0 { 1 } else { 0 } + onchain_receivers.len() as u32;

        // Build the connector tree
        let connectors = self.build_connector_tree(
            asp_pubkey,
            commitment_txid,
            connector_vout,
            connector_amount,
            offchain_receivers.len(),
        );

        Ok(CommitmentResult {
            commitment_tx: commitment_psbt_hex,
            vtxo_tree,
            connector_address,
            connectors,
        })
    }

    /// Build Taproot output scripts for each VTXO leaf receiver.
    ///
    /// Returns (script_pubkey, amount) pairs for each receiver.
    fn build_vtxo_leaf_outputs(
        &self,
        _asp_pubkey: &XOnlyPublicKey,
        receivers: &[&ReceiverInput],
    ) -> Result<Vec<(ScriptBuf, u64)>, String> {
        let mut outputs = Vec::new();

        for r in receivers {
            if !r.onchain_address.is_empty() {
                // On-chain output: parse the address directly
                let addr = Address::from_str(&r.onchain_address)
                    .map_err(|e| format!("Invalid address '{}': {e}", r.onchain_address))?
                    .require_network(self.network)
                    .map_err(|e| format!("Address network mismatch: {e}"))?;
                outputs.push((addr.script_pubkey(), r.amount));
            } else if !r.pubkey.is_empty() {
                // r.pubkey is already the final P2TR output key (VtxoTapKey) as extracted
                // from the receiver's TxOut in the intent proof tx — use it directly.
                let output_key = XOnlyPublicKey::from_str(&r.pubkey)
                    .map_err(|e| format!("Invalid receiver pubkey '{}': {e}", r.pubkey))?;
                let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(output_key);
                let script = ScriptBuf::new_p2tr_tweaked(tweaked);
                outputs.push((script, r.amount));
            } else {
                return Err("Receiver has neither pubkey nor on-chain address".to_string());
            }
        }

        Ok(outputs)
    }

    /// Build the VTXO tree from the commitment tx root output down to leaves.
    ///
    /// For ≤1 receiver: no intermediate tree transactions needed (leaf IS root).
    /// For multiple receivers: builds a binary tree of transactions.
    fn build_vtxo_tree_from_commitment(
        &self,
        asp_pubkey: &XOnlyPublicKey,
        receivers: &[&ReceiverInput],
        leaf_outputs: &[(ScriptBuf, u64)],
        parent_txid: Txid,
        parent_vout: u32,
        parent_amount: u64,
    ) -> Vec<TreeNode> {
        if receivers.is_empty() {
            // No receivers — return empty tree with just a root marker
            return vec![TreeNode {
                txid: parent_txid.to_string(),
                tx: String::new(),
                children: HashMap::new(),
            }];
        }

        // For 1-2 receivers, create a single leaf transaction spending the parent
        if receivers.len() <= VTXO_TREE_RADIX {
            let outputs: Vec<TxOut> = leaf_outputs
                .iter()
                .map(|(script, amount)| TxOut {
                    value: Amount::from_sat(*amount),
                    script_pubkey: script.clone(),
                })
                .collect();

            let tx = Transaction {
                version: Version::non_standard(3),
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: parent_txid,
                        vout: parent_vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                }],
                output: outputs,
            };

            let txid = tx.compute_txid();
            let psbt = Psbt::from_unsigned_tx(tx).expect("valid unsigned tx");

            return vec![TreeNode {
                txid: txid.to_string(),
                tx: {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
                },
                children: HashMap::new(),
            }];
        }

        // Multiple receivers: build a binary (radix-2) tree
        let mut tree_nodes = Vec::new();
        self.build_tree_level(
            asp_pubkey,
            leaf_outputs,
            parent_txid,
            parent_vout,
            parent_amount,
            &mut tree_nodes,
        );
        tree_nodes
    }

    /// Recursively build tree levels, splitting outputs into groups of RADIX.
    fn build_tree_level(
        &self,
        asp_pubkey: &XOnlyPublicKey,
        leaf_outputs: &[(ScriptBuf, u64)],
        parent_txid: Txid,
        parent_vout: u32,
        _parent_amount: u64,
        tree_nodes: &mut Vec<TreeNode>,
    ) {
        if leaf_outputs.len() <= VTXO_TREE_RADIX {
            // Base case: create a single transaction that fans out to all leaves
            // No fee deduction — tree tx amounts must match parent exactly
            let outputs: Vec<TxOut> = leaf_outputs
                .iter()
                .map(|(script, amount)| TxOut {
                    value: Amount::from_sat(*amount),
                    script_pubkey: script.clone(),
                })
                .collect();

            let tx = Transaction {
                version: Version::non_standard(3),
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: parent_txid,
                        vout: parent_vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                }],
                output: outputs,
            };

            let txid = tx.compute_txid();
            let psbt = Psbt::from_unsigned_tx(tx).expect("valid unsigned tx");

            // Leaf nodes don't have children in the tree
            let children = HashMap::new();

            tree_nodes.push(TreeNode {
                txid: txid.to_string(),
                tx: {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
                },
                children,
            });
            return;
        }

        // Split into RADIX groups and create intermediate node
        let chunk_size = leaf_outputs.len().div_ceil(VTXO_TREE_RADIX);
        let chunks: Vec<&[(ScriptBuf, u64)]> = leaf_outputs.chunks(chunk_size).collect();

        // Build intermediate outputs (P2TR to ASP for each chunk)
        let asp_script =
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(*asp_pubkey));

        let chunk_amounts: Vec<u64> = chunks
            .iter()
            .map(|chunk| chunk.iter().map(|(_, a)| a).sum())
            .collect();

        let _total_chunk: u64 = chunk_amounts.iter().sum();
        let intermediate_outputs: Vec<TxOut> = chunk_amounts
            .iter()
            .map(|&amount| TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: asp_script.clone(),
            })
            .collect();

        let intermediate_tx = Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: parent_vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: intermediate_outputs,
        };

        let intermediate_txid = intermediate_tx.compute_txid();
        let psbt = Psbt::from_unsigned_tx(intermediate_tx).expect("valid unsigned tx");

        let mut children_map = HashMap::new();

        // Recurse into each chunk
        for (i, chunk) in chunks.iter().enumerate() {
            let child_txid_placeholder = format!("pending_{intermediate_txid}_{i}");
            children_map.insert(i as u32, child_txid_placeholder);

            self.build_tree_level(
                asp_pubkey,
                chunk,
                intermediate_txid,
                i as u32,
                chunk_amounts[i],
                tree_nodes,
            );

            // Update the children map with actual child txid
            if let Some(last_node) = tree_nodes.last() {
                children_map.insert(i as u32, last_node.txid.clone());
            }
        }

        tree_nodes.push(TreeNode {
            txid: intermediate_txid.to_string(),
            tx: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
            },
            children: children_map,
        });
    }

    /// Finalize a PSBT and extract the raw transaction.
    ///
    /// Deserializes the hex-encoded PSBT, extracts the unsigned transaction
    /// (assuming all inputs have final script witnesses), and returns the
    /// consensus-serialized raw transaction hex.
    pub fn finalize_and_extract(&self, psbt_hex: &str) -> Result<String, String> {
        let psbt_bytes = hex::decode(psbt_hex).map_err(|e| format!("Invalid PSBT hex: {e}"))?;
        let mut psbt = Psbt::deserialize(&psbt_bytes)
            .map_err(|e| format!("Failed to deserialize PSBT: {e}"))?;

        // Finalize each input: assemble witness from taproot script-spend sigs
        for i in 0..psbt.inputs.len() {
            if psbt.inputs[i].final_script_witness.is_some() {
                continue; // Already finalized
            }

            // Try taproot script-path spend (most common in Ark)
            if !psbt.inputs[i].tap_script_sigs.is_empty() {
                let mut witness = Witness::default();

                // Find the leaf script and control block from tap_scripts
                let leaf_info = psbt.inputs[i].tap_scripts.iter().next();

                if let Some((_control_block, (script, _version))) = &leaf_info {
                    // Parse pubkeys from the script to determine signature order.
                    // Script format: <pubkey1> OP_CHECKSIGVERIFY <pubkey2> OP_CHECKSIG
                    // Witness order: [sig_for_pubkey2, sig_for_pubkey1] (stack: bottom→top)
                    let script_bytes = script.as_bytes();
                    let mut pubkeys_in_script: Vec<XOnlyPublicKey> = Vec::new();
                    let mut pos = 0;
                    while pos < script_bytes.len() {
                        if script_bytes[pos] == 0x20 && pos + 33 <= script_bytes.len() {
                            // 0x20 = OP_PUSHBYTES_32
                            if let Ok(pk) =
                                XOnlyPublicKey::from_slice(&script_bytes[pos + 1..pos + 33])
                            {
                                pubkeys_in_script.push(pk);
                            }
                            pos += 33;
                        } else {
                            pos += 1;
                        }
                    }

                    // Push sigs in REVERSE script order (last pubkey's sig first on stack)
                    for pk in pubkeys_in_script.iter().rev() {
                        for ((key, _leaf_hash), sig) in &psbt.inputs[i].tap_script_sigs {
                            if key == pk {
                                witness.push(sig.serialize());
                                break;
                            }
                        }
                    }
                } else {
                    // No script info — push sigs in arbitrary order
                    for ((_key, _leaf_hash), sig) in &psbt.inputs[i].tap_script_sigs {
                        witness.push(sig.serialize());
                    }
                }

                // Add the leaf script and control block
                if let Some((control_block, (script, _version))) = leaf_info {
                    witness.push(script.as_bytes());
                    witness.push(control_block.serialize());
                }

                psbt.inputs[i].final_script_witness = Some(witness);
                // Clear partial sig fields after finalization
                psbt.inputs[i].tap_script_sigs.clear();
                psbt.inputs[i].tap_scripts.clear();
                psbt.inputs[i].tap_key_sig = None;
                psbt.inputs[i].tap_internal_key = None;
                psbt.inputs[i].tap_merkle_root = None;
            } else if let Some(sig) = psbt.inputs[i].tap_key_sig {
                // Key-path spend
                let mut witness = Witness::default();
                witness.push(sig.serialize());
                psbt.inputs[i].final_script_witness = Some(witness);
                psbt.inputs[i].tap_key_sig = None;
                psbt.inputs[i].tap_internal_key = None;
                psbt.inputs[i].tap_merkle_root = None;
            }
        }

        let tx = psbt.extract_tx_unchecked_fee_rate();
        Ok(bitcoin::consensus::encode::serialize_hex(&tx))
    }

    /// Build the connector tree: single transaction with leaf outputs for each participant.
    fn build_connector_tree(
        &self,
        asp_pubkey: &XOnlyPublicKey,
        commitment_txid: Txid,
        connector_vout: u32,
        connector_amount: u64,
        participant_count: usize,
    ) -> Vec<TreeNode> {
        if participant_count == 0 {
            return vec![];
        }

        let asp_script =
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(*asp_pubkey));

        let leaf_amount = std::cmp::max(
            CONNECTOR_DUST,
            connector_amount.saturating_sub(TREE_TX_FEE) / participant_count as u64,
        );

        let outputs: Vec<TxOut> = (0..participant_count)
            .map(|_| TxOut {
                value: Amount::from_sat(leaf_amount),
                script_pubkey: asp_script.clone(),
            })
            .collect();

        let tx = Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: commitment_txid,
                    vout: connector_vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: outputs,
        };

        let txid = tx.compute_txid();
        let psbt = Psbt::from_unsigned_tx(tx).expect("valid unsigned tx");

        vec![TreeNode {
            txid: txid.to_string(),
            tx: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
            },
            children: HashMap::new(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    /// Deterministic x-only key from seed byte.
    fn xonly_key(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        let sk = SecretKey::from_slice(&bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        XOnlyPublicKey::from(pk)
    }

    fn make_intent(id: &str, receivers: Vec<ReceiverInput>) -> IntentInput {
        IntentInput {
            id: id.to_string(),
            receivers,
        }
    }

    fn make_receiver(seed: u8, amount: u64) -> ReceiverInput {
        ReceiverInput {
            pubkey: xonly_key(seed).to_string(),
            onchain_address: String::new(),
            amount,
        }
    }

    fn make_boarding(amount: u64) -> BoardingUtxo {
        BoardingUtxo {
            txid: Txid::from_byte_array([0xAA; 32]).to_string(),
            vout: 0,
            amount,
        }
    }

    /// Decode a base64-encoded PSBT string into bytes (PSBTs from build() are base64).
    fn psbt_b64_decode(b64: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64 PSBT")
    }

    /// Convert a base64 PSBT to the hex representation expected by finalize_and_extract.
    fn psbt_b64_to_hex(b64: &str) -> String {
        hex::encode(psbt_b64_decode(b64))
    }

    // ── Test 1: commitment PSBT is valid and deserializable ────────

    #[test]
    fn test_commitment_tx_is_valid_psbt() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let intent = make_intent("i1", vec![make_receiver(1, 50_000)]);
        let boarding = vec![make_boarding(100_000)];

        let result = builder.build(&asp, &[intent], &boarding).unwrap();

        // commitment_tx should be a valid base64-encoded PSBT
        let psbt_bytes = psbt_b64_decode(&result.commitment_tx);
        let psbt = Psbt::deserialize(&psbt_bytes).expect("valid PSBT");

        // Should have 1 input (the boarding UTXO)
        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        // Should have at least 2 outputs (VTXO root + connector)
        assert!(psbt.unsigned_tx.output.len() >= 2);
        // VTXO root output should carry the receiver amount
        assert_eq!(psbt.unsigned_tx.output[0].value.to_sat(), 50_000);
    }

    // ── Test 2: VTXO tree with multiple receivers produces real tree ─

    #[test]
    fn test_vtxo_tree_multiple_receivers() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let intent = make_intent(
            "i1",
            vec![
                make_receiver(1, 30_000),
                make_receiver(2, 20_000),
                make_receiver(3, 10_000),
            ],
        );
        let boarding = vec![make_boarding(200_000)];

        let result = builder.build(&asp, &[intent], &boarding).unwrap();

        // Tree should have multiple nodes
        assert!(
            !result.vtxo_tree.is_empty(),
            "VTXO tree should not be empty"
        );

        // Each tree node with a non-empty tx field should be a valid PSBT
        for node in &result.vtxo_tree {
            if !node.tx.is_empty() {
                let psbt_bytes = psbt_b64_decode(&node.tx);
                let psbt = Psbt::deserialize(&psbt_bytes).expect("tree node should be valid PSBT");
                assert!(
                    !psbt.unsigned_tx.output.is_empty(),
                    "tree tx should have outputs"
                );
            }
        }
    }

    // ── Test 3: connector tree produces valid connector outputs ─────

    #[test]
    fn test_connector_tree_valid() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let intent = make_intent(
            "i1",
            vec![make_receiver(1, 25_000), make_receiver(2, 25_000)],
        );
        let boarding = vec![make_boarding(100_000)];

        let result = builder.build(&asp, &[intent], &boarding).unwrap();

        // Connector tree should have at least one node
        assert!(
            !result.connectors.is_empty(),
            "connectors should not be empty"
        );

        // Connector node should be a valid PSBT
        let conn_node = &result.connectors[0];
        let psbt_bytes = psbt_b64_decode(&conn_node.tx);
        let psbt = Psbt::deserialize(&psbt_bytes).expect("connector PSBT");

        // Should have outputs equal to the number of receivers
        assert_eq!(psbt.unsigned_tx.output.len(), 2);

        // Connector address should be a valid bech32m P2TR
        assert!(
            result.connector_address.starts_with("bcrt1p"),
            "regtest P2TR address expected, got: {}",
            result.connector_address
        );
    }

    // ── Test 4: empty inputs rejected ──────────────────────────────

    #[test]
    fn test_build_empty_input_error() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);

        let result = builder.build(&asp, &[], &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No intents"));
    }

    // ── Test 5: deterministic output ───────────────────────────────

    #[test]
    fn test_build_deterministic() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let mk = || {
            make_intent(
                "intent-det",
                vec![ReceiverInput {
                    pubkey: xonly_key(5).to_string(),
                    onchain_address: String::new(),
                    amount: 10_000,
                }],
            )
        };
        let mkb = || make_boarding(50_000);

        let r1 = builder.build(&asp, &[mk()], &[mkb()]).unwrap();
        let r2 = builder.build(&asp, &[mk()], &[mkb()]).unwrap();

        assert_eq!(r1.commitment_tx, r2.commitment_tx);
        assert_eq!(r1.connector_address, r2.connector_address);
        assert_eq!(r1.vtxo_tree.len(), r2.vtxo_tree.len());
    }

    // ── Test 6: boarding-only (no receivers) ───────────────────────

    #[test]
    fn test_build_with_boarding_only() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let boarding = vec![make_boarding(200_000)];

        let result = builder.build(&asp, &[], &boarding).unwrap();

        // Should still produce a valid PSBT
        let psbt_bytes = psbt_b64_decode(&result.commitment_tx);
        let _psbt = Psbt::deserialize(&psbt_bytes).expect("valid PSBT");

        // VTXO tree should be minimal (empty/root-only)
        assert!(!result.vtxo_tree.is_empty());
    }

    // ── Test 7: finalize_and_extract roundtrip ────────────────────

    #[test]
    fn test_finalize_and_extract_roundtrip() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let intent = make_intent("i1", vec![make_receiver(1, 50_000)]);
        let boarding = vec![make_boarding(100_000)];

        let result = builder.build(&asp, &[intent], &boarding).unwrap();

        // finalize_and_extract expects hex-encoded PSBT (as used in production via merge path)
        let commitment_tx_hex = psbt_b64_to_hex(&result.commitment_tx);
        let raw_tx_hex = builder
            .finalize_and_extract(&commitment_tx_hex)
            .expect("finalize_and_extract should succeed");

        // The raw tx hex should be decodable as a Bitcoin transaction
        let raw_bytes = hex::decode(&raw_tx_hex).expect("valid hex output");
        let tx: Transaction =
            bitcoin::consensus::encode::deserialize(&raw_bytes).expect("valid Bitcoin tx");

        // Should match the same structure as the PSBT's unsigned tx
        let psbt_bytes = psbt_b64_decode(&result.commitment_tx);
        let psbt = Psbt::deserialize(&psbt_bytes).unwrap();
        assert_eq!(tx.compute_txid(), psbt.unsigned_tx.compute_txid());
    }

    // ── Test 8: different networks produce different addresses ─────

    #[test]
    fn test_different_networks() {
        let asp = xonly_key(10);
        let intent = make_intent("i1", vec![make_receiver(1, 10_000)]);
        let boarding = vec![make_boarding(50_000)];

        let r1 = LocalTxBuilder::new("regtest")
            .build(&asp, &[intent.clone()], &boarding)
            .unwrap();
        let r2 = LocalTxBuilder::new("mainnet")
            .build(&asp, &[intent], &boarding)
            .unwrap();

        // Same tx but different addresses
        assert!(r1.connector_address.starts_with("bcrt1p"));
        assert!(r2.connector_address.starts_with("bc1p"));
        assert_ne!(r1.connector_address, r2.connector_address);
    }
}
