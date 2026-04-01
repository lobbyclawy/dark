//! Local transaction builder for VTXO tree construction.
//!
//! Builds real Bitcoin PSBTs for commitment transactions, VTXO trees,
//! and connector trees using the `bitcoin` crate's PSBT support.
//!
//! The [`LocalTxBuilder`] struct provides the core logic. The `TxBuilder`
//! trait implementation (from `dark-core::ports`) is provided in `dark-core`
//! since `dark-bitcoin` cannot depend on `dark-core` (it's the other way).
//!
//! ## Compatibility with arkd Go
//!
//! Tree transactions use BIP-431 v3 with ephemeral anchor outputs (0-sat
//! `OP_1 OP_PUSHBYTES_2 4e73`). The batch output amount equals the sum of
//! receiver amounts — no tree fee budget is added. Tree node output scripts
//! are P2TR keys tweaked with the sweep tapscript root (a single
//! `<CSV_delay> OP_CSV OP_DROP <asp_key> OP_CHECKSIG` leaf). PSBT inputs
//! carry custom ark fields (cosigner public keys & vtxo tree expiry) using
//! key type 0xDE ("ark").

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bitcoin::psbt::raw::Key as PsbtRawKey;
use bitcoin::psbt::Psbt;
use bitcoin::script::Builder as ScriptBuilder;
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, XOnlyPublicKey,
};

#[cfg(test)]
use crate::tapscript::build_vtxo_taproot;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Default CSV delay for VTXO expiry leaves (in blocks).
const DEFAULT_CSV_DELAY: u16 = 144;

/// Radix (fan-out) of the VTXO tree.
const VTXO_TREE_RADIX: usize = 2;

/// Dust threshold for connector outputs (satoshis).
const CONNECTOR_DUST: u64 = 546;

/// Estimated fee for tree-internal transactions (conservative, in sats).
const TREE_TX_FEE: u64 = 300;

/// Anchor output: `OP_1 OP_PUSHBYTES_2 4e73` (BIP-431 ephemeral anchor).
const ANCHOR_PKSCRIPT: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];
/// Anchor output value (0 sats — ephemeral).
const ANCHOR_VALUE: u64 = 0;

/// PSBT unknown-field key type for ark protocol fields.
const ARK_PSBT_KEY_TYPE: u8 = 0xDE;

// ─── Ark PSBT field name tags ───────────────────────────────────────────────
const ARK_FIELD_COSIGNER: &[u8] = b"cosigner";
const ARK_FIELD_EXPIRY: &[u8] = b"expiry";

// ─── Helper: tree tx count ──────────────────────────────────────────────────

// NOTE: tree_fee_budget / count_tree_txs removed — the Go protocol uses
// ephemeral anchor outputs (BIP-431) for tree fees, so no fee budget is
// embedded in the batch output amount.

// ─── Public types ───────────────────────────────────────────────────────────

/// A node in a flattened transaction tree (mirrors `dark-core::domain::TxTreeNode`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TreeNode {
    pub txid: String,
    pub tx: String,
    pub children: HashMap<u32, String>,
}

/// Input descriptor for a receiver in the VTXO tree.
#[derive(Debug, Clone)]
pub struct ReceiverInput {
    /// Receiver public key (hex-encoded x-only or compressed SEC, empty for on-chain)
    pub pubkey: String,
    /// On-chain address (empty for off-chain)
    pub onchain_address: String,
    /// Amount in satoshis
    pub amount: u64,
}

/// Input descriptor for a commitment intent.
#[derive(Debug, Clone)]
pub struct IntentInput {
    pub id: String,
    pub receivers: Vec<ReceiverInput>,
    /// Cosigner public keys for this intent (hex-encoded compressed SEC pubkeys).
    /// Used to build MuSig2-aggregated tree node keys and PSBT cosigner fields.
    pub cosigners_public_keys: Vec<String>,
}

/// Boarding input descriptor.
#[derive(Debug, Clone)]
pub struct BoardingUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
}

/// Result of building a commitment transaction.
#[derive(Debug, Clone)]
pub struct CommitmentResult {
    pub commitment_tx: String,
    pub vtxo_tree: Vec<TreeNode>,
    pub connector_address: String,
    pub connectors: Vec<TreeNode>,
}

/// Local transaction builder for Bitcoin-based Ark rounds.
#[derive(Debug, Clone)]
pub struct LocalTxBuilder {
    pub network: Network,
    pub csv_delay: u16,
}

// ─── Internal tree-building data ────────────────────────────────────────────

/// A logical node in the VTXO tree (built bottom-up, then converted to PSBTs).
#[derive(Debug, Clone)]
struct VtxoNode {
    /// The total amount flowing through this node (sum of leaf receiver amounts
    /// in the subtree, plus ANCHOR_VALUE per child for branches).
    amount: i64,
    /// The P2TR script for spending *into* this node (its parent uses this as
    /// the output script at the position corresponding to this child).
    input_script: ScriptBuf,
    /// Cosigner compressed public keys (33 bytes, preserving 02/03 parity) that
    /// control this node (union of children's cosigners).
    cosigners: Vec<[u8; 33]>,
    /// Child nodes (empty for leaves).
    children: Vec<VtxoNode>,
    /// Leaf-level outputs (set only for leaf nodes).
    leaf_outputs: Vec<TxOut>,
}

impl VtxoNode {
    /// Collect output `TxOut`s that a parent transaction should create for this node's children.
    /// For a branch, one output per child (child.amount, child.input_script) + anchor.
    /// For a leaf, the leaf_outputs + anchor.
    fn outputs_with_anchor(&self) -> Vec<TxOut> {
        let mut outs = if self.children.is_empty() {
            self.leaf_outputs.clone()
        } else {
            self.children
                .iter()
                .map(|c| TxOut {
                    value: Amount::from_sat(c.amount as u64),
                    script_pubkey: c.input_script.clone(),
                })
                .collect()
        };
        // Append ephemeral anchor output
        outs.push(TxOut {
            value: Amount::from_sat(ANCHOR_VALUE),
            script_pubkey: ScriptBuf::from_bytes(ANCHOR_PKSCRIPT.to_vec()),
        });
        outs
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Build the sweep (CSV expiry) tapscript for the ASP key.
///
/// Script: `<csv_delay> OP_CSV OP_DROP <asp_x_only> OP_CHECKSIG`
fn sweep_script(asp_pubkey: &XOnlyPublicKey, csv_delay: u16) -> ScriptBuf {
    ScriptBuilder::new()
        .push_int(csv_delay as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(asp_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Compute the Taproot merkle root for a single-leaf tapscript tree.
fn single_leaf_merkle_root(script: &ScriptBuf) -> bitcoin::taproot::TapNodeHash {
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    bitcoin::taproot::TapNodeHash::from_byte_array(leaf_hash.to_byte_array())
}

/// Produce a P2TR script for a key tweaked with `merkle_root`.
///
/// Equivalent to Go's `txscript.ComputeTaprootOutputKey(key, merkle_root)`.
fn p2tr_with_merkle_root(
    key: &XOnlyPublicKey,
    merkle_root: bitcoin::taproot::TapNodeHash,
) -> ScriptBuf {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let (tweaked, _parity) = key.tap_tweak(&secp, Some(merkle_root));
    ScriptBuf::new_p2tr_tweaked(tweaked)
}

/// Produce a P2TR script for a key-path-only output (no tapscript tree).
fn asp_p2tr_script(key: &XOnlyPublicKey) -> ScriptBuf {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let (tweaked, _parity) = key.tap_tweak(&secp, None);
    ScriptBuf::new_p2tr_tweaked(tweaked)
}

/// Parse an x-only public key from a hex string that may be either
/// 32-byte x-only (64 hex) or 33-byte compressed SEC (66 hex).
fn parse_xonly(hex_str: &str) -> Result<XOnlyPublicKey, String> {
    XOnlyPublicKey::from_str(hex_str).or_else(|_| {
        let bytes =
            hex::decode(hex_str).map_err(|e| format!("Invalid pubkey hex '{hex_str}': {e}"))?;
        let compressed = bitcoin::secp256k1::PublicKey::from_slice(&bytes)
            .map_err(|e| format!("Invalid compressed pubkey '{hex_str}': {e}"))?;
        Ok(compressed.x_only_public_key().0)
    })
}

/// Parse a hex-encoded public key into a 33-byte compressed SEC representation.
///
/// Accepts both 32-byte x-only keys (prepends 0x02) and 33-byte compressed keys
/// (preserves the original 02/03 prefix so that MuSig2 parity is maintained).
fn parse_compressed(hex_str: &str) -> Result<[u8; 33], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid pubkey hex '{hex_str}': {e}"))?;
    match bytes.len() {
        33 => {
            // Validate it's a real compressed key
            bitcoin::secp256k1::PublicKey::from_slice(&bytes)
                .map_err(|e| format!("Invalid compressed pubkey '{hex_str}': {e}"))?;
            let mut buf = [0u8; 33];
            buf.copy_from_slice(&bytes);
            Ok(buf)
        }
        32 => {
            // x-only: prepend 0x02 (even parity)
            let mut buf = [0u8; 33];
            buf[0] = 0x02;
            buf[1..].copy_from_slice(&bytes);
            // Validate
            bitcoin::secp256k1::PublicKey::from_slice(&buf)
                .map_err(|e| format!("Invalid x-only pubkey '{hex_str}': {e}"))?;
            Ok(buf)
        }
        n => Err(format!(
            "Invalid pubkey length for '{hex_str}': expected 32 or 33 bytes, got {n}"
        )),
    }
}

/// Extract the x-only public key from a 33-byte compressed key.
fn compressed_to_xonly(key: &[u8; 33]) -> Result<XOnlyPublicKey, String> {
    let pk = bitcoin::secp256k1::PublicKey::from_slice(key)
        .map_err(|e| format!("Invalid compressed key: {e}"))?;
    Ok(pk.x_only_public_key().0)
}

/// Add a cosigner PSBT unknown field to `psbt.inputs[input_idx]`.
///
/// The `key` must be a 33-byte compressed SEC public key (with correct 02/03
/// parity prefix). This is written verbatim into the PSBT so that Go's
/// `btcec.ParsePubKey` recovers the original point and `musig2.Sign` can
/// match it against `signer.PubKey()`.
fn add_cosigner_field(psbt: &mut Psbt, input_idx: usize, index: u32, key: &[u8; 33]) {
    let mut field_key = vec![ARK_PSBT_KEY_TYPE];
    field_key.extend_from_slice(ARK_FIELD_COSIGNER);
    field_key.extend_from_slice(&index.to_be_bytes());
    let raw_key = PsbtRawKey {
        type_value: field_key[0],
        key: field_key[1..].to_vec(),
    };
    psbt.inputs[input_idx].unknown.insert(raw_key, key.to_vec());
}

/// Add a vtxo tree expiry PSBT unknown field to `psbt.inputs[input_idx]`.
fn add_expiry_field(psbt: &mut Psbt, input_idx: usize, csv_delay: u16) {
    // Encode as minimal little-endian bytes of the BIP-68 sequence number.
    // For block-based locks < 65536 this is just the delay as LE u16/u32.
    let sequence = csv_delay as u32; // block-based, type flag = 0
    let le_bytes = sequence.to_le_bytes();
    // Trim trailing zero bytes but keep at least 1 byte
    let mut num_bytes = 4;
    while num_bytes > 1 && le_bytes[num_bytes - 1] == 0 {
        num_bytes -= 1;
    }
    // If MSB of last byte is set, add one more byte to avoid sign ambiguity
    if le_bytes[num_bytes - 1] & 0x80 != 0 {
        num_bytes += 1;
    }

    let mut field_key = vec![ARK_PSBT_KEY_TYPE];
    field_key.extend_from_slice(ARK_FIELD_EXPIRY);
    let raw_key = PsbtRawKey {
        type_value: field_key[0],
        key: field_key[1..].to_vec(),
    };
    psbt.inputs[input_idx]
        .unknown
        .insert(raw_key, le_bytes[..num_bytes].to_vec());
}

// ─── LocalTxBuilder ─────────────────────────────────────────────────────────

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

    // ── Main build entry point ──────────────────────────────────────────────

    /// Build a commitment transaction, VTXO tree, and connector tree.
    ///
    /// ## Commitment tx output layout (matches Go `createCommitmentTx`):
    ///
    /// | Index | Content                              |
    /// |-------|--------------------------------------|
    /// | 0     | Batch output (VTXO tree root)        |
    /// | 1     | Connector output                     |
    /// |  2+   | On-chain (collaborative exit) outputs|
    /// |  N    | Wallet change (added later by ASP)   |
    pub fn build(
        &self,
        asp_pubkey: &XOnlyPublicKey,
        intents: &[IntentInput],
        boarding_inputs: &[BoardingUtxo],
    ) -> Result<CommitmentResult, String> {
        if intents.is_empty() && boarding_inputs.is_empty() {
            return Err("No intents or boarding inputs provided".to_string());
        }

        // ── Sweep tapscript root ────────────────────────────────────────────
        let sweep_sc = sweep_script(asp_pubkey, self.csv_delay);
        let sweep_merkle_root = single_leaf_merkle_root(&sweep_sc);

        // ── Separate receivers ──────────────────────────────────────────────
        // Collect per-intent leaf data (offchain only).
        struct LeafData {
            outputs: Vec<TxOut>,
            cosigners: Vec<[u8; 33]>,
            amount: i64,
        }
        let mut leaves: Vec<LeafData> = Vec::new();
        let mut onchain_outputs: Vec<TxOut> = Vec::new();

        for intent in intents {
            let mut leaf_outs: Vec<TxOut> = Vec::new();
            for r in &intent.receivers {
                if !r.onchain_address.is_empty() {
                    let addr = Address::from_str(&r.onchain_address)
                        .map_err(|e| format!("Invalid address '{}': {e}", r.onchain_address))?
                        .require_network(self.network)
                        .map_err(|e| format!("Address network mismatch: {e}"))?;
                    onchain_outputs.push(TxOut {
                        value: Amount::from_sat(r.amount),
                        script_pubkey: addr.script_pubkey(),
                    });
                } else if !r.pubkey.is_empty() {
                    let output_key = parse_xonly(&r.pubkey)?;
                    // Leaf VTXO output: simple P2TR to receiver pubkey (no tweak).
                    // This matches Go's `script.P2TRScript(pubkey)` which does
                    // `txscript.PayToTaprootScript(pubkey)` = OP_1 <32-byte-key>.
                    // Bitcoin-rs `dangerous_assume_tweaked` produces the same encoding.
                    let tweaked =
                        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(output_key);
                    let script = ScriptBuf::new_p2tr_tweaked(tweaked);
                    leaf_outs.push(TxOut {
                        value: Amount::from_sat(r.amount),
                        script_pubkey: script,
                    });
                } else {
                    return Err("Receiver has neither pubkey nor on-chain address".to_string());
                }
            }

            if leaf_outs.is_empty() {
                continue; // all receivers were on-chain
            }

            let leaf_amount: i64 = leaf_outs.iter().map(|o| o.value.to_sat() as i64).sum();

            // Parse cosigner keys for this intent (preserve compressed format
            // so that the PSBT stores the correct 02/03 parity byte — required
            // by btcec's musig2.Sign which does a full-point equality check).
            let cosigners: Vec<[u8; 33]> = if intent.cosigners_public_keys.is_empty() {
                // Fallback: use receiver pubkeys as cosigners (best effort)
                intent
                    .receivers
                    .iter()
                    .filter(|r| !r.pubkey.is_empty() && r.onchain_address.is_empty())
                    .filter_map(|r| parse_compressed(&r.pubkey).ok())
                    .collect()
            } else {
                intent
                    .cosigners_public_keys
                    .iter()
                    .map(|k| parse_compressed(k))
                    .collect::<Result<Vec<_>, _>>()?
            };

            leaves.push(LeafData {
                outputs: leaf_outs,
                cosigners,
                amount: leaf_amount,
            });
        }

        let _offchain_amount: i64 = leaves.iter().map(|l| l.amount).sum();
        let _total_boarding: u64 = boarding_inputs.iter().map(|b| b.amount).sum();

        // ── Build VTXO tree bottom-up ───────────────────────────────────────
        let vtxo_nodes: Vec<VtxoNode> = leaves
            .iter()
            .map(|l| {
                let input_script = self.compute_input_script(&l.cosigners, sweep_merkle_root)?;
                Ok(VtxoNode {
                    amount: l.amount,
                    input_script,
                    cosigners: l.cosigners.clone(),
                    children: Vec::new(),
                    leaf_outputs: l.outputs.clone(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        let vtxo_root = if vtxo_nodes.is_empty() {
            None
        } else {
            Some(self.build_tree_bottom_up(vtxo_nodes, sweep_merkle_root)?)
        };

        // ── Batch output ────────────────────────────────────────────────────
        // The batch output amount = sum of receiver amounts (no tree fee budget).
        // The script is derived from the root node's cosigner-aggregated key
        // tweaked with the sweep tapscript root.
        let batch_output = vtxo_root.as_ref().map(|root| TxOut {
            value: Amount::from_sat(root.amount as u64),
            script_pubkey: root.input_script.clone(),
        });

        // ── Connector output ────────────────────────────────────────────────
        let connector_script = asp_p2tr_script(asp_pubkey);
        let connector_address = Address::from_script(&connector_script, self.network)
            .map_err(|e| format!("Failed to derive connector address: {e}"))?
            .to_string();

        let num_connectors = intents
            .iter()
            .flat_map(|i| i.receivers.iter())
            .filter(|r| r.onchain_address.is_empty())
            .count();

        // In Go, connector amount comes from `BuildConnectorOutput` which uses
        // the connector tree leaf amounts summed up. For simplicity, we use
        // CONNECTOR_DUST per connector leaf.
        let connector_amount = if num_connectors > 0 {
            (num_connectors as u64) * CONNECTOR_DUST
        } else {
            0
        };

        // ── Build commitment tx ─────────────────────────────────────────────
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

        // Output layout: [batch, connector, onchain_exits...]
        // The server wallet adds change + fee input later.
        let mut outputs: Vec<TxOut> = Vec::new();

        tracing::info!(
            onchain_output_count = onchain_outputs.len(),
            offchain_leaf_count = leaves.len(),
            batch_output_sats = batch_output.as_ref().map(|o| o.value.to_sat()).unwrap_or(0),
            "build_commitment_tx: output summary"
        );

        // Index 0: batch output (if any offchain receivers)
        if let Some(bo) = &batch_output {
            outputs.push(bo.clone());
        }

        // Index 1: connector output (if any)
        if connector_amount > 0 {
            // When there's no batch output, we need something at index 0 first.
            // Go puts the first onchain output at index 0 in that case.
            if batch_output.is_none() && !onchain_outputs.is_empty() {
                outputs.push(onchain_outputs.remove(0));
            }
            outputs.push(TxOut {
                value: Amount::from_sat(connector_amount),
                script_pubkey: connector_script.clone(),
            });
        }

        // Remaining on-chain outputs
        outputs.extend(onchain_outputs.iter().cloned());

        let commitment_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        let psbt = Psbt::from_unsigned_tx(commitment_tx.clone())
            .map_err(|e| format!("Failed to create PSBT: {e}"))?;

        let commitment_psbt_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
        };

        let commitment_txid = commitment_tx.compute_txid();

        // ── Build VTXO tree PSBTs ───────────────────────────────────────────
        let vtxo_tree = if let Some(root) = &vtxo_root {
            let root_outpoint = OutPoint {
                txid: commitment_txid,
                vout: 0,
            };
            self.vtxo_node_to_psbts(root, &root_outpoint)?
        } else {
            Vec::new()
        };

        // ── Build connector tree ────────────────────────────────────────────
        let connector_vout = if batch_output.is_some() { 1u32 } else { 0u32 };
        let connectors = self.build_connector_tree(
            asp_pubkey,
            commitment_txid,
            connector_vout,
            connector_amount,
            num_connectors,
        );

        Ok(CommitmentResult {
            commitment_tx: commitment_psbt_b64,
            vtxo_tree,
            connector_address,
            connectors,
        })
    }

    // ── Sweep-tweaked P2TR for a set of cosigner keys ───────────────────────

    /// Compute the P2TR input script for a tree node given its cosigner keys.
    ///
    /// For a single cosigner key, this is equivalent to Go's:
    /// ```text
    /// aggregatedKey, _ := AggregateKeys([cosigner], sweepTapTreeRoot)
    /// script := P2TRScript(aggregatedKey.FinalKey)
    /// ```
    /// which, for a single key, is `P2TR(ComputeTaprootOutputKey(cosigner, sweepRoot))`.
    fn compute_input_script(
        &self,
        cosigners: &[[u8; 33]],
        sweep_root: bitcoin::taproot::TapNodeHash,
    ) -> Result<ScriptBuf, String> {
        if cosigners.is_empty() {
            return Err("No cosigner keys for tree node".to_string());
        }

        if cosigners.len() == 1 {
            // Single cosigner: classic P2TR with sweep tapscript tweak.
            // For single-key, Go's AggregateKeys returns ComputeTaprootOutputKey(pk, root).
            let xonly = compressed_to_xonly(&cosigners[0])?;
            Ok(p2tr_with_merkle_root(&xonly, sweep_root))
        } else {
            // Multiple cosigners: MuSig2 aggregate + sweep tweak.
            // Pass original compressed keys (with real 02/03 parity) to match
            // Go's btcec musig2.AggregateKeys which uses full compressed keys.
            use crate::tree::aggregate_keys;
            let agg = aggregate_keys(cosigners)
                .map_err(|e| format!("MuSig2 key aggregation failed: {e}"))?;
            Ok(p2tr_with_merkle_root(&agg, sweep_root))
        }
    }

    // ── Bottom-up tree construction ─────────────────────────────────────────

    /// Build the VTXO tree bottom-up from leaf VtxoNodes.
    fn build_tree_bottom_up(
        &self,
        mut nodes: Vec<VtxoNode>,
        sweep_root: bitcoin::taproot::TapNodeHash,
    ) -> Result<VtxoNode, String> {
        while nodes.len() > 1 {
            nodes = self.create_upper_level(nodes, sweep_root)?;
        }
        Ok(nodes.into_iter().next().unwrap())
    }

    /// Merge nodes pairwise (radix-2) to create the next tree level.
    fn create_upper_level(
        &self,
        nodes: Vec<VtxoNode>,
        sweep_root: bitcoin::taproot::TapNodeHash,
    ) -> Result<Vec<VtxoNode>, String> {
        if nodes.len() <= 1 {
            return Ok(nodes);
        }

        let radix = VTXO_TREE_RADIX;

        if nodes.len() < radix {
            return self.create_upper_level(nodes, sweep_root);
        }

        let remainder = nodes.len() % radix;
        if remainder != 0 {
            let split = nodes.len() - remainder;
            let (main, rest) = (nodes[..split].to_vec(), nodes[split..].to_vec());
            let mut groups = self.create_upper_level(main, sweep_root)?;
            groups.extend(rest);
            return Ok(groups);
        }

        let mut groups = Vec::new();
        for chunk in nodes.chunks(radix) {
            // Collect unique cosigners from all children (compare by x-only
            // portion so that duplicate keys with different parity are merged).
            let mut all_cosigners: Vec<[u8; 33]> = Vec::new();
            for child in chunk {
                for k in &child.cosigners {
                    if !all_cosigners.iter().any(|c| c[1..] == k[1..]) {
                        all_cosigners.push(*k);
                    }
                }
            }

            let input_script = self.compute_input_script(&all_cosigners, sweep_root)?;

            // Branch amount = sum of children amounts + ANCHOR_VALUE per child
            let branch_amount: i64 = chunk.iter().map(|c| c.amount + ANCHOR_VALUE as i64).sum();

            groups.push(VtxoNode {
                amount: branch_amount,
                input_script,
                cosigners: all_cosigners,
                children: chunk.to_vec(),
                leaf_outputs: Vec::new(),
            });
        }
        Ok(groups)
    }

    // ── Convert VtxoNode tree to flat PSBT list ─────────────────────────────

    /// Recursively convert a VtxoNode tree into a flat list of `TreeNode`s (PSBTs).
    fn vtxo_node_to_psbts(
        &self,
        node: &VtxoNode,
        input_outpoint: &OutPoint,
    ) -> Result<Vec<TreeNode>, String> {
        let outputs = node.outputs_with_anchor();

        let tx = Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: *input_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: outputs,
        };

        let txid = tx.compute_txid();
        let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| format!("PSBT error: {e}"))?;

        // Add cosigner fields to input[0]
        for (i, key) in node.cosigners.iter().enumerate() {
            add_cosigner_field(&mut psbt, 0, i as u32, key);
        }
        // Add vtxo tree expiry to input[0]
        add_expiry_field(&mut psbt, 0, self.csv_delay);

        // Sighash type
        psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from(
            bitcoin::sighash::TapSighashType::Default,
        ));

        let psbt_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
        };

        let mut all_nodes = Vec::new();
        let mut children_map: HashMap<u32, String> = HashMap::new();

        if node.children.is_empty() {
            // Leaf: no children
            all_nodes.push(TreeNode {
                txid: txid.to_string(),
                tx: psbt_b64,
                children: children_map,
            });
        } else {
            // Branch: recurse into children
            for (i, child) in node.children.iter().enumerate() {
                let child_outpoint = OutPoint {
                    txid,
                    vout: i as u32,
                };
                let child_nodes = self.vtxo_node_to_psbts(child, &child_outpoint)?;
                // The direct child's PSBT is the LAST element because
                // vtxo_node_to_psbts pushes descendants first, then self.
                if let Some(last) = child_nodes.last() {
                    children_map.insert(i as u32, last.txid.clone());
                }
                all_nodes.extend(child_nodes);
            }
            all_nodes.push(TreeNode {
                txid: txid.to_string(),
                tx: psbt_b64,
                children: children_map,
            });
        }

        Ok(all_nodes)
    }

    // ── Finalize and extract ────────────────────────────────────────────────

    /// Finalize a PSBT and extract the raw transaction.
    pub fn finalize_and_extract(&self, psbt_hex: &str) -> Result<String, String> {
        let psbt_bytes = hex::decode(psbt_hex).map_err(|e| format!("Invalid PSBT hex: {e}"))?;
        let mut psbt = Psbt::deserialize(&psbt_bytes)
            .map_err(|e| format!("Failed to deserialize PSBT: {e}"))?;

        for i in 0..psbt.inputs.len() {
            if psbt.inputs[i].final_script_witness.is_some() {
                continue;
            }

            if !psbt.inputs[i].tap_script_sigs.is_empty() {
                let mut witness = Witness::default();

                let leaf_info = {
                    use bitcoin::taproot::TapLeafHash;
                    let signed_leaf_hashes: std::collections::HashSet<TapLeafHash> = psbt.inputs[i]
                        .tap_script_sigs
                        .keys()
                        .map(|(_, lh)| *lh)
                        .collect();
                    psbt.inputs[i]
                        .tap_scripts
                        .iter()
                        .find(|(_, (script, version))| {
                            let lh = TapLeafHash::from_script(script, *version);
                            signed_leaf_hashes.contains(&lh)
                        })
                        .or_else(|| psbt.inputs[i].tap_scripts.iter().next())
                };

                if let Some((_control_block, (script, _version))) = &leaf_info {
                    let script_bytes = script.as_bytes();
                    let mut pubkeys_in_script: Vec<XOnlyPublicKey> = Vec::new();
                    let mut pos = 0;
                    while pos < script_bytes.len() {
                        if script_bytes[pos] == 0x20 && pos + 33 <= script_bytes.len() {
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

                    for pk in pubkeys_in_script.iter().rev() {
                        for ((key, _leaf_hash), sig) in &psbt.inputs[i].tap_script_sigs {
                            if key == pk {
                                witness.push(sig.serialize());
                                break;
                            }
                        }
                    }
                } else {
                    for ((_key, _leaf_hash), sig) in &psbt.inputs[i].tap_script_sigs {
                        witness.push(sig.serialize());
                    }
                }

                if let Some((control_block, (script, _version))) = leaf_info {
                    witness.push(script.as_bytes());
                    witness.push(control_block.serialize());
                }

                psbt.inputs[i].final_script_witness = Some(witness);
                psbt.inputs[i].tap_script_sigs.clear();
                psbt.inputs[i].tap_scripts.clear();
                psbt.inputs[i].tap_key_sig = None;
                psbt.inputs[i].tap_internal_key = None;
                psbt.inputs[i].tap_merkle_root = None;
            } else if let Some(sig) = psbt.inputs[i].tap_key_sig {
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

    // ── Connector tree ──────────────────────────────────────────────────────

    /// Build the connector tree.
    fn build_connector_tree(
        &self,
        asp_pubkey: &XOnlyPublicKey,
        commitment_txid: Txid,
        connector_vout: u32,
        connector_amount: u64,
        participant_count: usize,
    ) -> Vec<TreeNode> {
        if participant_count == 0 || connector_amount == 0 {
            return vec![];
        }

        let asp_script = asp_p2tr_script(asp_pubkey);

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

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

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
            receivers: receivers.clone(),
            cosigners_public_keys: receivers
                .iter()
                .filter(|r| !r.pubkey.is_empty())
                .map(|r| r.pubkey.clone())
                .collect(),
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

    fn psbt_b64_decode(b64: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64 PSBT")
    }

    fn psbt_b64_to_hex(b64: &str) -> String {
        hex::encode(psbt_b64_decode(b64))
    }

    // ── Test: commitment tx layout ──────────────────────────────────────

    #[test]
    fn test_commitment_tx_is_valid_psbt() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let intent = make_intent("i1", vec![make_receiver(1, 50_000)]);
        let boarding = vec![make_boarding(100_000)];

        let result = builder.build(&asp, &[intent], &boarding).unwrap();

        let psbt_bytes = psbt_b64_decode(&result.commitment_tx);
        let psbt = Psbt::deserialize(&psbt_bytes).expect("valid PSBT");

        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        // At least batch + connector
        assert!(psbt.unsigned_tx.output.len() >= 2);
        // Batch output (index 0) = receiver amount (no tree fees)
        assert_eq!(psbt.unsigned_tx.output[0].value.to_sat(), 50_000);
    }

    // ── Test: VTXO tree with anchor outputs ─────────────────────────────

    #[test]
    fn test_vtxo_tree_has_anchor_outputs() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let intent = make_intent("i1", vec![make_receiver(1, 50_000)]);
        let boarding = vec![make_boarding(100_000)];

        let result = builder.build(&asp, &[intent], &boarding).unwrap();

        for node in &result.vtxo_tree {
            if node.tx.is_empty() {
                continue;
            }
            let psbt_bytes = psbt_b64_decode(&node.tx);
            let psbt = Psbt::deserialize(&psbt_bytes).expect("tree node PSBT");
            let last_out = psbt.unsigned_tx.output.last().expect("has outputs");
            assert_eq!(
                last_out.value.to_sat(),
                ANCHOR_VALUE,
                "last output must be anchor"
            );
            assert_eq!(
                last_out.script_pubkey.as_bytes(),
                &ANCHOR_PKSCRIPT,
                "anchor script must match"
            );
        }
    }

    // ── Test: tree output amounts match batch output ────────────────────

    #[test]
    fn test_tree_root_outputs_sum_matches_batch() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let intent = make_intent(
            "i1",
            vec![make_receiver(1, 30_000), make_receiver(2, 20_000)],
        );
        let boarding = vec![make_boarding(200_000)];

        let result = builder.build(&asp, &[intent], &boarding).unwrap();

        let commitment_psbt_bytes = psbt_b64_decode(&result.commitment_tx);
        let commitment_psbt = Psbt::deserialize(&commitment_psbt_bytes).unwrap();
        let batch_amount = commitment_psbt.unsigned_tx.output[0].value.to_sat();

        // Find the root tree node (last one pushed for root)
        let root_node = result.vtxo_tree.last().expect("tree has root");
        let root_psbt_bytes = psbt_b64_decode(&root_node.tx);
        let root_psbt = Psbt::deserialize(&root_psbt_bytes).unwrap();
        let root_output_sum: u64 = root_psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .sum();

        assert_eq!(
            root_output_sum, batch_amount,
            "tree root output sum must equal batch output amount"
        );
    }

    // ── Test: PSBT has cosigner and expiry fields ───────────────────────

    #[test]
    fn test_tree_psbt_has_ark_fields() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let intent = make_intent("i1", vec![make_receiver(1, 50_000)]);
        let boarding = vec![make_boarding(100_000)];

        let result = builder.build(&asp, &[intent], &boarding).unwrap();

        let node = result.vtxo_tree.first().expect("has node");
        let psbt_bytes = psbt_b64_decode(&node.tx);
        let psbt = Psbt::deserialize(&psbt_bytes).unwrap();

        let unknowns = &psbt.inputs[0].unknown;
        let has_cosigner = unknowns
            .keys()
            .any(|k| k.key.starts_with(ARK_FIELD_COSIGNER));
        let has_expiry = unknowns.keys().any(|k| k.key.starts_with(ARK_FIELD_EXPIRY));

        assert!(has_cosigner, "PSBT input must have cosigner field");
        assert!(has_expiry, "PSBT input must have expiry field");
    }

    // ── Test: empty inputs rejected ─────────────────────────────────────

    #[test]
    fn test_build_empty_input_error() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);

        let result = builder.build(&asp, &[], &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No intents"));
    }

    // ── Test: deterministic output ──────────────────────────────────────

    #[test]
    fn test_build_deterministic() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let mk = || make_intent("intent-det", vec![make_receiver(5, 10_000)]);
        let mkb = || make_boarding(50_000);

        let r1 = builder.build(&asp, &[mk()], &[mkb()]).unwrap();
        let r2 = builder.build(&asp, &[mk()], &[mkb()]).unwrap();

        assert_eq!(r1.commitment_tx, r2.commitment_tx);
        assert_eq!(r1.connector_address, r2.connector_address);
        assert_eq!(r1.vtxo_tree.len(), r2.vtxo_tree.len());
    }

    // ── Test: finalize_and_extract roundtrip ────────────────────────────

    #[test]
    fn test_finalize_and_extract_roundtrip() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);
        let intent = make_intent("i1", vec![make_receiver(1, 50_000)]);
        let boarding = vec![make_boarding(100_000)];

        let result = builder.build(&asp, &[intent], &boarding).unwrap();

        let commitment_tx_hex = psbt_b64_to_hex(&result.commitment_tx);
        let raw_tx_hex = builder
            .finalize_and_extract(&commitment_tx_hex)
            .expect("finalize_and_extract should succeed");

        let raw_bytes = hex::decode(&raw_tx_hex).expect("valid hex output");
        let tx: Transaction =
            bitcoin::consensus::encode::deserialize(&raw_bytes).expect("valid Bitcoin tx");

        let psbt_bytes = psbt_b64_decode(&result.commitment_tx);
        let psbt = Psbt::deserialize(&psbt_bytes).unwrap();
        assert_eq!(tx.compute_txid(), psbt.unsigned_tx.compute_txid());
    }

    // ── Test: different networks produce different addresses ────────────

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

        assert!(r1.connector_address.starts_with("bcrt1p"));
        assert!(r2.connector_address.starts_with("bc1p"));
        assert_ne!(r1.connector_address, r2.connector_address);
    }

    // ── Test: multiple receivers tree ───────────────────────────────────

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

        assert!(
            !result.vtxo_tree.is_empty(),
            "VTXO tree should not be empty"
        );

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

    // ── Test: two separate intents (E2E scenario) ───────────────────────

    /// Mimics the Go E2E test: two clients each boarding with one receiver.
    /// Validates the same invariant the Go client checks:
    /// sum of root tx outputs == batch output amount at index 0.
    #[test]
    fn test_two_intents_root_sum_matches_batch() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);

        // Two separate intents (like Alice and Bob in Go e2e)
        let intent_a = make_intent("alice", vec![make_receiver(1, 21_000)]);
        let intent_b = make_intent("bob", vec![make_receiver(2, 21_000)]);
        let boarding = vec![make_boarding(100_000)];

        let result = builder
            .build(&asp, &[intent_a, intent_b], &boarding)
            .unwrap();

        let commitment_psbt_bytes = psbt_b64_decode(&result.commitment_tx);
        let commitment_psbt = Psbt::deserialize(&commitment_psbt_bytes).unwrap();
        let batch_amount = commitment_psbt.unsigned_tx.output[0].value.to_sat();

        // Find root: node not in any children map
        let child_txids: std::collections::HashSet<String> = result
            .vtxo_tree
            .iter()
            .flat_map(|n| n.children.values())
            .cloned()
            .collect();
        let root_node = result
            .vtxo_tree
            .iter()
            .find(|n| !child_txids.contains(&n.txid))
            .expect("tree must have a root");

        let root_psbt_bytes = psbt_b64_decode(&root_node.tx);
        let root_psbt = Psbt::deserialize(&root_psbt_bytes).unwrap();
        let root_output_sum: u64 = root_psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .sum();

        // Also verify all intermediate nodes
        for node in &result.vtxo_tree {
            if node.children.is_empty() {
                continue; // leaf
            }
            let node_psbt_bytes = psbt_b64_decode(&node.tx);
            let node_psbt = Psbt::deserialize(&node_psbt_bytes).unwrap();

            for (&child_idx, child_txid) in &node.children {
                let child_node = result
                    .vtxo_tree
                    .iter()
                    .find(|n| &n.txid == child_txid)
                    .expect("child must exist");
                let child_psbt_bytes = psbt_b64_decode(&child_node.tx);
                let child_psbt = Psbt::deserialize(&child_psbt_bytes).unwrap();
                let child_output_sum: u64 = child_psbt
                    .unsigned_tx
                    .output
                    .iter()
                    .map(|o| o.value.to_sat())
                    .sum();
                let parent_output_value = node_psbt.unsigned_tx.output[child_idx as usize]
                    .value
                    .to_sat();

                assert_eq!(
                    child_output_sum, parent_output_value,
                    "child {} output sum {} != parent output[{}] {} (Go Validate check)",
                    child_txid, child_output_sum, child_idx, parent_output_value
                );
            }
        }

        assert_eq!(
            root_output_sum, batch_amount,
            "root output sum {} != batch amount {} (Go ValidateVtxoTree check)",
            root_output_sum, batch_amount
        );
    }

    /// Test with 3 intents (odd number, tests remainder handling)
    #[test]
    fn test_three_intents_root_sum_matches_batch() {
        let builder = LocalTxBuilder::new("regtest");
        let asp = xonly_key(10);

        let intent_a = make_intent("a", vec![make_receiver(1, 10_000)]);
        let intent_b = make_intent("b", vec![make_receiver(2, 20_000)]);
        let intent_c = make_intent("c", vec![make_receiver(3, 15_000)]);
        let boarding = vec![make_boarding(200_000)];

        let result = builder
            .build(&asp, &[intent_a, intent_b, intent_c], &boarding)
            .unwrap();

        let commitment_psbt_bytes = psbt_b64_decode(&result.commitment_tx);
        let commitment_psbt = Psbt::deserialize(&commitment_psbt_bytes).unwrap();
        let batch_amount = commitment_psbt.unsigned_tx.output[0].value.to_sat();

        let child_txids: std::collections::HashSet<String> = result
            .vtxo_tree
            .iter()
            .flat_map(|n| n.children.values())
            .cloned()
            .collect();
        let root_node = result
            .vtxo_tree
            .iter()
            .find(|n| !child_txids.contains(&n.txid))
            .expect("tree must have a root");

        let root_psbt_bytes = psbt_b64_decode(&root_node.tx);
        let root_psbt = Psbt::deserialize(&root_psbt_bytes).unwrap();
        let root_output_sum: u64 = root_psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .sum();

        assert_eq!(
            root_output_sum, batch_amount,
            "3-intent: root output sum {} != batch amount {}",
            root_output_sum, batch_amount
        );
    }
}
