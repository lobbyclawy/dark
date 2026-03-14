//! Local transaction builder for VTXO tree construction.
//!
//! Builds commitment transactions with SHA-256 commitment hashes over
//! intent data, producing VTXO tree nodes, connector trees, and
//! deterministic connector addresses.
//!
//! The [`LocalTxBuilder`] struct provides the core logic. The `TxBuilder`
//! trait implementation (from `arkd-core::ports`) is provided in `arkd-core`
//! since `arkd-bitcoin` cannot depend on `arkd-core` (it's the other way).

use std::collections::HashMap;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::XOnlyPublicKey;

/// A node in a flattened transaction tree (mirrors `arkd-core::domain::TxTreeNode`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TreeNode {
    /// Transaction ID
    pub txid: String,
    /// Hex-encoded transaction data
    pub tx: String,
    /// Maps output index → child txid
    pub children: HashMap<u32, String>,
}

/// Input descriptor for a receiver in the VTXO tree.
#[derive(Debug, Clone)]
pub struct ReceiverInput {
    /// Receiver public key (empty for on-chain)
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
    /// Outpoint txid
    pub txid: String,
    /// Outpoint vout
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
}

/// Result of building a commitment transaction.
#[derive(Debug, Clone)]
pub struct CommitmentResult {
    /// Hex-encoded commitment transaction
    pub commitment_tx: String,
    /// VTXO tree nodes
    pub vtxo_tree: Vec<TreeNode>,
    /// Connector address
    pub connector_address: String,
    /// Connector tree nodes
    pub connectors: Vec<TreeNode>,
}

/// Local transaction builder for Bitcoin-based Ark rounds.
///
/// Produces commitment transactions by computing a SHA-256 hash over
/// serialized intent data, building VTXO tree nodes for each receiver,
/// and generating a deterministic connector address.
#[derive(Debug, Clone)]
pub struct LocalTxBuilder {
    /// Network name used for connector address derivation
    pub network: String,
}

impl LocalTxBuilder {
    /// Create a new `LocalTxBuilder`.
    pub fn new(network: impl Into<String>) -> Self {
        Self {
            network: network.into(),
        }
    }

    /// Build a commitment transaction from intents and boarding inputs.
    ///
    /// Returns an error string if no intents or boarding inputs are provided.
    pub fn build(
        &self,
        signer_pubkey: &XOnlyPublicKey,
        intents: &[IntentInput],
        boarding_inputs: &[BoardingUtxo],
    ) -> Result<CommitmentResult, String> {
        if intents.is_empty() && boarding_inputs.is_empty() {
            return Err("No intents or boarding inputs provided".to_string());
        }

        let commitment_hash = self.commitment_hash(intents, boarding_inputs, signer_pubkey);
        let vtxo_tree = self.build_vtxo_tree(intents, &commitment_hash);
        let connector_address = self.derive_connector_address(&commitment_hash);
        let connectors = self.build_connectors(&commitment_hash);
        let commitment_tx = hex::encode(commitment_hash.as_byte_array());

        Ok(CommitmentResult {
            commitment_tx,
            vtxo_tree,
            connector_address,
            connectors,
        })
    }

    /// Compute the SHA-256 commitment hash over intents + boarding inputs.
    pub fn commitment_hash(
        &self,
        intents: &[IntentInput],
        boarding_inputs: &[BoardingUtxo],
        signer_pubkey: &XOnlyPublicKey,
    ) -> sha256::Hash {
        let mut preimage = Vec::new();

        // Signer pubkey
        preimage.extend_from_slice(&signer_pubkey.serialize());

        // Intents
        for intent in intents {
            preimage.extend_from_slice(intent.id.as_bytes());
            for r in &intent.receivers {
                preimage.extend_from_slice(r.pubkey.as_bytes());
                preimage.extend_from_slice(r.onchain_address.as_bytes());
                preimage.extend_from_slice(&r.amount.to_le_bytes());
            }
        }

        // Boarding inputs
        for bi in boarding_inputs {
            preimage.extend_from_slice(bi.txid.as_bytes());
            preimage.extend_from_slice(&bi.vout.to_le_bytes());
            preimage.extend_from_slice(&bi.amount.to_le_bytes());
        }

        sha256::Hash::hash(&preimage)
    }

    /// Build the VTXO tree from intents.
    ///
    /// Root node uses the commitment hash as txid. Each receiver gets a
    /// leaf node with a deterministic txid derived from the root + index.
    pub fn build_vtxo_tree(
        &self,
        intents: &[IntentInput],
        commitment_hash: &sha256::Hash,
    ) -> Vec<TreeNode> {
        let root_txid = commitment_hash.to_string();
        let mut tree = Vec::new();
        let mut root_children = HashMap::new();
        let mut output_idx: u32 = 0;

        for intent in intents {
            for receiver in &intent.receivers {
                let mut leaf_preimage = Vec::new();
                leaf_preimage.extend_from_slice(root_txid.as_bytes());
                leaf_preimage.extend_from_slice(&output_idx.to_le_bytes());
                leaf_preimage.extend_from_slice(receiver.pubkey.as_bytes());
                leaf_preimage.extend_from_slice(receiver.onchain_address.as_bytes());
                leaf_preimage.extend_from_slice(&receiver.amount.to_le_bytes());

                let leaf_hash = sha256::Hash::hash(&leaf_preimage);
                let leaf_txid = leaf_hash.to_string();

                root_children.insert(output_idx, leaf_txid.clone());

                tree.push(TreeNode {
                    txid: leaf_txid,
                    tx: hex::encode(&leaf_preimage),
                    children: HashMap::new(),
                });

                output_idx += 1;
            }
        }

        // Insert root at position 0
        tree.insert(
            0,
            TreeNode {
                txid: root_txid,
                tx: hex::encode(commitment_hash.as_byte_array()),
                children: root_children,
            },
        );

        tree
    }

    /// Derive a deterministic connector address from the commitment hash.
    pub fn derive_connector_address(&self, commitment_hash: &sha256::Hash) -> String {
        let addr_hash = sha256::Hash::hash(commitment_hash.as_byte_array());
        let short = hex::encode(&addr_hash.as_byte_array()[..20]);
        format!("{}:{}", self.network, short)
    }

    /// Build the connector tree (single root node).
    pub fn build_connectors(&self, commitment_hash: &sha256::Hash) -> Vec<TreeNode> {
        let connector_txid = {
            let h = sha256::Hash::hash(format!("connector:{}", commitment_hash).as_bytes());
            h.to_string()
        };
        vec![TreeNode {
            txid: connector_txid,
            tx: hex::encode(commitment_hash.as_byte_array()),
            children: HashMap::new(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signer_pubkey() -> XOnlyPublicKey {
        // Generator point x-coordinate (valid x-only pubkey)
        let bytes: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        XOnlyPublicKey::from_slice(&bytes).unwrap()
    }

    fn make_intent(id: &str, receivers: Vec<ReceiverInput>) -> IntentInput {
        IntentInput {
            id: id.to_string(),
            receivers,
        }
    }

    #[test]
    fn test_build_basic() {
        let builder = LocalTxBuilder::new("regtest");
        let pubkey = make_signer_pubkey();
        let intent = make_intent(
            "intent-1",
            vec![
                ReceiverInput {
                    pubkey: "pk_alice".to_string(),
                    onchain_address: String::new(),
                    amount: 50_000,
                },
                ReceiverInput {
                    pubkey: "pk_bob".to_string(),
                    onchain_address: String::new(),
                    amount: 30_000,
                },
            ],
        );

        let result = builder.build(&pubkey, &[intent], &[]).unwrap();

        // Root + 2 leaves
        assert_eq!(result.vtxo_tree.len(), 3);
        assert_eq!(result.vtxo_tree[0].children.len(), 2);
        assert!(result.connector_address.starts_with("regtest:"));
        assert!(!result.commitment_tx.is_empty());
        assert_eq!(result.commitment_tx.len(), 64); // 32-byte hash hex
    }

    #[test]
    fn test_build_deterministic() {
        let builder = LocalTxBuilder::new("regtest");
        let pubkey = make_signer_pubkey();
        let mk = || {
            make_intent(
                "intent-det",
                vec![ReceiverInput {
                    pubkey: "pk_carol".to_string(),
                    onchain_address: String::new(),
                    amount: 10_000,
                }],
            )
        };

        let r1 = builder.build(&pubkey, &[mk()], &[]).unwrap();
        let r2 = builder.build(&pubkey, &[mk()], &[]).unwrap();

        assert_eq!(r1.commitment_tx, r2.commitment_tx);
        assert_eq!(r1.vtxo_tree.len(), r2.vtxo_tree.len());
        assert_eq!(r1.connector_address, r2.connector_address);
    }

    #[test]
    fn test_build_empty_input_error() {
        let builder = LocalTxBuilder::new("regtest");
        let pubkey = make_signer_pubkey();

        let result = builder.build(&pubkey, &[], &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No intents"));
    }

    #[test]
    fn test_build_with_boarding_inputs_only() {
        let builder = LocalTxBuilder::new("regtest");
        let pubkey = make_signer_pubkey();

        let boarding = vec![BoardingUtxo {
            txid: "bbbb".repeat(16),
            vout: 1,
            amount: 200_000,
        }];

        let result = builder.build(&pubkey, &[], &boarding).unwrap();

        // VTXO tree: just the root (no receivers)
        assert_eq!(result.vtxo_tree.len(), 1);
        assert!(result.vtxo_tree[0].children.is_empty());
        // Connectors still present
        assert_eq!(result.connectors.len(), 1);
    }

    #[test]
    fn test_different_networks_produce_different_addresses() {
        let pubkey = make_signer_pubkey();
        let intent = make_intent(
            "intent-net",
            vec![ReceiverInput {
                pubkey: "pk_net".to_string(),
                onchain_address: String::new(),
                amount: 5_000,
            }],
        );

        let r1 = LocalTxBuilder::new("regtest")
            .build(&pubkey, &[intent.clone()], &[])
            .unwrap();
        let r2 = LocalTxBuilder::new("mainnet")
            .build(&pubkey, &[intent], &[])
            .unwrap();

        // Same commitment hash, different address prefix
        assert_eq!(r1.commitment_tx, r2.commitment_tx);
        assert_ne!(r1.connector_address, r2.connector_address);
        assert!(r1.connector_address.starts_with("regtest:"));
        assert!(r2.connector_address.starts_with("mainnet:"));
    }
}
