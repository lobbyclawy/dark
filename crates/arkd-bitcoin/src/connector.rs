//! Connector tree construction for the Ark protocol.
//!
//! Connector outputs bind forfeit transactions to specific rounds.
//! The ASP builds a **connector tree** alongside the VTXO tree:
//!
//! - The root connector output is funded by the commitment transaction.
//! - Internal nodes fan out in a radix-4 pattern (up to 4 children each).
//! - Leaf connectors correspond to individual participants and are spent
//!   as inputs to forfeit transactions.
//!
//! The tree is built bottom-up: we start with one leaf per participant,
//! group them into sets of 4, and create parent transactions until a
//! single root remains.

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::error::BitcoinError;

/// Radix (fan-out) of the connector tree. Each internal node has up to
/// this many children.
const RADIX: usize = 4;

/// Errors specific to connector tree construction.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// Zero participants is invalid.
    #[error("connector tree requires at least 1 participant")]
    NoParticipants,

    /// The dust amount is below the Bitcoin relay minimum.
    #[error("dust amount {0} is below the 546-sat relay minimum")]
    DustTooLow(Amount),

    /// A wrapped Bitcoin-level error.
    #[error(transparent)]
    Bitcoin(#[from] BitcoinError),
}

/// A single connector output reference (outpoint + value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorOutput {
    /// Transaction ID that contains this output.
    pub txid: Txid,
    /// Output index within the transaction.
    pub vout: u32,
    /// Value held by this output.
    pub amount: Amount,
}

/// A node (transaction) in the connector tree.
#[derive(Debug, Clone)]
pub struct ConnectorNode {
    /// The fully-constructed transaction for this node.
    pub tx: Transaction,
    /// Tree level: 0 = closest to root, increases toward leaves.
    pub level: u32,
    /// Position among siblings at this level.
    pub index: u32,
}

/// The complete connector tree for a single round.
///
/// Construct via [`ConnectorTree::build`].
#[derive(Debug, Clone)]
pub struct ConnectorTree {
    /// Root output — must be included in the commitment transaction.
    pub root: ConnectorOutput,
    /// All internal-node transactions (does NOT include the root funding tx).
    pub nodes: Vec<ConnectorNode>,
    /// Leaf outputs, one per participant, in participant-index order.
    pub leaves: Vec<ConnectorOutput>,
}

/// Create a minimal P2WSH output script (OP_TRUE for now).
///
/// In production this would be replaced with a proper Taproot or
/// multisig script, but for the initial connector tree construction
/// a trivially-spendable script is sufficient.
fn connector_script() -> ScriptBuf {
    // OP_TRUE — anyone can spend.  This is a placeholder; the real
    // protocol uses key-path spends gated by the ASP's key.
    // TODO(#44): replace with ASP key-path Taproot script once forfeit
    // submission flow is wired (Issue #42). Using OP_TRUE here is safe
    // only for test/regtest environments.
    bitcoin::script::Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
        .into_script()
}

/// Build a single connector transaction that spends `input` and fans
/// out into `num_outputs` connector outputs, each holding `per_output`.
fn build_connector_tx(input: OutPoint, num_outputs: usize, per_output: Amount) -> Transaction {
    let script = connector_script();

    let tx_ins = vec![TxIn {
        previous_output: input,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    }];

    let tx_outs: Vec<TxOut> = (0..num_outputs)
        .map(|_| TxOut {
            value: per_output,
            script_pubkey: script.clone(),
        })
        .collect();

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_ins,
        output: tx_outs,
    }
}

impl ConnectorTree {
    /// Build a connector tree for `participants` participants.
    ///
    /// # Arguments
    /// * `participants` — number of leaf connectors (≥ 1).
    /// * `funding_outpoint` — the outpoint in the commitment tx that funds
    ///   the root of the connector tree.
    /// * `dust_amount` — value for each leaf connector (typically 546 sats).
    ///
    /// # Errors
    /// Returns [`ConnectorError`] when `participants == 0` or the dust
    /// amount is below the relay minimum.
    pub fn build(
        participants: usize,
        funding_outpoint: OutPoint,
        dust_amount: Amount,
    ) -> Result<Self, ConnectorError> {
        if participants == 0 {
            return Err(ConnectorError::NoParticipants);
        }

        let min_dust = Amount::from_sat(546);
        if dust_amount < min_dust {
            return Err(ConnectorError::DustTooLow(dust_amount));
        }

        // Special case: single participant — the root output IS the leaf.
        if participants == 1 {
            let root = ConnectorOutput {
                txid: funding_outpoint.txid,
                vout: funding_outpoint.vout,
                amount: dust_amount,
            };
            return Ok(Self {
                root: root.clone(),
                nodes: Vec::new(),
                leaves: vec![root],
            });
        }

        // ----- Bottom-up construction -----
        //
        // We build level by level from the leaves upward.  At each level
        // we group the outputs into chunks of RADIX and create a parent
        // transaction per chunk.  We repeat until there is exactly one
        // output left — the root.

        // `current_level_outputs` starts as one "virtual" output per participant.
        // We only need counts at first; actual OutPoints are assigned when
        // we create transactions top-down after determining the tree shape.

        // Step 1: Determine the tree shape (number of txs per level).
        //
        // levels[0] = leaf count (participants)
        // levels[1] = ⌈leaf_count / RADIX⌉
        // ...until 1
        let mut level_widths: Vec<usize> = vec![participants];
        while *level_widths.last().unwrap() > 1 {
            let prev = *level_widths.last().unwrap();
            level_widths.push(prev.div_ceil(RADIX));
        }
        // level_widths is bottom-to-top: [participants, ..., 1]
        // Reverse so index 0 = root level (width 1).
        level_widths.reverse();

        // Step 2: Build transactions top-down, assigning real txids.
        //
        // At the root level (0) there is a single "virtual" tx whose
        // funding input is `funding_outpoint`.
        //
        // For every subsequent level, each parent output fans out into a
        // child transaction whose outputs feed the next level.

        // `parent_outpoints[i]` = the outpoint that funds child group i at
        // the current level.
        let mut parent_outpoints: Vec<OutPoint> = vec![funding_outpoint];
        let mut all_nodes: Vec<ConnectorNode> = Vec::new();

        // We skip level 0 (the root itself is just the funding outpoint).
        for (level_idx, &width) in level_widths.iter().enumerate().skip(1) {
            let mut next_parent_outpoints: Vec<OutPoint> = Vec::new();

            // How many child outputs does each parent need?
            // The last parent may have fewer children if width isn't
            // perfectly divisible.
            for (parent_i, &parent_op) in parent_outpoints.iter().enumerate() {
                // How many children does this parent produce?
                let children_start = parent_i * RADIX;
                let children_end = std::cmp::min(children_start + RADIX, width);
                let num_children = children_end - children_start;

                if num_children == 0 {
                    continue;
                }

                let tx = build_connector_tx(parent_op, num_children, dust_amount);
                let txid = tx.compute_txid();

                all_nodes.push(ConnectorNode {
                    tx: tx.clone(),
                    level: level_idx as u32,
                    index: parent_i as u32,
                });

                for vout in 0..num_children {
                    next_parent_outpoints.push(OutPoint {
                        txid,
                        vout: vout as u32,
                    });
                }
            }

            parent_outpoints = next_parent_outpoints;
        }

        // After processing all levels the remaining `parent_outpoints` are
        // the leaf-level outputs.
        let leaves: Vec<ConnectorOutput> = parent_outpoints
            .into_iter()
            .map(|op| ConnectorOutput {
                txid: op.txid,
                vout: op.vout,
                amount: dust_amount,
            })
            .collect();

        debug_assert_eq!(leaves.len(), participants);

        // Root output is the funding outpoint itself.
        let root = ConnectorOutput {
            txid: funding_outpoint.txid,
            vout: funding_outpoint.vout,
            // Root value = total value needed to fund all leaves plus
            // intermediate outputs.  For simplicity we record dust_amount
            // here; a production implementation would compute the exact
            // aggregate.
            amount: dust_amount,
        };

        Ok(Self {
            root,
            nodes: all_nodes,
            leaves,
        })
    }

    /// Return the leaf connector for the participant at `index`.
    pub fn leaf_for_participant(&self, index: usize) -> Option<&ConnectorOutput> {
        self.leaves.get(index)
    }

    /// Total number of internal-node transactions in the tree.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of leaf connectors (should equal the participant count).
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Compute the depth (number of transaction levels) of the tree.
    /// A single-participant tree has depth 0.
    pub fn depth(&self) -> u32 {
        self.nodes.iter().map(|n| n.level).max().unwrap_or(0)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    /// Convenience helper: deterministic dummy outpoint.
    fn dummy_outpoint() -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([0xAA; 32]),
            vout: 0,
        }
    }

    const DUST: Amount = Amount::from_sat(546);

    // ── Error cases ────────────────────────────────────────────────────

    #[test]
    fn zero_participants_errors() {
        let err = ConnectorTree::build(0, dummy_outpoint(), DUST).unwrap_err();
        assert!(matches!(err, ConnectorError::NoParticipants));
    }

    #[test]
    fn dust_below_minimum_errors() {
        let err = ConnectorTree::build(4, dummy_outpoint(), Amount::from_sat(100)).unwrap_err();
        assert!(matches!(err, ConnectorError::DustTooLow(_)));
    }

    // ── Single participant ────────────────────────────────────────────

    #[test]
    fn single_participant_trivial() {
        let tree = ConnectorTree::build(1, dummy_outpoint(), DUST).unwrap();
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.node_count(), 0, "no internal nodes needed");
        assert_eq!(tree.leaves[0], tree.root);
    }

    // ── Exactly RADIX (4) participants → single level ─────────────────

    #[test]
    fn four_participants_single_level() {
        let tree = ConnectorTree::build(4, dummy_outpoint(), DUST).unwrap();
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.node_count(), 1, "one internal tx fans out to 4 leaves");
        // All leaves should have distinct vouts in the same tx.
        let txid = tree.leaves[0].txid;
        for (i, leaf) in tree.leaves.iter().enumerate() {
            assert_eq!(leaf.txid, txid, "all leaves come from same parent tx");
            assert_eq!(leaf.vout, i as u32);
            assert_eq!(leaf.amount, DUST);
        }
    }

    // ── 16 participants → two levels ──────────────────────────────────

    #[test]
    fn sixteen_participants_two_levels() {
        let tree = ConnectorTree::build(16, dummy_outpoint(), DUST).unwrap();
        assert_eq!(tree.leaf_count(), 16);
        // Level 1: 1 root tx → 4 outputs (4 children)
        // Level 2: 4 txs, each → 4 outputs = 16 leaves
        // Total internal txs = 1 + 4 = 5
        assert_eq!(tree.node_count(), 5);
    }

    // ── 100 participants → multi-level ────────────────────────────────

    #[test]
    fn hundred_participants_multi_level() {
        let tree = ConnectorTree::build(100, dummy_outpoint(), DUST).unwrap();
        assert_eq!(tree.leaf_count(), 100);

        // Verify tree depth:
        // 100 → ⌈100/4⌉ = 25 → ⌈25/4⌉ = 7 → ⌈7/4⌉ = 2 → ⌈2/4⌉ = 1
        // That's 4 levels above the leaves, so depth = 4.
        assert!(tree.depth() >= 3, "100 participants needs several levels");
        assert!(tree.node_count() > 0);
    }

    // ── Non-power-of-4 sizes ──────────────────────────────────────────

    #[test]
    fn five_participants_uneven() {
        let tree = ConnectorTree::build(5, dummy_outpoint(), DUST).unwrap();
        assert_eq!(tree.leaf_count(), 5);
        // ⌈5/4⌉ = 2 parent txs at level below root → 1 root tx → total = 3 nodes
        assert_eq!(tree.node_count(), 3);
    }

    #[test]
    fn two_participants() {
        let tree = ConnectorTree::build(2, dummy_outpoint(), DUST).unwrap();
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.node_count(), 1);
    }

    #[test]
    fn three_participants() {
        let tree = ConnectorTree::build(3, dummy_outpoint(), DUST).unwrap();
        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.node_count(), 1);
    }

    // ── leaf_for_participant ──────────────────────────────────────────

    #[test]
    fn leaf_for_participant_bounds() {
        let tree = ConnectorTree::build(10, dummy_outpoint(), DUST).unwrap();
        assert!(tree.leaf_for_participant(0).is_some());
        assert!(tree.leaf_for_participant(9).is_some());
        assert!(tree.leaf_for_participant(10).is_none());
    }

    // ── Leaves are unique ────────────────────────────────────────────

    #[test]
    fn all_leaves_unique_outpoints() {
        let tree = ConnectorTree::build(64, dummy_outpoint(), DUST).unwrap();
        let mut seen = std::collections::HashSet::new();
        for leaf in &tree.leaves {
            let key = (leaf.txid, leaf.vout);
            assert!(seen.insert(key), "duplicate leaf outpoint: {key:?}");
        }
    }

    // ── Deterministic ────────────────────────────────────────────────

    #[test]
    fn build_is_deterministic() {
        let a = ConnectorTree::build(20, dummy_outpoint(), DUST).unwrap();
        let b = ConnectorTree::build(20, dummy_outpoint(), DUST).unwrap();
        assert_eq!(a.leaves.len(), b.leaves.len());
        for (la, lb) in a.leaves.iter().zip(b.leaves.iter()) {
            assert_eq!(la, lb);
        }
    }

    // ── Root is always the funding outpoint ──────────────────────────

    #[test]
    fn root_matches_funding_outpoint() {
        let op = dummy_outpoint();
        let tree = ConnectorTree::build(50, op, DUST).unwrap();
        assert_eq!(tree.root.txid, op.txid);
        assert_eq!(tree.root.vout, op.vout);
    }

    // ── Large tree doesn't panic ─────────────────────────────────────

    #[test]
    fn large_tree_1000_participants() {
        let tree = ConnectorTree::build(1000, dummy_outpoint(), DUST).unwrap();
        assert_eq!(tree.leaf_count(), 1000);
    }
}
