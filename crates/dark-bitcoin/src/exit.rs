//! Exit transaction building for the Ark protocol
//!
//! Handles building Bitcoin transactions for:
//! - **Collaborative exits**: on-chain outputs included in a round's commitment tx
//! - **Unilateral exits**: publishing VTXO tree branches on-chain
//! - **Boarding inputs**: tapscript-based inputs for adding on-chain funds
//! - **Sweep transactions**: ASP recovering expired VTXOs

use bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, FeeRate, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};

use crate::error::{BitcoinError, BitcoinResult};

/// A node in the VTXO tree that can be published on-chain for unilateral exit
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Transaction at this node
    pub tx: Transaction,
    /// Parent outpoint this node spends
    pub parent_outpoint: OutPoint,
    /// Children outpoints (if intermediate node)
    pub children: Vec<OutPoint>,
    /// Depth in the tree (0 = root)
    pub depth: u32,
}

/// Branch of the VTXO tree from root to leaf for unilateral exit
#[derive(Debug, Clone)]
pub struct TreeBranch {
    /// Ordered nodes from root to leaf
    pub nodes: Vec<TreeNode>,
    /// The VTXO leaf outpoint being exited
    pub leaf_outpoint: OutPoint,
    /// The owner's public key
    pub owner_pubkey: XOnlyPublicKey,
}

impl TreeBranch {
    /// Get total number of intermediate transactions to publish
    pub fn intermediate_tx_count(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }

    /// Estimate total on-chain cost in vbytes
    pub fn estimate_total_vsize(&self) -> usize {
        // Each tree node tx is roughly 150-250 vbytes depending on witness
        self.nodes.len() * 200
    }
}

/// Builder for collaborative exit outputs
///
/// Creates on-chain outputs to be included in a round's commitment transaction.
#[derive(Debug)]
pub struct CollaborativeExitBuilder {
    outputs: Vec<ExitOutput>,
}

/// An exit output (destination + amount)
#[derive(Debug, Clone)]
pub struct ExitOutput {
    /// Destination address
    pub address: Address,
    /// Amount to send
    pub amount: Amount,
}

impl CollaborativeExitBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            outputs: Vec::new(),
        }
    }

    /// Add an exit output
    pub fn add_output(mut self, address: Address, amount: Amount) -> Self {
        self.outputs.push(ExitOutput { address, amount });
        self
    }

    /// Build the exit outputs as TxOuts for inclusion in commitment tx
    pub fn build(self) -> BitcoinResult<Vec<TxOut>> {
        if self.outputs.is_empty() {
            return Err(BitcoinError::TransactionBuildError(
                "No exit outputs".to_string(),
            ));
        }

        let mut tx_outs = Vec::with_capacity(self.outputs.len());
        for output in &self.outputs {
            if output.amount <= Amount::from_sat(546) {
                return Err(BitcoinError::InvalidAmount(format!(
                    "Exit output amount {} is dust",
                    output.amount
                )));
            }
            tx_outs.push(TxOut {
                value: output.amount,
                script_pubkey: output.address.script_pubkey(),
            });
        }

        Ok(tx_outs)
    }

    /// Get total amount of all exit outputs
    pub fn total_amount(&self) -> Amount {
        self.outputs
            .iter()
            .map(|o| o.amount)
            .fold(Amount::ZERO, |acc, a| acc + a)
    }

    /// Get number of outputs
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }
}

impl Default for CollaborativeExitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for unilateral exit transactions
///
/// Constructs the chain of transactions needed to publish a VTXO tree branch
/// on-chain, allowing the user to claim their funds after a timelock.
#[derive(Debug)]
pub struct UnilateralExitBuilder {
    /// VTXO tree branch to publish
    branch: Option<TreeBranch>,
    /// Fee rate for the transactions
    fee_rate: FeeRate,
    /// Claim destination address
    claim_address: Option<Address>,
    /// Timelock (in blocks) before funds are claimable
    exit_delay: u32,
}

impl UnilateralExitBuilder {
    /// Create a new builder
    pub fn new(fee_rate: FeeRate, exit_delay: u32) -> Self {
        Self {
            branch: None,
            fee_rate,
            claim_address: None,
            exit_delay,
        }
    }

    /// Set the tree branch to publish
    pub fn branch(mut self, branch: TreeBranch) -> Self {
        self.branch = Some(branch);
        self
    }

    /// Set the claim destination address
    pub fn claim_address(mut self, address: Address) -> Self {
        self.claim_address = Some(address);
        self
    }

    /// Build the unilateral exit — returns the list of transactions to broadcast
    /// in order (from root to leaf) plus the final claim transaction
    pub fn build(self) -> BitcoinResult<UnilateralExitPlan> {
        let branch = self
            .branch
            .as_ref()
            .ok_or_else(|| BitcoinError::TransactionBuildError("Tree branch not set".to_string()))?
            .clone();

        let claim_address = self
            .claim_address
            .as_ref()
            .ok_or_else(|| {
                BitcoinError::TransactionBuildError("Claim address not set".to_string())
            })?
            .clone();

        // Build intermediate tree transactions (to be broadcast in order)
        let mut intermediate_txs = Vec::new();
        for node in &branch.nodes {
            intermediate_txs.push(node.tx.clone());
        }

        // Build the claim transaction (spendable after timelock)
        let claim_tx = self.build_claim_tx(&branch, &claim_address)?;

        // Estimate total fees
        let total_vsize: u64 = intermediate_txs
            .iter()
            .map(|tx| tx.vsize() as u64)
            .sum::<u64>()
            + claim_tx.vsize() as u64;

        let total_fee = self
            .fee_rate
            .fee_vb(total_vsize)
            .ok_or_else(|| BitcoinError::TransactionBuildError("Fee overflow".to_string()))?;

        Ok(UnilateralExitPlan {
            intermediate_txs,
            claim_tx,
            exit_delay_blocks: self.exit_delay,
            total_fee,
            total_vsize,
        })
    }

    /// Build the claim transaction
    fn build_claim_tx(
        &self,
        branch: &TreeBranch,
        claim_address: &Address,
    ) -> BitcoinResult<Transaction> {
        // The claim tx spends the leaf VTXO output after the timelock
        let leaf_outpoint = branch.leaf_outpoint;

        // Use CSV (relative timelock) sequence
        let sequence = Sequence::from_height(self.exit_delay as u16);

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: leaf_outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(), // Will be filled during signing
            }],
            output: vec![TxOut {
                // Amount::ZERO is a placeholder — the actual value is computed
                // during signing when the VTXO leaf amount and fee are known.
                value: Amount::ZERO,
                script_pubkey: claim_address.script_pubkey(),
            }],
        };

        Ok(tx)
    }
}

/// Plan for executing a unilateral exit
#[derive(Debug, Clone)]
pub struct UnilateralExitPlan {
    /// Intermediate tree transactions to broadcast (root → leaf)
    pub intermediate_txs: Vec<Transaction>,
    /// Final claim transaction (requires timelock)
    pub claim_tx: Transaction,
    /// Number of blocks until claim is spendable
    pub exit_delay_blocks: u32,
    /// Total estimated fee
    pub total_fee: Amount,
    /// Total estimated vsize
    pub total_vsize: u64,
}

impl UnilateralExitPlan {
    /// Number of transactions to broadcast
    pub fn tx_count(&self) -> usize {
        self.intermediate_txs.len() + 1 // +1 for claim tx
    }
}

/// Builder for boarding tapscript inputs
///
/// Creates tapscript-based inputs that allow on-chain funds to be included
/// in a commitment transaction, converting them into VTXOs.
#[derive(Debug)]
pub struct BoardingInputBuilder {
    /// User's public key
    user_pubkey: XOnlyPublicKey,
    /// ASP's public key
    asp_pubkey: XOnlyPublicKey,
    /// Funding outpoint
    funding_outpoint: OutPoint,
    /// Funding amount
    funding_amount: Amount,
    /// Exit delay (blocks) — for the boarding tapscript timeout path
    exit_delay: u32,
}

impl BoardingInputBuilder {
    /// Create a new boarding input builder
    pub fn new(
        user_pubkey: XOnlyPublicKey,
        asp_pubkey: XOnlyPublicKey,
        funding_outpoint: OutPoint,
        funding_amount: Amount,
        exit_delay: u32,
    ) -> Self {
        Self {
            user_pubkey,
            asp_pubkey,
            funding_outpoint,
            funding_amount,
            exit_delay,
        }
    }

    /// Build the boarding tapscript
    ///
    /// The boarding address uses a tapscript with two spending paths:
    /// 1. **Cooperative**: Both user + ASP sign (used during round finalization)
    /// 2. **Timeout**: User can reclaim after exit_delay blocks (safety fallback)
    pub fn build_boarding_script(&self) -> BitcoinResult<BoardingScript> {
        // Cooperative path: 2-of-2 multisig (user + ASP)
        // In tapscript, this is done via key aggregation (MuSig2) on the internal key
        // and the timeout path goes in a tapleaf

        // Timeout/refund script (tapleaf):
        // <exit_delay> OP_CSV OP_DROP <user_pubkey> OP_CHECKSIG
        let csv_bytes = self.exit_delay.to_le_bytes().to_vec();
        let push_bytes = bitcoin::script::PushBytesBuf::try_from(csv_bytes)
            .map_err(|e| BitcoinError::ScriptError(e.to_string()))?;

        let timeout_script = bitcoin::script::Builder::new()
            .push_slice(push_bytes.as_push_bytes())
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .push_x_only_key(&self.user_pubkey)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();

        Ok(BoardingScript {
            user_pubkey: self.user_pubkey,
            asp_pubkey: self.asp_pubkey,
            timeout_script,
            exit_delay: self.exit_delay,
            funding_outpoint: self.funding_outpoint,
            funding_amount: self.funding_amount,
        })
    }
}

/// A boarding script with both spending paths
#[derive(Debug, Clone)]
pub struct BoardingScript {
    /// User's public key
    pub user_pubkey: XOnlyPublicKey,
    /// ASP's public key
    pub asp_pubkey: XOnlyPublicKey,
    /// Timeout/refund script (tapleaf)
    pub timeout_script: ScriptBuf,
    /// Exit delay in blocks
    pub exit_delay: u32,
    /// Funding outpoint
    pub funding_outpoint: OutPoint,
    /// Funding amount
    pub funding_amount: Amount,
}

/// Builder for sweep transactions (ASP recovering expired VTXOs)
#[derive(Debug)]
pub struct SweepTxBuilder {
    /// Inputs (expired VTXOs to sweep)
    inputs: Vec<SweepInput>,
    /// ASP's destination address
    sweep_address: Option<Address>,
    /// Fee rate
    fee_rate: FeeRate,
}

/// An input for a sweep transaction
#[derive(Debug, Clone)]
pub struct SweepInput {
    /// Outpoint of the expired VTXO
    pub outpoint: OutPoint,
    /// Amount
    pub amount: Amount,
    /// Script to satisfy the sweep spending condition
    pub witness_script: ScriptBuf,
}

impl SweepTxBuilder {
    /// Create a new sweep transaction builder
    pub fn new(fee_rate: FeeRate) -> Self {
        Self {
            inputs: Vec::new(),
            sweep_address: None,
            fee_rate,
        }
    }

    /// Add a sweep input
    pub fn add_input(mut self, input: SweepInput) -> Self {
        self.inputs.push(input);
        self
    }

    /// Add multiple inputs
    pub fn add_inputs(mut self, inputs: Vec<SweepInput>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    /// Set the sweep destination address
    pub fn sweep_address(mut self, address: Address) -> Self {
        self.sweep_address = Some(address);
        self
    }

    /// Build the sweep transaction
    pub fn build(self) -> BitcoinResult<SweepPlan> {
        if self.inputs.is_empty() {
            return Err(BitcoinError::TransactionBuildError(
                "No sweep inputs".to_string(),
            ));
        }

        let sweep_address = self.sweep_address.ok_or_else(|| {
            BitcoinError::TransactionBuildError("Sweep address not set".to_string())
        })?;

        let total_input: Amount = self.inputs.iter().map(|i| i.amount).sum();

        // Build the transaction
        let tx_ins: Vec<TxIn> = self
            .inputs
            .iter()
            .map(|input| TxIn {
                previous_output: input.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(), // Filled during signing
            })
            .collect();

        // Estimate fee
        let estimated_vsize = 10 + (self.inputs.len() * 68) + 43; // base + inputs + 1 output
        let fee = self
            .fee_rate
            .fee_vb(estimated_vsize as u64)
            .ok_or_else(|| BitcoinError::TransactionBuildError("Fee overflow".to_string()))?;

        if total_input <= fee {
            return Err(BitcoinError::InsufficientFunds {
                required: fee.to_sat(),
                available: total_input.to_sat(),
            });
        }

        let output_amount = total_input - fee;

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_ins,
            output: vec![TxOut {
                value: output_amount,
                script_pubkey: sweep_address.script_pubkey(),
            }],
        };

        Ok(SweepPlan {
            tx,
            input_count: self.inputs.len(),
            total_input,
            output_amount,
            fee,
        })
    }
}

/// Plan for a sweep transaction
#[derive(Debug, Clone)]
pub struct SweepPlan {
    /// The sweep transaction
    pub tx: Transaction,
    /// Number of VTXOs being swept
    pub input_count: usize,
    /// Total input amount
    pub total_input: Amount,
    /// Output amount (after fees)
    pub output_amount: Amount,
    /// Fee paid
    pub fee: Amount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{hashes::Hash, Txid};
    use std::str::FromStr;

    fn test_address() -> Address {
        Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
            .unwrap()
            .assume_checked()
    }

    fn test_xonly_pubkey() -> XOnlyPublicKey {
        let bytes = [2u8; 32];
        XOnlyPublicKey::from_slice(&bytes).unwrap()
    }

    #[test]
    fn test_collaborative_exit_builder() {
        let builder = CollaborativeExitBuilder::new()
            .add_output(test_address(), Amount::from_sat(100_000))
            .add_output(test_address(), Amount::from_sat(50_000));

        assert_eq!(builder.output_count(), 2);
        assert_eq!(builder.total_amount(), Amount::from_sat(150_000));

        let outputs = builder.build().unwrap();
        assert_eq!(outputs.len(), 2);
    }

    #[test]
    fn test_collaborative_exit_empty_fails() {
        let builder = CollaborativeExitBuilder::new();
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_collaborative_exit_dust_fails() {
        let builder =
            CollaborativeExitBuilder::new().add_output(test_address(), Amount::from_sat(100));

        assert!(builder.build().is_err());
    }

    #[test]
    fn test_unilateral_exit_builder() {
        let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
        let leaf_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };

        let branch = TreeBranch {
            nodes: vec![TreeNode {
                tx: Transaction {
                    version: Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: OutPoint {
                            txid: Txid::all_zeros(),
                            vout: 0,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    output: vec![TxOut {
                        value: Amount::from_sat(100_000),
                        script_pubkey: ScriptBuf::new(),
                    }],
                },
                parent_outpoint: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                children: vec![],
                depth: 0,
            }],
            leaf_outpoint,
            owner_pubkey: test_xonly_pubkey(),
        };

        let plan = UnilateralExitBuilder::new(fee_rate, 512)
            .branch(branch)
            .claim_address(test_address())
            .build()
            .unwrap();

        assert_eq!(plan.intermediate_txs.len(), 1);
        assert_eq!(plan.exit_delay_blocks, 512);
        assert_eq!(plan.tx_count(), 2);
    }

    #[test]
    fn test_tree_branch_metrics() {
        let branch = TreeBranch {
            nodes: vec![
                TreeNode {
                    tx: Transaction {
                        version: Version::TWO,
                        lock_time: LockTime::ZERO,
                        input: vec![],
                        output: vec![],
                    },
                    parent_outpoint: OutPoint {
                        txid: Txid::all_zeros(),
                        vout: 0,
                    },
                    children: vec![],
                    depth: 0,
                },
                TreeNode {
                    tx: Transaction {
                        version: Version::TWO,
                        lock_time: LockTime::ZERO,
                        input: vec![],
                        output: vec![],
                    },
                    parent_outpoint: OutPoint {
                        txid: Txid::all_zeros(),
                        vout: 0,
                    },
                    children: vec![],
                    depth: 1,
                },
                TreeNode {
                    tx: Transaction {
                        version: Version::TWO,
                        lock_time: LockTime::ZERO,
                        input: vec![],
                        output: vec![],
                    },
                    parent_outpoint: OutPoint {
                        txid: Txid::all_zeros(),
                        vout: 0,
                    },
                    children: vec![],
                    depth: 2,
                },
            ],
            leaf_outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            owner_pubkey: test_xonly_pubkey(),
        };

        assert_eq!(branch.intermediate_tx_count(), 2);
        assert_eq!(branch.estimate_total_vsize(), 600);
    }

    #[test]
    fn test_boarding_input_builder() {
        let user_pk = test_xonly_pubkey();
        let asp_pk = test_xonly_pubkey();
        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };

        let builder =
            BoardingInputBuilder::new(user_pk, asp_pk, outpoint, Amount::from_sat(100_000), 512);

        let script = builder.build_boarding_script().unwrap();
        assert_eq!(script.exit_delay, 512);
        assert!(!script.timeout_script.is_empty());
    }

    #[test]
    fn test_sweep_tx_builder() {
        let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

        let input = SweepInput {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            amount: Amount::from_sat(100_000),
            witness_script: ScriptBuf::new(),
        };

        let plan = SweepTxBuilder::new(fee_rate)
            .add_input(input)
            .sweep_address(test_address())
            .build()
            .unwrap();

        assert_eq!(plan.input_count, 1);
        assert!(plan.output_amount < plan.total_input); // Fees deducted
        assert!(plan.fee > Amount::ZERO);
    }

    #[test]
    fn test_sweep_tx_insufficient_funds() {
        let fee_rate = FeeRate::from_sat_per_vb(10000).unwrap(); // Very high fee rate

        let input = SweepInput {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            amount: Amount::from_sat(100), // Very small amount
            witness_script: ScriptBuf::new(),
        };

        let result = SweepTxBuilder::new(fee_rate)
            .add_input(input)
            .sweep_address(test_address())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_sweep_tx_multiple_inputs() {
        let fee_rate = FeeRate::from_sat_per_vb(5).unwrap();

        let inputs: Vec<SweepInput> = (0..5)
            .map(|i| SweepInput {
                outpoint: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: i,
                },
                amount: Amount::from_sat(50_000),
                witness_script: ScriptBuf::new(),
            })
            .collect();

        let plan = SweepTxBuilder::new(fee_rate)
            .add_inputs(inputs)
            .sweep_address(test_address())
            .build()
            .unwrap();

        assert_eq!(plan.input_count, 5);
        assert_eq!(plan.total_input, Amount::from_sat(250_000));
    }
}
