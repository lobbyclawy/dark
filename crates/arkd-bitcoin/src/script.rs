//! Script construction for Ark protocol

use crate::error::{BitcoinError, BitcoinResult};
use bitcoin::{
    absolute::LockTime,
    opcodes::all::*,
    script::{Builder, PushBytesBuf},
    Address, Network, PublicKey, ScriptBuf, Sequence, WitnessProgram,
};

/// Script builder utilities for common Bitcoin script patterns
pub struct ScriptBuilder;

impl ScriptBuilder {
    /// Create a P2WSH (Pay to Witness Script Hash) script
    pub fn p2wsh(witness_script: &ScriptBuf) -> BitcoinResult<ScriptBuf> {
        let witness_program = WitnessProgram::p2wsh(witness_script);
        Ok(ScriptBuf::new_witness_program(&witness_program))
    }

    /// Create a simple multisig script (n-of-m)
    pub fn multisig(threshold: usize, pubkeys: &[PublicKey]) -> BitcoinResult<ScriptBuf> {
        if threshold == 0 || threshold > pubkeys.len() {
            return Err(BitcoinError::ScriptError(format!(
                "Invalid threshold {threshold} for {} pubkeys",
                pubkeys.len()
            )));
        }

        if pubkeys.len() > 15 {
            return Err(BitcoinError::ScriptError(
                "Too many pubkeys (max 15)".to_string(),
            ));
        }

        let mut builder = Builder::new().push_int(threshold as i64);

        for pubkey in pubkeys {
            builder = builder.push_key(pubkey);
        }

        Ok(builder
            .push_int(pubkeys.len() as i64)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script())
    }

    /// Create a P2WSH multisig address
    pub fn p2wsh_multisig_address(
        threshold: usize,
        pubkeys: &[PublicKey],
        network: Network,
    ) -> BitcoinResult<Address> {
        let witness_script = Self::multisig(threshold, pubkeys)?;
        let script_pubkey = Self::p2wsh(&witness_script)?;

        Address::from_script(&script_pubkey, network)
            .map_err(|e| BitcoinError::ScriptError(e.to_string()))
    }
}

/// Timelock script utilities
pub mod timelock {
    use super::*;
    use bitcoin::Sequence;

    /// Create a script with absolute timelock (CLTV - CheckLockTimeVerify)
    pub fn cltv(lock_time: LockTime, pubkey: &PublicKey) -> BitcoinResult<ScriptBuf> {
        let lock_time_bytes = match lock_time {
            LockTime::Blocks(h) => h.to_consensus_u32().to_le_bytes().to_vec(),
            LockTime::Seconds(t) => t.to_consensus_u32().to_le_bytes().to_vec(),
        };

        let push_bytes = PushBytesBuf::try_from(lock_time_bytes)
            .map_err(|e| BitcoinError::ScriptError(e.to_string()))?;

        Ok(Builder::new()
            .push_slice(push_bytes.as_push_bytes())
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_key(pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script())
    }

    /// Create a script with relative timelock (CSV - CheckSequenceVerify)
    pub fn csv(sequence: Sequence, pubkey: &PublicKey) -> BitcoinResult<ScriptBuf> {
        let sequence_bytes = sequence.to_consensus_u32().to_le_bytes().to_vec();

        let push_bytes = PushBytesBuf::try_from(sequence_bytes)
            .map_err(|e| BitcoinError::ScriptError(e.to_string()))?;

        Ok(Builder::new()
            .push_slice(push_bytes.as_push_bytes())
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script())
    }
}

/// Covenant script utilities for Ark protocol
pub mod covenant {
    use super::*;

    /// Create a connector output script (used in Ark protocol)
    ///
    /// This script enforces that funds can only be spent to specific outputs,
    /// creating a "covenant" that restricts how coins can be used.
    ///
    /// **Current Implementation:**
    /// This is a placeholder that only checks a signature. It does NOT enforce
    /// the covenant structure yet.
    ///
    /// **TODO (Issue #3): Implement actual covenant enforcement**
    ///
    /// Options for covenant enforcement:
    /// 1. OP_CHECKTEMPLATEVERIFY (BIP-119) - if available on the network
    /// 2. Pre-signed transaction trees (current Ark approach)
    /// 3. OP_CAT + OP_CHECKSIGFROMSTACK (future opcodes)
    ///
    /// For now, Ark relies on pre-signed transactions rather than script covenants.
    /// This function serves as a placeholder for future covenant implementations.
    pub fn connector_script(pubkey: &PublicKey, _connector_outputs: &[ScriptBuf]) -> ScriptBuf {
        // Simple pubkey check - no covenant enforcement yet
        // The actual covenant is enforced through pre-signed transactions
        Builder::new()
            .push_key(pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// Create a VTXO (Virtual Transaction Output) script
    ///
    /// VTXOs are the core primitive of the Ark protocol, allowing off-chain
    /// transactions while maintaining Bitcoin security guarantees.
    pub fn vtxo_script(
        user_pubkey: &PublicKey,
        asp_pubkey: &PublicKey,
        exit_delta: u32,
    ) -> BitcoinResult<ScriptBuf> {
        // VTXO script structure:
        // IF
        //   <exit_delta> CSV DROP <user_pubkey> CHECKSIG
        // ELSE
        //   <asp_pubkey> CHECKSIG
        // ENDIF

        let csv_bytes = exit_delta.to_le_bytes().to_vec();
        let push_bytes = PushBytesBuf::try_from(csv_bytes)
            .map_err(|e| BitcoinError::ScriptError(e.to_string()))?;

        Ok(Builder::new()
            .push_opcode(OP_IF)
            .push_slice(push_bytes.as_push_bytes())
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(user_pubkey)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_key(asp_pubkey)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{rand, Secp256k1};

    fn test_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        PublicKey::new(public_key)
    }

    #[test]
    fn test_multisig_script() {
        let pubkey = test_pubkey();
        let pubkeys = vec![pubkey, pubkey];

        let script = ScriptBuilder::multisig(2, &pubkeys).unwrap();
        assert!(!script.is_empty());
    }

    #[test]
    fn test_invalid_multisig() {
        let pubkey = test_pubkey();
        let pubkeys = vec![pubkey];

        // 2-of-1 multisig should fail
        assert!(ScriptBuilder::multisig(2, &pubkeys).is_err());
    }

    #[test]
    fn test_cltv_script() {
        let pubkey = test_pubkey();
        let lock_time = LockTime::from_height(100).unwrap();

        let script = timelock::cltv(lock_time, &pubkey).unwrap();
        assert!(!script.is_empty());
    }

    #[test]
    fn test_csv_script() {
        let pubkey = test_pubkey();
        let sequence = Sequence::from_height(144); // ~1 day

        let script = timelock::csv(sequence, &pubkey).unwrap();
        assert!(!script.is_empty());
    }

    #[test]
    fn test_vtxo_script() {
        let user_pk = test_pubkey();
        let asp_pk = test_pubkey();
        let exit_delta = 144; // ~1 day

        let script = covenant::vtxo_script(&user_pk, &asp_pk, exit_delta).unwrap();
        assert!(!script.is_empty());
    }
}
