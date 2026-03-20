//! Script construction for Ark protocol

use crate::error::{BitcoinError, BitcoinResult};
use bitcoin::{
    absolute::LockTime,
    opcodes::all::*,
    script::{Builder, PushBytesBuf},
    Address, Network, PublicKey, ScriptBuf, WitnessProgram,
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

    /// Maximum block-height timelock (~10 years at 144 blocks/day).
    pub const MAX_TIMELOCK_BLOCKS: u32 = 525_960;

    /// Maximum CSV relative timelock (16-bit field in Sequence).
    pub const MAX_CSV_BLOCKS: u16 = 65535;

    /// Validate a block-height CLTV value.
    fn validate_cltv(lock_time: &LockTime) -> BitcoinResult<()> {
        match lock_time {
            LockTime::Blocks(h) => {
                let height = h.to_consensus_u32();
                if height == 0 {
                    return Err(BitcoinError::ScriptError(
                        "CLTV block height must be > 0".to_string(),
                    ));
                }
                if height > MAX_TIMELOCK_BLOCKS {
                    return Err(BitcoinError::ScriptError(format!(
                        "CLTV block height {height} exceeds maximum {MAX_TIMELOCK_BLOCKS}"
                    )));
                }
            }
            LockTime::Seconds(t) => {
                let secs = t.to_consensus_u32();
                // Seconds-based locktimes must be > 500_000_000 by consensus
                if secs <= 500_000_000 {
                    return Err(BitcoinError::ScriptError(format!(
                        "CLTV seconds value {secs} is at or below the locktime threshold"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Validate a CSV (relative timelock) sequence value.
    fn validate_csv(sequence: &Sequence) -> BitcoinResult<()> {
        let raw = sequence.to_consensus_u32();
        // CSV uses bits 0-15 for the value, bit 22 for type (blocks vs time)
        // and bit 31 must be 0 for CSV to be enforced.
        if raw & (1 << 31) != 0 {
            return Err(BitcoinError::ScriptError(
                "CSV sequence has disable flag set (bit 31)".to_string(),
            ));
        }
        let value = raw & 0x0000FFFF;
        if value == 0 {
            return Err(BitcoinError::ScriptError(
                "CSV value must be > 0".to_string(),
            ));
        }
        Ok(())
    }

    /// Create a script with absolute timelock (CLTV - CheckLockTimeVerify)
    pub fn cltv(lock_time: LockTime, pubkey: &PublicKey) -> BitcoinResult<ScriptBuf> {
        validate_cltv(&lock_time)?;

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
        validate_csv(&sequence)?;

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
        if exit_delta == 0 {
            return Err(BitcoinError::ScriptError(
                "VTXO exit_delta must be > 0".to_string(),
            ));
        }
        if exit_delta > 65535 {
            return Err(BitcoinError::ScriptError(format!(
                "VTXO exit_delta {exit_delta} exceeds CSV maximum 65535"
            )));
        }
        if user_pubkey == asp_pubkey {
            return Err(BitcoinError::ScriptError(
                "user_pubkey and asp_pubkey must be different".to_string(),
            ));
        }

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
    use bitcoin::Sequence;

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

    #[test]
    fn test_multisig_empty_pubkeys() {
        assert!(ScriptBuilder::multisig(0, &[]).is_err());
    }

    #[test]
    fn test_multisig_one_of_one() {
        let pubkey = test_pubkey();
        let script = ScriptBuilder::multisig(1, &[pubkey]).unwrap();
        assert!(!script.is_empty());
    }

    #[test]
    fn test_vtxo_script_different_keys() {
        let user_pk = test_pubkey();
        let asp_pk = test_pubkey();

        // Different exit delays should produce different scripts
        let script1 = covenant::vtxo_script(&user_pk, &asp_pk, 144).unwrap();
        let script2 = covenant::vtxo_script(&user_pk, &asp_pk, 288).unwrap();
        assert_ne!(script1, script2);
    }

    #[test]
    fn test_cltv_various_heights() {
        let pubkey = test_pubkey();
        for height in [1, 100, 500_000] {
            let lock_time = LockTime::from_height(height).unwrap();
            let script = timelock::cltv(lock_time, &pubkey).unwrap();
            assert!(!script.is_empty());
        }
    }

    #[test]
    fn test_cltv_rejects_excessive_height() {
        let pubkey = test_pubkey();
        // Height above MAX_TIMELOCK_BLOCKS should be rejected
        let lock_time = LockTime::from_height(timelock::MAX_TIMELOCK_BLOCKS + 1).unwrap();
        assert!(timelock::cltv(lock_time, &pubkey).is_err());
    }

    #[test]
    fn test_csv_various_sequences() {
        let pubkey = test_pubkey();
        for blocks in [1, 144, 1008, 65535] {
            let sequence = Sequence::from_height(blocks);
            let script = timelock::csv(sequence, &pubkey).unwrap();
            assert!(!script.is_empty());
        }
    }

    #[test]
    fn test_csv_rejects_disabled_flag() {
        let pubkey = test_pubkey();
        // Sequence with bit 31 set (CSV disabled)
        let sequence = Sequence::from_consensus(0x80000001);
        assert!(timelock::csv(sequence, &pubkey).is_err());
    }

    #[test]
    fn test_vtxo_script_rejects_zero_exit_delta() {
        let user_pk = test_pubkey();
        let asp_pk = test_pubkey();
        assert!(covenant::vtxo_script(&user_pk, &asp_pk, 0).is_err());
    }

    #[test]
    fn test_vtxo_script_rejects_excessive_exit_delta() {
        let user_pk = test_pubkey();
        let asp_pk = test_pubkey();
        assert!(covenant::vtxo_script(&user_pk, &asp_pk, 65536).is_err());
    }

    #[test]
    fn test_vtxo_script_rejects_same_keys() {
        let pk = test_pubkey();
        assert!(covenant::vtxo_script(&pk, &pk, 144).is_err());
    }
}
