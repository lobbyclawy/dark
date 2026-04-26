//! Network identifier for stealth meta-addresses.
//!
//! The network is encoded directly in the bech32m human-readable part
//! (HRP), so a meta-address from one network can never silently decode
//! as one from another. The HRP literals are the wire format and must
//! not change without minting a new version byte.

use bech32::Hrp;

use crate::{ConfidentialError, Result};

/// Stealth meta-address network. Mapped 1:1 to the bech32m HRP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StealthNetwork {
    /// Bitcoin mainnet. HRP `darks`.
    Mainnet,
    /// Bitcoin testnet (testnet3, testnet4, signet). HRP `tdarks`.
    Testnet,
    /// Bitcoin regtest. HRP `rdarks`.
    Regtest,
}

const HRP_MAINNET: &str = "darks";
const HRP_TESTNET: &str = "tdarks";
const HRP_REGTEST: &str = "rdarks";

impl StealthNetwork {
    /// Returns the bech32m HRP for this network.
    pub fn hrp(self) -> Hrp {
        let raw = match self {
            Self::Mainnet => HRP_MAINNET,
            Self::Testnet => HRP_TESTNET,
            Self::Regtest => HRP_REGTEST,
        };
        // Both candidates are compile-time constants — `parse_unchecked`
        // is sound because they are valid lowercase ASCII with no
        // mixed-case characters.
        Hrp::parse_unchecked(raw)
    }

    /// Decodes a network from a bech32m HRP. Comparison is case-insensitive
    /// to match BIP-173 semantics.
    pub fn from_hrp(hrp: Hrp) -> Result<Self> {
        let lowercase = hrp.to_lowercase();
        match lowercase.as_str() {
            HRP_MAINNET => Ok(Self::Mainnet),
            HRP_TESTNET => Ok(Self::Testnet),
            HRP_REGTEST => Ok(Self::Regtest),
            _ => Err(ConfidentialError::Stealth("unknown network prefix")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hrp_round_trip_for_each_network() {
        for net in [
            StealthNetwork::Mainnet,
            StealthNetwork::Testnet,
            StealthNetwork::Regtest,
        ] {
            assert_eq!(StealthNetwork::from_hrp(net.hrp()).unwrap(), net);
        }
    }

    #[test]
    fn unknown_hrp_is_rejected() {
        let unknown = Hrp::parse_unchecked("notreal");
        assert!(StealthNetwork::from_hrp(unknown).is_err());
    }
}
