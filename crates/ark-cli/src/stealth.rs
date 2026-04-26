//! Subcommands for stealth meta-addresses.
//!
//! Three actions are exposed:
//!
//! - `stealth address` — print the wallet's meta-address. Until the local
//!   wallet integration lands (TODO: #553 follow-up) this is a stub that
//!   exits with a clear not-implemented message.
//! - `stealth encode <scan_pk_hex> <spend_pk_hex>` — encode a meta-address
//!   from two compressed secp256k1 public keys.
//! - `stealth decode <bech32_addr>` — decode a meta-address and print its
//!   scan and spend keys in hex.
//!
//! # Privacy
//!
//! A meta-address is a long-lived public credential. Anyone holding it can
//! detect payments to its owner if they also see on-chain announcements.
//! The CLI prints a brief reminder of this in `--help`.
use anyhow::{anyhow, Context, Result};
use clap::{Subcommand, ValueEnum};
use dark_confidential::stealth::{MetaAddress, StealthNetwork};
use secp256k1::PublicKey;

/// Network selector for `stealth encode`. Maps 1:1 onto
/// [`StealthNetwork`] (mainnet/testnet/regtest), which in turn drives the
/// bech32m HRP (`darks` / `tdarks` / `rdarks`).
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<NetworkArg> for StealthNetwork {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Mainnet => StealthNetwork::Mainnet,
            NetworkArg::Testnet => StealthNetwork::Testnet,
            NetworkArg::Regtest => StealthNetwork::Regtest,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum StealthAction {
    /// Print the wallet's meta-address in bech32m form.
    ///
    /// Reminder: a meta-address is a public credential that any holder can
    /// use to detect payments to this wallet. Share with care.
    Address,

    /// Encode a meta-address from two compressed secp256k1 public keys.
    ///
    /// Both keys must be 33-byte hex strings (66 hex characters).
    Encode {
        /// Scan (view) public key in hex (compressed, 33 bytes).
        scan_pk_hex: String,
        /// Spend (authority) public key in hex (compressed, 33 bytes).
        spend_pk_hex: String,
        /// Network to encode for. Picks the bech32m HRP.
        #[arg(long, value_enum, default_value_t = NetworkArg::Mainnet)]
        network: NetworkArg,
    },

    /// Decode a bech32m meta-address and print its scan and spend keys.
    Decode {
        /// Bech32m-encoded meta-address (e.g. `darks1...`).
        address: String,
    },
}

pub fn handle(action: &StealthAction, json: bool) -> Result<()> {
    match action {
        StealthAction::Address => handle_address(json),
        StealthAction::Encode {
            scan_pk_hex,
            spend_pk_hex,
            network,
        } => handle_encode(scan_pk_hex, spend_pk_hex, (*network).into(), json),
        StealthAction::Decode { address } => handle_decode(address, json),
    }
}

fn handle_address(json: bool) -> Result<()> {
    // TODO(#553 follow-up): derive the meta-address from the local wallet
    // once `ark-cli` has key management. For now this mirrors the other
    // wallet-dependent commands (`receive`, `send`) and surfaces a clear
    // not-implemented message rather than printing dummy credentials.
    if json {
        let out = serde_json::json!({
            "command": "stealth address",
            "status": "not_implemented",
            "note": "Wallet key management is not yet wired into ark-cli; \
                     use `stealth encode <scan_pk> <spend_pk>` to derive an \
                     address from explicit keys."
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Stealth address command not yet implemented.");
        println!("Wallet key management is not yet wired into ark-cli.");
        println!("Use `ark-cli stealth encode <scan_pk_hex> <spend_pk_hex>`");
        println!("to derive a meta-address from explicit keys.");
    }
    Ok(())
}

fn handle_encode(
    scan_pk_hex: &str,
    spend_pk_hex: &str,
    network: StealthNetwork,
    json: bool,
) -> Result<()> {
    let scan_pk = parse_compressed_pubkey(scan_pk_hex, "scan_pk")?;
    let spend_pk = parse_compressed_pubkey(spend_pk_hex, "spend_pk")?;
    let address = MetaAddress::new(network, scan_pk, spend_pk).to_bech32m();

    if json {
        let out = serde_json::json!({ "address": address });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("{}", address);
    }
    Ok(())
}

fn handle_decode(encoded: &str, json: bool) -> Result<()> {
    let meta_address = MetaAddress::from_bech32m(encoded)
        .map_err(|e| anyhow!("failed to decode meta-address: {}", e))?;

    let hrp = meta_address.network().hrp().to_string();
    let scan_pk_hex = hex::encode(meta_address.scan_pk().serialize());
    let spend_pk_hex = hex::encode(meta_address.spend_pk().serialize());

    if json {
        let out = serde_json::json!({
            "hrp": hrp,
            "network": format!("{:?}", meta_address.network()),
            "scan_pk": scan_pk_hex,
            "spend_pk": spend_pk_hex,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("HRP:      {}", hrp);
        println!("network:  {:?}", meta_address.network());
        println!("scan_pk:  {}", scan_pk_hex);
        println!("spend_pk: {}", spend_pk_hex);
    }
    Ok(())
}

fn parse_compressed_pubkey(input: &str, label: &str) -> Result<PublicKey> {
    let bytes = hex::decode(input).with_context(|| format!("{} is not valid hex", label))?;
    if bytes.len() != 33 {
        return Err(anyhow!(
            "{} must be a 33-byte compressed secp256k1 key, got {} bytes",
            label,
            bytes.len()
        ));
    }
    PublicKey::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid secp256k1 public key", label))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn sample_pubkeys_hex() -> (String, String) {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[0xaau8; 32]).expect("valid sk");
        let spend_sk = SecretKey::from_slice(&[0xbbu8; 32]).expect("valid sk");
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
        (
            hex::encode(scan_pk.serialize()),
            hex::encode(spend_pk.serialize()),
        )
    }

    #[test]
    fn encode_then_decode_round_trips_keys() {
        let (scan_hex, spend_hex) = sample_pubkeys_hex();

        let scan_pk = parse_compressed_pubkey(&scan_hex, "scan_pk").expect("parse scan");
        let spend_pk = parse_compressed_pubkey(&spend_hex, "spend_pk").expect("parse spend");

        let address = MetaAddress::new(StealthNetwork::Mainnet, scan_pk, spend_pk).to_bech32m();

        let decoded = MetaAddress::from_bech32m(&address).expect("decode");

        assert_eq!(decoded.network(), StealthNetwork::Mainnet);
        assert_eq!(hex::encode(decoded.scan_pk().serialize()), scan_hex);
        assert_eq!(hex::encode(decoded.spend_pk().serialize()), spend_hex);
    }

    #[test]
    fn parse_pubkey_rejects_wrong_length() {
        let err = parse_compressed_pubkey("00", "scan_pk").unwrap_err();
        assert!(err.to_string().contains("must be a 33-byte"));
    }

    #[test]
    fn parse_pubkey_rejects_non_hex() {
        let err = parse_compressed_pubkey("zzzz", "scan_pk").unwrap_err();
        assert!(err.to_string().contains("not valid hex"));
    }
}
