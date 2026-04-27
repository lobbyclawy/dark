//! Local stub for `dark_client::create_confidential_tx` (#572).
//!
//! Issue #572 is in flight; until it lands, the CLI cannot build a real
//! confidential transaction. This module mirrors the eventual API
//! shape so callers can be wired up today and the stub can be deleted
//! once #572 ships:
//!
//! ```text
//! pub async fn create_confidential_tx(
//!     client: &mut ArkClient,
//!     request: ConfidentialSendRequest,
//! ) -> ClientResult<ConfidentialTxOutcome>;
//! ```
//!
//! The stub validates inputs, records the request, and returns a
//! deterministic placeholder outcome marked `not_built` so JSON
//! consumers can distinguish a stubbed call from a real one.

use anyhow::{anyhow, Result};
use dark_confidential::stealth::MetaAddress;

/// Inputs for a confidential VTXO send.
///
/// TODO(#572): replace with `dark_client::ConfidentialSendRequest` once
/// the real type is published. The fields here match the eventual API
/// 1:1 so call sites do not need to change.
#[derive(Debug, Clone)]
pub struct ConfidentialSendRequest<'a> {
    /// Recipient meta-address (already decoded).
    pub recipient: &'a MetaAddress,
    /// Amount to send, in satoshis.
    pub amount_sats: u64,
    /// Optional sender memo. Cleartext for now — encryption lands
    /// with #536.
    pub memo: Option<&'a str>,
}

/// Outcome of a stubbed confidential send.
///
/// `status` is always `"not_built"` so callers can detect the stub at
/// runtime without parsing comments.
#[derive(Debug, Clone)]
pub struct ConfidentialTxOutcome {
    pub status: &'static str,
    pub recipient_hrp: String,
    pub amount_sats: u64,
    pub memo: Option<String>,
}

/// Stubbed builder for a confidential VTXO transaction.
///
/// Validates the inputs the way the real builder will (positive
/// amount, memo length cap) and surfaces a structured outcome so the
/// CLI can render a consistent message.
///
/// TODO(#572): delete this file and call
/// `dark_client::create_confidential_tx` directly once the upstream
/// builder lands.
/// TODO(#536): the `memo` is currently passed through cleartext.
/// Once memo encryption ships, accept a `MemoPayload` and encrypt
/// inside the builder.
pub fn create_confidential_tx(
    request: ConfidentialSendRequest<'_>,
) -> Result<ConfidentialTxOutcome> {
    if request.amount_sats == 0 {
        return Err(anyhow!("send amount must be greater than zero"));
    }

    if let Some(memo) = request.memo {
        if memo.len() > MAX_MEMO_BYTES {
            return Err(anyhow!(
                "memo exceeds {} bytes (got {})",
                MAX_MEMO_BYTES,
                memo.len()
            ));
        }
    }

    Ok(ConfidentialTxOutcome {
        status: "not_built",
        recipient_hrp: request.recipient.network().hrp().to_string(),
        amount_sats: request.amount_sats,
        memo: request.memo.map(str::to_string),
    })
}

/// Maximum memo length, mirroring the cap the real builder is
/// expected to enforce. Tracked in #536.
pub const MAX_MEMO_BYTES: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;
    use dark_confidential::stealth::StealthNetwork;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn sample_meta_address() -> MetaAddress {
        let secp = Secp256k1::new();
        let scan_pk =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
        let spend_pk =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[4u8; 32]).unwrap());
        MetaAddress::new(StealthNetwork::Regtest, scan_pk, spend_pk)
    }

    #[test]
    fn stub_returns_not_built_outcome_for_valid_input() {
        let meta = sample_meta_address();
        let outcome = create_confidential_tx(ConfidentialSendRequest {
            recipient: &meta,
            amount_sats: 1_000,
            memo: Some("hello"),
        })
        .unwrap();
        assert_eq!(outcome.status, "not_built");
        assert_eq!(outcome.amount_sats, 1_000);
        assert_eq!(outcome.memo.as_deref(), Some("hello"));
        assert_eq!(outcome.recipient_hrp, "rdarks");
    }

    #[test]
    fn stub_rejects_zero_amount() {
        let meta = sample_meta_address();
        let err = create_confidential_tx(ConfidentialSendRequest {
            recipient: &meta,
            amount_sats: 0,
            memo: None,
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("greater than zero"));
    }

    #[test]
    fn stub_rejects_oversized_memo() {
        let meta = sample_meta_address();
        let big_memo = "x".repeat(MAX_MEMO_BYTES + 1);
        let err = create_confidential_tx(ConfidentialSendRequest {
            recipient: &meta,
            amount_sats: 1,
            memo: Some(&big_memo),
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("memo exceeds"));
    }
}
