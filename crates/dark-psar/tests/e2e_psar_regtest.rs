//! E2E regtest round-trip for [`SlotAttest`] OP_RETURN publication
//! (issue #669).
//!
//! Requires a running Bitcoin regtest node — the
//! [Nigiri](https://nigiri.vulpem.com/) defaults are honoured:
//!
//! ```bash
//! nigiri start
//! cargo test -p dark-psar --features regtest --test e2e_psar_regtest \
//!     -- --ignored --test-threads=1
//! ```
//!
//! Override the RPC URL with `BITCOIN_RPC_URL=http://user:pass@host:port`.
//!
//! All tests are `#[ignore]` so they are skipped during default
//! `cargo test` runs.

#![cfg(feature = "regtest")]

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use dark_psar::attest::{SlotAttest, SlotAttestUnsigned};
use dark_psar::publish::{decode_slot_attest_op_return, publish_slot_attest};
use secp256k1::{Keypair, Secp256k1, SecretKey};

const NIGIRI_DEFAULT_USER: &str = "admin1";
const NIGIRI_DEFAULT_PASS: &str = "123";

/// Strip an embedded `user:pass@` prefix from `https://user:pass@host:port`,
/// returning `(scheme://host:port, user, pass)`. Designed for the Nigiri
/// default URL format; we do not pull in the `url` crate for this.
fn split_rpc_url(raw: &str) -> (String, String, String) {
    let (scheme, rest) = raw
        .split_once("://")
        .map(|(s, r)| (format!("{s}://"), r.to_string()))
        .unwrap_or_else(|| ("http://".into(), raw.into()));
    let (creds, hostport) = match rest.split_once('@') {
        Some((c, h)) => (Some(c), h),
        None => (None, rest.as_str()),
    };
    let (user, pass) = creds
        .map(|c| match c.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (c.to_string(), String::new()),
        })
        .unwrap_or((NIGIRI_DEFAULT_USER.into(), NIGIRI_DEFAULT_PASS.into()));
    (format!("{scheme}{hostport}"), user, pass)
}

fn rpc_client() -> Client {
    let raw = std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| {
        format!("http://{NIGIRI_DEFAULT_USER}:{NIGIRI_DEFAULT_PASS}@127.0.0.1:18443")
    });
    let (host, user, pass) = split_rpc_url(&raw);
    Client::new(&host, Auth::UserPass(user, pass)).expect("rpc client")
}

fn ensure_funded(client: &Client) {
    // If the wallet has no spendable UTXO, mine 101 blocks to itself.
    let balance = client
        .get_balance(None, None)
        .unwrap_or(Amount::ZERO)
        .to_sat();
    if balance < 1_000_000 {
        let addr = client
            .get_new_address(None, None)
            .expect("new address")
            .assume_checked();
        let _ = client.generate_to_address(101, &addr);
    }
}

fn make_attest() -> (SlotAttest, secp256k1::XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0xa7u8; 32]).unwrap());
    let pk = kp.x_only_public_key().0;
    let attest = SlotAttestUnsigned {
        slot_root: [0xab; 32],
        cohort_id: [0xcd; 32],
        setup_id: [0xef; 32],
        n: 12,
        k: 100,
    }
    .sign(&secp, &kp);
    (attest, pk)
}

#[test]
#[ignore = "requires running Nigiri / regtest node — opt-in via --ignored"]
fn op_return_publication_round_trip() {
    let client = rpc_client();
    // Sanity: make sure the wallet is funded before publishing.
    ensure_funded(&client);

    let (attest, pk) = make_attest();
    let txid = publish_slot_attest(&client, &attest).expect("publish");

    // Mine the publication into a block so `getrawtransaction` returns it
    // without `txindex=1` enabled.
    let mining_addr = client
        .get_new_address(None, None)
        .expect("new addr")
        .assume_checked();
    let _ = client.generate_to_address(1, &mining_addr);

    let raw = client
        .get_raw_transaction(&txid, None)
        .expect("raw tx fetch");
    let payload = decode_slot_attest_op_return(&raw).expect("op_return present");

    // Recover and verify against the off-chain unsigned payload.
    let recovered =
        SlotAttest::from_op_return_with_unsigned(&payload, attest.unsigned, &pk).expect("verify");
    assert_eq!(recovered, attest);
}
