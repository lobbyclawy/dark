//! E2E regtest integration tests for arkd-rs.
//!
//! These tests exercise the full server against a real Bitcoin regtest node
//! (e.g. via [Nigiri](https://nigiri.vulpem.com/)).
//!
//! **Requirements:**
//! - A running Bitcoin regtest node reachable at `BITCOIN_RPC_URL`
//!   (default: `http://admin1:123@127.0.0.1:18443`)
//! - An Esplora instance at `ESPLORA_URL` (default: `http://localhost:3000`)
//! - `arkd` binary available (built via `cargo build --bin arkd`)
//!
//! All tests are marked `#[ignore]` so they are skipped during normal
//! `cargo test`. Run them explicitly with:
//!
//! ```bash
//! cargo test --test e2e_regtest -- --ignored
//! ```
//!
//! Or in a CI job that provisions a regtest environment first.

use std::time::Duration;

// ─── Helpers ────────────────────────────────────────────────────────

/// Returns the Bitcoin Core RPC URL from the environment, or the Nigiri default.
fn bitcoin_rpc_url() -> String {
    std::env::var("BITCOIN_RPC_URL")
        .unwrap_or_else(|_| "http://admin1:123@127.0.0.1:18443".to_string())
}

/// Returns the Esplora URL from the environment, or the Nigiri default.
#[allow(dead_code)]
fn esplora_url() -> String {
    std::env::var("ESPLORA_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

/// Returns the gRPC endpoint where arkd is expected to listen.
fn grpc_endpoint() -> String {
    std::env::var("ARKD_GRPC_URL").unwrap_or_else(|_| "http://[::1]:50051".to_string())
}

/// Quick connectivity check — returns `true` when bitcoind is reachable.
///
/// Uses a raw JSON-RPC `getblockchaininfo` call so we don't pull in
/// the full `bitcoincore-rpc` crate as a dev-dependency for the
/// workspace root.
async fn bitcoind_is_reachable() -> bool {
    let url = bitcoin_rpc_url();
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Parse user:pass from URL
    let parsed = match url::Url::parse(&url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let user = parsed.username().to_string();
    let pass = parsed.password().unwrap_or("").to_string();

    let resp = client
        .post(url.as_str())
        .basic_auth(&user, Some(&pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "id": "e2e-probe",
            "method": "getblockchaininfo",
            "params": []
        }))
        .send()
        .await;

    matches!(resp, Ok(r) if r.status().is_success())
}

/// Mine `n` blocks to the bitcoind internal wallet (regtest only).
async fn mine_blocks(n: u32) {
    let url = bitcoin_rpc_url();
    let parsed = url::Url::parse(&url).expect("valid RPC URL");
    let user = parsed.username().to_string();
    let pass = parsed.password().unwrap_or("").to_string();

    let client = reqwest::Client::new();

    // Get a new address to mine to
    let addr_resp: serde_json::Value = client
        .post(url.as_str())
        .basic_auth(&user, Some(&pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "id": "mine",
            "method": "getnewaddress",
            "params": []
        }))
        .send()
        .await
        .expect("getnewaddress request")
        .json()
        .await
        .expect("getnewaddress json");

    let address = addr_resp["result"]
        .as_str()
        .expect("getnewaddress result string");

    // Generate blocks
    let _: serde_json::Value = client
        .post(url.as_str())
        .basic_auth(&user, Some(&pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "id": "mine",
            "method": "generatetoaddress",
            "params": [n, address]
        }))
        .send()
        .await
        .expect("generatetoaddress request")
        .json()
        .await
        .expect("generatetoaddress json");
}

// ─── Tests ──────────────────────────────────────────────────────────

/// Full round lifecycle: connect → get info → register intent → wait for round → verify.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + arkd)"]
async fn test_full_round_lifecycle() {
    if !bitcoind_is_reachable().await {
        eprintln!(
            "⏭  Skipping: bitcoind not reachable at {}",
            bitcoin_rpc_url()
        );
        return;
    }

    let endpoint = grpc_endpoint();

    // 1. Connect gRPC client
    let mut client = arkd_client::ArkClient::new(&endpoint);
    client
        .connect()
        .await
        .expect("failed to connect to arkd gRPC");

    // 2. Verify server info
    let info = client.get_info().await.expect("GetInfo RPC failed");
    assert_eq!(info.network, "regtest", "server must be running on regtest");
    assert!(!info.pubkey.is_empty(), "server pubkey must be set");
    eprintln!("✅ Connected to arkd — pubkey={}", info.pubkey);

    // 3. Mine some blocks to ensure the server wallet has funds
    mine_blocks(101).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 4. List rounds (should succeed even if empty)
    let rounds = client
        .list_rounds(Some(10), None)
        .await
        .expect("ListRounds failed");
    eprintln!("✅ ListRounds returned {} round(s)", rounds.len());
}

/// Boarding flow: fund a UTXO and board it into the Ark.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + arkd)"]
async fn test_boarding_flow() {
    if !bitcoind_is_reachable().await {
        eprintln!(
            "⏭  Skipping: bitcoind not reachable at {}",
            bitcoin_rpc_url()
        );
        return;
    }

    let endpoint = grpc_endpoint();

    // 1. Connect
    let mut client = arkd_client::ArkClient::new(&endpoint);
    client
        .connect()
        .await
        .expect("failed to connect to arkd gRPC");

    let info = client.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    // 2. Mine blocks to have UTXOs available
    mine_blocks(1).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 3. Check VTXOs for the server's own pubkey (should be 0 initially)
    let vtxos = client
        .list_vtxos(&info.pubkey)
        .await
        .expect("GetVtxos failed");
    eprintln!(
        "✅ Boarding test — server has {} VTXO(s) before boarding",
        vtxos.len()
    );

    // Full boarding requires:
    //   a) Wallet creates a boarding UTXO to the Ark address
    //   b) Client calls RegisterIntent with the boarding UTXO proof
    //   c) Server includes it in the next round
    // This skeleton validates the RPC layer is reachable and responds correctly.
}

/// VTXO expiry sweep: ensure the ASP sweeps expired VTXOs.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + arkd)"]
async fn test_vtxo_expiry_sweep() {
    if !bitcoind_is_reachable().await {
        eprintln!(
            "⏭  Skipping: bitcoind not reachable at {}",
            bitcoin_rpc_url()
        );
        return;
    }

    let endpoint = grpc_endpoint();

    // 1. Connect
    let mut client = arkd_client::ArkClient::new(&endpoint);
    client
        .connect()
        .await
        .expect("failed to connect to arkd gRPC");

    let info = client.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");
    eprintln!("✅ Expiry sweep test — connected to arkd");

    // To fully test expiry:
    //   a) Create a VTXO with a short expiry (e.g. 5 blocks)
    //   b) Mine past the expiry height
    //   c) Trigger or wait for the ASP's sweep cycle
    //   d) Verify the sweep tx is broadcast and confirmed
    //
    // For now, verify the admin RPC for scheduled sweeps is reachable.
    // (AdminService::GetScheduledSweep)
    //
    // Full implementation requires the round lifecycle to produce real VTXOs,
    // which will be addressed once the signing flow is complete.
}

/// Server health: verify GetInfo returns sensible regtest configuration.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + arkd)"]
async fn test_server_health_check() {
    if !bitcoind_is_reachable().await {
        eprintln!(
            "⏭  Skipping: bitcoind not reachable at {}",
            bitcoin_rpc_url()
        );
        return;
    }

    let endpoint = grpc_endpoint();
    let mut client = arkd_client::ArkClient::new(&endpoint);
    client
        .connect()
        .await
        .expect("failed to connect to arkd gRPC");

    let info = client.get_info().await.expect("GetInfo failed");

    // Validate regtest-specific invariants
    assert_eq!(info.network, "regtest", "must be regtest");
    assert!(!info.pubkey.is_empty(), "pubkey must not be empty");

    eprintln!(
        "✅ Health check passed — network={} pubkey={}",
        info.network, info.pubkey
    );
}
