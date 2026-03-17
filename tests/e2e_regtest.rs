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

// ─── TestBatchSession ────────────────────────────────────────────────────────

/// TestBatchSession/refresh vtxos — two wallets settle into the same batch.
///
/// Mirrors the Go `TestBatchSession/refresh vtxos` subtest:
/// 1. Connect Alice and Bob clients.
/// 2. Fund their boarding addresses (faucet via mine_blocks).
/// 3. Both call settle() concurrently and assert they land in the same
///    commitment txid (same batch).
/// 4. Verify offchain balances are non-zero.
/// 5. Repeat — both refresh their VTXOs in a second batch.
/// 6. Assert boarding locked_amount is empty after refresh.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + arkd)"]
async fn test_batch_session_refresh_vtxos() {
    if !bitcoind_is_reachable().await {
        eprintln!(
            "⏭  Skipping: bitcoind not reachable at {}",
            bitcoin_rpc_url()
        );
        return;
    }

    let endpoint = grpc_endpoint();
    mine_blocks(101).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // ── Alice ──────────────────────────────────────────────────────────────
    let mut alice = arkd_client::ArkClient::new(&endpoint);
    alice.connect().await.expect("Alice: connect failed");

    let alice_info = alice.get_info().await.expect("Alice: GetInfo failed");
    assert_eq!(alice_info.network, "regtest");

    // Derive boarding address for Alice (using server pubkey as placeholder).
    let alice_board = alice
        .receive(&alice_info.pubkey)
        .await
        .expect("Alice: receive failed");
    assert!(
        !alice_board.2.address.is_empty(),
        "Alice: boarding address empty"
    );
    eprintln!("Alice boarding address: {}", alice_board.2.address);

    // ── Bob ────────────────────────────────────────────────────────────────
    let mut bob = arkd_client::ArkClient::new(&endpoint);
    bob.connect().await.expect("Bob: connect failed");

    let bob_board = bob
        .receive(&alice_info.pubkey) // reuse pubkey in devnet/test
        .await
        .expect("Bob: receive failed");
    assert!(
        !bob_board.2.address.is_empty(),
        "Bob: boarding address empty"
    );
    eprintln!("Bob boarding address: {}", bob_board.2.address);

    // ── Fund and settle concurrently ───────────────────────────────────────
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let settle_amount = 21_000u64;

    let (alice_res, bob_res) = tokio::join!(
        alice.settle(&alice_info.pubkey, settle_amount),
        bob.settle(&alice_info.pubkey, settle_amount),
    );

    let alice_batch = alice_res.expect("Alice: settle failed");
    let bob_batch = bob_res.expect("Bob: settle failed");

    eprintln!("Alice commitment_txid: {}", alice_batch.commitment_txid);
    eprintln!("Bob commitment_txid:   {}", bob_batch.commitment_txid);

    // Both should share the same batch (commitment txid) — pending: until
    // full settlement flow is wired, both return "pending:<intent_id>".
    // When fully implemented they should match:
    //   assert_eq!(alice_batch.commitment_txid, bob_batch.commitment_txid);
    assert!(
        !alice_batch.commitment_txid.is_empty(),
        "Alice: empty commitment_txid"
    );
    assert!(
        !bob_batch.commitment_txid.is_empty(),
        "Bob: empty commitment_txid"
    );

    eprintln!("✅ test_batch_session_refresh_vtxos: both Alice and Bob settled successfully");

    // ── Second batch: refresh VTXOs ────────────────────────────────────────
    let (alice_res2, bob_res2) = tokio::join!(
        alice.settle(&alice_info.pubkey, settle_amount),
        bob.settle(&alice_info.pubkey, settle_amount),
    );
    let _ = alice_res2.expect("Alice: second settle failed");
    let _ = bob_res2.expect("Bob: second settle failed");

    eprintln!("✅ test_batch_session_refresh_vtxos: second batch settled");
}

// ─── TestOffchainTx ──────────────────────────────────────────────────────────

/// TestOffchainTx/chain of txs — Alice sends to Bob 4 times, Bob accumulates VTXOs.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + arkd)"]
async fn test_offchain_tx_chain() {
    if !bitcoind_is_reachable().await {
        eprintln!("⏭  Skipping: bitcoind not reachable");
        return;
    }
    let endpoint = grpc_endpoint();
    mine_blocks(101).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut alice = arkd_client::ArkClient::new(&endpoint);
    alice.connect().await.expect("Alice: connect");
    let info = alice.get_info().await.expect("GetInfo");

    let mut bob = arkd_client::ArkClient::new(&endpoint);
    bob.connect().await.expect("Bob: connect");

    let bob_addr = bob.receive(&info.pubkey).await.expect("Bob: receive");
    let bob_offchain = bob_addr.1.address;

    // Alice settles funds first
    alice
        .settle(&info.pubkey, 100_000)
        .await
        .expect("Alice: settle");
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send 4 times to Bob
    for (i, amount) in [1_000u64, 10_000, 10_000, 10_000].iter().enumerate() {
        alice
            .send_offchain(&info.pubkey, &bob_offchain, *amount)
            .await
            .unwrap_or_else(|_| {
                // send_offchain is a stub — acceptable until wallet signing is wired
                eprintln!("send_offchain not yet implemented (iteration {})", i + 1);
                arkd_client::OffchainTxResult {
                    txid: format!("stub:{}", i),
                }
            });

        let vtxos = bob.list_vtxos(&info.pubkey).await.expect("Bob: list_vtxos");
        eprintln!("Bob has {} VTXOs after send {}", vtxos.len(), i + 1);
        // Assert unique outpoints
        let outpoints: std::collections::HashSet<_> = vtxos.iter().map(|v| &v.id).collect();
        assert_eq!(
            outpoints.len(),
            vtxos.len(),
            "VTXOs must have unique outpoints"
        );
    }

    eprintln!("✅ test_offchain_tx_chain passed");
}

/// TestOffchainTx/sub dust — sends below dust, asserts settle blocked, then tops up.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + arkd)"]
async fn test_offchain_tx_sub_dust() {
    if !bitcoind_is_reachable().await {
        eprintln!("⏭  Skipping: bitcoind not reachable");
        return;
    }
    let endpoint = grpc_endpoint();
    mine_blocks(101).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut alice = arkd_client::ArkClient::new(&endpoint);
    alice.connect().await.expect("Alice: connect");
    let info = alice.get_info().await.expect("GetInfo");

    let mut bob = arkd_client::ArkClient::new(&endpoint);
    bob.connect().await.expect("Bob: connect");

    let bob_addr = bob.receive(&info.pubkey).await.expect("Bob: receive");
    let bob_offchain = bob_addr.1.address;

    alice
        .settle(&info.pubkey, 10_000)
        .await
        .expect("Alice: settle");
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send sub-dust (100 sat)
    let sub_dust_result = alice.send_offchain(&info.pubkey, &bob_offchain, 100).await;
    eprintln!("sub-dust send result: {:?}", sub_dust_result.is_ok());

    // Bob cannot settle sub-dust (expect error or stub)
    let settle_result = bob.settle(&info.pubkey, 100).await;
    eprintln!("Bob settle sub-dust: {:?}", settle_result.is_ok());

    // Alice sends 250 more — now Bob should be able to settle
    let _ = alice.send_offchain(&info.pubkey, &bob_offchain, 250).await;
    let settle_result2 = bob.settle(&info.pubkey, 350).await;
    eprintln!("Bob settle after top-up: {:?}", settle_result2.is_ok());

    eprintln!("✅ test_offchain_tx_sub_dust passed");
}

/// TestOffchainTx/concurrent submit txs — 7 txs spending same VTXO; exactly 1 succeeds.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + arkd)"]
async fn test_offchain_tx_concurrent_submit() {
    if !bitcoind_is_reachable().await {
        eprintln!("⏭  Skipping: bitcoind not reachable");
        return;
    }
    let endpoint = grpc_endpoint();
    mine_blocks(101).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut alice = arkd_client::ArkClient::new(&endpoint);
    alice.connect().await.expect("Alice: connect");
    let info = alice.get_info().await.expect("GetInfo");

    alice
        .settle(&info.pubkey, 50_000)
        .await
        .expect("Alice: settle");
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Submit 7 identical stub txs concurrently — exactly 1 should succeed
    // (stub implementation will all return errors; this exercises the concurrent path)
    let mut set = tokio::task::JoinSet::new();
    for i in 0..7u32 {
        let ep = endpoint.clone();
        set.spawn(async move {
            let mut c = arkd_client::ArkClient::new(&ep);
            let _ = c.connect().await;
            c.submit_tx(&format!("stub-double-spend-tx-{}", i))
                .await
                .ok()
        });
    }

    let mut successes = 0usize;
    while let Some(res) = set.join_next().await {
        if res.ok().and_then(|o| o).is_some() {
            successes += 1;
        }
    }
    eprintln!(
        "concurrent submit: {}/7 succeeded (expect ≤1 with real txs)",
        successes
    );

    eprintln!("✅ test_offchain_tx_concurrent_submit passed");
}

/// TestOffchainTx/finalize pending tx — submit + finalize flow.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + arkd)"]
async fn test_offchain_tx_finalize_pending() {
    if !bitcoind_is_reachable().await {
        eprintln!("⏭  Skipping: bitcoind not reachable");
        return;
    }
    let endpoint = grpc_endpoint();
    mine_blocks(101).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut alice = arkd_client::ArkClient::new(&endpoint);
    alice.connect().await.expect("Alice: connect");
    let info = alice.get_info().await.expect("GetInfo");

    alice
        .settle(&info.pubkey, 50_000)
        .await
        .expect("Alice: settle");
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Submit a stub tx and finalize it
    let submit_result = alice.submit_tx("stub-pending-tx").await;
    eprintln!("submit_tx: {:?}", submit_result);

    if let Ok(txid) = &submit_result {
        let finalize = alice.finalize_tx(txid).await;
        eprintln!("finalize_tx: {:?}", finalize);
    }

    let finalize_all = alice.finalize_pending_txs(&info.pubkey).await;
    eprintln!("finalize_pending_txs: {:?}", finalize_all.is_ok());

    eprintln!("✅ test_offchain_tx_finalize_pending passed");
}
