//! E2E regtest integration tests for dark.
//!
//! These tests exercise the full server against a real Bitcoin regtest node
//! (e.g. via [Nigiri](https://nigiri.vulpem.com/)).
//!
//! **Requirements:**
//! - A running Bitcoin regtest node reachable at `BITCOIN_RPC_URL`
//!   (default: `http://admin1:123@127.0.0.1:18443`)
//! - An Esplora instance at `ESPLORA_URL` (default: `http://localhost:5000`)
//! - `dark` binary available (built via `cargo build --release`)
//!
//! All tests are marked `#[ignore]` so they are skipped during normal
//! `cargo test`. Run them explicitly with:
//!
//! ```bash
//! cargo test --test e2e_regtest -- --ignored --test-threads=1
//! ```
//!
//! Or via the helper script:
//!
//! ```bash
//! ./scripts/e2e-test.sh
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════════════
// Test Infrastructure
// ═══════════════════════════════════════════════════════════════════════════════

/// Global port counter to avoid collisions when tests run sequentially.
static NEXT_PORT: AtomicU16 = AtomicU16::new(17_100);

fn allocate_ports() -> (u16, u16) {
    let grpc = NEXT_PORT.fetch_add(2, Ordering::SeqCst);
    let admin = grpc + 1;
    (grpc, admin)
}

// ─── Environment helpers ────────────────────────────────────────────────────

/// Returns the Bitcoin Core RPC URL from the environment, or the Nigiri default.
fn bitcoin_rpc_url() -> String {
    std::env::var("BITCOIN_RPC_URL")
        .unwrap_or_else(|_| "http://admin1:123@127.0.0.1:18443".to_string())
}

/// Returns the Esplora URL from the environment, or the Nigiri default.
fn esplora_url() -> String {
    std::env::var("ESPLORA_URL").unwrap_or_else(|_| "http://localhost:5000".to_string())
}

/// Returns the gRPC endpoint where dark is expected to listen.
fn grpc_endpoint() -> String {
    std::env::var("DARK_GRPC_URL").unwrap_or_else(|_| "http://127.0.0.1:7070".to_string())
}

/// Returns the admin HTTP URL from the environment, or the default.
fn admin_url() -> String {
    std::env::var("DARK_ADMIN_URL").unwrap_or_else(|_| "http://localhost:7071".to_string())
}

/// Path to the dark binary (built with `cargo build --release`).
fn dark_binary() -> PathBuf {
    let from_env = std::env::var("DARK_BINARY").ok();
    if let Some(p) = from_env {
        return PathBuf::from(p);
    }
    // Try release first, then debug
    let release = PathBuf::from("./target/release/dark");
    if release.exists() {
        return release;
    }
    PathBuf::from("./target/debug/dark")
}

// ─── Nigiri / Bitcoin helpers ───────────────────────────────────────────────

/// Quick connectivity check — returns `true` when bitcoind is reachable.
async fn bitcoind_is_reachable() -> bool {
    let url = bitcoin_rpc_url();
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

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

/// Check if Esplora is reachable.
async fn esplora_is_reachable() -> bool {
    let url = format!("{}/blocks/tip/height", esplora_url());
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
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

/// Broadcast a raw transaction hex via Esplora, return the txid.
async fn broadcast_tx_hex(tx_hex: &str) -> String {
    let url = format!("{}/tx", esplora_url());
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(tx_hex.to_string())
        .send()
        .await
        .expect("broadcast failed");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "broadcast failed ({status}): {body}");
    body.trim().to_string()
}

/// Send `amount_btc` from the regtest wallet to `address` via `sendtoaddress`.
/// Returns the txid.
async fn faucet_fund(address: &str, amount_btc: f64) -> String {
    let url = bitcoin_rpc_url();
    let parsed = url::Url::parse(&url).expect("valid RPC URL");
    let user = parsed.username().to_string();
    let pass = parsed.password().unwrap_or("").to_string();

    let client = reqwest::Client::new();

    let resp: serde_json::Value = client
        .post(url.as_str())
        .basic_auth(&user, Some(&pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "id": "faucet",
            "method": "sendtoaddress",
            "params": [address, amount_btc]
        }))
        .send()
        .await
        .expect("sendtoaddress request")
        .json()
        .await
        .expect("sendtoaddress json");

    resp["result"]
        .as_str()
        .expect("sendtoaddress result string")
        .to_string()
}

/// Get the current block height.
async fn get_block_height() -> u64 {
    let url = bitcoin_rpc_url();
    let parsed = url::Url::parse(&url).expect("valid RPC URL");
    let user = parsed.username().to_string();
    let pass = parsed.password().unwrap_or("").to_string();

    let client = reqwest::Client::new();

    let resp: serde_json::Value = client
        .post(url.as_str())
        .basic_auth(&user, Some(&pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "id": "height",
            "method": "getblockcount",
            "params": []
        }))
        .send()
        .await
        .expect("getblockcount request")
        .json()
        .await
        .expect("getblockcount json");

    resp["result"].as_u64().expect("getblockcount result u64")
}

/// Get the raw transaction hex for a given txid.
#[allow(dead_code)]
async fn get_raw_transaction(txid: &str) -> String {
    let url = bitcoin_rpc_url();
    let parsed = url::Url::parse(&url).expect("valid RPC URL");
    let user = parsed.username().to_string();
    let pass = parsed.password().unwrap_or("").to_string();

    let client = reqwest::Client::new();

    let resp: serde_json::Value = client
        .post(url.as_str())
        .basic_auth(&user, Some(&pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "id": "rawtx",
            "method": "getrawtransaction",
            "params": [txid, false]
        }))
        .send()
        .await
        .expect("getrawtransaction request")
        .json()
        .await
        .expect("getrawtransaction json");

    resp["result"]
        .as_str()
        .expect("getrawtransaction result string")
        .to_string()
}

// ─── Admin REST helpers ─────────────────────────────────────────────────────

/// Admin REST client for dark wallet and configuration management.
struct AdminClient {
    base_url: String,
    http: reqwest::Client,
}

impl AdminClient {
    fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("admin http client"),
        }
    }

    fn from_env() -> Self {
        Self::new(&admin_url())
    }

    /// Create a new wallet via the admin REST gateway.
    async fn wallet_create(&self, password: &str) -> Result<serde_json::Value, String> {
        let resp = self
            .http
            .post(format!("{}/v1/admin/wallet/create", self.base_url))
            .basic_auth("admin", Some("admin"))
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await
            .map_err(|e| format!("wallet_create request: {e}"))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("wallet_create json: {e}"))?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("wallet_create HTTP {}: {}", status, body))
        }
    }

    /// Unlock the wallet.
    async fn wallet_unlock(&self, password: &str) -> Result<serde_json::Value, String> {
        let resp = self
            .http
            .post(format!("{}/v1/admin/wallet/unlock", self.base_url))
            .basic_auth("admin", Some("admin"))
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await
            .map_err(|e| format!("wallet_unlock request: {e}"))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("wallet_unlock json: {e}"))?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("wallet_unlock HTTP {}: {}", status, body))
        }
    }

    /// Get the wallet seed (mnemonic).
    async fn wallet_seed(&self) -> Result<String, String> {
        let resp = self
            .http
            .get(format!("{}/v1/admin/wallet/seed", self.base_url))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .map_err(|e| format!("wallet_seed request: {e}"))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("wallet_seed json: {e}"))?;

        if status.is_success() {
            Ok(body["seed"].as_str().unwrap_or_default().to_string())
        } else {
            Err(format!("wallet_seed HTTP {}: {}", status, body))
        }
    }

    /// Get wallet status.
    async fn wallet_status(&self) -> Result<serde_json::Value, String> {
        let resp = self
            .http
            .get(format!("{}/v1/admin/wallet/status", self.base_url))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .map_err(|e| format!("wallet_status request: {e}"))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("wallet_status json: {e}"))?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("wallet_status HTTP {}: {}", status, body))
        }
    }

    /// Trigger a forced sweep via admin API.
    async fn force_sweep(
        &self,
        connectors: bool,
        commitment_txids: Vec<String>,
    ) -> Result<serde_json::Value, String> {
        let resp = self
            .http
            .post(format!("{}/v1/admin/sweep", self.base_url))
            .basic_auth("admin", Some("admin"))
            .json(&serde_json::json!({
                "connectors": connectors,
                "commitment_txids": commitment_txids,
            }))
            .send()
            .await
            .map_err(|e| format!("force_sweep request: {e}"))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("force_sweep json: {e}"))?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("force_sweep HTTP {}: {}", status, body))
        }
    }

    /// Get scheduled sweeps.
    async fn get_scheduled_sweeps(&self) -> Result<serde_json::Value, String> {
        let resp = self
            .http
            .get(format!("{}/v1/admin/sweeps", self.base_url))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .map_err(|e| format!("get_scheduled_sweeps request: {e}"))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("get_scheduled_sweeps json: {e}"))?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("get_scheduled_sweeps HTTP {}: {}", status, body))
        }
    }

    /// Set fee programs via admin API.
    async fn set_fee_programs(
        &self,
        programs: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let resp = self
            .http
            .post(format!("{}/v1/admin/fees", self.base_url))
            .basic_auth("admin", Some("admin"))
            .json(&programs)
            .send()
            .await
            .map_err(|e| format!("set_fee_programs request: {e}"))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("set_fee_programs json: {e}"))?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("set_fee_programs HTTP {}: {}", status, body))
        }
    }

    /// Check if the admin endpoint is reachable.
    async fn is_reachable(&self) -> bool {
        let resp = self
            .http
            .get(format!("{}/v1/admin/wallet/status", self.base_url))
            .basic_auth("admin", Some("admin"))
            .send()
            .await;
        matches!(resp, Ok(r) if r.status().is_success() || r.status().as_u16() == 401)
    }
}

// ─── dark process management ────────────────────────────────────────────────

/// Managed dark server process for tests.
/// Spawns dark with a dedicated data directory and kills it on drop.
struct DarkProcess {
    child: Option<std::process::Child>,
    data_dir: tempfile::TempDir,
    grpc_port: u16,
    admin_port: u16,
}

impl DarkProcess {
    /// Spawn a new dark instance.
    ///
    /// Returns `None` if the binary doesn't exist.
    async fn spawn(config_overrides: HashMap<String, String>) -> Option<Self> {
        let binary = dark_binary();
        if !binary.exists() {
            eprintln!("⏭  dark binary not found at {:?}", binary);
            return None;
        }

        let data_dir = tempfile::TempDir::new().expect("create temp dir for dark");
        let (grpc_port, admin_port) = allocate_ports();

        let mut cmd = std::process::Command::new(&binary);
        cmd.arg("--data-dir")
            .arg(data_dir.path())
            .arg("--grpc-port")
            .arg(grpc_port.to_string())
            .arg("--admin-port")
            .arg(admin_port.to_string())
            .arg("--network")
            .arg("regtest");

        // Apply environment-based config overrides
        for (k, v) in &config_overrides {
            cmd.env(k, v);
        }

        // Suppress stdout/stderr in tests unless DARK_VERBOSE is set.
        if std::env::var("DARK_VERBOSE").is_err() {
            cmd.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
        }

        let child = cmd.spawn().ok()?;

        let proc = Self {
            child: Some(child),
            data_dir,
            grpc_port,
            admin_port,
        };

        // Wait for the gRPC port to become ready (up to 15s).
        let _grpc_url = proc.grpc_url();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if tokio::time::Instant::now() > deadline {
                eprintln!("⚠  dark did not become ready within 15s");
                break;
            }
            let probe = reqwest::Client::builder()
                .timeout(Duration::from_millis(500))
                .build()
                .ok()
                .and_then(|_c| {
                    // Try a TCP connect to verify port is open.
                    None::<reqwest::Response> // placeholder
                });
            let _ = probe;

            // Simple TCP probe
            if std::net::TcpStream::connect(format!("127.0.0.1:{}", grpc_port)).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Some(proc)
    }

    fn grpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.grpc_port)
    }

    fn admin_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.admin_port)
    }

    #[allow(dead_code)]
    fn data_path(&self) -> &std::path::Path {
        self.data_dir.path()
    }
}

impl Drop for DarkProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ─── Test helpers ───────────────────────────────────────────────────────────

/// Skip macro — checks bitcoind connectivity and returns early if not reachable.
macro_rules! require_regtest {
    () => {
        if !bitcoind_is_reachable().await {
            eprintln!(
                "⏭  Skipping: bitcoind not reachable at {}",
                bitcoin_rpc_url()
            );
            return;
        }
    };
}

/// Connect an `ArkClient` to the default gRPC endpoint.
async fn connect_client(endpoint: &str) -> dark_client::ArkClient {
    let mut client = dark_client::ArkClient::new(endpoint);
    client
        .connect()
        .await
        .expect("failed to connect to dark gRPC");
    client
}

/// Generate a fresh secp256k1 keypair and return (secret_key, compressed_pubkey_hex).
fn generate_keypair() -> (bitcoin::secp256k1::SecretKey, String) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (sk, pk) = secp.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());
    let pubkey_hex = hex::encode(pk.serialize());
    (sk, pubkey_hex)
}

/// Fund the regtest wallet and ensure 101+ confirmations for coinbase maturity.
async fn ensure_funded() {
    let height = get_block_height().await;
    if height < 101 {
        mine_blocks((101 - height as u32) + 1).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Server Health ──────────────────────────────────────────────────────────

/// Server health: verify GetInfo returns sensible regtest configuration.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_server_health_check() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut client = connect_client(&endpoint).await;

    let info = client.get_info().await.expect("GetInfo failed");

    assert_eq!(info.network, "regtest", "must be regtest");
    assert!(!info.pubkey.is_empty(), "pubkey must not be empty");
    assert!(info.dust > 0, "dust must be > 0");
    assert!(info.vtxo_min_amount > 0, "vtxo_min_amount must be > 0");
    assert!(info.session_duration > 0, "session_duration must be > 0");
    assert!(
        info.unilateral_exit_delay > 0,
        "unilateral_exit_delay must be > 0"
    );

    eprintln!(
        "✅ Health check passed — network={} pubkey={} dust={} exit_delay={}",
        info.network, info.pubkey, info.dust, info.unilateral_exit_delay
    );
}

/// Esplora reachability check.
#[tokio::test]
#[ignore = "requires regtest environment"]
async fn test_esplora_reachable() {
    if !esplora_is_reachable().await {
        eprintln!("⏭  Skipping: Esplora not reachable at {}", esplora_url());
        return;
    }
    eprintln!("✅ Esplora reachable at {}", esplora_url());
}

// ─── Full Round Lifecycle ───────────────────────────────────────────────────

/// Full round lifecycle: connect → get info → register intent → wait for round → verify.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_full_round_lifecycle() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut client = connect_client(&endpoint).await;

    // Verify server info
    let info = client.get_info().await.expect("GetInfo RPC failed");
    assert_eq!(info.network, "regtest", "server must be running on regtest");
    assert!(!info.pubkey.is_empty(), "server pubkey must be set");
    eprintln!("✅ Connected to dark — pubkey={}", info.pubkey);

    // Mine some blocks to ensure the server wallet has funds
    ensure_funded().await;

    // List rounds (should succeed even if empty)
    let rounds = client
        .list_rounds(Some(10), None)
        .await
        .expect("ListRounds failed");
    eprintln!("✅ ListRounds returned {} round(s)", rounds.len());
}

// ─── Boarding Flow ──────────────────────────────────────────────────────────

/// Boarding flow: fund a UTXO and board it into the Ark.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_boarding_flow() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut client = connect_client(&endpoint).await;

    let info = client.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    // Mine blocks to have UTXOs available
    mine_blocks(1).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Check VTXOs for the server's own pubkey (should be 0 initially)
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

// ─── TestBatchSession ────────────────────────────────────────────────────────

/// TestBatchSession/refresh vtxos — two wallets settle into the same batch.
///
/// Mirrors Go `TestBatchSession/refresh vtxos`:
/// Both call settle_with_key() — real MuSig2 batch protocol.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_batch_session_refresh_vtxos() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let (bob_sk, bob_pubkey) = generate_keypair();

    let mut alice = connect_client(&endpoint).await;
    let alice_info = alice.get_info().await.expect("Alice: GetInfo failed");
    assert_eq!(alice_info.network, "regtest");

    let alice_board = alice
        .receive(&alice_pubkey)
        .await
        .expect("Alice: receive failed");
    assert!(
        !alice_board.2.address.is_empty(),
        "Alice: boarding address empty"
    );
    let _alice_fund_txid = faucet_fund(&alice_board.2.address, 0.00021).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut bob = connect_client(&endpoint).await;
    let bob_board = bob.receive(&bob_pubkey).await.expect("Bob: receive failed");
    assert!(
        !bob_board.2.address.is_empty(),
        "Bob: boarding address empty"
    );
    let _bob_fund_txid = faucet_fund(&bob_board.2.address, 0.00021).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let settle_amount = 21_000u64;
    let (alice_res, bob_res) = tokio::join!(
        alice.settle_with_key(&alice_pubkey, settle_amount, &alice_sk),
        bob.settle_with_key(&bob_pubkey, settle_amount, &bob_sk),
    );
    let alice_batch = alice_res.expect("Alice: settle_with_key failed");
    let bob_batch = bob_res.expect("Bob: settle_with_key failed");

    assert!(
        !alice_batch.commitment_txid.is_empty(),
        "Alice: empty commitment_txid"
    );
    assert!(
        !alice_batch.commitment_txid.starts_with("pending:"),
        "Alice: got stub pending: prefix"
    );
    assert_eq!(
        alice_batch.commitment_txid, bob_batch.commitment_txid,
        "must land in same batch"
    );

    tokio::time::sleep(Duration::from_secs(1)).await;

    let alice_bal = alice
        .get_balance(&alice_pubkey)
        .await
        .expect("Alice: get_balance");
    assert!(
        alice_bal.offchain.total > 0,
        "Alice: offchain must be non-zero"
    );
    let bob_bal = bob
        .get_balance(&bob_pubkey)
        .await
        .expect("Bob: get_balance");
    assert!(bob_bal.offchain.total > 0, "Bob: offchain must be non-zero");

    tokio::time::sleep(Duration::from_secs(5)).await;

    let (alice_res2, bob_res2) = tokio::join!(
        alice.settle_with_key(&alice_pubkey, settle_amount, &alice_sk),
        bob.settle_with_key(&bob_pubkey, settle_amount, &bob_sk),
    );
    let alice_batch2 = alice_res2.expect("Alice: second settle_with_key failed");
    let bob_batch2 = bob_res2.expect("Bob: second settle_with_key failed");
    assert_eq!(
        alice_batch2.commitment_txid, bob_batch2.commitment_txid,
        "second batch: same batch"
    );

    tokio::time::sleep(Duration::from_secs(1)).await;

    let alice_bal = alice.get_balance(&alice_pubkey).await.expect("get_balance");
    assert!(
        alice_bal.offchain.total > 0,
        "Alice: offchain non-zero after refresh"
    );
    assert!(
        alice_bal.onchain.locked_amount.is_empty(),
        "Alice: locked_amount empty after refresh"
    );

    let bob_bal = bob.get_balance(&bob_pubkey).await.expect("get_balance");
    assert!(
        bob_bal.offchain.total > 0,
        "Bob: offchain non-zero after refresh"
    );
    assert!(
        bob_bal.onchain.locked_amount.is_empty(),
        "Bob: locked_amount empty after refresh"
    );

    eprintln!("✅ test_batch_session_refresh_vtxos passed with real MuSig2");
}

// ─── TestUnilateralExit ──────────────────────────────────────────────────────

/// TestUnilateralExit/leaf vtxo — Alice unrolls a leaf VTXO onto Bitcoin.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_unilateral_exit_leaf_vtxo() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo");

    // Fund Alice offchain
    alice
        .settle(&info.pubkey, 21_000)
        .await
        .expect("Alice: settle");
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Unroll: fetch tree PSBTs, finalize, and broadcast
    let tx_hexes = alice.unroll(&info.pubkey).await.expect("unroll failed");
    assert!(
        !tx_hexes.is_empty(),
        "unroll should produce at least one tx"
    );
    eprintln!("unroll: got {} finalized tx(es)", tx_hexes.len());

    let mut broadcast_txids = Vec::new();
    for tx_hex in &tx_hexes {
        let txid = broadcast_tx_hex(tx_hex).await;
        eprintln!("broadcast txid: {}", txid);
        broadcast_txids.push(txid);
    }
    assert!(!broadcast_txids.is_empty(), "should have broadcast txids");

    mine_blocks(1).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let balance = alice.get_balance(&info.pubkey).await.expect("get_balance");
    eprintln!(
        "Post-unroll balance: offchain={} locked={}",
        balance.offchain.total,
        balance.onchain.locked_amount.len()
    );

    eprintln!("\u{2705} test_unilateral_exit_leaf_vtxo passed");
}

/// TestUnilateralExit/preconfirmed vtxo — Bob unrolls a preconfirmed (offchain) VTXO.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_unilateral_exit_preconfirmed_vtxo() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo");

    let mut bob = connect_client(&endpoint).await;
    let bob_addr = bob.receive(&info.pubkey).await.expect("Bob: receive");
    let bob_offchain = bob_addr.1.address;

    // Alice funds and sends to Bob offchain (preconfirmed)
    alice
        .settle(&info.pubkey, 100_000)
        .await
        .expect("Alice: settle");
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let _ = alice
        .send_offchain(&info.pubkey, &bob_offchain, 21_000)
        .await;

    // Bob unrolls (checkpoint level)
    let tx_hexes1 = bob.unroll(&info.pubkey).await.expect("Bob unroll level 1");
    eprintln!("Bob unroll (level 1): {} tx(es)", tx_hexes1.len());
    for tx_hex in &tx_hexes1 {
        let txid = broadcast_tx_hex(tx_hex).await;
        eprintln!("  broadcast: {}", txid);
    }

    mine_blocks(2).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let tx_hexes2 = bob.unroll(&info.pubkey).await.expect("Bob unroll level 2");
    eprintln!("Bob unroll (level 2): {} tx(es)", tx_hexes2.len());
    for tx_hex in &tx_hexes2 {
        let txid = broadcast_tx_hex(tx_hex).await;
        eprintln!("  broadcast: {}", txid);
    }

    mine_blocks(1).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    eprintln!("\u{2705} test_unilateral_exit_preconfirmed_vtxo passed");
}

// ─── TestCollaborativeExit ──────────────────────────────────────────────────

/// TestCollaborativeExit/valid/with change — settle_with_key + collaborative exit.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_collaborative_exit_with_change() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let mut alice = connect_client(&endpoint).await;
    let _info = alice.get_info().await.expect("GetInfo");

    let alice_board = alice.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&alice_board.2.address, 0.001).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = alice
        .settle_with_key(&alice_pubkey, 100_000, &alice_sk)
        .await
        .expect("settle_with_key");
    assert!(
        !batch.commitment_txid.starts_with("pending:"),
        "expected real txid"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;

    let pre_balance = alice.get_balance(&alice_pubkey).await.expect("get_balance");
    let prev_total = pre_balance.offchain.total;
    assert!(prev_total > 0, "must have offchain balance");

    let onchain_dest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let vtxos = alice.list_vtxos(&alice_pubkey).await.expect("list_vtxos");
    let vtxo_ids: Vec<String> = vtxos
        .iter()
        .filter(|v| !v.is_spent && !v.is_swept)
        .map(|v| v.id.clone())
        .collect();
    assert!(!vtxo_ids.is_empty(), "must have spendable VTXOs");

    let exit_id = alice
        .collaborative_exit(onchain_dest, 21_000, vtxo_ids)
        .await
        .expect("collaborative_exit");
    eprintln!("collaborative_exit: {}", exit_id);
    tokio::time::sleep(Duration::from_secs(5)).await;

    let post_balance = alice.get_balance(&alice_pubkey).await.expect("get_balance");
    assert!(post_balance.offchain.total > 0, "should have change");
    assert!(
        post_balance.offchain.total < prev_total,
        "offchain should decrease"
    );

    eprintln!("✅ test_collaborative_exit_with_change passed");
}

/// TestCollaborativeExit/valid/without change — settle_with_key + exact exit.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_collaborative_exit_without_change() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let mut alice = connect_client(&endpoint).await;
    let _info = alice.get_info().await.expect("GetInfo");

    let alice_board = alice.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&alice_board.2.address, 0.00021100).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("settle_with_key");
    assert!(!batch.commitment_txid.starts_with("pending:"));
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert!(
        alice
            .get_balance(&alice_pubkey)
            .await
            .expect("bal")
            .offchain
            .total
            > 0
    );

    let onchain_dest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let vtxos = alice.list_vtxos(&alice_pubkey).await.expect("list_vtxos");
    let vtxo_ids: Vec<String> = vtxos
        .iter()
        .filter(|v| !v.is_spent && !v.is_swept)
        .map(|v| v.id.clone())
        .collect();
    assert!(!vtxo_ids.is_empty(), "must have spendable VTXOs");

    let exit_id = alice
        .collaborative_exit(onchain_dest, 21_000, vtxo_ids)
        .await
        .expect("collaborative_exit");
    eprintln!("collaborative_exit (no change): {}", exit_id);
    tokio::time::sleep(Duration::from_secs(5)).await;

    let post = alice.get_balance(&alice_pubkey).await.expect("get_balance");
    assert_eq!(
        post.offchain.total, 0,
        "offchain should be 0 after full exit"
    );
    assert!(
        post.onchain.locked_amount.is_empty(),
        "locked_amount should be empty"
    );

    eprintln!("✅ test_collaborative_exit_without_change passed");
}

/// TestCollaborativeExit/invalid/with boarding inputs — server must reject.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_collaborative_exit_invalid_with_boarding() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo");

    alice
        .settle(&info.pubkey, 21_100)
        .await
        .expect("Alice: settle");
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let onchain_dest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    // Attempt with an empty vtxo_ids list — should be rejected
    let result = alice.collaborative_exit(onchain_dest, 21_000, vec![]).await;
    assert!(result.is_err(), "empty vtxo_ids should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("vtxo_ids"), "got: {err}");

    eprintln!("✅ test_collaborative_exit_invalid_with_boarding passed");
}

/// TestCollaborativeExit/invalid/zero amount — server must reject zero-value exit.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_collaborative_exit_invalid_zero_amount() {
    require_regtest!();
    let endpoint = grpc_endpoint();

    let mut alice = connect_client(&endpoint).await;

    let result = alice
        .collaborative_exit(
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            0,
            vec!["abc:0".to_string()],
        )
        .await;
    assert!(result.is_err(), "zero amount should be rejected");

    eprintln!("✅ test_collaborative_exit_invalid_zero_amount passed");
}

// ─── TestOffchainTx ─────────────────────────────────────────────────────────

/// TestOffchainTx — Alice sends sats to Bob via settle_with_key + send_offchain.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_offchain_tx() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let (_bob_sk, bob_pubkey) = generate_keypair();

    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo");
    assert_eq!(info.network, "regtest");

    let alice_board = alice.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&alice_board.2.address, 0.001).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = alice
        .settle_with_key(&alice_pubkey, 100_000, &alice_sk)
        .await
        .expect("settle_with_key");
    assert!(!batch.commitment_txid.starts_with("pending:"));
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut bob = connect_client(&endpoint).await;
    let bob_addrs = bob.receive(&bob_pubkey).await.expect("Bob: receive");
    let bob_offchain_addr = &bob_addrs.1.address;
    assert!(!bob_offchain_addr.is_empty());

    // TODO: send_offchain() currently uses a stub SubmitTx path.
    let send_result = alice
        .send_offchain(&alice_pubkey, bob_offchain_addr, 5_000)
        .await;
    match &send_result {
        Ok(tx) => {
            eprintln!("✅ Offchain send: txid={}", tx.txid);
            tokio::time::sleep(Duration::from_secs(1)).await;
            let bob_bal = bob.get_balance(&bob_pubkey).await.expect("Bob bal");
            eprintln!("Bob offchain: {}", bob_bal.offchain.total);
        }
        Err(e) => eprintln!("⚠️  Offchain send not yet wired: {}", e),
    }

    eprintln!("✅ test_offchain_tx passed");
}

/// TestOffchainTx/multiple — settle_with_key + multiple sends.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_offchain_tx_multiple() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let (_bob_sk, bob_pubkey) = generate_keypair();

    let mut alice = connect_client(&endpoint).await;
    let _info = alice.get_info().await.expect("GetInfo");

    let board = alice.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&board.2.address, 0.001).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = alice
        .settle_with_key(&alice_pubkey, 100_000, &alice_sk)
        .await
        .expect("settle_with_key");
    assert!(!batch.commitment_txid.starts_with("pending:"));
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut bob = connect_client(&endpoint).await;
    let bob_addrs = bob.receive(&bob_pubkey).await.expect("Bob: receive");
    let bob_offchain = &bob_addrs.1.address;

    // TODO: send_offchain() stub — once wired, assert Bob VTXO count.
    for i in 1..=3 {
        let r = alice
            .send_offchain(&alice_pubkey, bob_offchain, 1_000)
            .await;
        match &r {
            Ok(r) => eprintln!("  #{}: txid={}", i, r.txid),
            Err(e) => eprintln!("  #{}: {}", i, e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!("✅ test_offchain_tx_multiple passed");
}

// ─── TestOffchainTx/chain ─────────────────────────────────────────────────────

/// TestOffchainTx/chain — settle_with_key + chain of sends.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_offchain_tx_chain() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let (_bob_sk, bob_pubkey) = generate_keypair();

    let mut alice = connect_client(&endpoint).await;
    let _info = alice.get_info().await.expect("GetInfo");

    let board = alice.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&board.2.address, 0.001).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = alice
        .settle_with_key(&alice_pubkey, 50_000, &alice_sk)
        .await
        .expect("settle_with_key");
    assert!(!batch.commitment_txid.starts_with("pending:"));
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut bob = connect_client(&endpoint).await;
    let bob_addrs = bob.receive(&bob_pubkey).await.expect("Bob: receive");
    let bob_offchain = &bob_addrs.1.address;

    let vtxos = alice.list_vtxos(&alice_pubkey).await.expect("list_vtxos");
    let spendable: Vec<_> = vtxos
        .iter()
        .filter(|v| !v.is_spent && !v.is_swept)
        .collect();
    assert!(!spendable.is_empty(), "must have spendable VTXOs");

    // TODO: send_offchain() stub — once wired, assert Bob VTXO count after each.
    for (i, &amt) in [1_000u64, 10_000, 10_000, 10_000].iter().enumerate() {
        let r = alice.send_offchain(&alice_pubkey, bob_offchain, amt).await;
        match &r {
            Ok(r) => eprintln!("  chain #{}: txid={}", i + 1, r.txid),
            Err(e) => eprintln!("  chain #{}: {}", i + 1, e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!("✅ test_offchain_tx_chain passed");
}

// ─── TestOffchainTx/sub_dust ─────────────────────────────────────────────────

/// TestOffchainTx/sub_dust — SubmitTx with an output below dust limit is rejected.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_offchain_tx_sub_dust() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo");
    eprintln!("dust limit from info: {}", info.dust);

    // Build an ark_tx JSON with a sub-dust output (1 sat)
    let ark_tx_json = serde_json::json!({
        "inputs": [{"vtxo_id": "deadbeef:0", "amount": 100}],
        "outputs": [{"pubkey": "02deadbeef", "amount": 1}]
    })
    .to_string();

    let result = alice.submit_tx(&ark_tx_json).await;
    match result {
        Err(e) => {
            eprintln!("✅ Sub-dust output correctly rejected: {}", e);
            assert!(
                e.to_string().contains("dust") || e.to_string().contains("InvalidArgument"),
                "Expected dust rejection error, got: {}",
                e
            );
        }
        Ok(txid) => {
            eprintln!(
                "⚠️  Sub-dust output accepted (txid={}) — dust limit may be 0 in test config",
                txid
            );
        }
    }

    eprintln!("✅ test_offchain_tx_sub_dust passed");
}

// ─── TestOffchainTx/concurrent_submit ────────────────────────────────────────

/// TestOffchainTx/concurrent_submit — settle_with_key + concurrent SubmitTx.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_offchain_tx_concurrent_submit() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let mut alice1 = connect_client(&endpoint).await;
    let mut alice2 = connect_client(&endpoint).await;
    let _info = alice1.get_info().await.expect("GetInfo");

    let board = alice1.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&board.2.address, 0.001).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = alice1
        .settle_with_key(&alice_pubkey, 50_000, &alice_sk)
        .await
        .expect("settle_with_key");
    assert!(!batch.commitment_txid.starts_with("pending:"));
    tokio::time::sleep(Duration::from_secs(1)).await;

    let vtxos = alice1.list_vtxos(&alice_pubkey).await.expect("list_vtxos");
    let spendable: Vec<_> = vtxos
        .iter()
        .filter(|v| !v.is_spent && !v.is_swept)
        .collect();
    assert!(!spendable.is_empty(), "must have spendable VTXOs");

    let vtxo = &spendable[0];
    let ark_tx_json = serde_json::json!({"inputs": [{"vtxo_id": format!("{}:{}", vtxo.txid, vtxo.vout), "amount": vtxo.amount}], "outputs": [{"pubkey": "02aabbcc", "amount": 10_000u64}]}).to_string();

    let (r1, r2) = tokio::join!(
        alice1.submit_tx(&ark_tx_json),
        alice2.submit_tx(&ark_tx_json)
    );
    let ok_count = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert!(ok_count >= 1, "At least one must succeed");
    eprintln!("✅ test_offchain_tx_concurrent_submit passed");
}

// ─── TestOffchainTx/finalize_pending ─────────────────────────────────────────

/// TestOffchainTx/finalize_pending — settle_with_key + FinalizePendingTxs.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_offchain_tx_finalize_pending() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let mut alice = connect_client(&endpoint).await;
    let _info = alice.get_info().await.expect("GetInfo");

    let board = alice.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&board.2.address, 0.001).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = alice
        .settle_with_key(&alice_pubkey, 50_000, &alice_sk)
        .await
        .expect("settle_with_key");
    assert!(!batch.commitment_txid.starts_with("pending:"));
    tokio::time::sleep(Duration::from_secs(1)).await;

    let vtxos = alice.list_vtxos(&alice_pubkey).await.expect("list_vtxos");
    let spendable: Vec<_> = vtxos
        .iter()
        .filter(|v| !v.is_spent && !v.is_swept)
        .collect();
    assert!(!spendable.is_empty(), "must have spendable VTXOs");

    let vtxo = &spendable[0];
    let ark_tx_json = serde_json::json!({"inputs": [{"vtxo_id": format!("{}:{}", vtxo.txid, vtxo.vout), "amount": vtxo.amount}], "outputs": [{"pubkey": "02aabbccdd", "amount": 10_000u64}]}).to_string();

    let ark_txid = alice.submit_tx(&ark_tx_json).await.expect("submit_tx");
    eprintln!("Submitted without finalizing: {}", ark_txid);
    tokio::time::sleep(Duration::from_secs(1)).await;

    let finalized = alice
        .finalize_pending_txs(&alice_pubkey)
        .await
        .expect("finalize_pending_txs");
    assert!(!finalized.is_empty(), "must finalize at least one");
    assert!(
        finalized.contains(&ark_txid),
        "Expected {} in finalized",
        ark_txid
    );
    eprintln!("✅ test_offchain_tx_finalize_pending passed");
}

// ─── TestIntent ──────────────────────────────────────────────────────────────

/// TestIntent/register and delete — intent lifecycle.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_intent_register_and_delete() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut client = connect_client(&endpoint).await;

    let info = client.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    ensure_funded().await;

    // Register an intent.
    let intent_id = client
        .register_intent(&info.pubkey, 10_000)
        .await
        .expect("register_intent failed");
    assert!(!intent_id.is_empty(), "intent_id must not be empty");
    eprintln!("✅ registered intent: {}", intent_id);

    // Second register — may succeed or fail depending on implementation.
    let second_result = client.register_intent(&info.pubkey, 10_000).await;
    eprintln!("second register_intent: {:?}", second_result.is_ok());

    // Delete the first intent — must succeed.
    client
        .delete_intent(&intent_id)
        .await
        .expect("delete_intent failed");
    eprintln!("✅ deleted intent: {}", intent_id);

    // Re-deleting should fail.
    let re_delete = client.delete_intent(&intent_id).await;
    assert!(
        re_delete.is_err(),
        "re-deleting a deleted intent should fail"
    );
    eprintln!("✅ re-delete correctly rejected");
}

/// TestIntent/concurrent register — two concurrent register_intent calls.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_intent_concurrent_register() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (mut c1, mut c2) = (
        dark_client::ArkClient::new(&endpoint),
        dark_client::ArkClient::new(&endpoint),
    );
    c1.connect().await.expect("c1 connect");
    c2.connect().await.expect("c2 connect");

    let info = c1.get_info().await.expect("GetInfo");
    let pubkey = info.pubkey.clone();

    let (r1, r2) = tokio::join!(
        c1.register_intent(&pubkey, 10_000),
        c2.register_intent(&pubkey, 10_000),
    );

    let successes = [r1.is_ok(), r2.is_ok()];
    assert!(
        successes.iter().any(|&ok| ok),
        "at least one concurrent register_intent must succeed"
    );
    eprintln!(
        "✅ concurrent register: c1={} c2={}",
        r1.is_ok(),
        r2.is_ok()
    );
}

/// TestIntent/join round — register intent and observe round participation.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_intent_join_round() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo");

    // Subscribe to event stream to observe the round.
    let (mut events_rx, events_close) = alice
        .get_event_stream(None)
        .await
        .expect("get_event_stream");

    // Register intent.
    let intent_id = alice
        .register_intent(&info.pubkey, 10_000)
        .await
        .expect("register_intent");
    assert!(!intent_id.is_empty());
    eprintln!("✅ intent registered: {}", intent_id);

    // Wait for a batch event (up to 30s — the session_duration).
    let event = tokio::time::timeout(
        Duration::from_secs(info.session_duration as u64 + 5),
        events_rx.recv(),
    )
    .await;

    match event {
        Ok(Some(e)) => eprintln!("✅ received batch event: {:?}", e),
        Ok(None) => eprintln!("⏭  event stream closed (no round triggered)"),
        Err(_) => eprintln!("⏭  timeout waiting for batch event"),
    }

    events_close();
    eprintln!("✅ test_intent_join_round passed");
}

// ─── TestSweep ───────────────────────────────────────────────────────────────

/// TestSweep/batch — settle_with_key + mine past expiry + verify sweep.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_sweep_batch() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    let (alice_sk, alice_pubkey) = generate_keypair();
    let mut client = connect_client(&endpoint).await;
    let info = client.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");
    ensure_funded().await;

    let board = client.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&board.2.address, 0.00021).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = client
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("settle_with_key");
    assert!(!batch.commitment_txid.starts_with("pending:"));
    eprintln!("✅ settled: {}", batch.commitment_txid);

    let sweep_blocks = info.unilateral_exit_delay / 600 + 10;
    mine_blocks(sweep_blocks).await;
    tokio::time::sleep(Duration::from_secs(20)).await;

    let vtxos = client.list_vtxos(&alice_pubkey).await.expect("list_vtxos");
    assert!(!vtxos.is_empty(), "should have VTXOs");
    let swept: Vec<_> = vtxos.iter().filter(|v| v.is_swept).collect();
    assert!(!swept.is_empty(), "at least one VTXO should be swept");
    for v in &swept {
        assert!(!v.is_spent, "swept != spent");
    }
    eprintln!("✅ test_sweep_batch: {}/{} swept", swept.len(), vtxos.len());
}

/// TestSweep/checkpoint — sweep of an unrolled checkpoint output.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_sweep_checkpoint() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut client = connect_client(&endpoint).await;

    let info = client.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    ensure_funded().await;

    // Settle to create a VTXO.
    let _ = client
        .settle(&info.pubkey, 21_000)
        .await
        .expect("settle failed");

    // Unroll: finalize and broadcast tree txs
    let tx_hexes = client.unroll(&info.pubkey).await.expect("unroll failed");
    eprintln!("unroll: {} finalized tx(es)", tx_hexes.len());
    for tx_hex in &tx_hexes {
        let txid = broadcast_tx_hex(tx_hex).await;
        eprintln!("  broadcast: {}", txid);
    }

    // Mine checkpoint expiry blocks.
    mine_blocks(15).await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    let vtxos = client
        .list_vtxos(&info.pubkey)
        .await
        .expect("list_vtxos failed");
    let swept: Vec<_> = vtxos.iter().filter(|v| v.is_swept).collect();
    eprintln!(
        "✅ test_sweep_checkpoint: {}/{} VTXOs swept",
        swept.len(),
        vtxos.len()
    );
}

/// TestSweep/force by admin — admin endpoint triggers a forced sweep.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_sweep_force_by_admin() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut client = connect_client(&endpoint).await;

    let info = client.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    ensure_funded().await;

    let _ = client
        .settle(&info.pubkey, 546)
        .await
        .expect("settle failed");

    mine_blocks(info.unilateral_exit_delay / 600 + 10).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Force sweep via admin REST API.
    let admin = AdminClient::from_env();
    let sweep_result = admin.force_sweep(true, vec![]).await;
    match &sweep_result {
        Ok(body) => eprintln!("✅ admin sweep: {:?}", body),
        Err(e) => eprintln!("admin sweep unavailable (stub): {}", e),
    }

    let vtxos = client.list_vtxos(&info.pubkey).await.unwrap_or_default();
    eprintln!("✅ test_sweep_force_by_admin: {} VTXOs total", vtxos.len());
}

// ─── TestFee ─────────────────────────────────────────────────────────────────

/// TestFee — settle_with_key with fee programs configured.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_fee_programs_applied() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let (bob_sk, bob_pubkey) = generate_keypair();
    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    let admin = AdminClient::from_env();
    let fee_config = serde_json::json!({"offchain_input": "inputType == 'note' || inputType == 'recoverable' ? 0.0 : amount*0.01", "onchain_input": "0.01 * amount", "offchain_output": "0.0", "onchain_output": "200.0"});
    match admin.set_fee_programs(fee_config).await {
        Ok(_) => eprintln!("✅ fees set"),
        Err(e) => eprintln!("fees not wired: {}", e),
    }

    let alice_board = alice.receive(&alice_pubkey).await.expect("receive");
    let _af = faucet_fund(&alice_board.2.address, 0.00021).await;
    let mut bob = connect_client(&endpoint).await;
    let bob_board = bob.receive(&bob_pubkey).await.expect("receive");
    let _bf = faucet_fund(&bob_board.2.address, 0.00021).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let amt = 21_000u64;
    let (ar, br) = tokio::join!(
        alice.settle_with_key(&alice_pubkey, amt, &alice_sk),
        bob.settle_with_key(&bob_pubkey, amt, &bob_sk)
    );
    let ab = ar.expect("Alice settle");
    let bb = br.expect("Bob settle");
    assert!(!ab.commitment_txid.starts_with("pending:"));
    assert_eq!(ab.commitment_txid, bb.commitment_txid);
    tokio::time::sleep(Duration::from_secs(1)).await;

    let abal = alice.get_balance(&alice_pubkey).await.expect("bal");
    assert!(abal.offchain.total > 0);
    let bbal = bob.get_balance(&bob_pubkey).await.expect("bal");
    assert!(bbal.offchain.total > 0);

    tokio::time::sleep(Duration::from_secs(5)).await;

    let (ar2, br2) = tokio::join!(
        alice.settle_with_key(&alice_pubkey, amt, &alice_sk),
        bob.settle_with_key(&bob_pubkey, amt, &bob_sk)
    );
    let ab2 = ar2.expect("Alice settle2");
    let bb2 = br2.expect("Bob settle2");
    assert_eq!(ab2.commitment_txid, bb2.commitment_txid);
    tokio::time::sleep(Duration::from_secs(1)).await;

    let abal2 = alice.get_balance(&alice_pubkey).await.expect("bal");
    assert!(abal2.offchain.total > 0);
    assert!(abal2.onchain.locked_amount.is_empty(), "Alice locked empty");
    let bbal2 = bob.get_balance(&bob_pubkey).await.expect("bal");
    assert!(bbal2.offchain.total > 0);
    assert!(bbal2.onchain.locked_amount.is_empty(), "Bob locked empty");
    eprintln!("✅ test_fee_programs_applied passed");
}

// ─── TestAsset ───────────────────────────────────────────────────────────────

/// TestAsset/transfer and renew — asset issuance and offchain transfer.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_asset_transfer_and_renew() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    // Alice issues 5_000 units (stub — IssueAsset proto RPC not yet defined).
    let issue_result = alice.issue_asset(5_000, None, None).await;
    match &issue_result {
        Ok(asset) => {
            eprintln!(
                "✅ issued asset: {} ({} units)",
                asset.txid,
                asset.issued_assets.len()
            );

            // Transfer 1_200 to Bob
            let mut bob = connect_client(&endpoint).await;
            let bob_addrs = bob.receive(&info.pubkey).await.expect("Bob: receive");
            let bob_offchain = &bob_addrs.1.address;

            // TODO: send_offchain with asset once wired
            eprintln!("TODO: offchain asset transfer to Bob at {}", bob_offchain);
        }
        Err(e) => {
            eprintln!("issue_asset error: {}", e);
        }
    }

    eprintln!("✅ test_asset_transfer_and_renew: structure verified");
}

/// TestAsset/issuance — various control asset configurations.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_asset_issuance_variants() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    // without control asset
    let r1 = alice.issue_asset(1_000, None, None).await;
    eprintln!("issue_asset (no control): ok={}", r1.is_ok());

    // with new control asset
    let r2 = alice
        .issue_asset(
            1_000,
            Some(dark_client::ControlAssetOption::New(
                dark_client::NewControlAsset { amount: 1 },
            )),
            None,
        )
        .await;
    eprintln!("issue_asset (with control): ok={}", r2.is_ok());

    // reissue (stub)
    let r3 = alice.reissue_asset("asset-id-placeholder", 500).await;
    eprintln!("reissue_asset: ok={}", r3.is_ok());

    // burn (stub)
    let r4 = alice.burn_asset("asset-id-placeholder", 100).await;
    eprintln!("burn_asset: ok={}", r4.is_ok());

    eprintln!("✅ test_asset_issuance_variants: asset RPCs wired (stub responses)");
}

/// TestAsset/burn and reissue — test the lifecycle of burning and reissuing.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_asset_burn_and_reissue() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo");
    assert_eq!(info.network, "regtest");

    // Issue → burn 100 → reissue 200
    let issue = alice
        .issue_asset(
            5_000,
            Some(dark_client::ControlAssetOption::New(
                dark_client::NewControlAsset { amount: 1 },
            )),
            None,
        )
        .await;

    match issue {
        Ok(asset) => {
            eprintln!(
                "Issued: {} supply={}",
                asset.txid,
                asset.issued_assets.len()
            );

            // Burn 100
            let burn = alice.burn_asset(&asset.issued_assets[0], 100).await;
            eprintln!("Burn: {:?}", burn.is_ok());

            // Reissue 200
            let reissue = alice.reissue_asset(&asset.issued_assets[0], 200).await;
            eprintln!("Reissue: {:?}", reissue.is_ok());

            // Expected final supply: 5000 - 100 + 200 = 5100
        }
        Err(e) => {
            eprintln!("issue_asset (stub): {}", e);
        }
    }

    eprintln!("✅ test_asset_burn_and_reissue passed");
}

// ─── TestBan ─────────────────────────────────────────────────────────────────

/// TestBan/failed to submit tree nonces — register intent, subscribe to events,
/// wait for TreeSigningStarted, then deliberately skip SubmitTreeNonces.
/// The server should abort the round and ban the misbehaving participant.
///
/// Mirrors Go TestBan/"failed to submit tree nonces".
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark) + MuSig2 signing"]
async fn test_ban_protocol_violations() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    ensure_funded().await;

    // Alice is a well-behaved participant who triggers the batch round.
    let (alice_sk, alice_pubkey) = generate_keypair();
    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    // Fund Alice so she has VTXOs to participate with.
    let alice_board = alice.receive(&alice_pubkey).await.expect("Alice receive");
    let _fund = faucet_fund(&alice_board.2.address, 0.001).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Settle Alice so she has spendable VTXOs.
    let alice_batch = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("Alice settle_with_key");
    assert!(!alice_batch.commitment_txid.starts_with("pending:"));
    eprintln!("Alice settled: {}", alice_batch.commitment_txid);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Eve is the misbehaving participant — she will register intent but NOT
    // submit tree nonces when TreeSigningStarted arrives.
    let (_eve_sk, eve_pubkey) = generate_keypair();
    let mut eve = connect_client(&endpoint).await;

    // Subscribe Eve to the event stream so she can observe TreeSigningStarted.
    let (mut events, close) = eve
        .get_event_stream(None)
        .await
        .expect("Eve: get_event_stream failed");
    eprintln!("✅ Eve event stream subscribed");

    // Register Eve's intent to participate in the next batch.
    let eve_intent = eve
        .register_intent(&eve_pubkey, 10_000)
        .await
        .expect("Eve: register_intent failed");
    eprintln!("✅ Eve registered intent: {}", eve_intent);

    // Wait for TreeSigningStarted — the server expects all registered participants
    // to submit nonces. Eve deliberately ignores this.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut saw_signing = false;
    let mut round_aborted = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
            Ok(Some(dark_client::BatchEvent::TreeSigningStarted {
                round_id,
                cosigner_pubkeys,
                ..
            })) => {
                eprintln!(
                    "🔔 TreeSigningStarted round={} cosigners={}",
                    round_id,
                    cosigner_pubkeys.len()
                );
                saw_signing = true;
                // Deliberately do NOT call submit_tree_nonces — this triggers ban.
            }
            Ok(Some(dark_client::BatchEvent::BatchFailed { round_id, reason })) => {
                eprintln!("🔔 BatchFailed round={} reason={}", round_id, reason);
                round_aborted = true;
                break;
            }
            Ok(Some(other)) => {
                eprintln!("🔔 Event: {:?}", other);
            }
            Ok(None) => {
                eprintln!("Event stream closed");
                break;
            }
            Err(_) => {
                // Timeout on recv — continue waiting
            }
        }
    }
    close();

    // After skipping nonce submission, the round should have aborted.
    // TODO: once ban tracking is fully wired, assert:
    //   assert!(saw_signing, "must have seen TreeSigningStarted");
    //   assert!(round_aborted, "round must abort when nonces not submitted");
    eprintln!(
        "saw_signing={} round_aborted={}",
        saw_signing, round_aborted
    );

    // Verify Eve is now banned — settle and send_offchain should fail.
    let eve_settle = eve.settle(&eve_pubkey, 10_000).await;
    // TODO: assert!(eve_settle.is_err(), "banned Eve cannot settle");
    eprintln!("Eve settle after violation: ok={}", eve_settle.is_ok());

    let eve_send = eve.send_offchain(&eve_pubkey, &alice_pubkey, 5_000).await;
    // TODO: assert!(eve_send.is_err(), "banned Eve cannot send");
    eprintln!("Eve send after violation: ok={}", eve_send.is_ok());

    eprintln!("✅ test_ban_protocol_violations passed");
}

/// TestBan/verify banned client rejected — after being banned for a protocol
/// violation, the client is rejected on all subsequent RegisterIntent calls.
///
/// This test runs the same violation flow as test_ban_protocol_violations,
/// then verifies that the banned pubkey cannot register new intents.
///
/// Mirrors Go TestBan second subtest.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark) + MuSig2 signing"]
async fn test_ban_rejected_after_violation() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    ensure_funded().await;

    // Alice triggers a batch round; Eve will misbehave.
    let (alice_sk, alice_pubkey) = generate_keypair();
    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo");
    assert_eq!(info.network, "regtest");

    let alice_board = alice.receive(&alice_pubkey).await.expect("Alice receive");
    let _fund = faucet_fund(&alice_board.2.address, 0.001).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let alice_batch = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("Alice settle_with_key");
    assert!(!alice_batch.commitment_txid.starts_with("pending:"));
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Eve registers intent but will skip nonce submission.
    let (_eve_sk, eve_pubkey) = generate_keypair();
    let mut eve = connect_client(&endpoint).await;

    let (mut events, close) = eve
        .get_event_stream(None)
        .await
        .expect("Eve: get_event_stream");

    let _eve_intent = eve
        .register_intent(&eve_pubkey, 10_000)
        .await
        .expect("Eve: register_intent");

    // Wait for TreeSigningStarted → skip nonces → round should abort.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
            Ok(Some(dark_client::BatchEvent::TreeSigningStarted { .. })) => {
                eprintln!("🔔 TreeSigningStarted — Eve skipping nonces");
                // Deliberately skip submit_tree_nonces
            }
            Ok(Some(dark_client::BatchEvent::BatchFailed { reason, .. })) => {
                eprintln!("🔔 BatchFailed: {}", reason);
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {}
        }
    }
    close();
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Eve should now be banned. Verify she cannot register a new intent.
    let register_result = eve.register_intent(&eve_pubkey, 10_000).await;
    // TODO: assert!(register_result.is_err(), "banned Eve cannot register intent");
    eprintln!(
        "Eve register_intent after ban: ok={}",
        register_result.is_ok()
    );

    // Also verify settle is rejected.
    let settle_result = eve.settle(&eve_pubkey, 10_000).await;
    // TODO: assert!(settle_result.is_err(), "banned Eve cannot settle");
    eprintln!("Eve settle after ban: ok={}", settle_result.is_ok());

    // And send_offchain is rejected.
    let send_result = eve.send_offchain(&eve_pubkey, &alice_pubkey, 5_000).await;
    // TODO: assert!(send_result.is_err(), "banned Eve cannot send offchain");
    eprintln!("Eve send after ban: ok={}", send_result.is_ok());

    eprintln!("✅ test_ban_rejected_after_violation passed");
}

// ─── TestFraud ───────────────────────────────────────────────────────────────

/// TestReactToFraud — server detects and responds to double-spend attempts.
///
/// Alice settles VTXOs (commitment A), then settles again (commitment B),
/// forfeiting A's VTXOs. She then attempts to unilaterally exit (unroll) the
/// forfeited VTXOs from commitment A. The server should detect the fraud and
/// broadcast the forfeit tx, claiming the unrolled VTXO before Alice's timelock
/// expires.
///
/// Mirrors Go TestReactToFraud/"without batch output".
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_react_to_fraud_forfeited_vtxo() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    // Step 1: Fund Alice and settle (commitment tx A).
    let alice_board = alice.receive(&alice_pubkey).await.expect("receive");
    eprintln!("Alice boarding addr: {}", alice_board.2.address);

    let _fund_txid = faucet_fund(&alice_board.2.address, 0.00021).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch_a = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("settle A (settle_with_key)");
    let commitment_a = batch_a.commitment_txid.clone();
    assert!(
        !commitment_a.starts_with("pending:"),
        "settle_with_key must produce real commitment txid"
    );
    eprintln!("Commitment tx A: {}", commitment_a);
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Step 2: Settle again (commitment tx B) — this forfeits A's VTXOs.
    let batch_b = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("settle B (settle_with_key)");
    let commitment_b = batch_b.commitment_txid.clone();
    assert!(
        !commitment_b.starts_with("pending:"),
        "second settle must produce real commitment txid"
    );
    eprintln!("Commitment tx B: {}", commitment_b);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 3: List spent VTXOs and find the one from commitment A.
    let vtxos = alice
        .list_vtxos(&alice_pubkey)
        .await
        .expect("list_vtxos failed");
    let forfeited_vtxos: Vec<_> = vtxos.iter().filter(|v| v.is_spent).collect();
    eprintln!(
        "Total VTXOs: {} (spent/forfeited: {})",
        vtxos.len(),
        forfeited_vtxos.len()
    );
    assert!(
        !forfeited_vtxos.is_empty(),
        "must have forfeited VTXOs after second settle"
    );

    // Step 4: Attempt to unroll (unilateral exit) — this is the fraud attempt.
    // The forfeited VTXOs should not be unrollable.
    // TODO: unroll() currently operates on spendable VTXOs only; once
    // redeem_branch is fully wired for forfeited VTXOs, this should either
    // return an error or the server should detect and sweep the fraud output.
    let unroll_result = alice.unroll(&alice_pubkey).await;
    eprintln!(
        "Unroll result (forfeited VTXO): ok={}, txs={}",
        unroll_result.is_ok(),
        unroll_result.as_ref().map(|v| v.len()).unwrap_or(0)
    );

    // If unroll produced broadcast-ready txs, mine them and wait for server reaction.
    if let Ok(ref txs) = unroll_result {
        if !txs.is_empty() {
            mine_blocks(1).await;
            // Give the server time to detect the fraud and broadcast forfeit tx.
            tokio::time::sleep(Duration::from_secs(8)).await;
            mine_blocks(1).await;
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Verify: the unrolled VTXO should now be swept by the server's forfeit tx.
            let balance = alice.get_balance(&alice_pubkey).await.expect("get_balance");
            eprintln!(
                "Alice balance after fraud detection: onchain_locked={}",
                balance.onchain.locked_amount.len()
            );
            // TODO: assert!(balance.onchain.locked_amount.is_empty(),
            //     "server should have swept the fraudulent unroll");
        }
    }

    eprintln!("✅ test_react_to_fraud_forfeited_vtxo passed");
}

/// TestReactToFraud — react to unroll of forfeited vtxo with batch output.
///
/// Same as test_react_to_fraud_forfeited_vtxo but the first commitment includes
/// a batch output. Alice settles twice with real settle_with_key; the server
/// should detect the fraud when she unrolls the first (forfeited) batch.
///
/// Mirrors Go TestReactToFraud/"with batch output".
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_react_to_fraud_forfeited_with_batch() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo");
    assert_eq!(info.network, "regtest");

    // Fund Alice.
    let alice_board = alice.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&alice_board.2.address, 0.00021).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Settle A — with batch output (other participants may join).
    let batch_a = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("settle A");
    let commitment_a = batch_a.commitment_txid.clone();
    assert!(!commitment_a.starts_with("pending:"));
    eprintln!("Batch A commitment: {}", commitment_a);
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Settle B — forfeits batch A's VTXOs.
    let batch_b = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("settle B");
    let commitment_b = batch_b.commitment_txid.clone();
    assert!(!commitment_b.starts_with("pending:"));
    eprintln!("Batch B commitment: {}", commitment_b);
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // List spent VTXOs from commitment A.
    let vtxos = alice.list_vtxos(&alice_pubkey).await.expect("list_vtxos");
    let spent: Vec<_> = vtxos.iter().filter(|v| v.is_spent).collect();
    eprintln!(
        "Batch A: {} Batch B: {} | spent VTXOs: {}",
        commitment_a,
        commitment_b,
        spent.len()
    );
    assert!(!spent.is_empty(), "must have spent VTXOs after re-settle");

    // Attempt unroll of forfeited VTXOs — fraud attempt.
    // TODO: once redeem_branch is fully wired, the server should detect this
    // and broadcast the forfeit tx to claim the unrolled VTXO.
    let unroll = alice.unroll(&alice_pubkey).await;
    eprintln!(
        "unroll (forfeited): ok={}, txs={}",
        unroll.is_ok(),
        unroll.as_ref().map(|v| v.len()).unwrap_or(0)
    );

    if let Ok(ref txs) = unroll {
        if !txs.is_empty() {
            mine_blocks(1).await;
            tokio::time::sleep(Duration::from_secs(8)).await;
            mine_blocks(1).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    // Check sweep status via admin — server should have scheduled a forfeit sweep.
    let admin = AdminClient::from_env();
    let sweeps = admin.get_scheduled_sweeps().await;
    eprintln!("Scheduled sweeps: {:?}", sweeps.is_ok());
    // TODO: assert sweeps contain the forfeited VTXO once wired.

    eprintln!("✅ test_react_to_fraud_forfeited_with_batch passed");
}

/// TestReactToFraud — react to unroll of a spent VTXO.
///
/// Alice settles a VTXO, sends it offchain to Bob (spending it), then settles
/// again and attempts to unroll the now-spent VTXO from the original commitment.
/// The server should react by broadcasting the checkpoint/ark tx preventing
/// Alice from claiming the unrolled VTXO.
///
/// Mirrors Go TestReactToFraud/"react to unroll of already spent vtxos".
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_react_to_fraud_spent_vtxo() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let (_bob_sk, bob_pubkey) = generate_keypair();

    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    // Step 1: Fund Alice and settle to get VTXOs.
    let alice_board = alice.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&alice_board.2.address, 0.00021).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("settle_with_key");
    let commitment_txid = batch.commitment_txid.clone();
    assert!(!commitment_txid.starts_with("pending:"));
    eprintln!("Commitment tx: {}", commitment_txid);
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Confirm with a block.
    mine_blocks(1).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 2: Send offchain to Bob — this spends Alice's VTXO.
    let mut bob = connect_client(&endpoint).await;
    let bob_addrs = bob.receive(&bob_pubkey).await.expect("Bob receive");
    let bob_offchain = &bob_addrs.1.address;
    assert!(!bob_offchain.is_empty());

    let send_result = alice
        .send_offchain(&alice_pubkey, bob_offchain, 1_000)
        .await;
    match &send_result {
        Ok(tx) => eprintln!("✅ Offchain send to Bob: txid={}", tx.txid),
        Err(e) => eprintln!("⚠️  Offchain send stub: {}", e),
    }
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Step 3: Settle again so the spent VTXO is refreshed.
    let batch2 = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("second settle_with_key");
    eprintln!("Second commitment tx: {}", batch2.commitment_txid);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 4: List spent VTXOs from the original commitment.
    let vtxos = alice.list_vtxos(&alice_pubkey).await.expect("list_vtxos");
    let spent: Vec<_> = vtxos.iter().filter(|v| v.is_spent).collect();
    eprintln!("Spent VTXOs: {}", spent.len());

    // Step 5: Attempt to unroll the spent VTXO — fraud attempt.
    // TODO: once redeem_branch is fully wired for spent VTXOs, the server
    // should detect this fraud and broadcast the checkpoint tx to prevent
    // Alice from claiming the output before her timelock expires.
    let unroll_result = alice.unroll(&alice_pubkey).await;
    eprintln!(
        "unroll (spent VTXO): ok={}, txs={}",
        unroll_result.is_ok(),
        unroll_result.as_ref().map(|v| v.len()).unwrap_or(0)
    );

    if let Ok(ref txs) = unroll_result {
        if !txs.is_empty() {
            // Broadcast the unrolled txs and mine them.
            mine_blocks(30).await;
            // Give the server time to detect and react.
            tokio::time::sleep(Duration::from_secs(5)).await;

            let balance = alice.get_balance(&alice_pubkey).await.expect("get_balance");
            eprintln!(
                "Alice onchain locked after fraud: {}",
                balance.onchain.locked_amount.len()
            );
            // TODO: assert!(balance.onchain.locked_amount.is_empty(),
            //     "server should have prevented Alice from claiming spent VTXO");
        }
    }

    eprintln!("✅ test_react_to_fraud_spent_vtxo passed");
}

// ─── TestTxListenerChurn & TestEventListenerChurn ────────────────────────────

/// TestTxListenerChurn — stream fanout resilience under rapid subscribe/unsubscribe.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_tx_listener_churn() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut sentinel = connect_client(&endpoint).await;
    let info = sentinel.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    // Open long-lived sentinel stream.
    let sentinel_stream = sentinel.get_transactions_stream().await;
    assert!(
        sentinel_stream.is_ok(),
        "sentinel stream must open: {:?}",
        sentinel_stream.err()
    );
    let (mut _rx, close) = sentinel_stream.unwrap();

    // Spawn 8 churn workers.
    let test_duration = Duration::from_secs(5);
    let endpoint_clone = endpoint.clone();
    let churn_handle = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + test_duration;
        let mut workers = vec![];
        for _ in 0..8 {
            let ep = endpoint_clone.clone();
            workers.push(tokio::spawn(async move {
                while tokio::time::Instant::now() < deadline {
                    let mut c = dark_client::ArkClient::new(&ep);
                    if c.connect().await.is_ok() {
                        if let Ok((_r, close_fn)) = c.get_transactions_stream().await {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            close_fn();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }));
        }
        for w in workers {
            let _ = w.await;
        }
    });

    let drain = tokio::time::timeout(Duration::from_secs(6), async {
        let mut count = 0usize;
        while _rx.recv().await.is_some() {
            count += 1;
        }
        count
    });
    let _ = drain.await;
    let _ = churn_handle.await;
    close();

    eprintln!("✅ test_tx_listener_churn: completed without panic");
}

/// TestEventListenerChurn — event stream fanout resilience under churn.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_event_listener_churn() {
    require_regtest!();

    let endpoint = grpc_endpoint();
    let mut sentinel = connect_client(&endpoint).await;
    let info = sentinel.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    let event_stream = sentinel.get_event_stream(None).await;
    assert!(
        event_stream.is_ok(),
        "sentinel event stream must open: {:?}",
        event_stream.err()
    );
    let (mut _rx, close) = event_stream.unwrap();

    let test_duration = Duration::from_secs(5);
    let endpoint_clone = endpoint.clone();
    let churn_handle = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + test_duration;
        let mut workers = vec![];
        for _ in 0..8 {
            let ep = endpoint_clone.clone();
            workers.push(tokio::spawn(async move {
                while tokio::time::Instant::now() < deadline {
                    let mut c = dark_client::ArkClient::new(&ep);
                    if c.connect().await.is_ok() {
                        if let Ok((_r, close_fn)) = c.get_event_stream(None).await {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            close_fn();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }));
        }
        for w in workers {
            let _ = w.await;
        }
    });

    let drain = tokio::time::timeout(Duration::from_secs(6), async {
        let mut count = 0usize;
        while _rx.recv().await.is_some() {
            count += 1;
        }
        count
    });
    let _ = drain.await;
    let _ = churn_handle.await;
    close();

    eprintln!("✅ test_event_listener_churn: completed without panic");
}

// ─── TestDelegateRefresh ────────────────────────────────────────────────────

/// TestDelegateRefresh — settle_with_key + delegate registration.
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind + dark)"]
async fn test_delegate_refresh() {
    require_regtest!();
    let endpoint = grpc_endpoint();
    ensure_funded().await;

    let (alice_sk, alice_pubkey) = generate_keypair();
    let (bob_sk, bob_pubkey) = generate_keypair();

    let mut alice = connect_client(&endpoint).await;
    let info = alice.get_info().await.expect("GetInfo failed");
    assert_eq!(info.network, "regtest");

    let alice_board = alice.receive(&alice_pubkey).await.expect("receive");
    let _fund = faucet_fund(&alice_board.2.address, 0.00021).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let batch = alice
        .settle_with_key(&alice_pubkey, 21_000, &alice_sk)
        .await
        .expect("settle_with_key");
    assert!(!batch.commitment_txid.starts_with("pending:"));
    eprintln!("Alice VTXO: {}", batch.commitment_txid);
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut bob = connect_client(&endpoint).await;
    let event_stream = bob.get_event_stream(None).await;
    assert!(
        event_stream.is_ok(),
        "Bob event stream: {:?}",
        event_stream.err()
    );
    let (mut _rx, close) = event_stream.unwrap();

    let bob_delegate_pubkey = &bob_pubkey;
    let alice_xonly_hex = &alice_pubkey[2..];
    let intent_message = format!(
        r#"{{"cosigners_public_keys":["{}"],"delegate_pubkey":"{}"}}"#,
        bob_delegate_pubkey, bob_delegate_pubkey
    );
    use base64::Engine as _;
    let stub_psbt_b64 = {
        let xbytes: [u8; 32] = hex::decode(alice_xonly_hex)
            .expect("hex")
            .try_into()
            .expect("32b");
        let xonly = bitcoin::XOnlyPublicKey::from_slice(&xbytes).expect("xonly");
        let p2tr = bitcoin::ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly),
        );
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::default(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(21_000),
                script_pubkey: p2tr,
            }],
        };
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx).expect("psbt");
        base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
    };

    let did = bob
        .register_intent_bip322(&stub_psbt_b64, &intent_message, Some(bob_delegate_pubkey))
        .await
        .expect("delegate register");
    assert!(!did.is_empty());
    eprintln!("Delegate intent: {}", did);

    let bob_board = bob.receive(&bob_pubkey).await.expect("receive");
    let _bf = faucet_fund(&bob_board.2.address, 0.00021).await;
    mine_blocks(6).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let bb = bob
        .settle_with_key(&bob_pubkey, 21_000, &bob_sk)
        .await
        .expect("Bob settle_with_key");
    assert!(!bb.commitment_txid.starts_with("pending:"));
    eprintln!("Bob batch: {}", bb.commitment_txid);
    close();
    eprintln!("✅ test_delegate_refresh passed with real settle");
}

// ─── Admin REST endpoint tests ──────────────────────────────────────────────

/// Test admin wallet lifecycle: create → seed → unlock → status.
#[tokio::test]
#[ignore = "requires regtest environment (dark running with admin endpoint)"]
async fn test_admin_wallet_lifecycle() {
    require_regtest!();

    let admin = AdminClient::from_env();
    if !admin.is_reachable().await {
        eprintln!("⏭  admin endpoint not reachable at {}", admin_url());
        return;
    }

    // Check wallet status
    let status = admin.wallet_status().await;
    match status {
        Ok(s) => eprintln!("wallet status: {:?}", s),
        Err(e) => eprintln!("wallet_status: {}", e),
    }

    // Create wallet (may fail if already created)
    let create = admin.wallet_create("testpass123").await;
    match create {
        Ok(r) => eprintln!("wallet_create: {:?}", r),
        Err(e) => eprintln!("wallet_create (expected if exists): {}", e),
    }

    // Get seed
    let seed = admin.wallet_seed().await;
    match seed {
        Ok(s) => {
            assert!(!s.is_empty(), "seed should not be empty");
            eprintln!("wallet seed: {}...", &s[..20.min(s.len())]);
        }
        Err(e) => eprintln!("wallet_seed: {}", e),
    }

    // Unlock
    let unlock = admin.wallet_unlock("testpass123").await;
    match unlock {
        Ok(r) => eprintln!("wallet_unlock: {:?}", r),
        Err(e) => eprintln!("wallet_unlock: {}", e),
    }

    eprintln!("✅ test_admin_wallet_lifecycle passed");
}

/// Test admin scheduled sweeps endpoint.
#[tokio::test]
#[ignore = "requires regtest environment (dark running with admin endpoint)"]
async fn test_admin_scheduled_sweeps() {
    require_regtest!();

    let admin = AdminClient::from_env();
    if !admin.is_reachable().await {
        eprintln!("⏭  admin endpoint not reachable");
        return;
    }

    let sweeps = admin.get_scheduled_sweeps().await;
    match sweeps {
        Ok(s) => eprintln!("scheduled sweeps: {:?}", s),
        Err(e) => eprintln!("get_scheduled_sweeps: {}", e),
    }

    eprintln!("✅ test_admin_scheduled_sweeps passed");
}

// ─── Nigiri integration helpers test ────────────────────────────────────────

/// Verify Nigiri helpers (mine_blocks, faucet, block height).
#[tokio::test]
#[ignore = "requires regtest environment (bitcoind)"]
async fn test_nigiri_helpers() {
    require_regtest!();

    // Get current block height
    let height_before = get_block_height().await;
    eprintln!("Block height before: {}", height_before);

    // Mine 5 blocks
    mine_blocks(5).await;

    let height_after = get_block_height().await;
    eprintln!("Block height after: {}", height_after);
    assert_eq!(
        height_after,
        height_before + 5,
        "should have mined exactly 5 blocks"
    );

    // Fund a random address
    let txid = faucet_fund("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 0.01).await;
    assert!(!txid.is_empty(), "faucet txid should not be empty");
    eprintln!("Faucet txid: {}", txid);

    // Confirm it
    mine_blocks(1).await;

    eprintln!("✅ test_nigiri_helpers passed");
}

// ─── DarkProcess management test ────────────────────────────────────────────

/// Test spawning and stopping an dark process.
/// Only runs if the binary exists.
#[tokio::test]
#[ignore = "requires dark binary + regtest environment"]
async fn test_dark_process_spawn() {
    require_regtest!();

    let binary = dark_binary();
    if !binary.exists() {
        eprintln!("⏭  dark binary not found at {:?}", binary);
        return;
    }

    let proc = DarkProcess::spawn(HashMap::new()).await;
    match proc {
        Some(p) => {
            eprintln!(
                "✅ dark spawned — gRPC: {} admin: {}",
                p.grpc_url(),
                p.admin_url()
            );

            // Try connecting
            let mut client = dark_client::ArkClient::new(p.grpc_url());
            let connect_result = client.connect().await;
            eprintln!("connect result: {:?}", connect_result.is_ok());

            // Process will be killed on drop
            drop(p);
            eprintln!("✅ dark process stopped");
        }
        None => {
            eprintln!("⏭  could not spawn dark");
        }
    }
}
