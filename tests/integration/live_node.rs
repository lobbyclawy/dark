//! Integration tests requiring a live Bitcoin regtest node.
//!
//! These tests are marked `#[ignore]` and only run when explicitly requested:
//!   `cargo test --test integration -- --ignored --test-threads=1`
//!
//! They require:
//!   - Bitcoin Core regtest on localhost:18443 (rpcuser=admin1, rpcpassword=123)
//!   - INTEGRATION_TEST=1 env var (CI sets this)

/// Test that arkd starts up and responds to GetInfo.
#[tokio::test]
#[ignore = "requires live Bitcoin regtest node"]
async fn test_getinfo_responds() {
    // TODO(#63): start arkd, call GetInfo via gRPC, assert response
    println!("Integration test placeholder — GetInfo");
}

/// Test round lifecycle against regtest.
#[tokio::test]
#[ignore = "requires live Bitcoin regtest node"]
async fn test_round_lifecycle_stub() {
    // TODO(#63): create round, verify state transitions
    println!("Round lifecycle test placeholder");
}

/// Test boarding flow against regtest.
#[tokio::test]
#[ignore = "requires live Bitcoin regtest node"]
async fn test_boarding_flow_stub() {
    // TODO(#63): board user, verify VTXO creation
    println!("Boarding flow test placeholder");
}
