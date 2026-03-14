//! Integration tests requiring a live Bitcoin regtest node.
//!
//! These tests are gated behind the `INTEGRATION_TEST` env var and are
//! skipped in normal `cargo test` runs. They require:
//!   - Bitcoin Core regtest on localhost:18443 (rpcuser=admin1, rpcpassword=123)
//!
//! Run with: `INTEGRATION_TEST=1 cargo test --test integration -- --test-threads=1`

/// Test that arkd starts up and responds to GetInfo.
/// Requires: INTEGRATION_TEST=1 env var (skipped otherwise).
#[tokio::test]
async fn test_getinfo_responds() {
    if std::env::var("INTEGRATION_TEST").is_err() {
        eprintln!("Skipping integration test (set INTEGRATION_TEST=1 to run)");
        return;
    }
    // TODO: start arkd, call GetInfo via gRPC, assert response
    // Real assertions come with gRPC client (#63)
    println!("Integration test placeholder — GetInfo");
}

#[tokio::test]
async fn test_round_lifecycle_stub() {
    if std::env::var("INTEGRATION_TEST").is_err() {
        return;
    }
    // TODO: create round, verify state transitions
    println!("Round lifecycle test placeholder");
}

#[tokio::test]
async fn test_boarding_flow_stub() {
    if std::env::var("INTEGRATION_TEST").is_err() {
        return;
    }
    // TODO: board user, verify VTXO creation
    println!("Boarding flow test placeholder");
}
