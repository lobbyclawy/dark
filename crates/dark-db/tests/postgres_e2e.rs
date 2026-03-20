//! PostgreSQL end-to-end integration test
//!
//! Requires a running PostgreSQL instance. Set `DATABASE_URL` to run:
//! ```bash
//! DATABASE_URL=postgres://user:pass@localhost/dark_test cargo test --features postgres -p dark-db --test postgres_e2e
//! ```
//! The test is silently skipped when `DATABASE_URL` is not set, so CI
//! won't fail on machines without a Postgres instance.

#![cfg(feature = "postgres")]

use dark_core::domain::{Round, RoundStage, Stage};
use dark_core::ports::RoundRepository;
use dark_db::{create_postgres_pool, run_postgres_migrations, PgRoundRepository};

/// Full round-trip: connect → migrate → insert round → read back → verify.
#[tokio::test]
async fn postgres_round_trip() {
    // Skip when no DATABASE_URL is provided (CI without Postgres).
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("DATABASE_URL not set — skipping PostgreSQL E2E test");
            return;
        }
    };

    // 1. Connect
    let pool = create_postgres_pool(&db_url)
        .await
        .expect("Failed to create PostgreSQL pool");

    // 2. Run migrations
    run_postgres_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    // 3. Build a test round
    let mut round = Round::new();
    round.starting_timestamp = 1_700_000_000;
    round.ending_timestamp = 1_700_003_600;
    round.stage = Stage {
        code: RoundStage::Finalization,
        ended: true,
        failed: false,
    };
    round.commitment_txid = "e2e_commit_txid".to_string();
    round.commitment_tx = "e2e_commit_tx_hex".to_string();
    round.connector_address = "tb1qtest".to_string();
    round.version = 1;
    round.swept = false;
    round.vtxo_tree_expiration = 1_700_100_000;

    let round_id = round.id.clone();

    // 4. Persist via PgRoundRepository
    let repo = PgRoundRepository::new(pool.clone());
    repo.add_or_update_round(&round)
        .await
        .expect("Failed to insert round");

    // 5. Read back and verify
    let fetched = repo
        .get_round_with_id(&round_id)
        .await
        .expect("Failed to fetch round")
        .expect("Round should exist");

    assert_eq!(fetched.id, round_id);
    assert_eq!(fetched.starting_timestamp, 1_700_000_000);
    assert_eq!(fetched.ending_timestamp, 1_700_003_600);
    assert_eq!(fetched.stage.code, RoundStage::Finalization);
    assert!(fetched.stage.ended);
    assert!(!fetched.stage.failed);
    assert_eq!(fetched.commitment_txid, "e2e_commit_txid");
    assert_eq!(fetched.commitment_tx, "e2e_commit_tx_hex");
    assert_eq!(fetched.connector_address, "tb1qtest");
    assert_eq!(fetched.version, 1);
    assert!(!fetched.swept);
    assert_eq!(fetched.vtxo_tree_expiration, 1_700_100_000);

    // 6. Clean up: remove the test round so the test is idempotent
    sqlx::query("DELETE FROM rounds WHERE id = $1")
        .bind(&round_id)
        .execute(&pool)
        .await
        .expect("Failed to clean up test round");
}
