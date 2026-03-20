-- Migration 006: Scheduled session configuration persistence (#271)
-- Singleton table — only one row (id=1) is ever stored.

CREATE TABLE IF NOT EXISTS scheduled_session_config (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    round_interval_secs     INTEGER NOT NULL,
    round_lifetime_secs     INTEGER NOT NULL,
    max_intents_per_round   INTEGER NOT NULL
);
