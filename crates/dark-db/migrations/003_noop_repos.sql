-- Migration 003: Tables for repos previously using Noop implementations
-- Boarding, Checkpoints, Forfeits, Convictions, Confirmations, Signing Sessions

-- Boarding transactions
CREATE TABLE IF NOT EXISTS boarding_txs (
    id              TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'awaiting_funding',
    amount          INTEGER NOT NULL DEFAULT 0,
    recipient_pubkey TEXT NOT NULL DEFAULT '',
    funding_txid    TEXT,
    funding_vout    INTEGER,
    round_id        TEXT,
    vtxo_id         TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_boarding_txs_status ON boarding_txs(status);

-- Checkpoint transactions
CREATE TABLE IF NOT EXISTS checkpoints (
    id              TEXT PRIMARY KEY,
    offchain_tx_id  TEXT NOT NULL,
    tapscript       TEXT NOT NULL DEFAULT '',
    exit_delay      INTEGER NOT NULL DEFAULT 144,
    created_at      INTEGER NOT NULL DEFAULT 0,
    swept           BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_swept ON checkpoints(swept);

-- Forfeit records
CREATE TABLE IF NOT EXISTS forfeits (
    id              TEXT PRIMARY KEY,
    round_id        TEXT NOT NULL,
    vtxo_id         TEXT NOT NULL,
    tx_hex          TEXT NOT NULL DEFAULT '',
    submitted_at    INTEGER NOT NULL DEFAULT 0,
    validated       BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_forfeits_round_id ON forfeits(round_id);

-- Conviction records
CREATE TABLE IF NOT EXISTS convictions (
    id              TEXT PRIMARY KEY,
    kind            INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL DEFAULT 0,
    expires_at      INTEGER NOT NULL DEFAULT 0,
    pardoned        BOOLEAN NOT NULL DEFAULT FALSE,
    script          TEXT NOT NULL DEFAULT '',
    crime_type      TEXT NOT NULL DEFAULT 'unspecified',
    round_id        TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_convictions_script ON convictions(script);
CREATE INDEX IF NOT EXISTS idx_convictions_round_id ON convictions(round_id);
CREATE INDEX IF NOT EXISTS idx_convictions_created_at ON convictions(created_at);

-- Confirmation tracking (per-round intent confirmations)
CREATE TABLE IF NOT EXISTS confirmations (
    round_id        TEXT NOT NULL,
    intent_id       TEXT NOT NULL,
    confirmed       BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (round_id, intent_id)
);

-- Signing session tracking
CREATE TABLE IF NOT EXISTS signing_sessions (
    session_id      TEXT PRIMARY KEY,
    participant_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS signing_nonces (
    session_id      TEXT NOT NULL REFERENCES signing_sessions(session_id),
    participant_id  TEXT NOT NULL,
    nonce           BLOB NOT NULL,
    PRIMARY KEY (session_id, participant_id)
);

CREATE TABLE IF NOT EXISTS signing_signatures (
    session_id      TEXT NOT NULL REFERENCES signing_sessions(session_id),
    participant_id  TEXT NOT NULL,
    signature       BLOB NOT NULL,
    PRIMARY KEY (session_id, participant_id)
);
