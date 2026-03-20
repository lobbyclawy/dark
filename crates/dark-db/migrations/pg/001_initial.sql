-- Initial schema for dark-rs database layer (PostgreSQL)
-- Ported from SQLite migrations/001_initial.sql

-- Rounds table
CREATE TABLE IF NOT EXISTS rounds (
    id                  TEXT PRIMARY KEY,
    starting_timestamp  BIGINT NOT NULL DEFAULT 0,
    ending_timestamp    BIGINT NOT NULL DEFAULT 0,
    stage_code          INTEGER NOT NULL DEFAULT 0,
    stage_ended         BOOLEAN NOT NULL DEFAULT FALSE,
    stage_failed        BOOLEAN NOT NULL DEFAULT FALSE,
    commitment_txid     TEXT NOT NULL DEFAULT '',
    commitment_tx       TEXT NOT NULL DEFAULT '',
    connector_address   TEXT NOT NULL DEFAULT '',
    version             INTEGER NOT NULL DEFAULT 0,
    swept               BOOLEAN NOT NULL DEFAULT FALSE,
    vtxo_tree_expiration BIGINT NOT NULL DEFAULT 0,
    fail_reason         TEXT NOT NULL DEFAULT ''
);

-- Round transactions (forfeit, connector tree, vtxo tree, sweep, commitment)
CREATE TABLE IF NOT EXISTS round_txs (
    id          BIGSERIAL PRIMARY KEY,
    round_id    TEXT NOT NULL REFERENCES rounds(id),
    txid        TEXT NOT NULL DEFAULT '',
    tx          TEXT NOT NULL DEFAULT '',
    type        TEXT NOT NULL DEFAULT '',
    position    INTEGER NOT NULL DEFAULT 0,
    children    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_round_txs_round_id ON round_txs(round_id);
CREATE INDEX IF NOT EXISTS idx_round_txs_type ON round_txs(round_id, type);

-- Intents
CREATE TABLE IF NOT EXISTS intents (
    id          TEXT PRIMARY KEY,
    round_id    TEXT NOT NULL REFERENCES rounds(id),
    proof       TEXT NOT NULL DEFAULT '',
    message     TEXT NOT NULL DEFAULT '',
    txid        TEXT NOT NULL DEFAULT '',
    leaf_tx_asset_packet TEXT NOT NULL DEFAULT '',
    confirmation_status TEXT NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_intents_round_id ON intents(round_id);

-- Intent receivers
CREATE TABLE IF NOT EXISTS intent_receivers (
    id              BIGSERIAL PRIMARY KEY,
    intent_id       TEXT NOT NULL REFERENCES intents(id),
    amount          BIGINT NOT NULL DEFAULT 0,
    onchain_address TEXT NOT NULL DEFAULT '',
    pubkey          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_intent_receivers_intent_id ON intent_receivers(intent_id);

-- VTXOs table
CREATE TABLE IF NOT EXISTS vtxos (
    txid                TEXT NOT NULL,
    vout                INTEGER NOT NULL,
    pubkey              TEXT NOT NULL DEFAULT '',
    amount              BIGINT NOT NULL DEFAULT 0,
    root_commitment_txid TEXT NOT NULL DEFAULT '',
    settled_by          TEXT,
    spent_by            TEXT,
    ark_txid            TEXT,
    spent               BOOLEAN NOT NULL DEFAULT FALSE,
    unrolled            BOOLEAN NOT NULL DEFAULT FALSE,
    swept               BOOLEAN NOT NULL DEFAULT FALSE,
    preconfirmed        BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at          BIGINT NOT NULL DEFAULT 0,
    created_at          BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (txid, vout)
);

CREATE INDEX IF NOT EXISTS idx_vtxos_pubkey ON vtxos(pubkey);
CREATE INDEX IF NOT EXISTS idx_vtxos_spent ON vtxos(spent);
CREATE INDEX IF NOT EXISTS idx_vtxos_ark_txid ON vtxos(ark_txid);

-- VTXO commitment txids (chain of commitment transactions)
CREATE TABLE IF NOT EXISTS vtxo_commitment_txids (
    vtxo_txid       TEXT NOT NULL,
    vtxo_vout       INTEGER NOT NULL,
    commitment_txid TEXT NOT NULL,
    position        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (vtxo_txid, vtxo_vout, commitment_txid),
    FOREIGN KEY (vtxo_txid, vtxo_vout) REFERENCES vtxos(txid, vout)
);

-- VTXO intent association
CREATE TABLE IF NOT EXISTS vtxo_intents (
    vtxo_txid   TEXT NOT NULL,
    vtxo_vout   INTEGER NOT NULL,
    intent_id   TEXT NOT NULL REFERENCES intents(id),
    PRIMARY KEY (vtxo_txid, vtxo_vout, intent_id),
    FOREIGN KEY (vtxo_txid, vtxo_vout) REFERENCES vtxos(txid, vout)
);

-- Sweep transactions mapping
CREATE TABLE IF NOT EXISTS round_sweep_txs (
    round_id    TEXT NOT NULL REFERENCES rounds(id),
    txid        TEXT NOT NULL,
    tx          TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (round_id, txid)
);
