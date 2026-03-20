-- Offchain transactions table

CREATE TABLE IF NOT EXISTS offchain_txs (
    id TEXT PRIMARY KEY,
    stage TEXT NOT NULL DEFAULT 'Requested',
    inputs_json TEXT NOT NULL,
    outputs_json TEXT NOT NULL,
    txid TEXT,
    rejection_reason TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_offchain_txs_stage ON offchain_txs(stage);
CREATE INDEX IF NOT EXISTS idx_offchain_txs_created_at ON offchain_txs(created_at);
