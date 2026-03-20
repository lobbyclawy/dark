-- Asset system tables
-- Part of Issue #241: Asset System

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    amount INTEGER NOT NULL,
    issuer_pubkey TEXT NOT NULL,
    max_supply INTEGER,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS asset_issuances (
    txid TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    issuer_pubkey TEXT NOT NULL,
    control_asset_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_issuances_asset_id ON asset_issuances(asset_id);
