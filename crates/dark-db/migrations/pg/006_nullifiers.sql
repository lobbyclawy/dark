-- Migration 006 (pg): Authoritative nullifier spent-set table (#534).
--
-- Mirrors the SQLite migration 009. See that file for the rationale on
-- using a dedicated table rather than reusing `vtxos.confidential_nullifier`
-- as the spent-set source of truth.
--
-- Idempotent: re-running this migration is a no-op against an already
-- migrated database thanks to IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS nullifiers (
    nullifier   BYTEA   PRIMARY KEY NOT NULL,
    round_id    TEXT,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nullifiers_round_id
    ON nullifiers(round_id);
