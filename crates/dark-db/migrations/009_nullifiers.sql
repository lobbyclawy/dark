-- Migration 009: Authoritative nullifier spent-set table (issue #534)
--
-- The `vtxos.confidential_nullifier` column from migration 008 stores the
-- nullifier ASSOCIATED WITH a confidential VTXO output row. The spent-set
-- check, however, is a separate concern: it answers "has this nullifier
-- already been revealed/spent?" independently of any specific VTXO row.
--
-- Reasons to use a dedicated table here rather than reuse the column:
--   - Append-only semantics: round commit only ever INSERTs, never UPDATEs.
--   - Single-column index, no joins, fits the O(1) lookup hot path.
--   - Crash-recovery is `SELECT nullifier FROM nullifiers` — no JOIN, no
--     conditional WHERE on a nullable column.
--   - Decouples spent-set growth from VTXO retention/sweep rules.
--
-- The PRIMARY KEY enforces uniqueness so a duplicate batch insert from a
-- replayed round commit fails at the DB layer, matching the in-memory
-- HashSet semantics.
CREATE TABLE IF NOT EXISTS nullifiers (
    nullifier  BLOB    PRIMARY KEY NOT NULL,
    round_id   TEXT,
    inserted_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_nullifiers_round_id
    ON nullifiers(round_id);
