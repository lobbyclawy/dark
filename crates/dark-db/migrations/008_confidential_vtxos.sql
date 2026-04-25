-- Migration 008: Confidential VTXO columns (issue #533)
--
-- Adds nullable columns to `vtxos` so transparent and confidential VTXOs share
-- the same row. Existing transparent VTXOs leave every column NULL.
--
-- Column shape mirrors the Postgres migration so #534 can write portable
-- repository code. Lengths match the Pedersen / range-proof / x-only-pubkey
-- sizes used by the confidential primitives:
--   - confidential_commitment:       33-byte compressed Pedersen commitment
--   - confidential_range_proof:      variable-length range proof (~1.3 KB)
--   - confidential_nullifier:        32-byte unique-when-present nullifier
--   - confidential_ephemeral_pubkey: 33-byte compressed sender pubkey
--   - confidential_encrypted_memo:   variable-length encrypted memo
--
-- The unique-when-present property of `confidential_nullifier` is enforced via
-- a partial UNIQUE index (supported by SQLite >= 3.8.0). The non-unique index
-- below it serves the spent-set membership check that #534 will implement.
ALTER TABLE vtxos ADD COLUMN confidential_commitment BLOB;
ALTER TABLE vtxos ADD COLUMN confidential_range_proof BLOB;
ALTER TABLE vtxos ADD COLUMN confidential_nullifier BLOB;
ALTER TABLE vtxos ADD COLUMN confidential_ephemeral_pubkey BLOB;
ALTER TABLE vtxos ADD COLUMN confidential_encrypted_memo BLOB;

CREATE UNIQUE INDEX IF NOT EXISTS uq_vtxos_confidential_nullifier
    ON vtxos(confidential_nullifier)
    WHERE confidential_nullifier IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_vtxos_confidential_nullifier
    ON vtxos(confidential_nullifier);
