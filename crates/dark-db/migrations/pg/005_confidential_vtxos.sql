-- Migration 005 (pg): Confidential VTXO columns on the `vtxos` table (#532).
--
-- Adds the storage foundation for confidential VTXOs alongside the existing
-- transparent VTXO schema. All new columns are NULLABLE so existing rows
-- (transparent VTXOs) continue to work unchanged. The Rust type that
-- read/writes these columns is unchanged in this migration — this only
-- prepares the schema. Issue #530 will land the Rust-side `Vtxo` variants
-- and #534 will introduce the spent-set membership query.
--
-- Idempotent: every column add and every index creation uses IF NOT EXISTS,
-- so re-running this migration is a no-op against an already-migrated DB.
--
-- Rollback: see 005_confidential_vtxos.down.sql.

-- Pedersen amount commitment (compressed point, 33 bytes when present).
ALTER TABLE vtxos
    ADD COLUMN IF NOT EXISTS confidential_commitment BYTEA NULL;

-- Bulletproofs range proof — variable size (~1.3 KB typical).
ALTER TABLE vtxos
    ADD COLUMN IF NOT EXISTS confidential_range_proof BYTEA NULL;

-- VTXO nullifier — 32 bytes, must be globally unique when present so the
-- spent-set membership check (#534) can rely on a single-row lookup.
ALTER TABLE vtxos
    ADD COLUMN IF NOT EXISTS confidential_nullifier BYTEA NULL;

-- Ephemeral pubkey used to derive the per-output encryption key (33 bytes).
ALTER TABLE vtxos
    ADD COLUMN IF NOT EXISTS confidential_ephemeral_pubkey BYTEA NULL;

-- Encrypted memo / receiver-side payload, variable length.
ALTER TABLE vtxos
    ADD COLUMN IF NOT EXISTS confidential_encrypted_memo BYTEA NULL;

-- Uniqueness of the nullifier across all confidential VTXOs.
-- Postgres treats NULLs as distinct in a UNIQUE INDEX by default, so
-- transparent rows (NULL nullifier) coexist freely with each other while
-- confidential rows are still constrained to be unique.
CREATE UNIQUE INDEX IF NOT EXISTS idx_vtxos_confidential_nullifier_unique
    ON vtxos (confidential_nullifier)
    WHERE confidential_nullifier IS NOT NULL;
