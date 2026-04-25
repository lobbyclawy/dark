-- Rollback for migration 005 (pg): drop confidential VTXO columns and indexes.
--
-- WARNING: running this rollback against a database that already contains
-- confidential VTXOs will permanently destroy that data. The transparent
-- VTXO schema is otherwise untouched.

DROP INDEX IF EXISTS idx_vtxos_confidential_nullifier_unique;

ALTER TABLE vtxos
    DROP COLUMN IF EXISTS confidential_encrypted_memo,
    DROP COLUMN IF EXISTS confidential_ephemeral_pubkey,
    DROP COLUMN IF EXISTS confidential_nullifier,
    DROP COLUMN IF EXISTS confidential_range_proof,
    DROP COLUMN IF EXISTS confidential_commitment;
