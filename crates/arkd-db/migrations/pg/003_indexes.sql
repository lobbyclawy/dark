-- Performance indexes for PostgreSQL (issue #243)
-- Complements existing indexes from 001_initial.sql and 002_offchain_txs.sql

-- Round lookup by stage and time
CREATE INDEX IF NOT EXISTS idx_rounds_stage_code ON rounds(stage_code);
CREATE INDEX IF NOT EXISTS idx_rounds_started_at ON rounds(starting_timestamp);
CREATE INDEX IF NOT EXISTS idx_rounds_ended_at ON rounds(ending_timestamp);
CREATE INDEX IF NOT EXISTS idx_rounds_swept ON rounds(swept);
CREATE INDEX IF NOT EXISTS idx_rounds_commitment_txid ON rounds(commitment_txid);

-- Intent confirmation lookups
CREATE INDEX IF NOT EXISTS idx_intents_confirmation ON intents(round_id, confirmation_status);

-- VTXO expiration scans
CREATE INDEX IF NOT EXISTS idx_vtxos_expires_at ON vtxos(expires_at);
CREATE INDEX IF NOT EXISTS idx_vtxos_created_at ON vtxos(created_at);
CREATE INDEX IF NOT EXISTS idx_vtxos_settled_by ON vtxos(settled_by);
