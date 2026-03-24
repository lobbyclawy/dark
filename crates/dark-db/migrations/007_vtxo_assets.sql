-- Add assets column to vtxos for tracking asset amounts per VTXO
-- Format: JSON array of {"asset_id": "...", "amount": N}
ALTER TABLE vtxos ADD COLUMN assets TEXT NOT NULL DEFAULT '[]';
