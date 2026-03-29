-- Add block-height-based expiry column to vtxos table
ALTER TABLE vtxos ADD COLUMN expires_at_block INTEGER NOT NULL DEFAULT 0;
