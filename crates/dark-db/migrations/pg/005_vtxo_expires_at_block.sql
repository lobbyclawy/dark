-- Add block-height-based expiry column to vtxos table
ALTER TABLE vtxos ADD COLUMN IF NOT EXISTS expires_at_block BIGINT NOT NULL DEFAULT 0;
