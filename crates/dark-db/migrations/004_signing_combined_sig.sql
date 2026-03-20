-- Migration 004: Add combined_sig column to signing_sessions for session completion
ALTER TABLE signing_sessions ADD COLUMN combined_sig BLOB;
