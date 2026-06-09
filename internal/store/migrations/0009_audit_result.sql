-- +goose Up
-- Add result column to audit_events for recording action outcome (backlog ④).
-- Existing rows are all successful actions, so DEFAULT 'ok' is correct.
-- modernc.org/sqlite bundles SQLite ≥ 3.38; ADD COLUMN with a DEFAULT on a
-- STRICT table is supported. An inline CHECK on ADD COLUMN is also accepted
-- by SQLite ≥ 3.25 (which modernc bundles), so we include it for consistency
-- with the table definition policy.
ALTER TABLE audit_events ADD COLUMN result TEXT NOT NULL DEFAULT 'ok' CHECK (result IN ('ok', 'denied'));

-- +goose Down
ALTER TABLE audit_events DROP COLUMN result;
