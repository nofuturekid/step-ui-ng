-- +goose Up
-- Foundation key/value table for cross-cutting application state (e.g. install
-- metadata). Domain tables are added by later specs.
CREATE TABLE app_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- +goose Down
DROP TABLE app_metadata;
