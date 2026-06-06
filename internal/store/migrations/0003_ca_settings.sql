-- +goose Up
-- Single-row table holding the Step-CA connection configured in the UI
-- (spec/0004). The CHECK (id = 1) constraint enforces at most one row.
-- admin_secret is sealed (AES-256-GCM, ADR-0006) before storage; the column
-- holds base64(nonce ‖ ciphertext), never clear text. NULL means "no secret set".
CREATE TABLE ca_settings (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    ca_url              TEXT    NOT NULL,
    root_fingerprint    TEXT    NOT NULL,
    admin_provisioner   TEXT,
    admin_subject       TEXT,
    admin_secret_sealed TEXT,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE ca_settings;
