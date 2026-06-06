-- +goose Up
-- Issued/signed certificate inventory (spec/0006) plus the append-only audit-log
-- foundation (spec/0009, introduced early so spec/0006's FR-4 is satisfiable).
--
-- certificates holds one row per certificate the UI obtained from the CA. The PEM
-- material is stored verbatim (cert/chain/fullchain are public). For
-- key_strategy='server' the UI generated the keypair, so privkey_sealed holds the
-- sealed (AES-256-GCM, ADR-0006) PEM private key — base64(nonce ‖ ciphertext),
-- never clear text. For key_strategy='csr' the client kept its private key, so
-- privkey_sealed is NULL. sans_json is the JSON-encoded SAN list. status is the
-- certificate lifecycle state (valid now; revoke/renew arrive in spec/0008).
-- created_by is the authenticated user who requested it.
CREATE TABLE certificates (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    cn             TEXT    NOT NULL,
    sans_json      TEXT    NOT NULL,
    serial         TEXT    NOT NULL,
    not_before     INTEGER NOT NULL,
    not_after      INTEGER NOT NULL,
    status         TEXT    NOT NULL,
    key_strategy   TEXT    NOT NULL CHECK (key_strategy IN ('server', 'csr')),
    cert_pem       TEXT    NOT NULL,
    chain_pem      TEXT    NOT NULL,
    fullchain_pem  TEXT    NOT NULL,
    privkey_sealed TEXT,
    created_by     TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;

-- Append-only audit events (spec/0009 data model, used by spec/0006 FR-4). who is
-- the authenticated user (never "system"); action is a short verb; target names
-- the affected resource; details carries free-form context.
CREATE TABLE audit_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    who        TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    target     TEXT    NOT NULL,
    details    TEXT    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE audit_events;
DROP TABLE certificates;
