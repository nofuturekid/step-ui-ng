-- +goose Up
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
) STRICT;

-- Session store for alexedwards/scs sqlite3store.
CREATE TABLE sessions (
    token  TEXT    PRIMARY KEY,
    data   BLOB    NOT NULL,
    expiry REAL    NOT NULL
) STRICT;
CREATE INDEX sessions_expiry_idx ON sessions (expiry);

-- +goose Down
DROP TABLE sessions;
DROP TABLE users;
