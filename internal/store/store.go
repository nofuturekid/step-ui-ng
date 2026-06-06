// Package store owns persistence: it opens the pure-Go SQLite database and
// applies the embedded, versioned goose migrations on startup (ADR-0003,
// ADR-0009). The CA remains the source of truth; local state is kept minimal.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// dbFile is the SQLite database filename inside the data directory.
const dbFile = "stepui.db"

// Store holds the database handle and migration provider.
type Store struct {
	db       *sql.DB
	provider *goose.Provider
}

// Open ensures dataDir exists, opens the SQLite database inside it, and applies
// all embedded migrations. Re-running against an already-migrated database is a
// no-op (idempotent).
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	db, err := sql.Open("sqlite", filepath.Join(dataDir, dbFile))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	migrations, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("locate migrations: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init migrations: %w", err)
	}

	if _, err := provider.Up(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	return &Store{db: db, provider: provider}, nil
}

// DB returns the underlying database handle for use by repositories.
func (s *Store) DB() *sql.DB { return s.db }

// Version returns the current applied schema version.
func (s *Store) Version() (int64, error) {
	return s.provider.GetDBVersion(context.Background())
}

// Close closes the database handle.
func (s *Store) Close() error { return s.db.Close() }
