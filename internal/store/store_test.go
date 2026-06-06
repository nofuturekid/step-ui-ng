package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/store"
)

// Acceptance (spec/0001-foundation.md): "Given no DATA_DIR exists, When the app
// starts, Then it is created and the DB + migrations are initialized without
// error." Open must create a missing data dir, open the SQLite file inside it,
// and apply the embedded migrations.
func TestOpenCreatesMissingDataDirAndAppliesMigrations(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist-yet")

	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("data dir not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "stepui.db")); err != nil {
		t.Fatalf("database file not created: %v", err)
	}

	v, err := st.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v < 1 {
		t.Fatalf("schema version = %d, want >= 1 (migrations did not apply)", v)
	}
}

// Acceptance (spec/0001-foundation.md test list): "migrations apply to a temp DB;
// re-running is idempotent." Opening an already-migrated DB a second time must
// succeed and leave the schema version unchanged.
func TestMigrationsAreIdempotent(t *testing.T) {
	dir := t.TempDir()

	st1, err := store.Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	v1, err := st1.Version()
	if err != nil {
		t.Fatalf("first Version: %v", err)
	}
	if err := st1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2, err := store.Open(dir)
	if err != nil {
		t.Fatalf("second Open (idempotent re-run): %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	v2, err := st2.Version()
	if err != nil {
		t.Fatalf("second Version: %v", err)
	}
	if v1 != v2 {
		t.Fatalf("schema version changed on re-run: %d -> %d", v1, v2)
	}
}
