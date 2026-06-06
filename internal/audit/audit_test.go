package audit_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/nofuturekid/step-ui-ng/internal/audit"
)

// newDB opens an in-memory SQLite database with the audit_events table created,
// mirroring the production schema (migration 0005). Keeping the schema here lets
// the audit package be tested in isolation from the store/migration machinery.
func newDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE audit_events (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		who        TEXT    NOT NULL,
		action     TEXT    NOT NULL,
		target     TEXT    NOT NULL,
		details    TEXT    NOT NULL,
		created_at INTEGER NOT NULL
	) STRICT;`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

// Record persists a row with exactly the supplied actor/action/target/details.
// This is the foundation FR-4 relies on: the actor must be the session user.
func TestRecordPersistsActor(t *testing.T) {
	db := newDB(t)
	rec := audit.NewRecorder(db)

	if err := rec.Record(context.Background(), "alice", "issue", "example.test", "cn=example.test"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	var (
		who, action, target, details string
		createdAt                    int64
	)
	if err := db.QueryRow(
		`SELECT who, action, target, details, created_at FROM audit_events WHERE id = 1`).
		Scan(&who, &action, &target, &details, &createdAt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if who != "alice" {
		t.Fatalf("who = %q, want alice (the session actor, not system)", who)
	}
	if action != "issue" || target != "example.test" || details != "cn=example.test" {
		t.Fatalf("row = %q/%q/%q, want issue/example.test/cn=example.test", action, target, details)
	}
	if createdAt == 0 {
		t.Fatalf("created_at not set")
	}
}

// Record is append-only: two calls produce two distinct rows in order.
func TestRecordAppends(t *testing.T) {
	db := newDB(t)
	rec := audit.NewRecorder(db)
	for _, a := range []string{"issue", "sign"} {
		if err := rec.Record(context.Background(), "bob", a, "t", "d"); err != nil {
			t.Fatalf("Record %s: %v", a, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("rows = %d, want 2 (append-only)", n)
	}
}

// An empty actor is rejected: every event must attribute a who (FR-4 / spec/0009
// "actor is the session user, not system").
func TestRecordRejectsEmptyActor(t *testing.T) {
	db := newDB(t)
	rec := audit.NewRecorder(db)
	if err := rec.Record(context.Background(), "", "issue", "t", "d"); err == nil {
		t.Fatal("expected an error recording an event with no actor")
	}
}
