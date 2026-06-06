package audit_test

import (
	"context"
	"database/sql"
	"fmt"
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

// --- FR-3: query / filter / pagination --------------------------------------

// List returns all events when no filter is set, newest first.
func TestListNewestFirst(t *testing.T) {
	db := newDB(t)
	rec := audit.NewRecorder(db)
	for _, a := range []string{"login", "logout", "login"} {
		if err := rec.Record(context.Background(), "alice", a, "t", "d"); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	events, err := rec.List(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("List count = %d, want 3", len(events))
	}
	// Newest (id=3) must come first.
	if events[0].ID < events[1].ID || events[1].ID < events[2].ID {
		t.Fatalf("events not newest-first: ids = %d %d %d", events[0].ID, events[1].ID, events[2].ID)
	}
}

// List filters by action — only matching rows are returned.
func TestListFilterByAction(t *testing.T) {
	db := newDB(t)
	rec := audit.NewRecorder(db)
	_ = rec.Record(context.Background(), "alice", "login", "t", "d")
	_ = rec.Record(context.Background(), "alice", "logout", "t", "d")
	_ = rec.Record(context.Background(), "bob", "login", "t", "d")

	events, err := rec.List(context.Background(), audit.Filter{Action: "login"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("filter action=login: got %d events, want 2", len(events))
	}
	for _, e := range events {
		if e.Action != "login" {
			t.Fatalf("filter returned non-login event: %+v", e)
		}
	}
}

// List filters by who — only matching actors are returned.
func TestListFilterByWho(t *testing.T) {
	db := newDB(t)
	rec := audit.NewRecorder(db)
	_ = rec.Record(context.Background(), "alice", "login", "t", "d")
	_ = rec.Record(context.Background(), "bob", "login", "t", "d")
	_ = rec.Record(context.Background(), "alice", "logout", "t", "d")

	events, err := rec.List(context.Background(), audit.Filter{Who: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("filter who=alice: got %d events, want 2", len(events))
	}
	for _, e := range events {
		if e.Who != "alice" {
			t.Fatalf("filter returned non-alice event: %+v", e)
		}
	}
}

// List filters by time range — only events within the window are returned.
func TestListFilterByTimeRange(t *testing.T) {
	db := newDB(t)
	rec := audit.NewRecorder(db)

	// Override now to control timestamps precisely.
	var tick int64
	orig := audit.ExportNow(func() int64 { tick++; return tick })
	defer audit.ExportNow(orig)

	// tick 1
	_ = rec.Record(context.Background(), "alice", "login", "t", "d")
	// tick 2
	_ = rec.Record(context.Background(), "alice", "issue", "t", "d")
	// tick 3
	_ = rec.Record(context.Background(), "alice", "logout", "t", "d")

	// Only the middle event (tick=2) should be in [2, 2].
	events, err := rec.List(context.Background(), audit.Filter{From: 2, To: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("time filter [2,2]: got %d events, want 1", len(events))
	}
	if events[0].Action != "issue" {
		t.Fatalf("time filter returned wrong event: %+v", events[0])
	}
}

// List respects limit + offset for pagination.
func TestListPagination(t *testing.T) {
	db := newDB(t)
	rec := audit.NewRecorder(db)
	for i := range 5 {
		_ = rec.Record(context.Background(), "alice", "login", fmt.Sprintf("t%d", i), "d")
	}

	// Page 0 (offset=0, limit=2): two newest.
	page0, err := rec.List(context.Background(), audit.Filter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("page 0: %v", err)
	}
	if len(page0) != 2 {
		t.Fatalf("page 0 len = %d, want 2", len(page0))
	}
	// Page 1 (offset=2, limit=2): next two.
	page1, err := rec.List(context.Background(), audit.Filter{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page 1 len = %d, want 2", len(page1))
	}
	// Pages are disjoint — no id appears twice.
	ids := map[int64]bool{}
	for _, e := range append(page0, page1...) {
		if ids[e.ID] {
			t.Fatalf("duplicate id %d across pages", e.ID)
		}
		ids[e.ID] = true
	}
	// Newest-first: page0 IDs must all be greater than page1 IDs.
	for _, e0 := range page0 {
		for _, e1 := range page1 {
			if e0.ID < e1.ID {
				t.Fatalf("page0 id %d < page1 id %d: not newest-first", e0.ID, e1.ID)
			}
		}
	}
}

// List with combined filters (action + who) returns only the intersection.
func TestListCombinedFilters(t *testing.T) {
	db := newDB(t)
	rec := audit.NewRecorder(db)
	_ = rec.Record(context.Background(), "alice", "login", "t", "d")
	_ = rec.Record(context.Background(), "bob", "login", "t", "d")
	_ = rec.Record(context.Background(), "alice", "logout", "t", "d")

	events, err := rec.List(context.Background(), audit.Filter{Action: "login", Who: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("combined filter: got %d events, want 1", len(events))
	}
	if events[0].Who != "alice" || events[0].Action != "login" {
		t.Fatalf("combined filter returned wrong event: %+v", events[0])
	}
}
