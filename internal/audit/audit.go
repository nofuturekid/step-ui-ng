// Package audit is the append-only security-event log foundation (spec/0009,
// introduced early so spec/0006's FR-4 is satisfiable). It records who did what,
// to which target, with optional details and a timestamp. spec/0009 builds the
// query/filter UI on top of this Recorder and wires the remaining emit points.
//
// The actor (who) is always the authenticated session user — never "system"
// (spec/0009 Tests). Record rejects an empty actor so a caller cannot silently
// drop attribution.
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNoActor means Record was called without an authenticated actor; every event
// must attribute a user.
var ErrNoActor = errors.New("audit: event has no actor")

// Recorder appends events to the audit_events table.
type Recorder struct {
	db *sql.DB
}

// NewRecorder returns a Recorder over an already-migrated DB.
func NewRecorder(db *sql.DB) *Recorder { return &Recorder{db: db} }

// now is overridable in tests; defaults to wall-clock unix seconds.
var now = func() int64 { return time.Now().Unix() }

// Record appends one audit event. who is the authenticated user (required);
// action is a short verb (e.g. "issue", "sign"); target identifies the affected
// resource (e.g. the CN or serial); details carries extra free-form context.
// The table is append-only — there is no update or delete path.
func (r *Recorder) Record(ctx context.Context, who, action, target, details string) error {
	if r == nil || r.db == nil {
		return nil
	}
	if who == "" {
		return ErrNoActor
	}
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_events (who, action, target, details, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		who, action, target, details, now()); err != nil {
		return fmt.Errorf("audit: record: %w", err)
	}
	return nil
}

// Filter constrains the query returned by List. Zero values mean "no filter".
// From and To are inclusive Unix timestamps; zero means unbounded.
type Filter struct {
	Action string
	Who    string
	From   int64 // Unix timestamp, inclusive; zero = no lower bound
	To     int64 // Unix timestamp, inclusive; zero = no upper bound
	Limit  int   // 0 → default (50)
	Offset int
}

// Event is one row from audit_events.
type Event struct {
	ID        int64
	Who       string
	Action    string
	Target    string
	Details   string
	CreatedAt int64 // Unix timestamp
}

// defaultLimit is used when Filter.Limit is zero.
const defaultLimit = 50

// List returns audit events matching filter, newest first. SQL parameters are
// always bound (no string interpolation) — parameterized SQL only (spec/0009
// FR-3). An empty filter returns all rows up to limit.
func (r *Recorder) List(ctx context.Context, f Filter) ([]Event, error) {
	if r == nil || r.db == nil {
		return nil, nil
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultLimit
	}

	var where []string
	var args []any

	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	if f.Who != "" {
		where = append(where, "who = ?")
		args = append(args, f.Who)
	}
	if f.From > 0 {
		where = append(where, "created_at >= ?")
		args = append(args, f.From)
	}
	if f.To > 0 {
		where = append(where, "created_at <= ?")
		args = append(args, f.To)
	}

	q := "SELECT id, who, action, target, details, created_at FROM audit_events"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, f.Offset)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Who, &e.Action, &e.Target, &e.Details, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: list scan: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: list rows: %w", err)
	}
	return events, nil
}
