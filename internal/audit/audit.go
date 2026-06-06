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
