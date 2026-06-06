package app

// spec/0009 — audit log query/filter handler (admin+, behind auth + CSRF).
//
// GET /audit renders a filter form (action dropdown, user text, from/to date)
// and a paginated table of audit events, newest first. Query parameters map
// directly to audit.Filter fields; all SQL is parameterized (FR-3).
//
// ACME events (spec/0010) will emit into the same audit_events table; leave
// a clear place here but do NOT handle ACME-specific filtering yet.

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/audit"
)

// auditPageSize is the number of audit events shown per page.
const auditPageSize = 50

// auditView carries the data the audit page renders.
type auditView struct {
	Events []audit.Event
	Filter auditFilterForm
	// HasMore is true when there are more results beyond this page (used to
	// show a "next page" link). The handler fetches limit+1 rows and sets this
	// flag when the extra row is present, then trims it before rendering.
	HasMore  bool
	Page     int // 0-based page number
	NextPage int
	PrevPage int
}

// auditFilterForm carries the decoded query parameters back to the template so
// the filter form is repopulated after a submit.
type auditFilterForm struct {
	Action string
	Who    string
	From   string // "YYYY-MM-DD" or empty
	To     string // "YYYY-MM-DD" or empty
}

// getAudit renders the audit log with optional filters (spec/0009 FR-3).
// Admin+ only; auth + CSRF enforced by the router middleware.
func (s *server) getAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 0 {
		page = 0
	}

	ff := auditFilterForm{
		Action: q.Get("action"),
		Who:    q.Get("who"),
		From:   q.Get("from"),
		To:     q.Get("to"),
	}

	f := audit.Filter{
		Action: ff.Action,
		Who:    ff.Who,
		Limit:  auditPageSize + 1, // fetch one extra to detect whether more exist
		Offset: page * auditPageSize,
	}

	if ff.From != "" {
		if t, err := time.ParseInLocation("2006-01-02", ff.From, time.UTC); err == nil {
			f.From = t.Unix()
		}
	}
	if ff.To != "" {
		// To is inclusive through end-of-day.
		if t, err := time.ParseInLocation("2006-01-02", ff.To, time.UTC); err == nil {
			f.To = t.Add(24*time.Hour - time.Second).Unix()
		}
	}

	events, err := s.audit.List(r.Context(), f)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	hasMore := len(events) > auditPageSize
	if hasMore {
		events = events[:auditPageSize] // drop the probe row before rendering
	}
	v := auditView{
		Events:   events,
		Filter:   ff,
		HasMore:  hasMore,
		Page:     page,
		NextPage: page + 1,
		PrevPage: page - 1,
	}

	d := s.page(r, "Audit log")
	s.render(w, r, http.StatusOK, auditPage(d, v))
}
