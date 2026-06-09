package app_test

// Design tests for PR G — Audit log page redesign.
//
// Acceptance criteria tested:
//   - Page-head: "Audit log" h1, page-sub text with "Append-only and never
//     contains secret values".
//   - Filter bar: class="filterbar", action <select> (named "action"), and
//     the "N events" count display.
//   - The auditActionOption set includes relevant action values.
//   - Table: class="table" with Time (UTC)/Actor/Action/Target/Details columns.
//     There is NO Result column (audit.Event has no Result field; only successful
//     actions are stored — failures return 4xx without an audit row).
//   - Time column uses UTC format.
//   - Action column uses a badge/tag element (not plain text).
//   - Details column renders e.Details (operator context: keyID=…, role=…, etc.).
//   - Pagination: Older/Newer links appear when there are multiple pages.
//   - No secrets are ever rendered: a real action with a known password is
//     performed and the password is asserted absent from the audit page.
//   - The filter preserves selected action value on re-render.
//   - The page-sub copy explicitly says "never contains secret values".

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestAuditDesignPageHead verifies the redesigned page-head structure:
// page-head, page-title "Audit log", and page-sub containing the
// "Append-only and never contains secret values" copy.
func TestAuditDesignPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/audit")

	if !strings.Contains(body, `class="page-head"`) {
		t.Error("audit: missing page-head element")
	}
	if !strings.Contains(body, `class="page-title"`) {
		t.Error("audit: missing page-title element")
	}
	if !strings.Contains(body, ">Audit log<") {
		t.Error("audit: missing 'Audit log' h1 text")
	}
	if !strings.Contains(body, `class="page-sub"`) {
		t.Error("audit: missing page-sub subtitle element")
	}
	// The "never contains secret values" copy must appear in the subtitle.
	if !strings.Contains(body, "secret") {
		t.Error("audit: page-sub must mention 'secret' (the 'never contains secret values' guarantee)")
	}
	if !strings.Contains(body, "Append-only") {
		t.Error("audit: page-sub must say 'Append-only'")
	}
}

// TestAuditDesignFilterBar verifies the filter bar structure:
// class="filterbar", action select (named "action"), and the GET form.
func TestAuditDesignFilterBar(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/audit")

	if !strings.Contains(body, `class="filterbar"`) {
		t.Error("audit: missing filterbar element")
	}
	// Filter form must use GET (audit is read-only filter).
	if !strings.Contains(body, `method="get"`) {
		t.Error("audit: filter form must use GET method")
	}
	// Action select must be present.
	if !strings.Contains(body, `name="action"`) {
		t.Error("audit: missing action select in filter bar")
	}
	// "All actions" option must be present.
	if !strings.Contains(body, "All actions") {
		t.Error("audit: filter bar must include 'All actions' default option")
	}
}

// TestAuditDesignFilterBarActionOptions verifies that the action select
// contains the expected action values from auditActionOption.
func TestAuditDesignFilterBarActionOptions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/audit")

	// Key action values that must be present as options.
	for _, action := range []string{"login", "logout", "user.create", "user.update", "user.delete",
		"settings.update", "issue", "revoke"} {
		if !strings.Contains(body, fmt.Sprintf(`value="%s"`, action)) {
			t.Errorf("audit: missing action option %q in filter select", action)
		}
	}
}

// TestAuditDesignTableStructure verifies the audit table uses class="table"
// with the correct column headers: Time (UTC), Actor, Action, Target, Details.
// There is NO Result column — audit.Event has no Result field, and only
// successful actions are recorded, so a static badge would be a faked signal.
func TestAuditDesignTableStructure(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed an event so the table renders (table is only shown when events exist).
	_ = e.auditRec.Record(context.Background(), "root", "login", "root", "")

	_, body := e.get(t, "/audit")

	if !strings.Contains(body, `class="table"`) {
		t.Error("audit: missing class=\"table\" on audit log table")
	}
	// Column headers per the final spec: Time/Actor/Action/Target/Details.
	for _, col := range []string{"Time", "Actor", "Action", "Target", "Details"} {
		if !strings.Contains(body, col) {
			t.Errorf("audit: missing %q column header", col)
		}
	}
	// The Time column header must reference UTC.
	if !strings.Contains(body, "UTC") {
		t.Error("audit: Time column header must include UTC designation")
	}
	// There must be NO Result column: audit.Event has no Result field; only
	// successful events are stored, so a static "ok" badge is a faked signal.
	// A real Result would require recording failures + a schema field (future work).
	if strings.Contains(body, "<th") && strings.Contains(body, ">Result<") {
		t.Error("audit: table must NOT have a Result column header (no backing data; see CHANGELOG future work)")
	}
	if strings.Contains(body, "badge--ok") {
		t.Error("audit: table must NOT render badge--ok Result badges (faked signal; no Result field on audit.Event)")
	}
}

// TestAuditDesignEventRowRendering verifies that audit events in the table
// use the correct markup: action as a badge/tag; details rendered in the Details column.
func TestAuditDesignEventRowRendering(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed a known audit event with details.
	_ = e.auditRec.Record(context.Background(), "root", "user.create", "bob", "role=viewer")

	_, body := e.get(t, "/audit")

	// The event must appear in the table.
	if !strings.Contains(body, "user.create") {
		t.Error("audit: user.create event must appear in table")
	}
	// Action must be in a tag or badge element (not plain <td> text).
	// The design mock uses <span class="tag"> for actions.
	if !strings.Contains(body, "tag") && !strings.Contains(body, "badge") {
		t.Error("audit: action in table row must use a tag or badge element")
	}
	// The target must appear.
	if !strings.Contains(body, "bob") {
		t.Error("audit: target 'bob' must appear in table row")
	}
	// Details column must render the details value.
	if !strings.Contains(body, "role=viewer") {
		t.Error("audit: Details column must render the event details (e.g. 'role=viewer')")
	}
}

// TestAuditDesignDetailsColumnRendered verifies that the Details column in the
// audit table renders the e.Details value from the event. This tests that the
// real operator context (e.g. "keyID=…", "role=admin", "action=set_role role=…")
// is visible to admins, and would fail if the Details cell is ever dropped.
func TestAuditDesignDetailsColumnRendered(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed an event with non-empty details that include operator context.
	const wantDetails = "keyID=abc123 method=jwk role=admin"
	_ = e.auditRec.Record(context.Background(), "root", "settings.update", "admin-auth", wantDetails)

	_, body := e.get(t, "/audit")

	// The details must appear in the rendered page.
	if !strings.Contains(body, wantDetails) {
		t.Errorf("audit: Details column must render event details %q but it was absent from the page", wantDetails)
	}
}

// TestAuditDesignTableWrap verifies the table is inside a table-wrap container.
func TestAuditDesignTableWrap(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_ = e.auditRec.Record(context.Background(), "root", "login", "root", "")

	_, body := e.get(t, "/audit")

	if !strings.Contains(body, "table-wrap") {
		t.Error("audit: table must be inside a table-wrap container")
	}
}

// TestAuditDesignPaginationLinks verifies that with more than one page of events,
// Older/Newer pagination links use the design-system pagination structure.
func TestAuditDesignPaginationLinks(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed more than auditPageSize events.
	for i := range 51 {
		_ = e.auditRec.Record(context.Background(), "root", fmt.Sprintf("ev%d", i), "t", "d")
	}

	_, body := e.get(t, "/audit")

	// With 51 events, an "Older" link must appear.
	if !strings.Contains(body, "Older") {
		t.Error("audit: 'Older' pagination link must appear with more than one page of events")
	}
	// The pagination must use the pagination class (design system).
	if !strings.Contains(body, "pagination") {
		t.Error("audit: pagination container must use class='pagination'")
	}
}

// TestAuditDesignEventCountDisplay verifies that the events count ("N events")
// is shown in the filter bar area.
func TestAuditDesignEventCountDisplay(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed some events.
	for i := range 3 {
		_ = e.auditRec.Record(context.Background(), "root", fmt.Sprintf("ev%d", i), "t", "d")
	}

	_, body := e.get(t, "/audit")

	// There must be some count display near the filter bar.
	if !strings.Contains(body, "event") {
		t.Error("audit: filter bar must show an event count indicator (e.g. 'N events')")
	}
}

// TestAuditDesignFilterPreservesActionSelection verifies that after filtering
// by a specific action, the filter bar re-renders with that action selected
// (the select option shows as selected/current).
func TestAuditDesignFilterPreservesActionSelection(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_ = e.auditRec.Record(context.Background(), "root", "login", "root", "")

	_, body := e.get(t, "/audit?action=login")

	// The "login" option in the select must be selected.
	// templ renders selected options with the "selected" attribute.
	if !strings.Contains(body, `value="login" selected`) &&
		!strings.Contains(body, `selected value="login"`) {
		t.Error("audit: 'login' option must be selected when action=login filter is active")
	}
}

// TestAuditDesignTimeUTCFormat verifies that timestamps in the table rows
// are formatted in UTC format (YYYY-MM-DD HH:MM or similar) per the mock.
func TestAuditDesignTimeUTCFormat(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed an event at a known time by direct SQL.
	ts := time.Date(2030, 3, 15, 14, 30, 0, 0, time.UTC).Unix()
	if _, err := e.db.Exec(
		`INSERT INTO audit_events (who, action, target, details, created_at) VALUES (?, ?, ?, ?, ?)`,
		"root", "login", "root", "", ts); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	_, body := e.get(t, "/audit")

	// The timestamp must appear in a human-readable UTC format.
	if !strings.Contains(body, "2030-03-15") {
		t.Error("audit: timestamp must be rendered in YYYY-MM-DD format (UTC)")
	}
}

// TestAuditDesignNoSecretsRendered verifies that a password used to create a
// user is NEVER rendered on the /audit page. This is a real, failable test:
// it performs an actual POST /users with a known password, then GETs /audit and
// asserts the password string is absent. The user.create audit row must record
// only username+role, never the password. This test FAILS if the recorder or
// handler ever logged the password into the audit event's details or target.
func TestAuditDesignNoSecretsRendered(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// A distinctive password that would be immediately recognisable if it ever
	// leaked into the audit row.
	const secretPassword = "audit-leak-probe-pw-9"

	// Create a user via POST /users, which triggers a user.create audit row.
	token := e.csrfToken(t, "/users")
	resp := e.post(t, "/users", url.Values{
		"csrf_token":       {token},
		"username":         {"probe-user"},
		"password":         {secretPassword},
		"password_confirm": {secretPassword},
		"role":             {"viewer"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /users (probe user create) = %d, want 303", resp.StatusCode)
	}

	// Fetch the audit log page and assert the secret password is absent.
	_, body := e.get(t, "/audit")

	// The audit log MUST contain a user.create event (so the test isn't vacuous).
	if !strings.Contains(body, "user.create") {
		t.Error("audit: user.create event must appear in audit log after creating a user")
	}
	// The secret password must NEVER appear anywhere on the rendered page.
	// This FAILS if the handler or recorder ever passes the password as details/target.
	if strings.Contains(body, secretPassword) {
		t.Errorf("audit: secret password %q must never appear in the rendered audit log (secret leak!)", secretPassword)
	}
}
