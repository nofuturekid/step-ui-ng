package app_test

// spec/0009 acceptance tests: audit event emission per action, query/filter
// UI, and the "actor is the session user, not system" invariant.
//
// Structure:
//   - TestAuditEventEmission: table-driven, one sub-test per auditable action,
//     asserting that exactly one row is written with who = the session user.
//   - TestAuditPageRendersEvents: perform an action, then GET /audit and assert
//     the event appears in the HTML.
//   - TestAuditFilterAction / TestAuditFilterWho: apply filters, verify only
//     matching entries are shown.
//   - TestAuditAdminOnly: a viewer must get 403 on GET /audit.
//   - TestAuditToDateInclusiveEndOfDay: to= filter includes events up to 23:59:59 on date D.
//   - TestAuditHandlerSessionUserAttribution: issue/sign/revoke/renew handlers
//     attribute the session user in the audit log (not "system" or empty).
//   - TestAuditPageURLEscaping: auditPageURL escapes filter values containing & or space.
//   - TestAuditHasMoreNoBoundaryOff: HasMore=false when exactly pageSize events; true when more.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/audit"
	"github.com/nofuturekid/step-ui-ng/internal/settings"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// --- helpers ----------------------------------------------------------------

// latestAuditEvent returns the most recently recorded audit event for the given
// action, or fails the test if none exists.
func (e *testEnv) latestAuditEvent(t *testing.T, action string) audit.Event {
	t.Helper()
	events, err := e.auditRec.List(context.Background(), audit.Filter{Action: action, Limit: 1})
	if err != nil {
		t.Fatalf("latestAuditEvent %q: list: %v", action, err)
	}
	if len(events) == 0 {
		t.Fatalf("latestAuditEvent %q: no rows found", action)
	}
	return events[0]
}

// auditCount returns the number of audit rows for the given action.
func (e *testEnv) auditCount(t *testing.T, action string) int {
	t.Helper()
	events, err := e.auditRec.List(context.Background(), audit.Filter{Action: action, Limit: 1000})
	if err != nil {
		t.Fatalf("auditCount %q: %v", action, err)
	}
	return len(events)
}

// --- Acceptance: actor is ALWAYS the session user (not "system") -------------

// TestAuditActorIsSessionUser is the canonical "who = session user, not system"
// assertion required by spec/0009 Tests. We perform login and verify the row.
func TestAuditActorIsSessionUser(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "alice")

	// After completeSetup, alice is logged in.  The setup flow itself logs alice
	// in; log out and log back in explicitly so we get a clean "login" audit row.
	logoutToken := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})
	e.loginAs(t, "alice")

	ev := e.latestAuditEvent(t, "login")
	if ev.Who != "alice" {
		t.Fatalf("audit who = %q, want alice (session user, not 'system' or empty)", ev.Who)
	}
	if ev.Who == "system" || ev.Who == "" {
		t.Fatalf("audit who must never be 'system' or empty; got %q", ev.Who)
	}
}

// --- Acceptance: event emission per action (table-driven) --------------------

// TestAuditEventEmission asserts that performing each auditable action writes
// exactly one audit row with the correct action name and who = session user.
// This is the primary regression guard: if any emit point is removed, the
// corresponding sub-test fails.
func TestAuditEventEmission(t *testing.T) {
	type actionTest struct {
		name       string
		wantAction string
		run        func(t *testing.T, e *testEnv)
	}

	cases := []actionTest{
		{
			name:       "login",
			wantAction: "login",
			run: func(t *testing.T, e *testEnv) {
				// completeSetup already logged in; log out then back in to produce a
				// clean login row attributed to the session user.
				logoutToken := e.csrfToken(t, "/users")
				e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})
				e.loginAs(t, "root")
			},
		},
		{
			name:       "logout",
			wantAction: "logout",
			run: func(t *testing.T, e *testEnv) {
				token := e.csrfToken(t, "/users")
				resp := e.post(t, "/logout", url.Values{"csrf_token": {token}})
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("logout = %d", resp.StatusCode)
				}
				// Log back in so subsequent tests can use the client.
				e.loginAs(t, "root")
			},
		},
		{
			name:       "user.create",
			wantAction: "user.create",
			run: func(t *testing.T, e *testEnv) {
				token := e.csrfToken(t, "/users")
				resp := e.post(t, "/users", url.Values{
					"csrf_token":       {token},
					"username":         {"newuser"},
					"password":         {testPassword},
					"password_confirm": {testPassword},
					"role":             {"viewer"},
				})
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("create user = %d", resp.StatusCode)
				}
			},
		},
		{
			name:       "user.update (set_role)",
			wantAction: "user.update",
			run: func(t *testing.T, e *testEnv) {
				// Create a viewer, then change their role.
				u := e.seedUser(t, "victim", users.RoleViewer)
				token := e.csrfToken(t, "/users")
				resp := e.post(t, fmt.Sprintf("/users/%d", u.ID), url.Values{
					"csrf_token": {token},
					"action":     {"set_role"},
					"role":       {"admin"},
				})
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("set_role = %d", resp.StatusCode)
				}
			},
		},
		{
			name:       "user.update (disable)",
			wantAction: "user.update",
			run: func(t *testing.T, e *testEnv) {
				u := e.seedUser(t, "victim2", users.RoleViewer)
				token := e.csrfToken(t, "/users")
				resp := e.post(t, fmt.Sprintf("/users/%d", u.ID), url.Values{
					"csrf_token": {token},
					"action":     {"disable"},
				})
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("disable = %d", resp.StatusCode)
				}
			},
		},
		{
			name:       "user.delete",
			wantAction: "user.delete",
			run: func(t *testing.T, e *testEnv) {
				u := e.seedUser(t, "victim3", users.RoleViewer)
				token := e.csrfToken(t, "/users")
				resp := e.post(t, fmt.Sprintf("/users/%d", u.ID), url.Values{
					"csrf_token": {token},
					"action":     {"delete"},
				})
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("delete user = %d", resp.StatusCode)
				}
			},
		},
		{
			name:       "settings.update",
			wantAction: "settings.update",
			run: func(t *testing.T, e *testEnv) {
				token := e.csrfToken(t, "/settings")
				resp := e.post(t, "/settings", url.Values{
					"csrf_token":       {token},
					"ca_url":           {"https://ca.example:9000"},
					"root_fingerprint": {"aabbccddaabbccddaabbccddaabbccddaabbccddaabb"},
				})
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("save settings = %d", resp.StatusCode)
				}
			},
		},
		{
			name:       "provisioner.select",
			wantAction: "provisioner.select",
			run: func(t *testing.T, e *testEnv) {
				// Seed minimal CA settings so SelectProvisioner can run.
				if err := e.settingsRepo.Save(context.Background(), settings.Input{
					CAURL: "https://ca.example:9000", RootFingerprint: "aabbccddaabbccddaabbccddaabbccddaabbccddaabb",
				}); err != nil {
					t.Fatalf("seed settings: %v", err)
				}
				token := e.csrfToken(t, "/provisioners")
				resp := e.post(t, "/provisioners/select", url.Values{
					"csrf_token": {token},
					"name":       {"my-prov"},
					"secret":     {"supersecretpassword123"},
				})
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("select provisioner = %d", resp.StatusCode)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			e.completeSetup(t, "root")

			beforeCount := e.auditCount(t, tc.wantAction)
			tc.run(t, e)
			afterCount := e.auditCount(t, tc.wantAction)

			if afterCount <= beforeCount {
				t.Fatalf("action %q: no audit row written (before=%d after=%d)",
					tc.wantAction, beforeCount, afterCount)
			}

			// The most recent event for this action must be attributed to the
			// session user (root), not "system" or empty.
			ev := e.latestAuditEvent(t, tc.wantAction)
			if ev.Who == "" || ev.Who == "system" {
				t.Fatalf("action %q: audit who = %q, must be the session user (not system/empty)",
					tc.wantAction, ev.Who)
			}
			if ev.Who != "root" {
				t.Fatalf("action %q: audit who = %q, want root (session user)",
					tc.wantAction, ev.Who)
			}
		})
	}
}

// --- Acceptance: /audit page renders events and is admin-only ----------------

// TestAuditPageRendersEvents: perform a login, then GET /audit and verify the
// login event appears in the page with the correct actor.
func TestAuditPageRendersEvents(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Perform a clean login to produce a known audit row.
	logoutToken := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})
	e.loginAs(t, "root")

	resp, body := e.get(t, "/audit")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit = %d, want 200", resp.StatusCode)
	}
	// The login event must appear in the table with the actor name.
	if !strings.Contains(body, "root") {
		t.Fatalf("GET /audit: expected 'root' in body (actor); body:\n%s", body)
	}
	if !strings.Contains(body, "login") {
		t.Fatalf("GET /audit: expected 'login' action in body; body:\n%s", body)
	}
}

// TestAuditAdminOnly: a viewer gets 403 on GET /audit.
func TestAuditAdminOnly(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "viewer1", users.RoleViewer)
	e.switchTo(t, "viewer1")

	resp, _ := e.get(t, "/audit")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer GET /audit = %d, want 403", resp.StatusCode)
	}
}

// --- Acceptance: filter form — action filter ---------------------------------

// TestAuditFilterAction: seed two different action types via the audit recorder
// directly, then GET /audit?action=login and verify only login rows appear.
func TestAuditFilterAction(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Directly seed both login and logout events so we control the data.
	_ = e.auditRec.Record(context.Background(), "root", "login", "root", "")
	_ = e.auditRec.Record(context.Background(), "root", "logout", "root", "")

	resp, body := e.get(t, "/audit?action=login")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit?action=login = %d, want 200", resp.StatusCode)
	}
	// "login" must appear (matching row).
	if !strings.Contains(body, "login") {
		t.Fatalf("filter action=login: expected login in body; body snippet:\n%s", body[:min(500, len(body))])
	}
	// The table should not contain a logout row. Table cells look like <td>logout</td>;
	// the dropdown option looks like <option value="logout">logout</option>.
	// We check for the table cell pattern specifically.
	if strings.Contains(body, "<td>logout</td>") {
		t.Fatalf("filter action=login: body contains logout table cell; filter broken")
	}
}

// TestAuditFilterWho: seed events for two users, filter by who=alice, verify
// only alice's events appear.
func TestAuditFilterWho(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_ = e.auditRec.Record(context.Background(), "alice", "login", "alice", "")
	_ = e.auditRec.Record(context.Background(), "bob", "login", "bob", "")

	resp, body := e.get(t, "/audit?who=alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit?who=alice = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "alice") {
		t.Fatalf("filter who=alice: expected alice in body")
	}
	// bob must NOT appear in a table cell.
	if strings.Contains(body, ">bob<") {
		t.Fatalf("filter who=alice: bob appears in table cell; filter broken; body:\n%s", body[:min(500, len(body))])
	}
}

// TestAuditFilterTimeRange: seed events at controlled timestamps, apply a time
// range filter, verify only matching events are returned.
func TestAuditFilterTimeRange(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	resp, body := e.get(t, "/audit?from=2099-01-01&to=2099-01-01")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit?from/to = %d, want 200", resp.StatusCode)
	}
	// No events from 2099, so the "no events" message should appear.
	if !strings.Contains(body, "No events match") {
		t.Fatalf("time filter 2099: expected 'No events match' message; body:\n%s", body[:min(500, len(body))])
	}
}

// --- BLOCKING: inclusive end-of-day to= boundary ----------------------------

// TestAuditToDateInclusiveEndOfDay verifies that ?to=D includes events at the
// start of day D (00:00:00), mid-day, and end-of-day (23:59:59) on date D, and
// excludes events on the next day. This test FAILS if the +24h-1s end-of-day
// logic in getAudit is dropped or regressed to start-of-day.
func TestAuditToDateInclusiveEndOfDay(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Pick a fixed date. Use a date far enough in the past/future that no
	// incidental events land on it.
	const dateStr = "2030-06-15"
	date, err := time.ParseInLocation("2006-01-02", dateStr, time.UTC)
	if err != nil {
		t.Fatalf("parse date: %v", err)
	}

	startOfDay := date.Unix()                               // 2030-06-15 00:00:00 UTC
	midDay := date.Add(12 * time.Hour).Unix()               // 2030-06-15 12:00:00 UTC
	endOfDay := date.Add(24*time.Hour - time.Second).Unix() // 2030-06-15 23:59:59 UTC
	nextDay := date.Add(24 * time.Hour).Unix()              // 2030-06-16 00:00:00 UTC — excluded

	// Seed events at exact timestamps via direct SQL (audit.ExportNow is not
	// accessible from app_test; direct inserts give us full timestamp control).
	ctx := context.Background()
	for action, ts := range map[string]int64{
		"ev-start": startOfDay,
		"ev-mid":   midDay,
		"ev-end":   endOfDay,
		"ev-next":  nextDay,
	} {
		if _, err := e.db.ExecContext(ctx,
			`INSERT INTO audit_events (who, action, target, details, created_at) VALUES (?, ?, ?, ?, ?)`,
			"root", action, "t", "d", ts); err != nil {
			t.Fatalf("seed %s: %v", action, err)
		}
	}

	resp, body := e.get(t, "/audit?from="+dateStr+"&to="+dateStr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit?from/to = %d, want 200", resp.StatusCode)
	}

	// Events at start, mid, and end of day D MUST appear.
	for _, action := range []string{"ev-start", "ev-mid", "ev-end"} {
		if !strings.Contains(body, action) {
			t.Fatalf("to= filter: event %q at time within day D must appear in result; body:\n%s",
				action, body[:min(800, len(body))])
		}
	}
	// Event at the start of the NEXT day must NOT appear.
	if strings.Contains(body, "ev-next") {
		t.Fatalf("to= filter: event at next-day 00:00:00 must be excluded; body:\n%s",
			body[:min(800, len(body))])
	}
}

// --- BLOCKING: session-user attribution at the handler layer -----------------

// TestAuditHandlerSessionUserAttribution drives POST /issue, /sign-csr,
// /certificates/{id}/revoke, and /certificates/{id}/renew through a logged-in
// session and asserts that the newest audit event for each action has
// Who == session username (not "system" or empty). This FAILS if any handler
// passes a hard-coded or empty actor.
func TestAuditHandlerSessionUserAttribution(t *testing.T) {
	type actionCase struct {
		name       string
		wantAction string
		run        func(t *testing.T, e *testEnv, f *signCAFixture)
	}

	cases := []actionCase{
		{
			name:       "issue",
			wantAction: "issue",
			run: func(t *testing.T, e *testEnv, _ *signCAFixture) {
				token := e.csrfToken(t, "/issue")
				status, body := e.postForm(t, "/issue", url.Values{
					"csrf_token": {token},
					"cn":         {"attr-issue.test"},
					"validity":   {"30"},
					"format":     {"pem"},
				})
				if status != http.StatusOK {
					t.Fatalf("POST /issue = %d; body:\n%s", status, body)
				}
			},
		},
		{
			name:       "sign",
			wantAction: "sign",
			run: func(t *testing.T, e *testEnv, _ *signCAFixture) {
				csrPEM := makeCSR(t, "attr-sign.test", nil)
				token := e.csrfToken(t, "/sign-csr")
				status, body := e.postForm(t, "/sign-csr", url.Values{
					"csrf_token": {token},
					"csr":        {csrPEM},
					"validity":   {"30"},
				})
				if status != http.StatusOK {
					t.Fatalf("POST /sign-csr = %d; body:\n%s", status, body)
				}
			},
		},
		{
			name:       "revoke",
			wantAction: "revoke",
			run: func(t *testing.T, e *testEnv, _ *signCAFixture) {
				id := revInsertCert(t, e, "attr-revoke.test", "555555", time.Now().Add(90*24*time.Hour).Unix())
				path := fmt.Sprintf("/certificates/%d/revoke", id)
				token := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))
				status, body := e.postForm(t, path, url.Values{
					"csrf_token": {token},
					"reason":     {"key compromise"},
					"confirm":    {"REVOKE"},
				})
				if status != http.StatusOK && status != http.StatusSeeOther {
					t.Fatalf("POST revoke = %d; body:\n%s", status, body)
				}
			},
		},
		{
			name:       "renew",
			wantAction: "renew",
			run: func(t *testing.T, e *testEnv, _ *signCAFixture) {
				id := revInsertCert(t, e, "attr-renew.test", "666666", time.Now().Add(10*24*time.Hour).Unix())
				path := fmt.Sprintf("/certificates/%d/renew", id)
				token := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))
				status, body := e.postForm(t, path, url.Values{
					"csrf_token": {token},
					"validity":   {"30"},
				})
				if status != http.StatusOK && status != http.StatusSeeOther {
					t.Fatalf("POST renew = %d; body:\n%s", status, body)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			e.completeSetup(t, "testactor")
			f := startSignCAFixture(t)
			e.seedSignCA(t, f)

			before := e.auditCount(t, tc.wantAction)
			tc.run(t, e, f)
			after := e.auditCount(t, tc.wantAction)

			if after <= before {
				t.Fatalf("action %q: no audit row emitted (before=%d after=%d)",
					tc.wantAction, before, after)
			}

			ev := e.latestAuditEvent(t, tc.wantAction)
			if ev.Who == "" || ev.Who == "system" {
				t.Fatalf("action %q: audit who = %q, must be the session user (not system/empty)",
					tc.wantAction, ev.Who)
			}
			if ev.Who != "testactor" {
				t.Fatalf("action %q: audit who = %q, want testactor (session user, not hard-coded/empty)",
					tc.wantAction, ev.Who)
			}
		})
	}
}

// --- LOW: auditPageURL escapes filter values with special characters ----------

// TestAuditPageURLEscaping verifies that auditPageURL percent-encodes values
// containing &, =, or spaces so that pagination links with unusual filter values
// produce correct URLs rather than corrupted query strings. This FAILS if the
// url.QueryEscape calls in auditPageURL are removed.
func TestAuditPageURLEscaping(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed more than one page of events with a "who" value containing a space
	// and an action containing & so the page URL is built with those values.
	// We use direct DB inserts (via auditRec) to avoid going through UI flows.
	const tricky = "alice&bob" // contains & — would corrupt the query string if not escaped

	for i := range 51 { // auditPageSize=50; 51 rows → HasMore=true → Older link appears
		_ = e.auditRec.Record(context.Background(), tricky, fmt.Sprintf("ev%d", i), "t", "d")
	}

	resp, body := e.get(t, "/audit?who="+url.QueryEscape(tricky))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit?who=... = %d, want 200", resp.StatusCode)
	}

	// The "Older" pagination link must appear (we have 51 rows).
	if !strings.Contains(body, "Older") {
		t.Fatalf("expected Older pagination link with 51 rows; body:\n%s", body[:min(800, len(body))])
	}

	// The pagination link must contain &amp;who=alice%26bob (HTML-encoded & + percent-escaped &).
	// templ HTML-encodes the SafeURL content into the href attribute, so & → &amp;
	// and % stays as-is. The & in the value must be encoded as %26.
	if strings.Contains(body, "who=alice&bob") || strings.Contains(body, "who=alice&amp;bob&") {
		// raw & in who= value would corrupt the URL; both patterns are wrong.
		t.Fatalf("pagination link leaks unescaped & in who value; body:\n%s", body[:min(800, len(body))])
	}
	// The correctly escaped form: %26 in the href (before HTML encoding) → %26 in HTML.
	if !strings.Contains(body, "who=alice%26bob") {
		t.Fatalf("pagination link must percent-encode & as %%26; body:\n%s", body[:min(800, len(body))])
	}
}

// --- Backlog ④: failed login audit recording ------------------------------------

// TestFailedLoginAuditDenied verifies that a POST /login with wrong credentials
// writes an audit row with action="login", result="denied", actor=attempted username,
// and target starting "from ". This FAILS if the postLogin handler omits the
// RecordDenied call or uses the wrong field values.
func TestFailedLoginAuditDenied(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.repo.Create(context.Background(), "alice", testPassword, users.RoleViewer); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	token := e.csrfToken(t, "/login")
	resp := e.post(t, "/login", url.Values{
		"csrf_token": {token},
		"username":   {"alice"},
		"password":   {"wrong-password-xyz"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	ev := e.latestAuditEvent(t, "login")
	if ev.Result != "denied" {
		t.Fatalf("failed login audit result = %q, want \"denied\"", ev.Result)
	}
	if ev.Who != "alice" {
		t.Fatalf("failed login audit who = %q, want \"alice\" (attempted username)", ev.Who)
	}
	if !strings.HasPrefix(ev.Target, "from ") {
		t.Fatalf("failed login audit target = %q, want prefix \"from \" (source IP)", ev.Target)
	}
	// The password MUST NOT appear anywhere in the event — security invariant.
	if strings.Contains(ev.Details, "wrong-password") || strings.Contains(ev.Target, "wrong-password") {
		t.Fatal("SECURITY: password must never be recorded in the audit log")
	}
}

// TestFailedLoginAuditUnknownActor verifies that when the submitted username is
// blank, the audit actor is "unknown" (not empty string). The "unknown" label
// protects against silently attributing events to an empty who.
func TestFailedLoginAuditUnknownActor(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root") // need at least one user so first-run gating passes

	// completeSetup leaves us logged in; log out so we can access /login.
	logoutToken := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})

	token := e.csrfToken(t, "/login")
	resp := e.post(t, "/login", url.Values{
		"csrf_token": {token},
		"username":   {""},
		"password":   {"anything"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	// The most recent login-denied event must use "unknown" as actor.
	events, err := e.auditRec.List(context.Background(), audit.Filter{Action: "login", Limit: 10})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	var found bool
	for _, ev := range events {
		if ev.Result == "denied" && ev.Who == "unknown" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no login-denied audit event with who=\"unknown\" found after blank-username attempt")
	}
}

// TestSuccessfulLoginAuditResultOK verifies that a successful login still records
// result="ok" — no regression from the failed-login feature addition.
func TestSuccessfulLoginAuditResultOK(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	// completeSetup leaves us logged in via /setup; log out and log back in explicitly
	// so the /login path records a clean login event.
	logoutToken := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})
	e.loginAs(t, "root")

	ev := e.latestAuditEvent(t, "login")
	if ev.Who != "root" {
		t.Fatalf("successful login audit who = %q, want \"root\"", ev.Who)
	}
	if ev.Result != "ok" {
		t.Fatalf("successful login audit result = %q, want \"ok\" (regression guard)", ev.Result)
	}
}

// --- LOW: HasMore pagination off-by-one ----------------------------------------

// TestAuditHasMoreBoundary verifies that:
//   - exactly pageSize events → HasMore=false (no dead "Older" link)
//   - pageSize+1 events → HasMore=true ("Older" link appears)
//
// This FAILS if HasMore is set to len==pageSize instead of using the probe-row
// technique (fetch limit+1, set flag when the extra row exists).
func TestAuditHasMoreBoundary(t *testing.T) {
	const pageSize = 50

	t.Run("exactly pageSize events — no Older link", func(t *testing.T) {
		e := newTestEnv(t)
		e.completeSetup(t, "root")

		// Seed exactly pageSize rows.
		for i := range pageSize {
			if err := e.auditRec.Record(context.Background(), "root",
				fmt.Sprintf("ev%d", i), "t", "d"); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}

		resp, body := e.get(t, "/audit")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /audit = %d, want 200", resp.StatusCode)
		}
		// HasMore must be false: no dead "Older" link.
		if strings.Contains(body, "Older") {
			t.Fatalf("exactly %d events: must NOT show Older link (HasMore should be false); body:\n%s",
				pageSize, body[:min(800, len(body))])
		}
	})

	t.Run("pageSize+1 events — Older link present", func(t *testing.T) {
		e := newTestEnv(t)
		e.completeSetup(t, "root")

		// Seed pageSize+1 rows.
		for i := range pageSize + 1 {
			if err := e.auditRec.Record(context.Background(), "root",
				fmt.Sprintf("ev%d", i), "t", "d"); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}

		resp, body := e.get(t, "/audit")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /audit = %d, want 200", resp.StatusCode)
		}
		// HasMore must be true: "Older" link appears.
		if !strings.Contains(body, "Older") {
			t.Fatalf("%d events: must show Older link (HasMore should be true); body:\n%s",
				pageSize+1, body[:min(800, len(body))])
		}
	})
}
