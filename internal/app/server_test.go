package app_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/app"
	"github.com/nofuturekid/step-ui-ng/internal/audit"
	"github.com/nofuturekid/step-ui-ng/internal/certs"
	"github.com/nofuturekid/step-ui-ng/internal/config"
	"github.com/nofuturekid/step-ui-ng/internal/crypto"
	"github.com/nofuturekid/step-ui-ng/internal/settings"
	"github.com/nofuturekid/step-ui-ng/internal/store"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

const testPassword = "correct-horse-battery-staple"

// testEnv bundles a running server, its repo, and a cookie-jar client that does
// NOT auto-follow redirects (so tests can assert on Location/status directly).
type testEnv struct {
	srv          *httptest.Server
	repo         *users.Repo
	settingsRepo *settings.Repo
	db           *sql.DB
	client       *http.Client
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	box, err := crypto.NewBox(dir)
	if err != nil {
		t.Fatalf("crypto.NewBox: %v", err)
	}

	repo := users.NewRepo(st.DB())
	settingsRepo := settings.NewRepo(st.DB(), box)
	certsSvc := certs.NewService(st.DB(), box, audit.NewRecorder(st.DB()), certs.LiveSigner())
	sessions := app.NewSessionManager(st.DB(), false)
	h := app.NewHandler(app.Deps{
		DB:       st.DB(),
		Users:    repo,
		Settings: settingsRepo,
		Certs:    certsSvc,
		Sessions: sessions,
		Config:   config.Config{},
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		// Surface redirects instead of following them.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &testEnv{srv: srv, repo: repo, settingsRepo: settingsRepo, db: st.DB(), client: client}
}

var csrfFieldRe = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)

// get performs a GET and returns the response and body.
func (e *testEnv) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	resp, err := e.client.Get(e.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

// csrfToken GETs path and extracts the hidden csrf_token field; the cookie jar
// retains the matching nosurf cookie so a follow-up POST validates.
func (e *testEnv) csrfToken(t *testing.T, path string) string {
	t.Helper()
	_, body := e.get(t, path)
	m := csrfFieldRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf_token field on %s; body:\n%s", path, body)
	}
	return m[1]
}

// post sends a same-origin form POST with the given values. The Origin/Referer
// headers mirror what a browser submitting the form would send; nosurf's
// same-origin check (v1.2+) requires them, so this keeps the CSRF middleware
// fully active rather than bypassing it.
func (e *testEnv) post(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build POST %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Referer", e.srv.URL+path)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	_ = resp.Body.Close()
	return resp
}

// completeSetup runs the first-run flow, leaving the client logged in as the
// created superadmin.
func (e *testEnv) completeSetup(t *testing.T, username string) {
	t.Helper()
	token := e.csrfToken(t, "/setup")
	resp := e.post(t, "/setup", url.Values{
		"csrf_token": {token},
		"username":   {username},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("setup status = %d, want 303", resp.StatusCode)
	}
}

// loginAs logs the current client in as username (must already exist).
func (e *testEnv) loginAs(t *testing.T, username string) {
	t.Helper()
	token := e.csrfToken(t, "/login")
	resp := e.post(t, "/login", url.Values{
		"csrf_token": {token},
		"username":   {username},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", resp.StatusCode)
	}
}

// sessionCookie returns the current value of the "session" cookie in the jar
// (empty if none). Used to assert session-token rotation on login.
func (e *testEnv) sessionCookie(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(e.srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	for _, c := range e.client.Jar.Cookies(u) {
		if c.Name == "session" {
			return c.Value
		}
	}
	return ""
}

// sessionRowCount returns the number of rows in the scs sessions table.
func (e *testEnv) sessionRowCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.repo.DB().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM sessions").Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

// --- Healthz (spec/0001 carried forward) ------------------------------------

func TestHealthz(t *testing.T) {
	e := newTestEnv(t)
	resp, body := e.get(t, "/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["status"] != "ok" || m["version"] != app.Version {
		t.Fatalf("body = %v", m)
	}
}

// --- Acceptance: first-run gating (FR-1) ------------------------------------

// Given no users, any page redirects to /setup.
func TestNoUsersRedirectsToSetup(t *testing.T) {
	e := newTestEnv(t)
	for _, path := range []string{"/users", "/", "/anything"} {
		resp, _ := e.get(t, path)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("GET %s status = %d, want 303", path, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "/setup" {
			t.Fatalf("GET %s Location = %q, want /setup", path, loc)
		}
	}
}

// Valid setup creates a superadmin and logs the user in (session set).
func TestSetupCreatesSuperadminAndLogsIn(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// The user exists as superadmin.
	u, err := e.repo.GetByID(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.Username != "root" || u.Role != users.RoleSuperadmin {
		t.Fatalf("created user = %+v, want root/superadmin", u)
	}

	// Logged in: /users now renders (200), not a redirect to /login.
	resp, body := e.get(t, "/users")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /users after setup = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "root") {
		t.Fatalf("/users body missing the logged-in user")
	}
}

// After setup completes, GET /setup is no longer available (redirects to /login).
func TestSetupUnavailableAfterFirstUser(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	resp, _ := e.get(t, "/setup")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET /setup after setup = %d %q, want 303 /login",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

// --- Acceptance: authentication (FR-3) --------------------------------------

// Unauthenticated request to a protected page redirects to /login.
func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	e := newTestEnv(t)
	// Create a user so first-run gating is satisfied but stay logged out.
	if _, err := e.repo.Create(context.Background(), "root", testPassword, users.RoleSuperadmin); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp, _ := e.get(t, "/users")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET /users unauthenticated = %d %q, want 303 /login",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

// Login with wrong credentials is rejected (401) and sets no session.
func TestLoginWrongPassword(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.repo.Create(context.Background(), "root", testPassword, users.RoleSuperadmin); err != nil {
		t.Fatalf("seed: %v", err)
	}
	token := e.csrfToken(t, "/login")
	resp := e.post(t, "/login", url.Values{
		"csrf_token": {token},
		"username":   {"root"},
		"password":   {"wrong-password-zzzz"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login status = %d, want 401", resp.StatusCode)
	}
	// Still locked out.
	r2, _ := e.get(t, "/users")
	if r2.Header.Get("Location") != "/login" {
		t.Fatalf("expected still-unauthenticated after bad login")
	}
}

// Logout clears the session.
func TestLogout(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	token := e.csrfToken(t, "/users")
	resp := e.post(t, "/logout", url.Values{"csrf_token": {token}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status = %d, want 303", resp.StatusCode)
	}
	r2, _ := e.get(t, "/users")
	if r2.Header.Get("Location") != "/login" {
		t.Fatalf("expected /login after logout, got %q", r2.Header.Get("Location"))
	}
}

// --- Acceptance: CSRF (FR-5) ------------------------------------------------

// A POST without a valid CSRF token is rejected with 403, even with a session.
func TestPostWithoutCSRFRejected(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// No csrf_token field, but a valid session cookie is in the jar.
	resp := e.post(t, "/users", url.Values{
		"username": {"bob"},
		"password": {testPassword},
		"role":     {"viewer"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without CSRF = %d, want 403", resp.StatusCode)
	}
	// And the user was not created.
	if n, _ := e.repo.Count(context.Background()); n != 1 {
		t.Fatalf("user count = %d, want 1 (CSRF should have blocked create)", n)
	}
}

// A POST with a stale/forged CSRF token is rejected too.
func TestPostWithForgedCSRFRejected(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	resp := e.post(t, "/users", url.Values{
		"csrf_token": {"not-a-real-token"},
		"username":   {"bob"},
		"password":   {testPassword},
		"role":       {"viewer"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST with forged CSRF = %d, want 403", resp.StatusCode)
	}
}

// --- Security regressions (spec/0003 review) --------------------------------

// Session fixation: authenticating must rotate the session token (scs
// RenewToken), so a value already bound to the session cannot survive across an
// authentication boundary. scs only issues a session cookie once session data
// exists, so to get a non-empty "before" we first authenticate (establishing a
// session + cookie T1), then authenticate again over the same session and assert
// the token rotated to T2 != T1. If RenewToken were dropped, T1 == T2 and this
// fails — the property this locks.
func TestSessionFixationTokenRotatesOnLogin(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.repo.Create(context.Background(), "root", testPassword, users.RoleSuperadmin); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// First login binds a session and yields cookie T1.
	e.loginAs(t, "root")
	before := e.sessionCookie(t)
	if before == "" {
		t.Fatal("no session cookie after first login")
	}

	// Re-authenticate over the existing session; RenewToken must rotate the token.
	token := e.csrfToken(t, "/users")
	resp := e.post(t, "/login", url.Values{
		"csrf_token": {token},
		"username":   {"root"},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("re-login status = %d, want 303", resp.StatusCode)
	}
	after := e.sessionCookie(t)
	if after == "" {
		t.Fatal("no session cookie after re-login")
	}
	if before == after {
		t.Fatalf("session token did not rotate on login (fixation): %q", after)
	}
}

// Same property for first-run setup: postSetup renews the token before storing
// the user id. We compare the post-setup token against a freshly re-renewed one
// obtained by logging in again, proving the authenticated session uses a rotated
// token rather than a pre-existing fixed value.
func TestSessionFixationTokenRotatesOnSetup(t *testing.T) {
	e := newTestEnv(t)

	e.completeSetup(t, "root")
	afterSetup := e.sessionCookie(t)
	if afterSetup == "" {
		t.Fatal("no session cookie after setup")
	}

	// Log out (destroys the session), then log in: the new authenticated token
	// must differ from the one minted at setup, confirming each auth renews.
	token := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {token}})
	e.loginAs(t, "root")
	afterLogin := e.sessionCookie(t)
	if afterLogin == "" {
		t.Fatal("no session cookie after login")
	}
	if afterSetup == afterLogin {
		t.Fatalf("session token did not rotate across setup→logout→login (fixation): %q", afterLogin)
	}
}

// Logout must destroy the server-side session, not merely redirect: the scs
// sessions table row must be gone afterwards. This guards against a logout that
// only clears the cookie while leaving a replayable session in the store.
func TestLogoutDestroysServerSession(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	if n := e.sessionRowCount(t); n == 0 {
		t.Fatal("expected a persisted session row after setup/login")
	}

	token := e.csrfToken(t, "/users")
	resp := e.post(t, "/logout", url.Values{"csrf_token": {token}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status = %d, want 303", resp.StatusCode)
	}
	if n := e.sessionRowCount(t); n != 0 {
		t.Fatalf("sessions table count = %d after logout, want 0 (session not destroyed)", n)
	}
}

// Cross-origin CSRF: a POST carrying a *valid* token+session cookie but a
// foreign Origin must be rejected (403) by nosurf's same-origin check. This is
// the defence that survives token theft via a cross-site form. Sending a real
// token proves the 403 is the origin check, not a token mismatch.
func TestCrossOriginPostRejected(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	token := e.csrfToken(t, "/users")
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/users",
		strings.NewReader(url.Values{
			"csrf_token": {token},
			"username":   {"bob"},
			"password":   {testPassword},
			"role":       {"viewer"},
		}.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Foreign Origin/Referer: a cross-site attacker's page.
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Referer", "https://evil.example.com/attack")

	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST = %d, want 403 (same-origin check)", resp.StatusCode)
	}
	// And nothing was created.
	if n, _ := e.repo.Count(context.Background()); n != 1 {
		t.Fatalf("user count = %d, want 1 (cross-origin POST should be blocked)", n)
	}
}

// --- Acceptance: RBAC (FR-4) ------------------------------------------------

// A viewer attempting a mutating action gets 403.
func TestViewerMutatingActionForbidden(t *testing.T) {
	e := newTestEnv(t)
	// superadmin creates a viewer.
	e.completeSetup(t, "root")
	createToken := e.csrfToken(t, "/users")
	if resp := e.post(t, "/users", url.Values{
		"csrf_token": {createToken},
		"username":   {"viewer1"},
		"password":   {testPassword},
		"role":       {"viewer"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create viewer status = %d", resp.StatusCode)
	}

	// Log out, then grab a valid CSRF token from the login page while still
	// logged out (the nosurf cookie is stable across login, so this token stays
	// valid afterwards). This lets the viewer POST with a *genuine* token, so a
	// 403 proves RBAC — not a CSRF rejection — blocks the mutation.
	logoutToken := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})
	token := e.csrfToken(t, "/login")
	e.loginAs(t, "viewer1")

	// Viewer GET /users: still forbidden (route requires admin+).
	if resp, _ := e.get(t, "/users"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer GET /users = %d, want 403", resp.StatusCode)
	}

	// Viewer mutating POST with that valid token → 403 (RBAC), not a CSRF 403.
	resp := e.post(t, "/users", url.Values{
		"csrf_token": {token},
		"username":   {"hacker"},
		"password":   {testPassword},
		"role":       {"admin"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST /users = %d, want 403", resp.StatusCode)
	}
}

// --- Acceptance: last-superadmin guard surfaced via the handler (FR-6) ------

// Deleting the only superadmin via the handler is refused and the user remains.
func TestDeleteLastSuperadminBlockedViaHandler(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	token := e.csrfToken(t, "/users")
	resp := e.post(t, "/users/1", url.Values{
		"csrf_token": {token},
		"action":     {"delete"},
	})
	// Redirects back to /users with a flash error; the user must still exist.
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete status = %d, want 303 (flash error)", resp.StatusCode)
	}
	if _, err := e.repo.GetByID(context.Background(), 1); err != nil {
		t.Fatalf("superadmin was deleted despite last-superadmin guard: %v", err)
	}

	// The error flash is shown on the next /users render.
	_, body := e.get(t, "/users")
	if !strings.Contains(body, "superadmin must remain") {
		t.Fatalf("expected last-superadmin flash error, body:\n%s", body)
	}
}

// An admin can create a user end-to-end through the handler.
func TestAdminCreateUserThroughHandler(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	token := e.csrfToken(t, "/users")
	resp := e.post(t, "/users", url.Values{
		"csrf_token": {token},
		"username":   {"bob"},
		"password":   {testPassword},
		"role":       {"admin"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create status = %d, want 303", resp.StatusCode)
	}
	if n, _ := e.repo.Count(context.Background()); n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
}

// --- Privilege escalation / role ceiling (FR-4) -----------------------------

// seedUser creates a user directly in the repo (bypassing the handler) so tests
// can set up an actor of a given role without going through the create ceiling.
func (e *testEnv) seedUser(t *testing.T, username string, role users.Role) users.User {
	t.Helper()
	u, err := e.repo.Create(context.Background(), username, testPassword, role)
	if err != nil {
		t.Fatalf("seed %s/%s: %v", username, role, err)
	}
	return u
}

// switchTo logs the client out (it is currently authenticated) and back in as
// username. The nosurf cookie is stable across the flow, so a token fetched
// afterwards from /users is valid for subsequent POSTs.
func (e *testEnv) switchTo(t *testing.T, username string) {
	t.Helper()
	// The caller is logged in, so /users renders a logout form with a token.
	logoutToken := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})
	e.loginAs(t, username)
}

// An admin acting through the handler must never be able to create, promote to,
// or manage a superadmin; a superadmin may. These cases would each succeed if
// the role ceiling / superadmin protection were reverted.
func TestRoleCeilingAndSuperadminProtection(t *testing.T) {
	type step struct {
		path   string
		form   url.Values
		status int
	}

	cases := []struct {
		name  string
		actor users.Role // role of the logged-in actor
		// build returns the POST to attempt against the seeded fixture ids.
		build func(token string, suID, adminID, selfID int64) step
	}{
		{
			name:  "admin cannot create superadmin",
			actor: users.RoleAdmin,
			build: func(token string, _, _, _ int64) step {
				return step{"/users", url.Values{
					"csrf_token": {token}, "username": {"newroot"},
					"password": {testPassword}, "role": {"superadmin"},
				}, http.StatusForbidden}
			},
		},
		{
			name:  "admin cannot set own role to superadmin",
			actor: users.RoleAdmin,
			build: func(token string, _, _, selfID int64) step {
				return step{"/users/" + i64(selfID), url.Values{
					"csrf_token": {token}, "action": {"set_role"}, "role": {"superadmin"},
				}, http.StatusForbidden}
			},
		},
		{
			name:  "admin cannot promote another user to superadmin",
			actor: users.RoleAdmin,
			build: func(token string, _, adminID, _ int64) step {
				return step{"/users/" + i64(adminID), url.Values{
					"csrf_token": {token}, "action": {"set_role"}, "role": {"superadmin"},
				}, http.StatusForbidden}
			},
		},
		{
			name:  "admin cannot delete a superadmin",
			actor: users.RoleAdmin,
			build: func(token string, suID, _, _ int64) step {
				return step{"/users/" + i64(suID), url.Values{
					"csrf_token": {token}, "action": {"delete"},
				}, http.StatusForbidden}
			},
		},
		{
			name:  "admin cannot disable a superadmin",
			actor: users.RoleAdmin,
			build: func(token string, suID, _, _ int64) step {
				return step{"/users/" + i64(suID), url.Values{
					"csrf_token": {token}, "action": {"disable"},
				}, http.StatusForbidden}
			},
		},
		{
			name:  "admin cannot demote a superadmin",
			actor: users.RoleAdmin,
			build: func(token string, suID, _, _ int64) step {
				return step{"/users/" + i64(suID), url.Values{
					"csrf_token": {token}, "action": {"set_role"}, "role": {"admin"},
				}, http.StatusForbidden}
			},
		},
		{
			name:  "admin can create an admin",
			actor: users.RoleAdmin,
			build: func(token string, _, _, _ int64) step {
				return step{"/users", url.Values{
					"csrf_token": {token}, "username": {"newadmin"},
					"password": {testPassword}, "role": {"admin"},
				}, http.StatusSeeOther}
			},
		},
		{
			name:  "admin can manage a viewer (disable)",
			actor: users.RoleAdmin,
			build: func(token string, _, adminID, _ int64) step {
				// adminID fixture is actually a viewer in this row's setup below.
				return step{"/users/" + i64(adminID), url.Values{
					"csrf_token": {token}, "action": {"disable"},
				}, http.StatusSeeOther}
			},
		},
		{
			name:  "superadmin can create a superadmin",
			actor: users.RoleSuperadmin,
			build: func(token string, _, _, _ int64) step {
				return step{"/users", url.Values{
					"csrf_token": {token}, "username": {"newroot"},
					"password": {testPassword}, "role": {"superadmin"},
				}, http.StatusSeeOther}
			},
		},
		{
			name:  "superadmin can demote another superadmin (second exists)",
			actor: users.RoleSuperadmin,
			build: func(token string, suID, _, _ int64) step {
				return step{"/users/" + i64(suID), url.Values{
					"csrf_token": {token}, "action": {"set_role"}, "role": {"admin"},
				}, http.StatusSeeOther}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			// Fixtures: a primary superadmin (id 1, the setup user), a second
			// superadmin so guard-vs-authorization is unambiguous, plus the actor
			// and a manageable viewer.
			e.completeSetup(t, "root") // id 1, superadmin
			su2 := e.seedUser(t, "root2", users.RoleSuperadmin)
			viewer := e.seedUser(t, "viewer1", users.RoleViewer)

			var selfID int64
			var actorName string
			switch tc.actor {
			case users.RoleSuperadmin:
				actorName, selfID = "root", 1
			default:
				actor := e.seedUser(t, "actoradmin", tc.actor)
				actorName, selfID = "actoradmin", actor.ID
			}

			e.switchTo(t, actorName)
			token := e.csrfToken(t, "/users")

			// For "admin can manage a viewer" the adminID slot carries the viewer.
			adminID := su2.ID
			if tc.name == "admin can manage a viewer (disable)" {
				adminID = viewer.ID
			}

			s := tc.build(token, su2.ID, adminID, selfID)
			resp := e.post(t, s.path, s.form)
			if resp.StatusCode != s.status {
				t.Fatalf("%s: status = %d, want %d", tc.name, resp.StatusCode, s.status)
			}
		})
	}
}

// i64 formats an int64 path segment.
func i64(n int64) string { return strconv.FormatInt(n, 10) }

// Sanity: the user id parsing path handles a bad id.
func TestPostUserBadID(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	token := e.csrfToken(t, "/users")
	resp := e.post(t, "/users/"+url.PathEscape("not-a-number"), url.Values{
		"csrf_token": {token},
		"action":     {"delete"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad id status = %d, want 400", resp.StatusCode)
	}
}
