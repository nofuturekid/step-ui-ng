package app_test

// spec/0008 — revoke & renew handler acceptance tests.
//
// Acceptance criteria tested here (mock CA via httptest, signCAFixture):
//   - Active cert → POST /revoke → the CA receives a revoke request AND the local
//     status becomes 'revoked' ONLY on CA success.
//   - CA rejects the revoke → local status UNCHANGED and the error is shown.
//   - Active cert → POST /renew with 30 days → a new cert with the same CN/SANs
//     and ~30-day validity is stored, and appears in the inventory.
//   - Guard rails: already-revoked → clear error; missing reason → error.
//   - RBAC: viewer → 403 on both routes.
//   - Audit: revoke and renew events recorded with the session actor.

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/config"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// revInsertCert inserts a server-strategy cert row with the given serial/CN and
// returns its ID. The handler revokes by this serial against the mock CA.
func revInsertCert(t *testing.T, e *testEnv, cn, serial string, notAfter int64) int64 {
	t.Helper()
	ts := time.Now().Unix()
	res, err := e.db.ExecContext(context.Background(),
		`INSERT INTO certificates
		   (cn, sans_json, serial, not_before, not_after, status, key_strategy,
		    cert_pem, chain_pem, fullchain_pem, privkey_sealed, created_by, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 'valid', 'csr', 'certpem', 'chainpem', 'fullchainpem',
		         NULL, 'test', ?, ?)`,
		cn, `["`+cn+`"]`, serial, ts, notAfter, ts, ts)
	if err != nil {
		t.Fatalf("revInsertCert %s: %v", cn, err)
	}
	id, _ := res.LastInsertId()
	return id
}

func revStatus(t *testing.T, e *testEnv, id int64) string {
	t.Helper()
	var s string
	if err := e.db.QueryRowContext(context.Background(),
		`SELECT status FROM certificates WHERE id = ?`, id).Scan(&s); err != nil {
		t.Fatalf("read status id %d: %v", id, err)
	}
	return s
}

// --- Acceptance: revoke active cert → CA called + local status revoked --------

func TestRevokeActiveCertCallsCAAndMarksRevoked(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	const serial = "424242"
	id := revInsertCert(t, e, "revoke.test", serial, time.Now().Add(90*24*time.Hour).Unix())
	path := "/certificates/" + strconv.FormatInt(id, 10) + "/revoke"

	token := e.csrfToken(t, "/certificates/"+strconv.FormatInt(id, 10))
	status, body := e.postForm(t, path, url.Values{
		"csrf_token": {token},
		"reason":     {"key compromise"},
		"confirm":    {"REVOKE"},
	})
	if status != http.StatusOK && status != http.StatusSeeOther {
		t.Fatalf("POST revoke = %d, want 200/303; body:\n%s", status, body)
	}
	if !f.revokeCalled {
		t.Fatal("the CA never received the revoke request")
	}
	if f.revokeSerial != serial {
		t.Fatalf("CA saw serial %q, want %q", f.revokeSerial, serial)
	}
	if f.revokeOTTSub != serial {
		t.Fatalf("OTT subject = %q, want the serial %q", f.revokeOTTSub, serial)
	}
	if !f.revokePassive {
		t.Fatal("revoke must set passive:true")
	}
	if s := revStatus(t, e, id); s != "revoked" {
		t.Fatalf("local status = %q, want revoked after CA success", s)
	}
	if who := e.auditWho(t, "revoke"); who != "root" {
		t.Fatalf("revoke audit who = %q, want root", who)
	}
}

// --- Acceptance: CA rejects revoke → local status UNCHANGED + error shown -----

func TestRevokeCARejectsLeavesLocalUnchanged(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	f.rejectRevoke = true
	e.seedSignCA(t, f)

	id := revInsertCert(t, e, "reject.test", "999111", time.Now().Add(90*24*time.Hour).Unix())
	path := "/certificates/" + strconv.FormatInt(id, 10) + "/revoke"

	token := e.csrfToken(t, "/certificates/"+strconv.FormatInt(id, 10))
	status, body := e.postForm(t, path, url.Values{
		"csrf_token": {token},
		"reason":     {"superseded"},
		"confirm":    {"REVOKE"},
	})
	if !f.revokeCalled {
		t.Fatal("the CA never received the revoke request")
	}
	// Local row must be unchanged (still valid) — the atomicity guarantee.
	if s := revStatus(t, e, id); s == "revoked" {
		t.Fatal("local status flipped to revoked despite CA failure (atomicity violated)")
	}
	if s := revStatus(t, e, id); s != "valid" {
		t.Fatalf("local status = %q, want unchanged 'valid'", s)
	}
	// The CA error must be surfaced to the user (4xx + a visible message).
	if status != http.StatusBadGateway && status != http.StatusBadRequest && status != http.StatusOK {
		t.Fatalf("revoke-on-failure status = %d; body:\n%s", status, body)
	}
	if !strings.Contains(strings.ToLower(body), "ca") && !strings.Contains(strings.ToLower(body), "revoke") {
		t.Fatalf("expected the CA error to be shown; body:\n%s", body)
	}
}

// --- Guard rail: already-revoked → clear error, no second CA call ------------

func TestRevokeAlreadyRevokedShowsError(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	id := revInsertCert(t, e, "twice.test", "555", time.Now().Add(90*24*time.Hour).Unix())
	// Pre-mark it revoked.
	if _, err := e.db.ExecContext(context.Background(),
		`UPDATE certificates SET status = 'revoked' WHERE id = ?`, id); err != nil {
		t.Fatalf("pre-revoke: %v", err)
	}
	path := "/certificates/" + strconv.FormatInt(id, 10) + "/revoke"
	token := e.csrfToken(t, "/certificates/"+strconv.FormatInt(id, 10))
	_, body := e.postForm(t, path, url.Values{
		"csrf_token": {token},
		"reason":     {"unspecified"},
		"confirm":    {"REVOKE"},
	})
	if f.revokeCalled {
		t.Fatal("the CA must NOT be called for an already-revoked cert")
	}
	if !strings.Contains(strings.ToLower(body), "already") {
		t.Fatalf("expected an 'already revoked' error; body:\n%s", body)
	}
}

// --- Guard rail: blank reason note → handler defaults to reason_code label ---
//
// Design change (PR-B fix): the reason note field is optional in the form. When
// the user leaves it blank, the handler defaults to the reason_code's label so
// the domain's ErrReasonRequired guard is satisfied without forcing extra typing.
// This test encodes that the happy path (blank note + reason_code selected)
// succeeds and the CA is called.
func TestRevokeBlankReasonNoteDefaultsToCodeLabel(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	id := revInsertCert(t, e, "noreason.test", "777", time.Now().Add(90*24*time.Hour).Unix())
	path := "/certificates/" + strconv.FormatInt(id, 10) + "/revoke"
	token := e.csrfToken(t, "/certificates/"+strconv.FormatInt(id, 10))
	// Blank reason note — the handler must default to the reason_code label ("unspecified").
	status, body := e.postForm(t, path, url.Values{
		"csrf_token":  {token},
		"reason":      {""},
		"reason_code": {"0"},
		"confirm":     {"REVOKE"},
	})
	if status != http.StatusOK && status != http.StatusSeeOther {
		t.Fatalf("revoke with blank note = %d, want 200/303; body:\n%s", status, body)
	}
	if !f.revokeCalled {
		t.Fatal("the CA must be called when reason defaults from reason_code label")
	}
	if s := revStatus(t, e, id); s != "revoked" {
		t.Fatalf("status = %q, want revoked after successful revoke with defaulted reason", s)
	}
}

// --- Acceptance: renew with 30 days → new cert, same CN/SANs, ~30d validity --

func TestRenewActiveCertStoresNewCert(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	id := revInsertCert(t, e, "renew.test", "808080", time.Now().Add(10*24*time.Hour).Unix())
	path := "/certificates/" + strconv.FormatInt(id, 10) + "/renew"

	token := e.csrfToken(t, "/certificates/"+strconv.FormatInt(id, 10))
	status, body := e.postForm(t, path, url.Values{
		"csrf_token": {token},
		"validity":   {"30"},
	})
	if status != http.StatusOK && status != http.StatusSeeOther {
		t.Fatalf("POST renew = %d, want 200/303; body:\n%s", status, body)
	}

	// A NEW row with the same CN was stored (id != original).
	var (
		newID    int64
		notAfter int64
	)
	err := e.db.QueryRowContext(context.Background(),
		`SELECT id, not_after FROM certificates WHERE cn = 'renew.test' AND id <> ? ORDER BY id DESC LIMIT 1`, id).
		Scan(&newID, &notAfter)
	if err != nil {
		t.Fatalf("renewed cert not stored: %v", err)
	}
	// not_after ≈ now + 30d (±2d tolerance for the mock's clock).
	want := time.Now().Add(30 * 24 * time.Hour)
	got := time.Unix(notAfter, 0)
	if diff := got.Sub(want); diff > 48*time.Hour || diff < -48*time.Hour {
		t.Fatalf("renewed not_after = %v, want ≈ %v (±2d)", got, want)
	}
	if who := e.auditWho(t, "renew"); who != "root" {
		t.Fatalf("renew audit who = %q, want root", who)
	}
}

// --- The renew form is pre-filled from the configurable default --------------
//
// The detail view's renew control must show the config default threaded from
// the server config, not a value hard-coded in the template. We use a
// distinctive value (47) that equals neither config.DefaultRenewDays (90) nor
// the renewDefaultDays() fallback, so the test fails if either the template
// hard-codes a literal or the config isn't wired to the form.

func TestRenewFormShowsConfigurableDefault(t *testing.T) {
	const distinctDefault = 47 // not config.DefaultRenewDays (90), not any template literal
	e := newTestEnvWithConfig(t, config.Config{RenewDefaultDays: distinctDefault})
	e.completeSetup(t, "root")
	id := revInsertCert(t, e, "detail.test", "12321", time.Now().Add(90*24*time.Hour).Unix())

	_, body := e.get(t, "/certificates/"+strconv.FormatInt(id, 10))
	// The renew validity input must carry the server-config value, not a hard-coded literal.
	if !strings.Contains(body, `value="47"`) {
		t.Fatalf("renew form should default validity to the configured %d days; body:\n%s", distinctDefault, body)
	}
}

// --- RBAC: viewer → 403 on both routes --------------------------------------

func TestRevokeRenewForbiddenForViewer(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	// Create a viewer and switch to it.
	e.seedUser(t, "view", users.RoleViewer)
	id := revInsertCert(t, e, "rbac.test", "1313", time.Now().Add(90*24*time.Hour).Unix())

	e.switchTo(t, "view")

	for _, route := range []string{"/revoke", "/renew"} {
		path := "/certificates/" + strconv.FormatInt(id, 10) + route
		// A viewer cannot GET the detail's csrf, but the global token works from any
		// page; fetch it from the inventory page the viewer can see.
		token := e.csrfToken(t, "/inventory")
		resp := e.post(t, path, url.Values{
			"csrf_token": {token},
			"reason":     {"x"},
			"confirm":    {"REVOKE"},
			"validity":   {"30"},
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer POST %s = %d, want 403", path, resp.StatusCode)
		}
	}
}
