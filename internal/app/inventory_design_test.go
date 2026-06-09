package app_test

// Design tests for spec PR-B — inventory + cert-detail redesign.
//
// Acceptance criteria tested:
//   - inventoryPage renders the new page-head structure (page-title, page-sub,
//     action buttons for admin+, not for viewer).
//   - The "recorded view" info flash is present.
//   - The filter bar uses the new .filterbar / .searchbox / .select classes.
//   - The table uses the new .table-wrap / table.table classes and correct columns:
//     Common name, Status, Expires, Serial.
//   - Status badges use the new classes:
//     active  → badge--ok "Valid"
//     expired → badge--neutral "Expired"
//     revoked → badge--danger "Revoked"
//     expiring (active, daysLeft ≤ 30) → badge--warn "Expiring"
//   - The days-countdown is shown for expiring certs.
//   - certDetailPage renders the page-head with breadcrumb and status badge.
//   - Admin+ sees action buttons (Download bundle, Renew, Revoke).
//   - A viewer sees the page but NOT the action buttons.
//   - The "recorded view" banner keeps honest copy.
//   - htmx filter partial (HX-Request) swaps only the table.

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// TestInventoryPageHead verifies the new page-head structure is rendered on the
// inventory page: page-title, page-sub, and action buttons for admin+.
func TestInventoryPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root") // superadmin

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, `class="page-title"`) {
		t.Error("inventory: missing page-title element")
	}
	if !strings.Contains(body, "Certificates") {
		t.Error("inventory: missing 'Certificates' heading text")
	}
	if !strings.Contains(body, "page-sub") {
		t.Error("inventory: missing page-sub subtitle")
	}
	// Admin+ should see issue/sign-csr action buttons in the page-head__actions
	if !strings.Contains(body, "page-head__actions") {
		t.Error("inventory: admin should see page-head__actions")
	}
	if !strings.Contains(body, "Issue certificate") {
		t.Error("inventory: admin should see 'Issue certificate' action button")
	}
}

// TestInventoryPageHeadViewerNoActions verifies that a viewer sees the page
// but NOT the admin action buttons in the page header.
func TestInventoryPageHeadViewerNoActions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "viewer42", users.RoleViewer)
	e.switchTo(t, "viewer42")

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, `class="page-title"`) {
		t.Error("inventory viewer: missing page-title")
	}
	// Viewer must not see issue/sign-csr action buttons
	if strings.Contains(body, "Issue certificate") {
		t.Error("inventory viewer: should NOT see 'Issue certificate' action button")
	}
}

// TestInventoryRecordedViewBanner verifies the "recorded view" info flash is
// present with honest copy (no fake timestamp).
func TestInventoryRecordedViewBanner(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, "recorded view") {
		t.Error("inventory: missing 'recorded view' text in info banner")
	}
	if !strings.Contains(body, "flash--info") {
		t.Error("inventory: missing flash--info class on recorded-view banner")
	}
	// We must NOT display a fake "last reconciled X minutes ago" — only honest copy
	if strings.Contains(body, "minutes ago") {
		t.Error("inventory: must not display fake 'minutes ago' reconcile timestamp")
	}
}

// TestInventoryFilterBarClasses verifies the filter bar uses the new CSS classes.
func TestInventoryFilterBarClasses(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, `class="filterbar"`) {
		t.Error("inventory: missing filterbar class")
	}
	if !strings.Contains(body, `class="searchbox"`) {
		t.Error("inventory: missing searchbox class")
	}
	if !strings.Contains(body, `class="select"`) {
		t.Error("inventory: missing select class on status dropdown")
	}
}

// TestInventoryTableClasses verifies the table uses the new design-system classes.
func TestInventoryTableClasses(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertMinimalCert(t, e.db, "table-class.test", now.Add(60*24*time.Hour).Unix())

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, "table-wrap") {
		t.Error("inventory: missing table-wrap class")
	}
	if !strings.Contains(body, `class="table"`) {
		t.Error("inventory: missing table class on <table> element")
	}
}

// TestInventoryStatusBadgeActive verifies that an active cert renders the
// badge--ok "Valid" badge.
func TestInventoryStatusBadgeActive(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertMinimalCert(t, e.db, "badge-active.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, "badge--ok") {
		t.Error("active cert: missing badge--ok class")
	}
	if !strings.Contains(body, ">Valid<") {
		t.Error("active cert: missing 'Valid' label in badge")
	}
}

// TestInventoryStatusBadgeExpired verifies that an expired cert renders the
// badge--neutral "Expired" badge.
func TestInventoryStatusBadgeExpired(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertMinimalCert(t, e.db, "badge-expired.test", now.Add(-24*time.Hour).Unix())

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, "badge--neutral") {
		t.Error("expired cert: missing badge--neutral class")
	}
	if !strings.Contains(body, ">Expired<") {
		t.Error("expired cert: missing 'Expired' label in badge")
	}
}

// TestInventoryStatusBadgeRevoked verifies that a revoked cert renders the
// badge--danger "Revoked" badge.
func TestInventoryStatusBadgeRevoked(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "badge-revoked.test", now.Add(90*24*time.Hour).Unix())
	// Mark it revoked in the DB
	_, err := e.db.Exec(`UPDATE certificates SET status='revoked' WHERE id=?`, id)
	if err != nil {
		t.Fatalf("mark revoked: %v", err)
	}

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, "badge--danger") {
		t.Error("revoked cert: missing badge--danger class")
	}
	if !strings.Contains(body, ">Revoked<") {
		t.Error("revoked cert: missing 'Revoked' label in badge")
	}
}

// TestInventoryStatusBadgeExpiring verifies that a cert expiring within 30 days
// renders the badge--warn "Expiring" badge with a day countdown.
// This test encodes the business rule: active + DaysLeft ≤ 30 → "Expiring".
func TestInventoryStatusBadgeExpiring(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	// 9 days until expiry — should show Expiring
	invInsertMinimalCert(t, e.db, "badge-expiring.test", now.Add(9*24*time.Hour).Unix())

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, "badge--warn") {
		t.Error("expiring cert: missing badge--warn class")
	}
	if !strings.Contains(body, ">Expiring<") {
		t.Error("expiring cert: missing 'Expiring' label in badge")
	}
	// The countdown should be present (e.g. "9d")
	if !strings.Contains(body, "d</") && !strings.Contains(body, "d<") {
		t.Error("expiring cert: missing day countdown (e.g. '9d')")
	}
}

// TestInventoryFilterBarStatusOptions verifies the status filter select has
// the correct new option values matching the mock.
func TestInventoryFilterBarStatusOptions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/inventory")

	// The filter must have options for the new status values
	for _, want := range []string{"All statuses", "Valid", "Expired", "Revoked", "Expiring"} {
		if !strings.Contains(body, want) {
			t.Errorf("inventory filter: missing status option %q", want)
		}
	}
}

// TestInventoryHTMXPartial verifies that an htmx request (HX-Request: true)
// returns only the table partial, not the full page.
func TestInventoryHTMXPartial(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertMinimalCert(t, e.db, "htmx-partial.test", now.Add(30*24*time.Hour).Unix())

	req, err := http.NewRequest(http.MethodGet, e.srv.URL+"/inventory", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("HX-Request", "true")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("GET /inventory (htmx): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("htmx partial = %d, want 200", resp.StatusCode)
	}
	// The partial must not include the full layout (no <html> tag)
	// but must include the table
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	body := sb.String()
	if strings.Contains(body, "<html") {
		t.Error("htmx partial: must not include full <html> layout")
	}
	if !strings.Contains(body, "htmx-partial.test") {
		t.Error("htmx partial: missing cert CN in partial response")
	}
}

// TestCertDetailPageHead verifies the cert detail page renders the new
// page-head with breadcrumb, page-title (the CN), and the status badge.
func TestCertDetailPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "detail-head.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	if !strings.Contains(body, "breadcrumb") {
		t.Error("cert detail: missing breadcrumb element")
	}
	if !strings.Contains(body, "page-title") {
		t.Error("cert detail: missing page-title element")
	}
	if !strings.Contains(body, "detail-head.test") {
		t.Error("cert detail: missing CN in page-title")
	}
}

// TestCertDetailAdminActions verifies that admin+ sees the action buttons
// (Download bundle, Revoke) on the detail page.
func TestCertDetailAdminActions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root") // superadmin

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "detail-admin.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	if !strings.Contains(body, "page-head__actions") {
		t.Error("cert detail admin: missing page-head__actions")
	}
	if !strings.Contains(body, "Download bundle") {
		t.Error("cert detail admin: missing 'Download bundle' action button")
	}
	// Revoke section should be present for non-revoked cert
	if !strings.Contains(body, "Revoke") {
		t.Error("cert detail admin: missing Revoke action")
	}
}

// TestCertDetailViewerNoAdminActions verifies that a viewer can see the
// metadata and PEM blocks but NOT the admin action buttons.
func TestCertDetailViewerNoAdminActions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "viewer77", users.RoleViewer)
	e.switchTo(t, "viewer77")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "detail-viewer.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// Viewer should see the cert CN (metadata is visible)
	if !strings.Contains(body, "detail-viewer.test") {
		t.Error("cert detail viewer: missing CN (metadata should be visible)")
	}
	// Viewer must NOT see admin action buttons in page-head__actions
	if strings.Contains(body, "Download bundle") {
		t.Error("cert detail viewer: must NOT see 'Download bundle' action button")
	}
	if strings.Contains(body, "Revoke this certificate") {
		t.Error("cert detail viewer: must NOT see revoke form")
	}
	if strings.Contains(body, "Renew certificate") {
		t.Error("cert detail viewer: must NOT see renew form")
	}
	// But the PEM viewer should be present
	if !strings.Contains(body, "codeblock") || !strings.Contains(body, "Certificate (PEM)") {
		t.Error("cert detail viewer: should see PEM block")
	}
}

// TestCertDetailMetadataLayout verifies the detail page uses the new
// card/dl layout for metadata (Overview card with dl).
func TestCertDetailMetadataLayout(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "detail-meta.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	if !strings.Contains(body, `class="dl"`) {
		t.Error("cert detail: missing dl class for metadata layout")
	}
	if !strings.Contains(body, "card__header") {
		t.Error("cert detail: missing card__header")
	}
	if !strings.Contains(body, "Overview") {
		t.Error("cert detail: missing 'Overview' card title")
	}
}

// TestCertDetailPEMViewer verifies the detail page renders PEM blocks using
// the new .codeblock.pem layout with copy affordance.
func TestCertDetailPEMViewer(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "detail-pem.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	if !strings.Contains(body, "codeblock") {
		t.Error("cert detail: missing codeblock class on PEM viewer")
	}
	if !strings.Contains(body, "codeblock__bar") {
		t.Error("cert detail: missing codeblock__bar toolbar")
	}
	// Copy button should be present
	if !strings.Contains(body, "copy-btn") {
		t.Error("cert detail: missing copy-btn on PEM block")
	}
}

// TestRevokeFormRendersConfirmInput verifies that the revoke form on the cert
// detail page includes a hidden confirm=REVOKE input. Without this input, every
// real browser submission fails the handler's FR-3 guard (the bug this test
// encodes: the redesigned form dropped the confirm field).
func TestRevokeFormRendersConfirmInput(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "revoke-form.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// The revoke form must submit name="confirm" value="REVOKE" so the handler
	// accepts the POST. The field can be hidden (the user confirms by clicking
	// the Revoke button, not by typing the word).
	if !strings.Contains(body, `name="confirm"`) {
		t.Error("revoke form: missing confirm input (name=\"confirm\")")
	}
	if !strings.Contains(body, `value="REVOKE"`) {
		t.Error("revoke form: missing REVOKE value on confirm input")
	}
}

// TestRevokeFormSubmitSucceeds verifies that submitting the revoke form as
// rendered by the template (with confirm=REVOKE and a reason derived from the
// selected reason code) reaches the CA and succeeds. This is the handler-level
// regression guard: the form must produce a complete, valid POST.
func TestRevokeFormSubmitSucceeds(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	const serial = "777888"
	id := revInsertCert(t, e, "revoke-form-submit.test", serial, time.Now().Add(90*24*time.Hour).Unix())
	path := "/certificates/" + strconv.FormatInt(id, 10) + "/revoke"

	token := e.csrfToken(t, "/certificates/"+strconv.FormatInt(id, 10))
	// Submit exactly what the rendered form sends: confirm=REVOKE and a reason
	// (either from the reason_code label or the note field).
	status, body := e.postForm(t, path, url.Values{
		"csrf_token":  {token},
		"confirm":     {"REVOKE"},
		"reason_code": {"0"},
		"reason":      {"unspecified"},
	})
	if status != http.StatusOK && status != http.StatusSeeOther {
		t.Fatalf("revoke form submit = %d, want 200/303; body:\n%s", status, body)
	}
	if strings.Contains(strings.ToLower(body), "not confirmed") {
		t.Fatalf("revoke form: got 'not confirmed' error — confirm input missing from form; body:\n%s", body)
	}
	if s := revStatus(t, e, id); s != "revoked" {
		t.Fatalf("local status = %q after successful revoke, want revoked", s)
	}
}

// TestRenewFormOnActiveCertIsEditable verifies that the cert detail page shows
// the editable validity Renew form (with a number input) for non-revoked
// (active/expiring) certs. The old inverted logic showed only a hidden default
// for active certs and the editable form only for revoked certs.
func TestRenewFormOnActiveCertIsEditable(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "renew-active.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// The Renew section must render a validity number input for non-revoked certs
	// (spec/0008 FR-2: user chooses the validity before renewing).
	if !strings.Contains(body, `name="validity"`) {
		t.Error("active cert: renew section must have an editable validity input (name=\"validity\")")
	}
	// The input must be of type number, not type hidden
	if strings.Contains(body, `type="hidden" name="validity"`) {
		t.Error("active cert: validity input must NOT be hidden — it must be user-editable")
	}
}

// TestRenewFormOnRevokedCertIsAbsent verifies that a revoked cert does NOT
// show a Renew form (renewing a revoked cert is nonsensical and would fail at
// the CA).
func TestRenewFormOnRevokedCertIsAbsent(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "renew-revoked.test", now.Add(90*24*time.Hour).Unix())
	if _, err := e.db.Exec(`UPDATE certificates SET status='revoked' WHERE id=?`, id); err != nil {
		t.Fatalf("mark revoked: %v", err)
	}

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// A revoked cert must not offer a Renew form
	if strings.Contains(body, "Renew certificate") {
		t.Error("revoked cert: must NOT show 'Renew certificate' button")
	}
}

// TestSerialCopylineHasHiddenInput verifies that the identifiers card's
// copyline for the serial number contains a hidden input so that copyText()
// can read the value. Without this the Copy button is a no-op because
// copyText() looks for input/textarea in the parent element.
func TestSerialCopylineHasHiddenInput(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "serial-copy.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	if !strings.Contains(body, `class="copyline"`) {
		t.Error("cert detail: missing copyline for serial number")
	}
	// The serial copyline must contain a hidden input holding the serial value
	// so that copyText() (which queries for input/textarea in the parent element)
	// can actually copy it. Without this the Copy button is a no-op.
	// The serial value is "serial-serial-copy.test" from invInsertMinimalCert.
	serial := "serial-serial-copy.test"
	if !strings.Contains(body, `type="hidden" value="`+serial+`"`) {
		t.Errorf("serial copyline: missing hidden input with serial value %q — copyText reads input/textarea only", serial)
	}
}

// TestInventoryStatusBadgeActiveNotExpiring verifies that an active cert with
// > 30 days left does NOT get the Expiring badge (boundary condition).
func TestInventoryStatusBadgeActiveNotExpiring(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	// 45 days — clearly active, not expiring
	invInsertMinimalCert(t, e.db, "badge-not-expiring.test", now.Add(45*24*time.Hour).Unix())

	_, body := e.get(t, "/inventory")

	// Should show Valid badge for this cert, not Expiring
	// Note: we need to ensure that Expiring does not appear at all if there's no
	// expiring cert in the list. Since this test only has one cert (45 days), there
	// should be no Expiring badge.
	// We check that badge--warn is NOT present for a cert that's >30 days out.
	// We use the specific cert row to check — just verify badge--ok is present.
	if !strings.Contains(body, "badge--ok") {
		t.Error("active cert (45d): should have badge--ok (Valid), not expiring")
	}
	// Expiring badge should not appear since DaysLeft=45 > 30
	if strings.Contains(body, "badge--warn") {
		t.Error("active cert (45d): must NOT have badge--warn (Expiring) for 45d cert")
	}
}
