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
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
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

// TestCertDetailDownloadFormHasPFXPasswordInput verifies that the cert-detail
// download form (admin+ only) exposes a pfx_password input so the user can
// obtain a password-protected PKCS#12 bundle. The backend supports PFX via
// Service.Bundle when pfx_password is non-empty (spec/0007 FR-3); the UI must
// surface this path.
func TestCertDetailDownloadFormHasPFXPasswordInput(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "pfx-form.test", now.Add(90*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// The download form must include a pfx_password input so the user can
	// request a PKCS#12 bundle from the detail page.
	if !strings.Contains(body, `name="pfx_password"`) {
		t.Error("cert detail download form: missing pfx_password input — " +
			"the user must be able to request a PKCS#12 bundle via the detail download form")
	}
	// The pfx_password input must NOT be type="hidden" (it must be user-fillable).
	if strings.Contains(body, `type="hidden" name="pfx_password"`) {
		t.Error("cert detail download form: pfx_password must be a visible text/password input, " +
			"not a hidden field with an empty value")
	}
}

// TestCertDetailDownloadFormPFXPasswordYieldsP12 verifies that submitting the
// cert-detail download form with a non-empty pfx_password produces a ZIP that
// contains cert.p12. This is the end-to-end path: form → handler (postCertDownload)
// → Service.Bundle(pfxPassword) → cert.p12 in ZIP (spec/0007 FR-3).
func TestCertDetailDownloadFormPFXPasswordYieldsP12(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed a server-issued cert (sealed private key required to build the PFX).
	id := invSeedServerCert(t, e, "pfx-detail-dl.test")
	path := fmt.Sprintf("/certificates/%d/download", id)

	token := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))
	resp, rawBody := e.postResp(t, path, url.Values{
		"csrf_token":   {token},
		"pfx_password": {"hunter2"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail download with pfx_password = %d; body: %s", resp.StatusCode, truncate(rawBody, 300))
	}

	// Parse the ZIP and assert cert.p12 is present.
	zr, err := zip.NewReader(bytes.NewReader([]byte(rawBody)), int64(len(rawBody)))
	if err != nil {
		t.Fatalf("parse ZIP: %v (first 64 bytes: %q)", err, truncate(rawBody, 64))
	}
	var found bool
	for _, f := range zr.File {
		if f.Name == "cert.p12" {
			found = true
			// Verify the entry is non-empty (a valid PKCS#12 is at least a few bytes).
			rc, _ := f.Open()
			p12bytes, _ := io.ReadAll(rc)
			_ = rc.Close()
			if len(p12bytes) == 0 {
				t.Error("cert.p12 in ZIP is empty")
			}
		}
	}
	if !found {
		var names []string
		for _, f := range zr.File {
			names = append(names, f.Name)
		}
		t.Fatalf("ZIP missing cert.p12; entries: %v", names)
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

// --- PEM enrichment: cert-detail page (backlog item ①) ----------------------
//
// These tests verify that the cert-detail page renders the derived fields
// (SHA-256 fingerprint, issuer, public key type, key usage and EKU tags) when
// the stored cert_pem is a real parseable certificate. They would FAIL if:
//   - ParseLeafPEM stops being called in the handler
//   - The fingerprint / issuer / key-type fields are removed from the template
//   - Key usage / EKU tags are no longer rendered as .tag chips

// TestCertDetailFingerprintRendered verifies that the SHA-256 fingerprint of
// the leaf cert is shown in the Identifiers card with a copy affordance.
// Business rule: the fingerprint must be visible, copyable, and in plain
// lowercase hex format (no separators) — matching "step certificate fingerprint".
// A format regression (e.g. reverting to colon-separated) would fail this test.
func TestCertDetailFingerprintRendered(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed a real server-issued cert so cert_pem is parseable.
	id := invSeedServerCert(t, e, "fp-test.test")

	// Independently compute the expected fingerprint from the stored cert PEM.
	var certPEMStr string
	if err := e.db.QueryRow(`SELECT cert_pem FROM certificates WHERE id=?`, id).Scan(&certPEMStr); err != nil {
		t.Fatalf("fetch cert_pem for id %d: %v", id, err)
	}
	block, _ := pem.Decode([]byte(certPEMStr))
	if block == nil {
		t.Fatal("cert_pem stored in DB is not a valid PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse stored cert DER: %v", err)
	}
	sum := sha256.Sum256(leaf.Raw)
	wantFingerprint := hex.EncodeToString(sum[:])

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// The fingerprint label must appear in the Identifiers card.
	if !strings.Contains(body, "SHA-256 fingerprint") {
		t.Error("cert detail: missing 'SHA-256 fingerprint' label in Identifiers card")
	}

	// The exact fingerprint string must appear (plain lowercase hex, 64 chars, no colons).
	// This fails if the format changes (e.g. colons are added) or the wrong digest is used.
	if !strings.Contains(body, wantFingerprint) {
		t.Errorf("cert detail: rendered fingerprint %q not found in page body", wantFingerprint)
	}

	// Double-check: the fingerprint we assert is plain hex (no colons) — so a
	// colon-separated format would fail the above check.
	if strings.ContainsRune(wantFingerprint, ':') {
		t.Errorf("test bug: wantFingerprint should be plain hex, got %q", wantFingerprint)
	}

	// data-copy-target must be present for the copy button to work.
	if !strings.Contains(body, `data-copy-target="#cert-fp"`) {
		t.Error("cert detail: missing data-copy-target for fingerprint copy button")
	}
}

// TestCertDetailIssuerRendered verifies that the issuer (CA name) is shown in
// the Overview card. Business rule: the issuer DN / CN must be visible so
// users can identify which CA issued the certificate.
func TestCertDetailIssuerRendered(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// The fake CA used by invSeedServerCert has CN "Inv Test Root".
	id := invSeedServerCert(t, e, "issuer-test.test")

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	if !strings.Contains(body, "Issuer") {
		t.Error("cert detail: missing 'Issuer' label in Overview card")
	}
	// The fake CA's CN is "Inv Test Root".
	if !strings.Contains(body, "Inv Test Root") {
		t.Error("cert detail: issuer CN 'Inv Test Root' not found in Overview card")
	}
}

// TestCertDetailPublicKeyTypeRendered verifies that the public-key algorithm
// and size are shown in the Overview card.
// Business rule: the key type ("ECDSA P-256", "RSA 2048", etc.) must be
// visible so users know the cryptographic strength of the certificate.
func TestCertDetailPublicKeyTypeRendered(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// invSeedServerCert uses certs.Issue which generates an ECDSA P-256 key.
	id := invSeedServerCert(t, e, "keytype-test.test")

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	if !strings.Contains(body, "Public key") {
		t.Error("cert detail: missing 'Public key' label in Overview card")
	}
	// The issued leaf is ECDSA P-256.
	if !strings.Contains(body, "ECDSA P-256") {
		t.Error("cert detail: 'ECDSA P-256' public key type not rendered in Overview card")
	}
}

// TestCertDetailKeyUsageTagsRendered verifies that key usage strings are shown
// as tag chips in the Identifiers card.
// Business rule: usage tags (e.g. "digitalSignature") must be visible so
// users can confirm the cert's intended purpose.
func TestCertDetailKeyUsageTagsRendered(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// invSeedServerCert → invFakeCA sets KeyUsage=DigitalSignature and
	// ExtKeyUsage=ServerAuth on the leaf.
	id := invSeedServerCert(t, e, "usage-test.test")

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// Key usage section heading must be present.
	if !strings.Contains(body, "Key usage") {
		t.Error("cert detail: missing 'Key usage' label in Identifiers card")
	}
	// At least the digitalSignature tag must appear.
	if !strings.Contains(body, "digitalSignature") {
		t.Error("cert detail: 'digitalSignature' key usage tag not rendered")
	}
	// Server auth EKU tag must appear (fake CA sets ExtKeyUsageServerAuth).
	if !strings.Contains(body, "serverAuth") {
		t.Error("cert detail: 'serverAuth' EKU tag not rendered")
	}
}

// TestCertDetailDegradationOnBadPEM verifies that the cert-detail page renders
// gracefully when cert_pem cannot be parsed (e.g. placeholder text in the DB),
// showing the existing fields without crashing or returning a 5xx.
// Business rule: parse failures must not surface as an error page — they
// should degrade to showing what we have (CN, SANs, etc.) and omit derived fields.
func TestCertDetailDegradationOnBadPEM(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// invInsertMinimalCert stores "certpem" (non-PEM) — simulating a bad PEM.
	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "bad-pem.test", now.Add(90*24*time.Hour).Unix())

	resp, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// Must render a 200 — no panic, no 5xx.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cert detail bad PEM = %d, want 200; body: %s", resp.StatusCode, truncate(body, 300))
	}
	// The CN must still be visible.
	if !strings.Contains(body, "bad-pem.test") {
		t.Error("cert detail bad PEM: CN not rendered (degradation broken)")
	}
}

// --- Provisioner column + filter (backlog item ②) ---------------------------

// TestInventoryProvisionerColumnHeader verifies the inventory table has a
// "Provisioner" column header.
func TestInventoryProvisionerColumnHeader(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertMinimalCert(t, e.db, "col-header.test", now.Add(60*24*time.Hour).Unix())

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, "Provisioner") {
		t.Error("inventory: missing 'Provisioner' column header in table")
	}
}

// TestInventoryProvisionerColumnValue verifies that a cert with a stored
// provisioner shows the provisioner name in the table row.
func TestInventoryProvisionerColumnValue(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertCertWithProvisioner(t, e.db, "prov-col.test", now.Add(60*24*time.Hour).Unix(), "my-jwk-prov")

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, "my-jwk-prov") {
		t.Error("inventory: stored provisioner name 'my-jwk-prov' not visible in table row")
	}
}

// TestInventoryProvisionerColumnNullShowsDash verifies that a cert whose
// provisioner is NULL (pre-migration cert) renders a muted dash "—" in the
// Provisioner column, not an empty cell.
func TestInventoryProvisionerColumnNullShowsDash(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertMinimalCert(t, e.db, "null-prov-dash.test", now.Add(60*24*time.Hour).Unix())

	_, body := e.get(t, "/inventory")

	// The em-dash character must appear in the provisioner cell for NULL rows.
	if !strings.Contains(body, "—") {
		t.Error("inventory: NULL provisioner must render as '—' (em-dash) in the table")
	}
}

// TestInventoryProvisionerFilterSelect verifies that the filter bar contains a
// provisioner filter <select> with the "All provisioners" option.
func TestInventoryProvisionerFilterSelect(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/inventory")

	if !strings.Contains(body, "All provisioners") {
		t.Error("inventory filter: missing 'All provisioners' option in provisioner filter select")
	}
}

// TestInventoryProvisionerFilterShowsDistinctOptions verifies that the
// provisioner filter dropdown contains the distinct provisioner names from the
// DB. This fails if the options are hardcoded or come from the wrong source.
func TestInventoryProvisionerFilterShowsDistinctOptions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertCertWithProvisioner(t, e.db, "opt-acme1.test", now.Add(60*24*time.Hour).Unix(), "acme-prov")
	invInsertCertWithProvisioner(t, e.db, "opt-acme2.test", now.Add(60*24*time.Hour).Unix(), "acme-prov") // duplicate → must appear once
	invInsertCertWithProvisioner(t, e.db, "opt-jwk.test", now.Add(60*24*time.Hour).Unix(), "jwk-prov")
	invInsertMinimalCert(t, e.db, "opt-null.test", now.Add(60*24*time.Hour).Unix()) // NULL → must not appear as option

	_, body := e.get(t, "/inventory")

	// The filter option tag for acme-prov must appear exactly once in the
	// <select> (value attribute), even though acme-prov was seeded twice.
	// We check the value="acme-prov" attribute form which appears only in options.
	if strings.Count(body, `value="acme-prov"`) != 1 {
		t.Errorf("provisioner filter: value=\"acme-prov\" option count = %d, want 1 (distinct)",
			strings.Count(body, `value="acme-prov"`))
	}
	if strings.Count(body, `value="jwk-prov"`) != 1 {
		t.Errorf("provisioner filter: value=\"jwk-prov\" option count = %d, want 1",
			strings.Count(body, `value="jwk-prov"`))
	}
}

// TestInventoryProvisionerFilterFilters verifies that selecting a provisioner
// in the filter restricts the table to certs issued by that provisioner.
// This is the end-to-end integration test: ?provisioner=X → handler → List(Provisioner:X).
func TestInventoryProvisionerFilterFilters(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertCertWithProvisioner(t, e.db, "filter-acme.test", now.Add(60*24*time.Hour).Unix(), "acme-prov")
	invInsertCertWithProvisioner(t, e.db, "filter-jwk.test", now.Add(60*24*time.Hour).Unix(), "jwk-prov")
	invInsertMinimalCert(t, e.db, "filter-null.test", now.Add(60*24*time.Hour).Unix())

	// Filter by acme-prov → only filter-acme.test visible.
	_, body := e.get(t, "/inventory?provisioner=acme-prov")

	if !strings.Contains(body, "filter-acme.test") {
		t.Error("provisioner filter: 'filter-acme.test' must be in results for provisioner=acme-prov")
	}
	if strings.Contains(body, "filter-jwk.test") {
		t.Error("provisioner filter: 'filter-jwk.test' must NOT be in results for provisioner=acme-prov")
	}
	if strings.Contains(body, "filter-null.test") {
		t.Error("provisioner filter: NULL-provisioner cert must NOT appear for provisioner=acme-prov")
	}
}

// TestInventoryAllProvisionersShowsAll verifies that the "All provisioners"
// selection (empty provisioner param) shows all certs including NULL-provisioner.
func TestInventoryAllProvisionersShowsAll(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertCertWithProvisioner(t, e.db, "all-acme.test", now.Add(60*24*time.Hour).Unix(), "acme-prov")
	invInsertMinimalCert(t, e.db, "all-null.test", now.Add(60*24*time.Hour).Unix())

	_, body := e.get(t, "/inventory") // no provisioner param = All provisioners

	if !strings.Contains(body, "all-acme.test") {
		t.Error("All provisioners: missing 'all-acme.test'")
	}
	if !strings.Contains(body, "all-null.test") {
		t.Error("All provisioners: missing 'all-null.test' (NULL provisioner must appear)")
	}
}

// TestInventoryProvisionerStatusComposeFilter verifies that provisioner + status
// filters compose (AND semantics) at the handler level.
func TestInventoryProvisionerStatusComposeFilter(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	// active + acme-prov
	invInsertCertWithProvisioner(t, e.db, "compose-active-acme.test", now.Add(60*24*time.Hour).Unix(), "acme-prov")
	// expired + acme-prov
	invInsertCertWithProvisioner(t, e.db, "compose-expired-acme.test", now.Add(-24*time.Hour).Unix(), "acme-prov")
	// active + jwk-prov
	invInsertCertWithProvisioner(t, e.db, "compose-active-jwk.test", now.Add(60*24*time.Hour).Unix(), "jwk-prov")

	_, body := e.get(t, "/inventory?status=active&provisioner=acme-prov")

	if !strings.Contains(body, "compose-active-acme.test") {
		t.Error("compose filter: 'compose-active-acme.test' must appear for status=active&provisioner=acme-prov")
	}
	if strings.Contains(body, "compose-expired-acme.test") {
		t.Error("compose filter: expired cert must NOT appear for status=active")
	}
	if strings.Contains(body, "compose-active-jwk.test") {
		t.Error("compose filter: jwk-prov cert must NOT appear for provisioner=acme-prov")
	}
}

// invInsertCertWithProvisioner inserts a minimal cert row with the given provisioner.
func invInsertCertWithProvisioner(t *testing.T, db *sql.DB, cn string, notAfter int64, provisioner string) int64 {
	t.Helper()
	ts := time.Now().Unix()
	res, err := db.Exec(`INSERT INTO certificates
		(cn, sans_json, serial, not_before, not_after, status, key_strategy,
		 cert_pem, chain_pem, fullchain_pem, privkey_sealed, created_by, created_at, updated_at, provisioner)
		VALUES (?, ?, ?, ?, ?, 'valid', 'csr', 'certpem', 'chainpem', 'fullchainpem',
		        NULL, 'test', ?, ?, ?)`,
		cn, `["`+cn+`"]`, "serial-"+cn, ts, notAfter, ts, ts, provisioner)
	if err != nil {
		t.Fatalf("invInsertCertWithProvisioner %s: %v", cn, err)
	}
	id, _ := res.LastInsertId()
	return id
}
