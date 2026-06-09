package app_test

// Regression tests for the two bugs in the certificate issue/download flow.
//
// Bug 1 — Issue / Sign CSR show NO error when the CA rejects the request.
//   The error message was placed in d.Error (rendered by the layout, OUTSIDE the
//   #issue-panel/#sign-panel swap target). htmx does not swap non-2xx responses by
//   default. Fix: render the error INSIDE the panel and return HTTP 200 so htmx
//   swaps it.
//
// Bug 2 — server-generated private key cannot be downloaded at creation AND later.
//   hx-boost="true" on <body> intercepts file-download forms and anchors, routing
//   them through XHR so the browser never saves the file.
//   Fix: hx-boost="false" on every file-download element.
//   Also: the cert-detail private-key copy is misleading for key_strategy=server.

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/certs"
)

// ============================================================
// Bug 1 — in-panel error visibility on CA rejection
// ============================================================

// TestIssueCARejectErrorInPanel verifies that when the CA rejects a sign
// request (e.g. validity exceeds the provisioner's maximum), the error message
// is rendered INSIDE #issue-panel so htmx can swap it, the response is HTTP 200
// (htmx swaps 2xx by default), and the form fields are repopulated.
func TestIssueCARejectErrorInPanel(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixtureMax(t, 30) // provisioner max = 30 days
	e.seedSignCA(t, f.signCAFixture)

	token := e.csrfToken(t, "/issue")
	status, body := e.postForm(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"toolong.test"},
		"validity":   {"365"},
		"format":     {"pem"},
	})

	// The response MUST be HTTP 200 so htmx will swap the panel.
	if status != http.StatusOK {
		t.Fatalf("CA-reject issue = %d, want 200 (htmx must be able to swap it)", status)
	}

	// The rejection message must be present in the body.
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "rejected") && !strings.Contains(lower, "maximum") {
		t.Fatalf("CA-reject issue: expected rejection message in body; body:\n%s", body)
	}

	// The error must appear INSIDE #issue-panel (i.e. the panel element
	// must appear BEFORE the error text in the document, because the error
	// is rendered within the panel).
	panelIdx := strings.Index(body, "issue-panel")
	errorIdx := strings.Index(strings.ToLower(body), "flash--error")
	if panelIdx < 0 {
		t.Fatal("CA-reject issue: #issue-panel element missing from response")
	}
	if errorIdx < 0 {
		t.Fatal("CA-reject issue: flash--error not found in response")
	}
	if errorIdx < panelIdx {
		t.Fatalf("CA-reject issue: flash--error (at %d) appears before #issue-panel (at %d) — error must be inside the panel", errorIdx, panelIdx)
	}

	// The CN field must be repopulated.
	if !strings.Contains(body, "toolong.test") {
		t.Fatal("CA-reject issue: CN 'toolong.test' not repopulated in the form")
	}
	// The validity must be repopulated.
	if !strings.Contains(body, "365") {
		t.Fatal("CA-reject issue: validity '365' not repopulated in the form")
	}
}

// TestSignCSRCARejectErrorInPanel verifies that when the CA rejects a sign-CSR
// request, the error is rendered INSIDE #sign-panel, the response is HTTP 200,
// and the CSR textarea + validity are repopulated.
func TestSignCSRCARejectErrorInPanel(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixtureMax(t, 30) // provisioner max = 30 days
	e.seedSignCA(t, f.signCAFixture)

	csrPEM := makeCSR(t, "toolong.csr.test", nil)
	token := e.csrfToken(t, "/sign-csr")
	status, body := e.postForm(t, "/sign-csr", url.Values{
		"csrf_token": {token},
		"csr":        {csrPEM},
		"validity":   {"365"},
	})

	if status != http.StatusOK {
		t.Fatalf("CA-reject sign-csr = %d, want 200 (htmx must be able to swap it)", status)
	}

	lower := strings.ToLower(body)
	if !strings.Contains(lower, "rejected") && !strings.Contains(lower, "maximum") {
		t.Fatalf("CA-reject sign-csr: expected rejection message in body; body:\n%s", body)
	}

	panelIdx := strings.Index(body, "sign-panel")
	errorIdx := strings.Index(strings.ToLower(body), "flash--error")
	if panelIdx < 0 {
		t.Fatal("CA-reject sign-csr: #sign-panel element missing from response")
	}
	if errorIdx < 0 {
		t.Fatal("CA-reject sign-csr: flash--error not found in response")
	}
	if errorIdx < panelIdx {
		t.Fatalf("CA-reject sign-csr: flash--error (at %d) appears before #sign-panel (at %d) — error must be inside the panel", errorIdx, panelIdx)
	}

	// CSR textarea must be repopulated.
	if !strings.Contains(body, "CERTIFICATE REQUEST") {
		t.Fatal("CA-reject sign-csr: CSR not repopulated in the form")
	}
	// Validity must be repopulated.
	if !strings.Contains(body, "365") {
		t.Fatal("CA-reject sign-csr: validity '365' not repopulated in the form")
	}
}

// TestIssueValidityErrorInPanel tests the validity-parse error path (non-CA)
// also lands in-panel with HTTP 200.
func TestIssueValidityErrorInPanel(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	token := e.csrfToken(t, "/issue")
	status, body := e.postForm(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"any.test"},
		"validity":   {"abc"},
		"format":     {"pem"},
	})

	if status != http.StatusOK {
		t.Fatalf("validity-parse error issue = %d, want 200", status)
	}
	if !strings.Contains(strings.ToLower(body), "validity") {
		t.Fatalf("validity-parse error issue: expected validity message; body:\n%s", body)
	}
	panelIdx := strings.Index(body, "issue-panel")
	errorIdx := strings.Index(strings.ToLower(body), "flash--error")
	if panelIdx < 0 || errorIdx < 0 {
		t.Fatalf("validity-parse error issue: expected issue-panel and flash--error in body; got panel=%d, error=%d", panelIdx, errorIdx)
	}
	if errorIdx < panelIdx {
		t.Fatalf("validity-parse error issue: flash--error must be inside #issue-panel")
	}
}

// ============================================================
// Bug 2 — hx-boost="false" on download elements
// ============================================================

// TestIssueDownloadAnchorsHaveHxBoostFalse verifies that the private-key and
// PFX download anchors in the issue success panel carry hx-boost="false".
// Without this, hx-boost on <body> intercepts the click and the browser never
// triggers a native file download.
func TestIssueDownloadAnchorsHaveHxBoostFalse(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	token := e.csrfToken(t, "/issue")
	_, body := e.postForm(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"download-test.example"},
		"validity":   {"30"},
		"format":     {"pem"},
	})

	// The PEM key download anchor must carry hx-boost="false".
	// Locate the download anchor for the key.
	if !strings.Contains(body, `x-pem-file`) {
		t.Fatal("issue result: private-key data URI not found — test prerequisite failed")
	}

	// Check that the download anchor carries hx-boost="false".
	// We search for the pattern near the download attribute.
	keyDownloadSection := extractAroundKeyword(body, "x-pem-file", 300)
	if !strings.Contains(keyDownloadSection, `hx-boost="false"`) {
		t.Errorf("issue result: private-key download anchor missing hx-boost=\"false\"; near anchor:\n%s", keyDownloadSection)
	}
}

// TestIssuePFXDownloadAnchorHasHxBoostFalse verifies the PFX download anchor
// in the issue success panel carries hx-boost="false".
func TestIssuePFXDownloadAnchorHasHxBoostFalse(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	const pfxPass = "test-pfx-pass"
	token := e.csrfToken(t, "/issue")
	_, body := e.postForm(t, "/issue", url.Values{
		"csrf_token":   {token},
		"cn":           {"pfx-download-test.example"},
		"validity":     {"30"},
		"format":       {"pfx"},
		"pfx_password": {pfxPass},
	})

	if !strings.Contains(body, `x-pkcs12`) {
		t.Fatal("issue result (PFX): PFX data URI not found — test prerequisite failed")
	}

	pfxSection := extractAroundKeyword(body, "x-pkcs12", 300)
	if !strings.Contains(pfxSection, `hx-boost="false"`) {
		t.Errorf("issue result: PFX download anchor missing hx-boost=\"false\"; near anchor:\n%s", pfxSection)
	}
}

// TestCertDetailDownloadFormHasHxBoostFalse verifies that the "Download bundle"
// form on the cert-detail page carries hx-boost="false". Without this attribute
// the hx-boost body intercepts the submit and the browser never saves the ZIP.
func TestCertDetailDownloadFormHasHxBoostFalse(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "dl-test.example", now.Add(30*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// The download form must be present.
	if !strings.Contains(body, "/download") {
		t.Fatal("cert detail: download form not found — test prerequisite failed")
	}

	// The form element containing action=.../download must carry hx-boost="false".
	downloadSection := extractAroundKeyword(body, "/download", 400)
	if !strings.Contains(downloadSection, `hx-boost="false"`) {
		t.Errorf("cert detail: download form missing hx-boost=\"false\"; near form:\n%s", downloadSection)
	}
}

// ============================================================
// Bug 2 — misleading private-key copy on cert detail
// ============================================================

// TestCertDetailServerCertKeyDescription verifies that for a server-strategy cert
// (key generated and sealed by the server), the cert detail page does NOT claim the
// private key is "never stored" — because it IS stored (sealed). The text must be
// truthful: the key is not shown inline but is included in the downloadable bundle.
func TestCertDetailServerCertKeyDescription(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed a server-strategy cert.
	id := invSeedServerCert(t, e, "server-desc.example")

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// Must NOT claim the key is "never stored" for a server cert.
	lower := strings.ToLower(body)
	if strings.Contains(lower, "never stored") {
		t.Errorf("cert detail (server): copy falsely claims private key is 'never stored'; "+
			"for key_strategy=server the key IS sealed at rest. Body snippet around issue:\n%s",
			extractAroundKeyword(body, "never stored", 200))
	}

	// The description must acknowledge the key is included in the bundle.
	if !strings.Contains(lower, "bundle") && !strings.Contains(lower, "sealed") && !strings.Contains(lower, "download") {
		t.Errorf("cert detail (server): copy must acknowledge the key is in the downloadable bundle "+
			"(bundle/sealed/download); body segment:\n%s",
			extractAroundKeyword(body, "private key", 300))
	}
}

// TestCertDetailCSRCertKeyDescription verifies that for a CSR-strategy cert the
// cert detail page accurately states the UI never holds the private key.
func TestCertDetailCSRCertKeyDescription(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "csr-desc.example", now.Add(30*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))

	// For CSR strategy the UI genuinely never held the private key — the copy is
	// different. It should NOT claim the key is in the bundle (there is none).
	// It may say something like "UI does not hold the private key" or similar.
	lower := strings.ToLower(body)
	if strings.Contains(lower, "sealed at rest") || strings.Contains(lower, "downloadable bundle") {
		// Only wrong if it's in the cert PEM section and refers to a key we hold.
		// For CSR certs this copy must NOT appear.
		t.Errorf("cert detail (csr): copy mentions sealed key or bundle for a CSR cert (we don't hold it); "+
			"body segment:\n%s", extractAroundKeyword(body, "private key", 300))
	}
}

// ============================================================
// helpers
// ============================================================

// extractAroundKeyword returns up to windowSize bytes of body centred around
// the first occurrence of keyword (useful for test failure messages).
func extractAroundKeyword(body, keyword string, windowSize int) string {
	idx := strings.Index(strings.ToLower(body), strings.ToLower(keyword))
	if idx < 0 {
		return "(keyword not found)"
	}
	start := idx - windowSize/2
	if start < 0 {
		start = 0
	}
	end := idx + len(keyword) + windowSize/2
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// Ensure certs package is imported for invSeedServerCert usage.
var _ = certs.FormatPEM
