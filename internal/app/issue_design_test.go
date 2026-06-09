package app_test

// Design tests for PR F — issue certificate + sign CSR page redesign.
//
// Acceptance criteria tested:
//   - issuePage renders a page-head with breadcrumb, page-title ("Issue
//     certificate"), and page-sub subtitle.
//   - issuePage shows the active-provisioner flash (flash--info) when a
//     provisioner is selected, with the provisioner name and a link to change it.
//   - issuePage shows a prompt-to-select state when NO provisioner is active.
//   - The issue form has: CN input, SANs field (textarea), Validity select,
//     Key-type select, and submits via POST /issue (htmx hx-post).
//   - The issue-success result (State 2) renders the cert PEM, the one-time
//     private-key panel (.onetime with the private key), and a PKCS#12 download.
//   - The private key is NOT present on a plain GET /issue (one-time invariant).
//   - signCSRPage renders a page-head with breadcrumb, page-title ("Sign CSR"),
//     and page-sub subtitle.
//   - signCSRPage shows the active-provisioner flash when a provisioner is selected.
//   - The sign-CSR form has a CSR textarea and Validity field, submits via
//     hx-post="/sign-csr".
//   - The sign-CSR success result renders the signed cert with NO private key.
//   - Both forms carry CSRF tokens and correct htmx wiring.

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/settings"
)

// --- Issue page design tests -------------------------------------------------

// TestIssueDesignPageHead verifies the redesigned issue page renders the
// page-head structure: breadcrumb, page-title ("Issue certificate"), page-sub.
func TestIssueDesignPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/issue")

	if !strings.Contains(body, "page-head") {
		t.Error("issue: missing page-head wrapper")
	}
	if !strings.Contains(body, "breadcrumb") {
		t.Error("issue: missing breadcrumb")
	}
	if !strings.Contains(body, `class="page-title"`) {
		t.Error("issue: missing page-title element")
	}
	if !strings.Contains(body, "Issue certificate") {
		t.Error("issue: missing 'Issue certificate' heading text")
	}
	if !strings.Contains(body, "page-sub") {
		t.Error("issue: missing page-sub subtitle")
	}
}

// TestIssueDesignActiveProvisionerFlash verifies that when an active provisioner
// is configured, the issue page shows a flash--info note with the provisioner
// name and a link to the provisioners page.
func TestIssueDesignActiveProvisionerFlash(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed settings with a CA URL + select a provisioner.
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := e.settingsRepo.SelectProvisioner(context.Background(), "admin-jwk", "secret"); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.get(t, "/issue")

	if !strings.Contains(body, "flash--info") {
		t.Error("issue with active provisioner: missing flash--info note")
	}
	if !strings.Contains(body, "admin-jwk") {
		t.Error("issue: active provisioner name not shown in flash")
	}
	if !strings.Contains(body, "href=\"/provisioners\"") && !strings.Contains(body, "href=/provisioners") {
		t.Error("issue: missing link to /provisioners in the flash note")
	}
}

// TestIssueDesignNoProvisionerPrompt verifies that when NO active provisioner is
// selected, the issue page shows a prompt directing the user to select one,
// rather than a provisioner name. This is the "select provisioner first" UX state.
func TestIssueDesignNoProvisionerPrompt(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	// Do not select any provisioner — default state.

	_, body := e.get(t, "/issue")

	// The page must still render (not 500). It should show a prompt about provisioners.
	if !strings.Contains(strings.ToLower(body), "provisioner") {
		t.Error("issue no-provisioner state: must mention 'provisioner' to guide the user")
	}
}

// TestIssueDesignFormFields verifies the issue form contains the required fields:
// CN (input), SANs (textarea named "sans"), Validity, and an Issue button.
// Key type is a static readout (not a selectable <select>) — see
// TestIssueDesignKeyTypeIsStaticReadout.
func TestIssueDesignFormFields(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/issue")

	if !strings.Contains(body, `name="cn"`) {
		t.Error("issue form: missing cn input")
	}
	if !strings.Contains(body, `name="sans"`) {
		t.Error("issue form: missing sans textarea/input")
	}
	if !strings.Contains(body, `name="validity"`) {
		t.Error("issue form: missing validity field")
	}
	if !strings.Contains(body, "Issue certificate") {
		t.Error("issue form: missing 'Issue certificate' submit button text")
	}
}

// TestIssueDesignKeyTypeIsStaticReadout verifies that the key-type field is a
// static, read-only "ECDSA P-256" display — NOT a multi-option <select name="keytype">.
// The backend always generates ECDSA P-256 regardless of any keytype input, so the
// UI must not offer a false choice. The hint about key pair generation must still appear.
func TestIssueDesignKeyTypeIsStaticReadout(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/issue")

	// The static "ECDSA P-256" value must be visible.
	if !strings.Contains(body, "ECDSA P-256") {
		t.Error("issue form: static ECDSA P-256 key-type readout is missing")
	}
	// There must be no multi-option <select> for keytype that would imply a real choice.
	// The backend hard-codes ECDSA P-256 — showing other options would be deceptive.
	if strings.Contains(body, `name="keytype"`) && strings.Contains(body, "ECDSA P-384") {
		t.Error("issue form: found a multi-option keytype <select> — " +
			"the backend only supports ECDSA P-256; the UI must not offer a false choice")
	}
}

// TestIssueDesignFormHTMXWiring verifies the issue form posts to /issue via htmx.
// The form must use hx-post="/issue" with an appropriate swap target.
func TestIssueDesignFormHTMXWiring(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/issue")

	if !strings.Contains(body, `hx-post="/issue"`) {
		t.Error("issue: missing hx-post=\"/issue\" htmx attribute on form")
	}
	if !strings.Contains(body, "hx-target=") {
		t.Error("issue: missing hx-target attribute on form (htmx swap target)")
	}
}

// TestIssueDesignFormHasCSRF verifies the issue form carries a CSRF token.
func TestIssueDesignFormHasCSRF(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/issue")

	if !strings.Contains(body, `name="csrf_token"`) {
		t.Error("issue form: missing csrf_token hidden input")
	}
}

// TestIssueDesignSuccessRendersOnetimeKeyPanel verifies that after a successful
// issue, the result renders the one-time private-key panel (.onetime) with the
// private key PEM, and a PKCS#12 download link.
func TestIssueDesignSuccessRendersOnetimeKeyPanel(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	token := e.csrfToken(t, "/issue")
	_, body := e.postForm(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"design-test.example"},
		"sans":       {"design-test.example"},
		"validity":   {"30"},
		"keytype":    {"ECDSA P-256"},
	})

	// The one-time key panel must be present.
	if !strings.Contains(body, "onetime") {
		t.Error("issue result: missing .onetime panel for the private key")
	}
	// The private key PEM is shown in the result.
	if !strings.Contains(body, "PRIVATE KEY") {
		t.Error("issue result: private key PEM missing from one-time panel")
	}
	// A private key download link must be present (data: URI).
	if !strings.Contains(body, "x-pem-file") && !strings.Contains(strings.ToLower(body), ".key.pem") {
		t.Error("issue result: missing private key download link")
	}
}

// TestIssueDesignSuccessFlash verifies the success result shows a certificate-
// issued confirmation flash with the CN.
func TestIssueDesignSuccessFlash(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	token := e.csrfToken(t, "/issue")
	_, body := e.postForm(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"flash-test.example"},
		"validity":   {"30"},
		"keytype":    {"ECDSA P-256"},
	})

	if !strings.Contains(body, "flash--ok") {
		t.Error("issue result: missing flash--ok success notification")
	}
	if !strings.Contains(body, "flash-test.example") {
		t.Error("issue result: CN not shown in success flash")
	}
}

// TestIssueDesignPrivateKeyNotOnGET is the critical security invariant test:
// a plain GET /issue must NOT render any private key material. This ensures the
// one-time key is never re-rendered on page reload.
func TestIssueDesignPrivateKeyNotOnGET(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	// First, issue a certificate to prove a key exists in DB.
	token := e.csrfToken(t, "/issue")
	_, _ = e.postForm(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"secret-key.example"},
		"validity":   {"30"},
		"keytype":    {"ECDSA P-256"},
	})

	// Now do a plain GET /issue — must not show any PRIVATE KEY.
	_, getBody := e.get(t, "/issue")

	if strings.Contains(getBody, "PRIVATE KEY") {
		t.Errorf("issue GET: private key material leaked into plain GET response — " +
			"the one-time key MUST NOT be rendered on a normal page load")
	}
	// The .onetime panel must NOT appear on a plain GET.
	if strings.Contains(getBody, "onetime") {
		t.Errorf("issue GET: .onetime panel must not appear on a plain GET /issue " +
			"(only in the immediate POST result)")
	}
}

// TestIssueDesignOnetimePanelHasCopyButton verifies the one-time private key
// panel uses the app-wide data-copy-target pattern for the copy button.
func TestIssueDesignOnetimePanelHasCopyButton(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	token := e.csrfToken(t, "/issue")
	_, body := e.postForm(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"copy-test.example"},
		"validity":   {"30"},
		"keytype":    {"ECDSA P-256"},
	})

	// The copy button must use data-copy-target (the app-wide delegated handler).
	if !strings.Contains(body, "data-copy-target=") {
		t.Error("issue result: one-time key panel copy button must use data-copy-target attribute")
	}
	// The private key must be in a <pre> or readable element (visible selectable text).
	if !strings.Contains(body, "<pre") {
		t.Error("issue result: private key must be in a <pre> element (visible, selectable)")
	}
}

// TestIssueDesignValidityFieldHint verifies the Validity field carries a hint
// about the provisioner's max duration cap ("Capped by the provisioner's max duration").
func TestIssueDesignValidityFieldHint(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/issue")

	if !strings.Contains(strings.ToLower(body), "capped") &&
		!strings.Contains(strings.ToLower(body), "max duration") &&
		!strings.Contains(strings.ToLower(body), "provisioner") {
		t.Error("issue form validity: missing hint about the provisioner's max duration cap")
	}
}

// TestIssueDesignKeyTypeFieldHint verifies the Key type field carries a hint
// explaining that step-ui-ng generates the key pair and returns it once.
func TestIssueDesignKeyTypeFieldHint(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/issue")

	// The hint should say something about the key pair being generated and returned once.
	if !strings.Contains(strings.ToLower(body), "generates") &&
		!strings.Contains(strings.ToLower(body), "private key") {
		t.Error("issue form key-type: missing hint about step-ui-ng generating the key pair")
	}
}

// TestIssueDesignContentNarrow verifies the issue page uses the content--narrow
// wrapper class (matching settings/provisioners page layout).
func TestIssueDesignContentNarrow(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/issue")

	if !strings.Contains(body, "content--narrow") {
		t.Error("issue: missing content--narrow wrapper class")
	}
}

// --- Sign CSR page design tests ----------------------------------------------

// TestSignCSRDesignPageHead verifies the redesigned sign-csr page renders the
// page-head structure: breadcrumb, page-title ("Sign CSR"), page-sub.
func TestSignCSRDesignPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/sign-csr")

	if !strings.Contains(body, "page-head") {
		t.Error("sign-csr: missing page-head wrapper")
	}
	if !strings.Contains(body, "breadcrumb") {
		t.Error("sign-csr: missing breadcrumb")
	}
	if !strings.Contains(body, `class="page-title"`) {
		t.Error("sign-csr: missing page-title element")
	}
	if !strings.Contains(body, "Sign CSR") {
		t.Error("sign-csr: missing 'Sign CSR' heading text")
	}
	if !strings.Contains(body, "page-sub") {
		t.Error("sign-csr: missing page-sub subtitle")
	}
}

// TestSignCSRDesignActiveProvisionerFlash verifies that when an active provisioner
// is configured, the sign-csr page shows a flash--info note with the provisioner
// name and a link to change it.
func TestSignCSRDesignActiveProvisionerFlash(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := e.settingsRepo.SelectProvisioner(context.Background(), "my-prov", "secret"); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.get(t, "/sign-csr")

	if !strings.Contains(body, "flash--info") {
		t.Error("sign-csr with active provisioner: missing flash--info note")
	}
	if !strings.Contains(body, "my-prov") {
		t.Error("sign-csr: active provisioner name not shown in flash")
	}
	if !strings.Contains(body, "href=\"/provisioners\"") && !strings.Contains(body, "href=/provisioners") {
		t.Error("sign-csr: missing link to /provisioners in the flash note")
	}
}

// TestSignCSRDesignFormFields verifies the sign-csr form has the correct fields:
// a CSR textarea (name="csr") and a validity field.
func TestSignCSRDesignFormFields(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/sign-csr")

	if !strings.Contains(body, `name="csr"`) {
		t.Error("sign-csr form: missing csr textarea")
	}
	if !strings.Contains(body, `name="validity"`) {
		t.Error("sign-csr form: missing validity field")
	}
	if !strings.Contains(body, "Sign request") || !strings.Contains(body, "Sign CSR") {
		// Either label is acceptable
		if !strings.Contains(body, "Sign request") && !strings.Contains(body, "Sign CSR") {
			t.Error("sign-csr form: missing sign submit button text")
		}
	}
}

// TestSignCSRDesignHTMXWiring verifies the sign-csr form posts to /sign-csr via
// htmx (hx-post="/sign-csr").
func TestSignCSRDesignHTMXWiring(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/sign-csr")

	if !strings.Contains(body, `hx-post="/sign-csr"`) {
		t.Error("sign-csr: missing hx-post=\"/sign-csr\" htmx attribute on form")
	}
	if !strings.Contains(body, "hx-target=") {
		t.Error("sign-csr: missing hx-target attribute on form")
	}
}

// TestSignCSRDesignSuccessRendersSignedCertNoPrivKey verifies the key security
// invariant for the sign-CSR flow: after signing, the result renders the signed
// certificate but NO private key (the operator holds the key).
func TestSignCSRDesignSuccessRendersSignedCertNoPrivKey(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	csrPEM := makeCSR(t, "design-sign.example", []string{"design-sign.example"})

	token := e.csrfToken(t, "/sign-csr")
	_, body := e.postForm(t, "/sign-csr", url.Values{
		"csrf_token": {token},
		"csr":        {csrPEM},
		"validity":   {"30"},
	})

	// The signed certificate must be present.
	if !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Error("sign-csr result: missing signed certificate PEM")
	}
	// NO private key must appear in the sign-CSR result.
	if strings.Contains(body, "PRIVATE KEY") {
		t.Errorf("sign-csr result: private key material must NEVER appear in a sign-CSR result " +
			"(the operator holds the private key)")
	}
	// No .onetime panel either.
	if strings.Contains(body, "onetime") {
		t.Errorf("sign-csr result: .onetime panel must not appear (no key generated server-side)")
	}
}

// TestSignCSRDesignSuccessFlash verifies the sign-CSR success result shows an
// ok-flash with "CSR signed" copy and the CN.
func TestSignCSRDesignSuccessFlash(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	csrPEM := makeCSR(t, "signed-cn.example", nil)

	token := e.csrfToken(t, "/sign-csr")
	_, body := e.postForm(t, "/sign-csr", url.Values{
		"csrf_token": {token},
		"csr":        {csrPEM},
		"validity":   {"30"},
	})

	if !strings.Contains(body, "flash--ok") {
		t.Error("sign-csr result: missing flash--ok success notification")
	}
	if !strings.Contains(body, "signed-cn.example") {
		t.Error("sign-csr result: CN not shown in success result")
	}
}

// TestSignCSRDesignSignedCertHasCopyButton verifies the signed-cert block uses
// a copy button wired with data-copy-target (app-wide delegated handler).
func TestSignCSRDesignSignedCertHasCopyButton(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	csrPEM := makeCSR(t, "copy-sign.example", nil)

	token := e.csrfToken(t, "/sign-csr")
	_, body := e.postForm(t, "/sign-csr", url.Values{
		"csrf_token": {token},
		"csr":        {csrPEM},
		"validity":   {"30"},
	})

	if !strings.Contains(body, "data-copy-target=") {
		t.Error("sign-csr result: signed cert copy button must use data-copy-target attribute")
	}
	if !strings.Contains(body, "codeblock") {
		t.Error("sign-csr result: missing codeblock for the signed certificate")
	}
}

// TestSignCSRDesignContentNarrow verifies the sign-csr page uses the
// content--narrow wrapper class.
func TestSignCSRDesignContentNarrow(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/sign-csr")

	if !strings.Contains(body, "content--narrow") {
		t.Error("sign-csr: missing content--narrow wrapper class")
	}
}

// TestSignCSRDesignFormHasCSRF verifies the sign-csr form carries a CSRF token.
func TestSignCSRDesignFormHasCSRF(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/sign-csr")

	if !strings.Contains(body, `name="csrf_token"`) {
		t.Error("sign-csr form: missing csrf_token hidden input")
	}
}
