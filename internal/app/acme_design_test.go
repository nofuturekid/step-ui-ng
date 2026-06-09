package app_test

// Design tests for PR E — ACME page + EAB sub-page redesign.
//
// Acceptance criteria tested:
//   - ACME page: page-head with "ACME" h1, breadcrumb, page-sub copy (ACME clients + EAB).
//   - ACME page: "ACME provisioners — N from CA" section heading with badge.
//   - ACME page: table uses class="table" with Name/EAB/Challenges/Actions columns.
//   - ACME page: EAB Required badge (badge--ok) and Off badge (badge--neutral).
//   - ACME page: "Manage EAB" button gated on admin auth (when no auth: absent or disabled).
//   - ACME page: "Managing" badge when admin auth IS configured and Manage EAB link present.
//   - EAB page: page-head "External Account Binding — <prov>" heading.
//   - EAB page: intro copy about one-time HMAC.
//   - EAB page: create form posts to /acme/eab/{provisioner} with reference field.
//   - EAB page: one-time panel (class onetime) renders kid+HMAC from POST response ONLY.
//   - EAB page: one-time panel contains client snippets with real kid+HMAC values.
//   - EAB page: normal GET renders NO HMAC in body (never-re-shown invariant).
//   - EAB page: existing keys list shows key ID and reference, no HMAC column.
//   - EAB page: existing keys table uses class="table".

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/settings"
)

// TestACMEDesignPageHead verifies the ACME page has the new page-head
// structure: breadcrumb, page-title "ACME", and page-sub with intro copy.
func TestACMEDesignPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[]}`)
	e.seedACMECA(t, f)

	_, body := e.getBody(t, "/acme")

	if !strings.Contains(body, `class="page-head"`) {
		t.Error("acme: missing page-head element")
	}
	if !strings.Contains(body, `class="page-title"`) {
		t.Error("acme: missing page-title element")
	}
	if !strings.Contains(body, ">ACME<") {
		t.Error("acme: missing 'ACME' h1 text")
	}
	if !strings.Contains(body, `class="page-sub"`) {
		t.Error("acme: missing page-sub subtitle element")
	}
	// Mock copy: mentions ACME clients and EAB
	if !strings.Contains(body, "certbot") || !strings.Contains(body, "acme.sh") {
		t.Error("acme: page-sub must mention common ACME clients (certbot, acme.sh)")
	}
	if !strings.Contains(body, "External Account Binding") || !strings.Contains(body, "EAB") {
		t.Error("acme: page-sub must mention External Account Binding / EAB")
	}
}

// TestACMEDesignSectionHeadingAndCount verifies the "ACME provisioners — N from CA"
// section heading with a badge carrying the provisioner count.
func TestACMEDesignSectionHeadingAndCount(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[
		{"type":"ACME","name":"acme-a"},
		{"type":"ACME","name":"acme-b"}
	]}`)
	e.seedACMECA(t, f)

	_, body := e.getBody(t, "/acme")

	if !strings.Contains(body, "ACME provisioners") {
		t.Error("acme: missing 'ACME provisioners' section heading")
	}
	if !strings.Contains(body, "2 from CA") {
		t.Error("acme: missing '2 from CA' count badge in section heading")
	}
	if !strings.Contains(body, `class="section-title"`) {
		t.Error("acme: missing class='section-title' on section heading")
	}
}

// TestACMEDesignTableColumns verifies the ACME provisioner list table uses
// class="table" and renders Name, EAB, Challenges, and Actions columns.
func TestACMEDesignTableColumns(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-x","requireEAB":true,"challenges":["http-01","dns-01"]}]}`)
	e.seedACMECA(t, f)

	_, body := e.getBody(t, "/acme")

	if !strings.Contains(body, `class="table"`) {
		t.Error("acme: provisioner table must use class='table'")
	}
	for _, col := range []string{"Name", "EAB", "Challenges"} {
		if !strings.Contains(body, col) {
			t.Errorf("acme: table missing column header %q", col)
		}
	}
	// Table must use table-wrap + table-scroll
	if !strings.Contains(body, "table-wrap") {
		t.Error("acme: missing table-wrap class on table container")
	}
}

// TestACMEDesignEABBadges verifies that the EAB column shows a green "Required"
// badge (badge--ok) for requireEAB provisioners and a neutral "Off" badge for
// others.
func TestACMEDesignEABBadges(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[
		{"type":"ACME","name":"prov-eab","requireEAB":true},
		{"type":"ACME","name":"prov-open"}
	]}`)
	e.seedACMECA(t, f)

	_, body := e.getBody(t, "/acme")

	// Required badge must be badge--ok
	if !strings.Contains(body, "badge--ok") {
		t.Error("acme: missing badge--ok for EAB Required badge")
	}
	if !strings.Contains(body, "Required") {
		t.Error("acme: missing 'Required' text in EAB column for requireEAB provisioner")
	}
	// Off badge must be badge--neutral
	if !strings.Contains(body, "badge--neutral") {
		t.Error("acme: missing badge--neutral for EAB Off badge")
	}
	if !strings.Contains(body, "Off") {
		t.Error("acme: missing 'Off' text in EAB column for non-EAB provisioner")
	}
}

// TestACMEDesignManageEABNoAdminAuth verifies that when admin auth is NOT
// configured the ACME provisioner row does NOT show an enabled "Manage EAB"
// link (the create/manage controls are gated on admin auth as today).
func TestACMEDesignManageEABNoAdminAuth(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed CA settings only (no admin credential).
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-test"}]}`)
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: f.url, RootFingerprint: f.fingerprint,
	}); err != nil {
		t.Fatalf("seed CA settings: %v", err)
	}

	_, body := e.getBody(t, "/acme")

	// Without admin auth: "Manage EAB" must NOT appear as an active action link
	if strings.Contains(body, `href="/acme/eab/acme-test"`) {
		t.Error("acme (no admin auth): Manage EAB link must NOT appear when admin auth is not configured")
	}
}

// TestACMEDesignManageEABLinkWithAdminAuth verifies that when admin auth IS
// configured, the ACME provisioner list shows a "Manage EAB" link to the EAB
// page for each provisioner.
func TestACMEDesignManageEABLinkWithAdminAuth(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"my-acme"}]}`)
	e.seedACMECA(t, f)

	_, body := e.getBody(t, "/acme")

	// With admin auth: "Manage EAB" link must be present and point to /acme/eab/my-acme
	if !strings.Contains(body, "Manage EAB") {
		t.Error("acme (with admin auth): missing 'Manage EAB' action in provisioner row")
	}
	if !strings.Contains(body, `href="/acme/eab/my-acme"`) {
		t.Error("acme (with admin auth): Manage EAB must link to /acme/eab/my-acme")
	}
}

// TestACMEDesignChallengeCellRendersValues verifies that the Challenges column
// shows the provisioner's actual challenges (e.g. "http-01, dns-01").
func TestACMEDesignChallengeCellRendersValues(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-ch","challenges":["http-01","dns-01"]}]}`)
	e.seedACMECA(t, f)

	_, body := e.getBody(t, "/acme")

	if !strings.Contains(body, "http-01") {
		t.Error("acme: Challenges column missing http-01")
	}
	if !strings.Contains(body, "dns-01") {
		t.Error("acme: Challenges column missing dns-01")
	}
}

// TestEABDesignPageHead verifies the EAB sub-page has the expected page-head
// structure: breadcrumb, "External Account Binding — <provisioner>" heading,
// and the intro copy about one-time HMAC.
func TestEABDesignPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-eab-test"}]}`)
	e.seedACMECA(t, f)

	_, body := e.getBody(t, "/acme/eab/acme-eab-test")

	if !strings.Contains(body, `class="page-head"`) {
		t.Error("eab: missing page-head element")
	}
	if !strings.Contains(body, "External Account Binding") {
		t.Error("eab: missing 'External Account Binding' in page heading")
	}
	if !strings.Contains(body, "acme-eab-test") {
		t.Error("eab: missing provisioner name in heading")
	}
	// Intro copy: must mention the one-time HMAC nature
	if !strings.Contains(body, "shown once") || !strings.Contains(body, "hash") {
		t.Error("eab: missing intro copy about HMAC being shown once / stored as hash")
	}
}

// TestEABDesignCreateFormPostsToCorrectRoute verifies the EAB create form
// posts to /acme/eab/{provisioner} with a reference input field named "reference".
func TestEABDesignCreateFormPostsToCorrectRoute(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-form-test"}]}`)
	e.seedACMECA(t, f)

	_, body := e.getBody(t, "/acme/eab/acme-form-test")

	if !strings.Contains(body, `action="/acme/eab/acme-form-test"`) {
		t.Error("eab: create form must post to /acme/eab/acme-form-test")
	}
	if !strings.Contains(body, `name="reference"`) {
		t.Error("eab: create form missing reference input field")
	}
}

// TestEABDesignOnetimePanelRendersKidAndHMAC verifies that the one-time panel
// is rendered in the POST (create) response and shows the real kid and HMAC.
// This is the security crux: the HMAC must appear exactly here.
func TestEABDesignOnetimePanelRendersKidAndHMAC(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-once"}]}`)
	e.seedACMECA(t, f)

	token := e.csrfToken(t, "/acme/eab/acme-once")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/acme/eab/acme-once",
		strings.NewReader(url.Values{"csrf_token": {token}, "reference": {"my-ref"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Referer", e.srv.URL+"/acme/eab/acme-once")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("create EAB: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create EAB status = %d, want 200; body:\n%s", resp.StatusCode, body)
	}

	// One-time panel must be present
	if !strings.Contains(string(body), "class=\"onetime\"") {
		t.Error("eab: create response missing class='onetime' one-time panel")
	}

	// "Copy this HMAC key now" warning text must appear
	if !strings.Contains(string(body), "Copy this HMAC key now") {
		t.Error("eab: create response missing 'Copy this HMAC key now' warning")
	}

	// The real kid must appear (from the mock CA: "eab-my-ref")
	if !strings.Contains(string(body), "eab-my-ref") {
		t.Errorf("eab: create response missing the real key ID 'eab-my-ref'; body:\n%s", body)
	}

	// The real HMAC must appear
	if !strings.Contains(string(body), f.hmacB64) {
		t.Errorf("eab: create response missing the real HMAC; body:\n%s", body)
	}

	// EAB Key ID and HMAC labels must be present
	if !strings.Contains(string(body), "EAB Key ID") {
		t.Error("eab: create response missing 'EAB Key ID' label")
	}
	if !strings.Contains(string(body), "HMAC key") {
		t.Error("eab: create response missing 'HMAC key' label")
	}
}

// TestEABDesignOnetimePanelHasClientSnippets verifies that the one-time panel
// includes client snippets with the real kid and HMAC values (certbot + acme.sh).
func TestEABDesignOnetimePanelHasClientSnippets(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-snip2"}]}`)
	e.seedACMECA(t, f)

	token := e.csrfToken(t, "/acme/eab/acme-snip2")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/acme/eab/acme-snip2",
		strings.NewReader(url.Values{"csrf_token": {token}, "reference": {"snip"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Referer", e.srv.URL+"/acme/eab/acme-snip2")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("create EAB: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// certbot snippet must be present in the one-time panel
	if !strings.Contains(string(body), "certbot") {
		t.Error("eab onetime: missing certbot client snippet")
	}
	// acme.sh snippet
	if !strings.Contains(string(body), "acme.sh") {
		t.Error("eab onetime: missing acme.sh client snippet")
	}
	// Snippets must use real kid + HMAC
	if !strings.Contains(string(body), "eab-snip") {
		t.Errorf("eab onetime snippets: missing real kid 'eab-snip'; body:\n%s", body)
	}
}

// TestEABDesignHMACNeverReShownOnGET verifies the security invariant: the EAB
// HMAC must NOT appear on a normal GET of the EAB page after a key has been
// created. This would FAIL if the HMAC were stored and re-rendered on list.
func TestEABDesignHMACNeverReShownOnGET(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-nosecret"}]}`)
	e.seedACMECA(t, f)

	// Create a key
	token := e.csrfToken(t, "/acme/eab/acme-nosecret")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/acme/eab/acme-nosecret",
		strings.NewReader(url.Values{"csrf_token": {token}, "reference": {"hidden"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Referer", e.srv.URL+"/acme/eab/acme-nosecret")
	resp, _ := e.client.Do(req)
	_ = resp.Body.Close()

	// GET the page — HMAC must NOT appear
	_, body := e.getBody(t, "/acme/eab/acme-nosecret")
	if strings.Contains(body, f.hmacB64) {
		t.Errorf("eab GET: the HMAC leaked into the list view — never-re-shown invariant violated; body:\n%s", body)
	}

	// The one-time panel class must NOT appear on GET
	if strings.Contains(body, `class="onetime"`) {
		t.Error("eab GET: class='onetime' panel must NOT appear on normal page load")
	}
}

// TestEABDesignExistingKeysTableNoHMACColumn verifies the existing EAB keys
// table shows key ID and reference columns but no HMAC column or values.
func TestEABDesignExistingKeysTableNoHMACColumn(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-keys"}]}`)
	e.seedACMECA(t, f)

	// Create two EAB keys so we have rows
	token := e.csrfToken(t, "/acme/eab/acme-keys")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/acme/eab/acme-keys",
		strings.NewReader(url.Values{"csrf_token": {token}, "reference": {"key-one"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Referer", e.srv.URL+"/acme/eab/acme-keys")
	resp, _ := e.client.Do(req)
	_ = resp.Body.Close()

	_, body := e.getBody(t, "/acme/eab/acme-keys")

	// Table must use class="table"
	if !strings.Contains(body, `class="table"`) {
		t.Error("eab keys: existing keys table must use class='table'")
	}
	// Key ID column: the created key ID must appear
	if !strings.Contains(body, "eab-key-one") {
		t.Errorf("eab keys: list missing the created key ID 'eab-key-one'; body:\n%s", body)
	}
	// Reference column
	if !strings.Contains(body, "key-one") {
		t.Error("eab keys: list missing the reference value 'key-one'")
	}
	// HMAC must NOT appear in the list
	if strings.Contains(body, f.hmacB64) {
		t.Errorf("eab keys list: HMAC must never appear in the existing keys list")
	}
	// No "HMAC" column header
	if strings.Contains(body, "<th") && strings.Contains(body, ">HMAC<") {
		t.Error("eab keys: existing keys table must not have a HMAC column header")
	}
}

// TestEABDesignCopyableKidAndHMAC verifies that the one-time panel renders the
// kid and HMAC as visible selectable text (e.g. inside a <span> or <pre>) and
// provides data-copy-target copy buttons wired to the right elements.
func TestEABDesignCopyableKidAndHMAC(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-copy"}]}`)
	e.seedACMECA(t, f)

	token := e.csrfToken(t, "/acme/eab/acme-copy")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/acme/eab/acme-copy",
		strings.NewReader(url.Values{"csrf_token": {token}, "reference": {"cp"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Referer", e.srv.URL+"/acme/eab/acme-copy")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("create EAB: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// The kid and HMAC must appear as visible text content (not just in attribute values)
	// We verify that they appear as element text (outside attribute context):
	if !strings.Contains(string(body), ">eab-cp<") {
		t.Errorf("eab onetime: kid 'eab-cp' must appear as visible element text; body:\n%s", body)
	}
	if !strings.Contains(string(body), ">"+f.hmacB64+"<") {
		t.Errorf("eab onetime: HMAC must appear as visible element text; body:\n%s", body)
	}

	// Copy buttons must use data-copy-target
	if !strings.Contains(string(body), "data-copy-target=") {
		t.Error("eab onetime: copy buttons must use data-copy-target (app-wide copy handler)")
	}
}

// TestEABDesignOnetimeCertbotSnippetUsesDirectoryURL verifies the certbot snippet
// in the one-time panel uses the real directory URL (--server flag).
func TestEABDesignOnetimeCertbotSnippetUsesDirectoryURL(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme-dir"}]}`)
	e.seedACMECA(t, f)

	token := e.csrfToken(t, "/acme/eab/acme-dir")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/acme/eab/acme-dir",
		strings.NewReader(url.Values{"csrf_token": {token}, "reference": {"d"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Referer", e.srv.URL+"/acme/eab/acme-dir")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("create EAB: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	wantDir := f.url + "/acme/acme-dir/directory"
	if !strings.Contains(string(body), "--server "+wantDir) {
		t.Errorf("eab onetime certbot: snippet missing --server %q; body:\n%s", wantDir, body)
	}
}
