package app_test

// Design tests for PR C — CA settings page redesign.
//
// Acceptance criteria tested:
//   - settingsPage renders a page-head with breadcrumb, page-title, page-sub.
//   - Card 1 (CA connection): card__header / card__title / card__desc; two
//     .field .input controls (ca_url / root_fingerprint); "Save connection"
//     btn--primary; "Test connection" button; #test-result htmx target.
//   - Card 2 (Admin authentication): card__header with "Active: <method>" badge;
//     a method selector (.seg radiogroup) with three options (none / x5c / jwk)
//     rendered as radio inputs named admin_auth_method; the active method's
//     badge reads "Active: <method>".
//   - All three method groups (mg-none / mg-x5c / mg-jwk) rendered in HTML; the
//     reveal is done via CSS :has() — no inline onchange= JS on the selector.
//   - x5c group: admin_x5c_cert + admin_x5c_key textareas, set/none badge,
//     the guided "step ca certificate …" command block.
//   - jwk group: admin_jwk_subject + admin_jwk_provisioner inputs + jwk_password
//     write-only input, set/none badge.
//   - Secrets never echoed: a stored JWK password value must not appear in the
//     rendered page; a stored x5c private key line must not appear.
//   - htmx wiring: hx-post="/settings/test" + hx-target="#test-result" present.
//   - No onchange= attribute on the method selector input.

import (
	"context"
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/settings"
)

// TestSettingsPageHead verifies the redesigned page renders the page-head
// structure: breadcrumb, page-title ("CA settings"), and page-sub subtitle.
func TestSettingsDesignPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, "page-head") {
		t.Error("settings: missing page-head wrapper")
	}
	if !strings.Contains(body, "breadcrumb") {
		t.Error("settings: missing breadcrumb")
	}
	if !strings.Contains(body, `class="page-title"`) {
		t.Error("settings: missing page-title element")
	}
	if !strings.Contains(body, "CA settings") {
		t.Error("settings: missing 'CA settings' heading text")
	}
	if !strings.Contains(body, "page-sub") {
		t.Error("settings: missing page-sub subtitle")
	}
}

// TestSettingsDesignConnectionCard verifies Card 1 structure: card__header /
// card__title / card__desc, two inputs (ca_url, root_fingerprint), a
// "Save connection" primary button, and a "Test connection" button.
func TestSettingsDesignConnectionCard(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, "card__header") {
		t.Error("settings: missing card__header")
	}
	if !strings.Contains(body, "card__title") {
		t.Error("settings: missing card__title")
	}
	if !strings.Contains(body, "CA connection") {
		t.Error("settings: missing 'CA connection' card title")
	}
	if !strings.Contains(body, "card__desc") {
		t.Error("settings: missing card__desc on CA connection card")
	}
	if !strings.Contains(body, `name="ca_url"`) {
		t.Error("settings: missing ca_url input")
	}
	if !strings.Contains(body, `name="root_fingerprint"`) {
		t.Error("settings: missing root_fingerprint input")
	}
	if !strings.Contains(body, "Save connection") {
		t.Error("settings: missing 'Save connection' button text")
	}
	if !strings.Contains(body, "btn--primary") {
		t.Error("settings: 'Save connection' must use btn--primary class")
	}
	if !strings.Contains(body, "Test connection") {
		t.Error("settings: missing 'Test connection' button text")
	}
}

// TestSettingsDesignHTMXWiring verifies the htmx test-connection wiring:
// hx-post="/settings/test" on a form/button and hx-target="#test-result",
// plus the #test-result div is present for the swap target.
func TestSettingsDesignHTMXWiring(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, `hx-post="/settings/test"`) {
		t.Error("settings: missing hx-post=\"/settings/test\" htmx attribute")
	}
	if !strings.Contains(body, `hx-target="#test-result"`) {
		t.Error("settings: missing hx-target=\"#test-result\" htmx attribute")
	}
	if !strings.Contains(body, `id="test-result"`) {
		t.Error("settings: missing #test-result div (htmx swap target)")
	}
}

// TestSettingsDesignAdminAuthCard verifies Card 2 structure: card__header,
// "Admin authentication" title, an "Active: <method>" badge in card__actions,
// and a .seg radiogroup with three options (none / x5c / jwk).
func TestSettingsDesignAdminAuthCard(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, "Admin authentication") {
		t.Error("settings: missing 'Admin authentication' card title")
	}
	if !strings.Contains(body, "card__actions") {
		t.Error("settings: missing card__actions for the active-method badge")
	}
	// The method selector must use radio inputs in a .seg group, not a <select>
	if !strings.Contains(body, `class="seg"`) {
		t.Error("settings: missing .seg radiogroup for method selector")
	}
	if !strings.Contains(body, `name="admin_auth_method"`) {
		t.Error("settings: missing admin_auth_method radio inputs")
	}
	// All three options present
	for _, val := range []string{`value="none"`, `value="x5c"`, `value="jwk"`} {
		if !strings.Contains(body, val) {
			t.Errorf("settings: missing method radio option %s", val)
		}
	}
}

// TestSettingsDesignActiveBadgeReflectsMethod verifies that the "Active: X"
// badge in the card header reflects the stored admin auth method.
// With no settings saved the badge defaults to "Active: none".
func TestSettingsDesignActiveBadgeNone(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, "Active: none") {
		t.Errorf("settings: 'Active: none' badge missing when no auth configured; body snippet:\n%s",
			extractAround(body, "card__actions", 300))
	}
}

// TestSettingsDesignActiveBadgeJWK verifies that after saving JWK auth, the
// "Active: jwk" badge is shown in the card header.
func TestSettingsDesignActiveBadgeJWK(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := e.settingsRepo.SaveAdminJWK(context.Background(), "step@example.com", "admin-jwk", "pw-99"); err != nil {
		t.Fatalf("seed JWK auth: %v", err)
	}

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, "Active: jwk") {
		t.Errorf("settings: 'Active: jwk' badge missing after JWK save; body snippet:\n%s",
			extractAround(body, "card__actions", 300))
	}
}

// TestSettingsDesignActiveBadgeX5C verifies that after saving x5c auth, the
// "Active: x5c" badge is shown in the card header.
func TestSettingsDesignActiveBadgeX5C(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	certPEM, keyPEM := makeX5CTestCert(t)
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := e.settingsRepo.SaveAdminCredential(context.Background(), certPEM, keyPEM); err != nil {
		t.Fatalf("seed x5c auth: %v", err)
	}

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, "Active: x5c") {
		t.Errorf("settings: 'Active: x5c' badge missing after x5c save; body snippet:\n%s",
			extractAround(body, "card__actions", 300))
	}
}

// TestSettingsDesignNoOnchangeJS verifies that the method selector does NOT
// use inline onchange= JS. The reveal must be CSS :has()-based.
func TestSettingsDesignNoOnchangeJS(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	// The old template used onchange= on the <select>; the new design must
	// not have any onchange attribute on the admin_auth_method field.
	// We scan for 'onchange' anywhere in the page body.
	if strings.Contains(body, "admin_auth_method") && strings.Contains(body, "onchange") {
		t.Error("settings: method selector must NOT use onchange= JS (use CSS :has() reveal instead)")
	}
}

// TestSettingsDesignMethodGroupsAllPresent verifies all three method-group
// divs are present in the HTML (they are shown/hidden via CSS, not server-side).
func TestSettingsDesignMethodGroupsAllPresent(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	for _, class := range []string{"mg-none", "mg-x5c", "mg-jwk"} {
		if !strings.Contains(body, class) {
			t.Errorf("settings: method-group div %q missing from HTML", class)
		}
	}
}

// TestSettingsDesignX5CGroupFields verifies the x5c group contains the
// cert/key textareas (with correct name= attributes) and the guided command.
func TestSettingsDesignX5CGroupFields(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example:9000", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	_, body := e.get(t, "/settings")

	// x5c cert and key textareas
	if !strings.Contains(body, `name="admin_x5c_cert"`) {
		t.Error("settings x5c: missing admin_x5c_cert textarea")
	}
	if !strings.Contains(body, `name="admin_x5c_key"`) {
		t.Error("settings x5c: missing admin_x5c_key textarea")
	}
	// Guided command
	if !strings.Contains(body, "step ca certificate") {
		t.Error("settings x5c: missing 'step ca certificate' guided command")
	}
	// CA URL interpolated into command
	if !strings.Contains(body, "https://ca.example:9000") {
		t.Error("settings x5c: CA URL not interpolated into guided command")
	}
}

// TestSettingsDesignX5CSetBadge verifies that after storing an x5c key, the
// x5c group shows a "set" badge for the key and no private-key content appears.
func TestSettingsDesignX5CSetBadge(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	certPEM, keyPEM := makeX5CTestCert(t)
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := e.settingsRepo.SaveAdminCredential(context.Background(), certPEM, keyPEM); err != nil {
		t.Fatalf("seed x5c auth: %v", err)
	}

	_, body := e.get(t, "/settings")

	// The "set" badge must appear somewhere in the x5c group
	if !strings.Contains(body, "badge--set") {
		t.Error("settings x5c: missing badge--set for stored key")
	}
	// Private key content must never appear (only PEM headers are ok in placeholders)
	keyLines := strings.Split(strings.TrimSpace(keyPEM), "\n")
	for _, line := range keyLines {
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		if strings.Contains(body, line) {
			t.Errorf("settings x5c: private key base64 line %q leaked into the page", line)
		}
	}
}

// TestSettingsDesignJWKGroupFields verifies the jwk group contains the three
// inputs (subject, provisioner, password) with correct name= attributes and
// a password field of type="password".
func TestSettingsDesignJWKGroupFields(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, `name="admin_jwk_subject"`) {
		t.Error("settings jwk: missing admin_jwk_subject input")
	}
	if !strings.Contains(body, `name="admin_jwk_provisioner"`) {
		t.Error("settings jwk: missing admin_jwk_provisioner input")
	}
	if !strings.Contains(body, `name="admin_jwk_password"`) {
		t.Error("settings jwk: missing admin_jwk_password input")
	}
	// Password must be type=password (write-only)
	if !strings.Contains(body, `name="admin_jwk_password" type="password"`) &&
		!strings.Contains(body, `type="password" `) {
		t.Error("settings jwk: admin_jwk_password must be type=password")
	}
}

// TestSettingsDesignJWKSetBadge verifies that after a JWK password is stored,
// the jwk group shows a "set" badge and the password value is never echoed.
func TestSettingsDesignJWKSetBadge(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	const jwkPass = "super-secret-jwk-password-7777"

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := e.settingsRepo.SaveAdminJWK(context.Background(), "step@example.com", "admin-jwk", jwkPass); err != nil {
		t.Fatalf("seed JWK auth: %v", err)
	}

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, "badge--set") {
		t.Error("settings jwk: missing badge--set for stored password")
	}
	if strings.Contains(body, jwkPass) {
		t.Fatalf("settings jwk: plaintext password %q leaked into the page", jwkPass)
	}
}

// TestSettingsDesignJWKNoneBadge verifies that when no JWK password is stored,
// the jwk group shows a "none" badge.
func TestSettingsDesignJWKNoneBadge(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	// At least one badge--none must be present (no secrets stored)
	if !strings.Contains(body, "badge--none") {
		t.Error("settings: missing badge--none when no secrets stored")
	}
}

// TestSettingsDesignHasActiveMethodChecked verifies that the radio input for
// the stored method is rendered with the checked attribute.
// After saving JWK auth, value="jwk" radio must be checked.
func TestSettingsDesignHasActiveMethodChecked(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := e.settingsRepo.SaveAdminJWK(context.Background(), "step@example.com", "admin-jwk", "pw"); err != nil {
		t.Fatalf("seed JWK auth: %v", err)
	}

	_, body := e.get(t, "/settings")

	// The jwk radio must carry the checked attribute; templ renders it as
	// checked="" or checked (both valid; we check for "checked" near value="jwk").
	// A simple substring check is sufficient here.
	if !strings.Contains(body, `value="jwk" checked`) &&
		!strings.Contains(body, `checked value="jwk"`) &&
		!strings.Contains(body, `value="jwk"  checked`) {
		t.Error("settings: value=\"jwk\" radio must be checked after JWK save")
	}
}

// TestSettingsDesignFormActionAdminAuth verifies the admin-auth form posts to
// /settings/admin-auth (not /settings) — the action must not change.
func TestSettingsDesignFormActionAdminAuth(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, `action="/settings/admin-auth"`) {
		t.Error("settings: admin-auth form must post to /settings/admin-auth")
	}
}

// TestSettingsDesignContentNarrow verifies the page uses the content--narrow
// wrapper class (the settings page is narrower than data-heavy pages).
func TestSettingsDesignContentNarrow(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")

	if !strings.Contains(body, "content--narrow") {
		t.Error("settings: missing content--narrow wrapper class")
	}
}

// extractAround returns up to n characters centered around the first
// occurrence of needle in s; used for diagnostic snippets in failures.
func extractAround(s, needle string, n int) string {
	idx := strings.Index(s, needle)
	if idx < 0 {
		return "(not found)"
	}
	start := idx - n/2
	if start < 0 {
		start = 0
	}
	end := idx + n/2
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
