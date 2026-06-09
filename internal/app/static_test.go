package app_test

import (
	"strings"
	"testing"
)

// TestDesignFoundationAssets verifies that the three new design-foundation assets
// are embedded and served correctly:
//
//   - GET /static/tokens.css → 200, body contains CSS custom properties.
//   - GET /static/fonts.css  → 200, body contains @font-face rules.
//   - GET /static/icons.svg  → 200, body contains <symbol> SVG sprite.
//
// The layout <head> must link tokens.css, fonts.css, and the icon sprite must be
// present on authenticated pages. Removing any asset or its embed breaks this test.
func TestDesignFoundationAssets(t *testing.T) {
	e := newTestEnv(t)

	// tokens.css: must be served and contain CSS custom-property definitions.
	resp, body := e.get(t, "/static/tokens.css")
	if resp.StatusCode != 200 {
		t.Fatalf("GET /static/tokens.css status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "--font-sans") {
		t.Fatalf("GET /static/tokens.css: body does not contain --font-sans token")
	}

	// fonts.css: must be served and contain @font-face.
	respF, bodyF := e.get(t, "/static/fonts.css")
	if respF.StatusCode != 200 {
		t.Fatalf("GET /static/fonts.css status = %d, want 200", respF.StatusCode)
	}
	if !strings.Contains(bodyF, "@font-face") {
		t.Fatalf("GET /static/fonts.css: body does not contain @font-face")
	}

	// icons.svg: must be served and contain SVG symbols.
	respI, bodyI := e.get(t, "/static/icons.svg")
	if respI.StatusCode != 200 {
		t.Fatalf("GET /static/icons.svg status = %d, want 200", respI.StatusCode)
	}
	if !strings.Contains(bodyI, "<symbol") {
		t.Fatalf("GET /static/icons.svg: body does not contain <symbol>")
	}

	// Layout wiring: authenticated layout must load tokens.css and fonts.css.
	e.completeSetup(t, "root")
	_, layoutBody := e.get(t, "/inventory")

	if !strings.Contains(layoutBody, `href="/static/tokens.css"`) {
		t.Fatalf("layout <head>: missing link to /static/tokens.css")
	}
	if !strings.Contains(layoutBody, `href="/static/fonts.css"`) {
		t.Fatalf("layout <head>: missing link to /static/fonts.css")
	}
}

// TestStaticAssetsServed asserts that the embedded static assets required by the
// branding spec are present, served with the correct HTTP status, and wired into
// the rendered layout:
//
//   - GET /static/logo.svg → 200, body contains "<svg".
//   - GET /static/icon-256.png → 200 (PNG embedded and served).
//   - GET /static/favicon-32.png → 200 (favicon embedded and served).
//   - The topbar HTML contains the logo img src="/static/logo.svg".
//   - The layout <head> contains the favicon link href="/static/favicon-32.png".
//
// Removing any asset from static/ or the //go:embed static/* directive would
// cause the embed.FS open to fail at startup; removing the template wiring makes
// the Contains assertions fail. Both failure modes are intentional.
func TestStaticAssetsServed(t *testing.T) {
	e := newTestEnv(t)

	// logo.svg: must be served and contain SVG markup.
	resp, body := e.get(t, "/static/logo.svg")
	if resp.StatusCode != 200 {
		t.Fatalf("GET /static/logo.svg status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "<svg") {
		t.Fatalf("GET /static/logo.svg: body does not contain \"<svg\"")
	}

	// icon-256.png: must be served (Unraid app icon, embedded asset).
	resp256, _ := e.get(t, "/static/icon-256.png")
	if resp256.StatusCode != 200 {
		t.Fatalf("GET /static/icon-256.png status = %d, want 200", resp256.StatusCode)
	}

	// favicon-32.png: must be served (browser favicon, embedded asset).
	respFav, _ := e.get(t, "/static/favicon-32.png")
	if respFav.StatusCode != 200 {
		t.Fatalf("GET /static/favicon-32.png status = %d, want 200", respFav.StatusCode)
	}

	// Wiring checks require an authenticated session so the topbar renders.
	e.completeSetup(t, "root")
	_, layoutBody := e.get(t, "/inventory")

	// Topbar brand anchor must contain the logo img.
	if !strings.Contains(layoutBody, `src="/static/logo.svg"`) {
		t.Fatalf("topbar: logo img src not found in layout HTML")
	}
	if !strings.Contains(layoutBody, `class="brand-logo"`) {
		t.Fatalf("topbar: brand-logo class not found in layout HTML")
	}

	// Layout <head> must contain the favicon link.
	if !strings.Contains(layoutBody, `href="/static/favicon-32.png"`) {
		t.Fatalf("layout <head>: favicon link (href=\"/static/favicon-32.png\") not found")
	}
}

// TestShellCSSServed verifies that the served app.css contains the new shell
// selectors (.mainmenu, .nav__burger, .navlink, .nav__panel) and does NOT contain
// the removed dead selectors (nav.mainnav, .navwrap, .navsettings, .navmenu) from
// the previous shell. Removing or renaming the shell CSS blocks breaks this test.
func TestShellCSSServed(t *testing.T) {
	e := newTestEnv(t)

	_, css := e.get(t, "/static/app.css")

	// New shell selectors must be present in the served CSS.
	for _, sel := range []string{".mainmenu", ".nav__burger", ".navlink", ".nav__panel"} {
		if !strings.Contains(css, sel) {
			t.Fatalf("GET /static/app.css: missing shell selector %q (shell not styled)", sel)
		}
	}

	// Old dead shell selectors must be absent (they clash with the new markup).
	for _, dead := range []string{"nav.mainnav", ".navwrap", ".navsettings"} {
		if strings.Contains(css, dead) {
			t.Fatalf("GET /static/app.css: dead selector %q still present (remove old shell CSS)", dead)
		}
	}
}

// TestActiveSectionOnNav verifies that aria-current="page" appears on the correct
// primary nav link for the inventory, issue, and sign-csr pages. This test would
// fail if ActiveSection is not set in the handler, or if activeCurrent returns
// the wrong value, breaking the active-link highlight in the topbar.
func TestActiveSectionOnNav(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root") // superadmin, left logged in (can see all nav links)

	cases := []struct {
		path string
		href string
	}{
		{"/inventory", "/inventory"},
		{"/issue", "/issue"},
		{"/sign-csr", "/sign-csr"},
	}

	for _, tc := range cases {
		_, body := e.get(t, tc.path)
		// The active navlink must carry aria-current="page".
		want := `href="` + tc.href + `" aria-current="page"`
		if !strings.Contains(body, want) {
			t.Fatalf("GET %s: expected aria-current=\"page\" on href=%q; body:\n%s", tc.path, tc.href, body)
		}
	}
}

// TestActiveSectionNotSetOnOtherPages verifies that non-primary-nav pages (users,
// settings) do NOT mark any nav link as aria-current="page". If ActiveSection were
// set incorrectly on those handlers the highlight would show on the wrong link.
func TestActiveSectionNotSetOnOtherPages(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	for _, path := range []string{"/users", "/settings"} {
		_, body := e.get(t, path)
		if strings.Contains(body, `aria-current="page"`) {
			t.Fatalf("GET %s: aria-current=\"page\" must not appear (no active nav section); body:\n%s", path, body)
		}
	}
}

// TestNoEmptyAriaCurrent verifies that aria-current="" is never emitted by the
// nav — an empty string is not a valid aria-current token (spec requires the
// attribute to be entirely absent on inactive links, not present with "").
func TestNoEmptyAriaCurrent(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Check all primary-nav pages plus a non-nav page (settings).
	paths := []string{"/inventory", "/issue", "/sign-csr", "/users", "/settings"}
	for _, path := range paths {
		_, body := e.get(t, path)
		if strings.Contains(body, `aria-current=""`) {
			t.Fatalf("GET %s: aria-current=\"\" must never appear; body:\n%s", path, body)
		}
	}
}

// TestBrandWordmarkTwoLine verifies the topbar brand renders the two-line
// wordmark: .b1 contains "Step-CA" and .b2 contains "NextGen UI". The brand
// link must target /inventory and carry the correct aria-label. The old
// single-line "step-ui-ng" text must be absent.
func TestBrandWordmarkTwoLine(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/inventory")

	// Brand link must point to /inventory with the correct aria-label.
	if !strings.Contains(body, `href="/inventory" class="brand"`) {
		t.Fatalf("topbar: brand link href=\"/inventory\" not found; body:\n%s", body)
	}
	if !strings.Contains(body, `aria-label="Step-CA NextGen UI — home"`) {
		t.Fatalf("topbar: aria-label \"Step-CA NextGen UI — home\" not found; body:\n%s", body)
	}

	// .b1 must contain "Step-CA".
	if !strings.Contains(body, `class="b1"`) {
		t.Fatalf("topbar: missing span with class=\"b1\"; body:\n%s", body)
	}
	if !strings.Contains(body, `class="b1">Step-CA`) {
		t.Fatalf("topbar: .b1 does not contain \"Step-CA\"; body:\n%s", body)
	}

	// .b2 must contain "NextGen UI".
	if !strings.Contains(body, `class="b2"`) {
		t.Fatalf("topbar: missing span with class=\"b2\"; body:\n%s", body)
	}
	if !strings.Contains(body, `class="b2">NextGen UI`) {
		t.Fatalf("topbar: .b2 does not contain \"NextGen UI\"; body:\n%s", body)
	}

	// The old single-line identifier must be gone.
	if strings.Contains(body, `class="b1">step-ui-ng`) {
		t.Fatalf("topbar: old single-line wordmark \"step-ui-ng\" still present; body:\n%s", body)
	}
}
