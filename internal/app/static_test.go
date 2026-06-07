package app_test

import (
	"strings"
	"testing"
)

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
