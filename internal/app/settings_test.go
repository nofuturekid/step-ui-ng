package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/settings"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// A valid 64-hex placeholder used where the value must NOT match a real CA.
const fakeFP = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

// --- Acceptance: secret is write-only and never sent to the browser (FR-5) ---

// Saving an admin secret, then reloading, shows the field as "set" and the
// plaintext value never appears in the response body.
func TestSettingsSecretNeverSentToBrowser(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	const secret = "top-secret-admin-password-9876"

	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings", url.Values{
		"csrf_token":       {token},
		"ca_url":           {"https://ca.example:9000"},
		"root_fingerprint": {fakeFP},
		"admin_secret":     {secret},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save status = %d, want 303", resp.StatusCode)
	}

	// Reload: secret shows as "set", and the plaintext is absent from the page.
	r2, body := e.get(t, "/settings")
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings = %d, want 200", r2.StatusCode)
	}
	if strings.Contains(body, secret) {
		t.Fatal("the plaintext admin secret leaked into the /settings page")
	}
	// The "set" indicator must be present (it follows the Admin secret label).
	if !strings.Contains(body, "set") {
		t.Fatal("expected a 'set' indicator for the stored secret")
	}

	// Defence in depth: the stored column must be sealed, not plaintext.
	var sealed string
	if err := e.db.QueryRowContext(context.Background(),
		"SELECT admin_secret_sealed FROM ca_settings WHERE id = 1").Scan(&sealed); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if sealed == "" || sealed == secret {
		t.Fatalf("admin secret not sealed at rest (got %q)", sealed)
	}
}

// --- Acceptance: invalid CA URL → validation rejects (FR-4) ------------------

func TestSettingsInvalidURLRejected(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings", url.Values{
		"csrf_token":       {token},
		"ca_url":           {"ftp://nope"},
		"root_fingerprint": {fakeFP},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (flash error redirect)", resp.StatusCode)
	}
	// Nothing was persisted.
	if _, ok, _ := e.settingsRepo.Get(context.Background()); ok {
		t.Fatal("invalid URL was persisted despite validation")
	}
	// The error flash is shown on the next render.
	_, body := e.get(t, "/settings")
	if !strings.Contains(body, "http://") {
		t.Fatalf("expected the URL-validation error flash, body:\n%s", body)
	}
}

// Invalid fingerprint via the handler is rejected too.
func TestSettingsInvalidFingerprintRejected(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings", url.Values{
		"csrf_token":       {token},
		"ca_url":           {"https://ca.example"},
		"root_fingerprint": {"xyz"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if _, ok, _ := e.settingsRepo.Get(context.Background()); ok {
		t.Fatal("invalid fingerprint was persisted")
	}
}

// --- Acceptance: Test connection success and failure (FR-2) -----------------

// startMockCA returns a TLS server mimicking GET /roots plus its URL and the
// SHA-256 fingerprint of its served root.
func startMockCA(t *testing.T) (caURL, fingerprint string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cert := srv.Certificate()
	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		b, _ := json.Marshal(struct {
			Crts []string `json:"crts"`
		}{Crts: []string{string(p)}})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	srv.Config.Handler = mux

	sum := sha256.Sum256(cert.Raw)
	return srv.URL, hex.EncodeToString(sum[:])
}

// Given valid CA URL + fingerprint, the Test action reports success and roots.
func TestSettingsTestConnectionSuccess(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	caURL, fp := startMockCA(t)

	// Save the (valid) settings through the repo so the handler reads them.
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: caURL, RootFingerprint: fp,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	token := e.csrfToken(t, "/settings")
	status, body := e.postBody(t, "/settings/test", url.Values{"csrf_token": {token}})
	if status != http.StatusOK {
		t.Fatalf("test status = %d, want 200", status)
	}
	if !strings.Contains(strings.ToLower(body), "ok") {
		t.Fatalf("expected success message, got:\n%s", body)
	}
}

// startMockCAPhase2Fail stands up a CA whose Phase 1 passes (the pinned root is
// present in the TLS chain and served at /roots) but whose live TLS leaf is
// signed by a DIFFERENT root, so Phase-2 chain validation fails → ErrBadTLS. It
// returns the URL and the pinned root's fingerprint. This drives the app-layer
// testFailureMessage(ErrBadTLS) path through the real handler.
func startMockCAPhase2Fail(t *testing.T) (caURL, fingerprint string) {
	t.Helper()
	rootA := genCASelfSigned(t, "Pinned Root A")
	rootB := genCASelfSigned(t, "Impostor Root B")
	leaf := genCALeaf(t, rootB, "ca.test") // signed by B, not the pinned A

	rootAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootA.der})
	body, _ := json.Marshal(struct {
		Crts []string `json:"crts"`
	}{Crts: []string{string(rootAPEM)}})

	srv := httptest.NewUnstartedServer(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	srv.Config.Handler = mux
	// Present leaf + B (real signer) + A (so Phase 1's pin scan finds A).
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{leaf.der, rootB.der, rootA.der},
		PrivateKey:  leaf.key,
		Leaf:        leaf.cert,
	}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	sum := sha256.Sum256(rootA.der)
	return srv.URL, hex.EncodeToString(sum[:])
}

// caKeyPair is a generated cert + key (app-layer mirror of the ca package's helper).
type caKeyPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func genCASelfSigned(t *testing.T, cn string) *caKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}
	return &caKeyPair{cert: cert, key: key, der: der}
}

func genCALeaf(t *testing.T, root *caKeyPair, cn string) *caKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &key.PublicKey, root.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return &caKeyPair{cert: cert, key: key, der: der}
}

// A Phase-2 (TLS-anchor) failure renders a clear TLS-related message, not a
// fingerprint or generic error. This exercises testFailureMessage(ErrBadTLS)
// end-to-end through the test-connection handler.
func TestSettingsTestConnectionBadTLS(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	caURL, fp := startMockCAPhase2Fail(t)

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: caURL, RootFingerprint: fp,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	token := e.csrfToken(t, "/settings")
	_, body := e.postBody(t, "/settings/test", url.Values{"csrf_token": {token}})
	if !strings.Contains(strings.ToLower(body), "tls") {
		t.Fatalf("expected a TLS-verification failure message, got:\n%s", body)
	}
}

// Given a wrong fingerprint, the Test action fails with a clear message.
func TestSettingsTestConnectionWrongFingerprint(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	caURL, _ := startMockCA(t)

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: caURL, RootFingerprint: fakeFP, // deliberately wrong
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	token := e.csrfToken(t, "/settings")
	_, body := e.postBody(t, "/settings/test", url.Values{"csrf_token": {token}})
	if !strings.Contains(strings.ToLower(body), "fingerprint") {
		t.Fatalf("expected a fingerprint-mismatch message, got:\n%s", body)
	}
}

// Test connection without any saved settings reports a clear message, not a crash.
func TestSettingsTestConnectionNoSettings(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	token := e.csrfToken(t, "/settings")
	status, body := e.postBody(t, "/settings/test", url.Values{"csrf_token": {token}})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (no settings)", status)
	}
	if !strings.Contains(strings.ToLower(body), "save") {
		t.Fatalf("expected a 'save first' message, got:\n%s", body)
	}
}

// --- RBAC: settings is admin+ ------------------------------------------------

func TestSettingsViewerForbidden(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "viewer1", users.RoleViewer)

	// Log out, then grab a genuine CSRF token from /login while logged out (the
	// nosurf cookie is stable across login, so it stays valid for the POST). A
	// 403 then proves RBAC blocked the mutation, not a CSRF mismatch — mirroring
	// the user-management RBAC tests.
	logoutToken := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})
	token := e.csrfToken(t, "/login")
	e.loginAs(t, "viewer1")

	if resp, _ := e.get(t, "/settings"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer GET /settings = %d, want 403", resp.StatusCode)
	}
	resp := e.post(t, "/settings", url.Values{
		"csrf_token": {token}, "ca_url": {"https://ca.example"}, "root_fingerprint": {fakeFP},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST /settings = %d, want 403", resp.StatusCode)
	}
}

// postBody sends a same-origin form POST and returns the status and the response
// body (unlike testEnv.post, which discards the body). Used to assert on the
// htmx test-connection partials.
func (e *testEnv) postBody(t *testing.T, path string, form url.Values) (int, string) {
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
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}
