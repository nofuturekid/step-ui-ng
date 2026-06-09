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

// --- Acceptance: Admin Authentication card (spec/0012) ----------------------

// The settings page must render the admin-auth method selector with all three
// options (none / x5c / jwk) so the operator can choose a method.
func TestSettingsPageRendersAdminAuthSelector(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/settings")
	for _, want := range []string{"admin_auth_method", "none", "x5c", "jwk"} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings page missing admin-auth element %q; body:\n%s", want, body)
		}
	}
}

// POST /settings/admin-auth with method=jwk persists the subject, provisioner,
// and a sealed password. The password must never be echoed on the page and the
// HasAdminJWK indicator must flip to "set" (FR-5).
func TestAdminAuthJWKSaveAndIndicator(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	const jwkPass = "super-secret-jwk-password-9999"

	// Seed base CA settings so SaveAdminJWK doesn't fail on ErrNoSettings.
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":            {token},
		"admin_auth_method":     {"jwk"},
		"admin_jwk_subject":     {"step@example.com"},
		"admin_jwk_provisioner": {"admin-jwk"},
		"admin_jwk_password":    {jwkPass},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin-auth JWK POST = %d, want 303", resp.StatusCode)
	}

	// After redirect: the page must show "jwk" badge, "set" password indicator,
	// and MUST NOT echo the plaintext password.
	_, body := e.get(t, "/settings")
	if strings.Contains(body, jwkPass) {
		t.Fatal("plaintext JWK password leaked into the /settings page")
	}
	if !strings.Contains(body, "jwk") {
		t.Fatalf("expected 'jwk' method badge on /settings page; body:\n%s", body)
	}
	// The HasAdminJWK badge "set" must appear.
	if !strings.Contains(body, ">set<") {
		t.Fatalf("expected a 'set' indicator for the stored JWK password; body:\n%s", body)
	}

	// DB-level: password must be sealed (not plaintext).
	var sealed string
	if err := e.db.QueryRowContext(context.Background(),
		"SELECT admin_jwk_password_sealed FROM ca_settings WHERE id = 1").Scan(&sealed); err != nil {
		t.Fatalf("read sealed JWK password: %v", err)
	}
	if sealed == "" || sealed == jwkPass {
		t.Fatalf("JWK password not sealed at rest (got %q)", sealed)
	}
}

// POST /settings/admin-auth with method=none clears all admin credential
// material and the page shows no "set" indicators.
func TestAdminAuthNoneClears(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed a JWK auth first.
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := e.settingsRepo.SaveAdminJWK(context.Background(), "step@example.com", "admin-jwk", "password-aaa"); err != nil {
		t.Fatalf("seed JWK auth: %v", err)
	}

	// Now clear with method=none.
	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":        {token},
		"admin_auth_method": {"none"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin-auth none POST = %d, want 303", resp.StatusCode)
	}

	// The repo must reflect method=none and no HasAdminJWK.
	view, _, err := e.settingsRepo.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if view.AdminAuthMethod != settings.AdminAuthNone {
		t.Fatalf("AdminAuthMethod = %q, want none", view.AdminAuthMethod)
	}
	if view.HasAdminJWK {
		t.Fatal("HasAdminJWK should be false after clearing to none")
	}
}

// POST /settings/admin-auth with method=jwk and blank password must NOT
// overwrite the existing sealed password (write-only semantics, FR-5).
func TestAdminAuthJWKBlankPasswordKeepsExisting(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	const origPass = "original-jwk-password-1234"

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := e.settingsRepo.SaveAdminJWK(context.Background(), "step@example.com", "admin-jwk", origPass); err != nil {
		t.Fatalf("seed JWK auth: %v", err)
	}
	var firstSealed string
	if err := e.db.QueryRowContext(context.Background(),
		"SELECT admin_jwk_password_sealed FROM ca_settings WHERE id = 1").Scan(&firstSealed); err != nil {
		t.Fatalf("read first sealed: %v", err)
	}

	// Re-submit with blank password; sealed value must be unchanged.
	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":            {token},
		"admin_auth_method":     {"jwk"},
		"admin_jwk_subject":     {"step@example.com"},
		"admin_jwk_provisioner": {"admin-jwk"},
		"admin_jwk_password":    {""},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin-auth JWK blank-pass POST = %d, want 303", resp.StatusCode)
	}

	var secondSealed string
	if err := e.db.QueryRowContext(context.Background(),
		"SELECT admin_jwk_password_sealed FROM ca_settings WHERE id = 1").Scan(&secondSealed); err != nil {
		t.Fatalf("read second sealed: %v", err)
	}
	if secondSealed != firstSealed {
		t.Fatalf("blank password changed the sealed value: %q -> %q", firstSealed, secondSealed)
	}
}

// The provisioner page shows an honest FR-6 hint (naming both x5c and jwk)
// when no admin authentication is configured. The old message "Add an admin
// certificate and key" must not appear.
func TestProvisionersPageHonestHintWhenNoAuth(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, false) // no admin auth configured

	_, body := e.getBody(t, "/provisioners")
	// Must name both options and not use the old misleading text.
	if !strings.Contains(strings.ToLower(body), "x5c") {
		t.Fatalf("provisioners page missing 'x5c' hint; body:\n%s", body)
	}
	if !strings.Contains(strings.ToLower(body), "jwk") {
		t.Fatalf("provisioners page missing 'jwk' hint; body:\n%s", body)
	}
	if strings.Contains(body, "Add an admin certificate and key") {
		t.Fatalf("provisioners page still shows misleading old message; body:\n%s", body)
	}
}

// method=jwk but NO password stored is not usable: the create controls must be
// gated OFF (gate on usable material, not just the method label), otherwise the
// form renders enabled while every action fails closed — a confusing footgun.
func TestProvisionersPageGatedWhenJWKWithoutPassword(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, false)

	// Select JWK with subject + provisioner but a BLANK password (none stored).
	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":            {token},
		"admin_auth_method":     {"jwk"},
		"admin_jwk_subject":     {"step"},
		"admin_jwk_provisioner": {"admin"},
		"admin_jwk_password":    {""},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin-auth POST status = %d, want 303", resp.StatusCode)
	}

	_, body := e.getBody(t, "/provisioners")
	if !strings.Contains(body, "Creating and deleting provisioners requires an admin credential") {
		t.Fatalf("jwk-without-password must gate the create form, but it appears enabled; body:\n%s", body)
	}
}

// --- Acceptance: x5c upload (spec/0012 FR-2) -----------------------------------

// makeX5CTestCert generates a leaf certificate with digitalSignature + clientAuth EKU
// and a non-empty CN, signed by a freshly-minted self-signed root. Returns the PEM
// cert chain (leaf + root) and the PEM private key for the leaf. This mirrors
// startAppAdminCA's logic so tests share the same cert shape as the mock CA.
// A leaf whose EKU is ExtKeyUsageAny satisfies clientAuth at the CA, so the
// upload must ACCEPT it (rejecting it would be a false-negative).
func TestAdminAuthX5CAnyEKUAccepted(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, false)

	cert, key := makeX5CCertEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageAny})
	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":        {token},
		"admin_auth_method": {"x5c"},
		"admin_x5c_cert":    {cert},
		"admin_x5c_key":     {key},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin-auth POST status = %d, want 303", resp.StatusCode)
	}
	_, body := e.getBody(t, "/settings")
	if !strings.Contains(body, "Admin authentication saved (x5c).") {
		t.Fatalf("a leaf with ExtKeyUsageAny must be accepted; body:\n%s", body)
	}
}

// makeX5CCertEKU generates a self-signed root and a leaf (digitalSignature) whose
// extended key usages are exactly ekus (pass nil for a leaf with no EKU). Returns
// the leaf+root chain PEM and the leaf private key PEM.
func makeX5CCertEKU(t *testing.T, ekus []x509.ExtKeyUsage) (certChainPEM, keyPEM string) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "x5c-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "x5c-admin@test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}

	certChainPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}))
	return certChainPEM, keyPEM
}

// makeX5CTestCert generates a valid admin cert with the clientAuth EKU.
func makeX5CTestCert(t *testing.T) (certChainPEM, keyPEM string) {
	t.Helper()
	return makeX5CCertEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

// makeX5CCertNoClientAuth generates a cert with digitalSignature but no EKU at all
// (used to assert the upload's clientAuth requirement).
func makeX5CCertNoClientAuth(t *testing.T) (certChainPEM, keyPEM string) {
	t.Helper()
	return makeX5CCertEKU(t, nil)
}

// TestAdminAuthX5CUploadValidCredential: a valid x5c cert+key upload via
// POST /settings/admin-auth (method=x5c) must:
// - save the credential (HasAdminKey → true),
// - show the "set" badge on /settings,
// - never echo the private key in any response,
// - enable the provisioner create controls.
func TestAdminAuthX5CUploadValidCredential(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	certPEM, keyPEM := makeX5CTestCert(t)

	// Seed base CA settings.
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":        {token},
		"admin_auth_method": {"x5c"},
		"admin_x5c_cert":    {certPEM},
		"admin_x5c_key":     {keyPEM},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("x5c upload POST = %d, want 303", resp.StatusCode)
	}

	// Repo must reflect method=x5c and HasAdminKey=true.
	view, _, err := e.settingsRepo.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if view.AdminAuthMethod != settings.AdminAuthX5C {
		t.Fatalf("AdminAuthMethod = %q, want x5c", view.AdminAuthMethod)
	}
	if !view.HasAdminKey {
		t.Fatal("HasAdminKey must be true after a valid x5c upload")
	}

	// The settings page must show "set" badge for the key and not echo the key PEM.
	_, body := e.get(t, "/settings")
	// The private key PEM contains unique base64 content — check that the actual
	// key material (beyond the generic header) is not echoed.
	// keyPEM has format: "-----BEGIN PRIVATE KEY-----\n<base64>\n-----END PRIVATE KEY-----\n"
	// We extract a unique segment of the base64 content to check for leakage.
	keyLines := strings.Split(keyPEM, "\n")
	if len(keyLines) > 2 {
		// Second line is the start of unique base64 key material.
		if strings.Contains(body, keyLines[1]) {
			t.Fatal("private key material leaked into the /settings page")
		}
	}
	if !strings.Contains(body, ">set<") {
		t.Fatalf("expected 'set' badge for x5c key on /settings; body:\n%s", body)
	}

	// DB-level: key must be sealed (not plaintext).
	var sealedKey string
	if err := e.db.QueryRowContext(context.Background(),
		"SELECT admin_key_sealed FROM ca_settings WHERE id = 1").Scan(&sealedKey); err != nil {
		t.Fatalf("read sealed key: %v", err)
	}
	if sealedKey == "" || sealedKey == keyPEM {
		t.Fatalf("admin key not sealed at rest (got %q)", sealedKey)
	}
}

// TestAdminAuthX5CMissingClientAuth: uploading a cert without clientAuth EKU
// must be rejected with a clear error and nothing saved.
func TestAdminAuthX5CMissingClientAuth(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	certPEM, keyPEM := makeX5CCertNoClientAuth(t)

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":        {token},
		"admin_auth_method": {"x5c"},
		"admin_x5c_cert":    {certPEM},
		"admin_x5c_key":     {keyPEM},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("x5c no-clientAuth POST = %d, want 303", resp.StatusCode)
	}

	// Nothing must be saved.
	view, _, _ := e.settingsRepo.Get(context.Background())
	if view.HasAdminKey {
		t.Fatal("HasAdminKey should be false after uploading a cert without clientAuth")
	}

	// The settings page must show an error mentioning clientAuth.
	_, body := e.get(t, "/settings")
	if !strings.Contains(strings.ToLower(body), "clientauth") {
		t.Fatalf("expected clientAuth error message; body:\n%s", body)
	}
}

// TestAdminAuthX5CBlankFieldsRejected: submitting x5c with blank cert or key
// must produce an error and save nothing.
func TestAdminAuthX5CBlankFieldsRejected(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":        {token},
		"admin_auth_method": {"x5c"},
		"admin_x5c_cert":    {""},
		"admin_x5c_key":     {""},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("x5c blank-fields POST = %d, want 303", resp.StatusCode)
	}

	view, _, _ := e.settingsRepo.Get(context.Background())
	if view.HasAdminKey {
		t.Fatal("HasAdminKey should be false after blank x5c fields")
	}

	_, body := e.get(t, "/settings")
	if !strings.Contains(strings.ToLower(body), "required") {
		t.Fatalf("expected 'required' error; body:\n%s", body)
	}
}

// TestAdminAuthX5CInvalidKeypair: a mismatched cert+key must be rejected with a
// clear error (ErrInvalidAdminCredential) and nothing saved.
func TestAdminAuthX5CInvalidKeypair(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	certPEM, _ := makeX5CTestCert(t)
	_, keyPEM := makeX5CTestCert(t) // different cert/key pair → mismatch

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":        {token},
		"admin_auth_method": {"x5c"},
		"admin_x5c_cert":    {certPEM},
		"admin_x5c_key":     {keyPEM},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("x5c mismatch POST = %d, want 303", resp.StatusCode)
	}

	view, _, _ := e.settingsRepo.Get(context.Background())
	if view.HasAdminKey {
		t.Fatal("HasAdminKey should be false after a mismatched keypair")
	}

	_, body := e.get(t, "/settings")
	if !strings.Contains(strings.ToLower(body), "invalid") {
		t.Fatalf("expected an 'invalid' error for mismatched keypair; body:\n%s", body)
	}
}

// TestAdminAuthX5CSettingsPageRendersX5CFields: the settings page must render
// an #x5c-fields section with the cert/key textareas and the hint command.
func TestAdminAuthX5CSettingsPageRendersX5CFields(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example:9000", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	_, body := e.get(t, "/settings")
	// The x5c fields block and hint command must appear.
	for _, want := range []string{
		"x5c-fields",
		"admin_x5c_cert",
		"admin_x5c_key",
		"step ca certificate",
		"https://ca.example:9000",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings page missing %q in x5c block; body:\n%s", want, body)
		}
	}
}

// TestAdminAuthX5CPrivateKeyNeverEchoed: after a successful x5c upload, the
// private key PEM must never appear in any GET /settings response.
func TestAdminAuthX5CPrivateKeyNeverEchoed(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	certPEM, keyPEM := makeX5CTestCert(t)

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	token := e.csrfToken(t, "/settings")
	e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":        {token},
		"admin_auth_method": {"x5c"},
		"admin_x5c_cert":    {certPEM},
		"admin_x5c_key":     {keyPEM},
	})

	_, body := e.get(t, "/settings")
	// The key PEM contains unique base64 material — verify no key content is echoed.
	// (The generic "-----BEGIN PRIVATE KEY-----" string appears in the textarea
	// placeholder, so we check for the unique base64 lines, not the header.)
	keyLines := strings.Split(strings.TrimSpace(keyPEM), "\n")
	for _, line := range keyLines {
		if line == "" || strings.HasPrefix(line, "-----") {
			continue // skip PEM headers/footers — they appear in placeholder text
		}
		if strings.Contains(body, line) {
			t.Fatalf("private key base64 line %q leaked into the /settings page after x5c upload", line)
		}
	}
}

// TestAdminAuthX5CEnablesProvisionerCreate: after a valid x5c upload, the
// provisioner create controls become visible (HasAdminCred=true).
func TestAdminAuthX5CEnablesProvisionerCreate(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, false) // no admin cred yet

	// Upload the fixture's cert+key (which the mock CA trusts).
	token := e.csrfToken(t, "/settings")
	resp := e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":        {token},
		"admin_auth_method": {"x5c"},
		"admin_x5c_cert":    {f.adminCert},
		"admin_x5c_key":     {f.adminKey},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("x5c upload POST = %d, want 303", resp.StatusCode)
	}

	// The provisioner page must now show the create form (gated on HasAdminCred).
	_, body := e.getBody(t, "/provisioners")
	if strings.Contains(body, "requires an admin credential") {
		t.Fatalf("create form still gated after valid x5c upload; body:\n%s", body)
	}
}

// TestAdminAuthX5CSwitchToJWKClearsX5C: switching from x5c to JWK must clear
// the x5c cert/key (FR-5 switching is clean).
func TestAdminAuthX5CSwitchToJWKClearsX5C(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	certPEM, keyPEM := makeX5CTestCert(t)

	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example", RootFingerprint: fakeFP,
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	// Upload x5c first.
	token := e.csrfToken(t, "/settings")
	e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":        {token},
		"admin_auth_method": {"x5c"},
		"admin_x5c_cert":    {certPEM},
		"admin_x5c_key":     {keyPEM},
	})
	viewAfterX5C, _, _ := e.settingsRepo.Get(context.Background())
	if !viewAfterX5C.HasAdminKey {
		t.Fatal("precondition: HasAdminKey must be true after x5c upload")
	}

	// Switch to JWK.
	token2 := e.csrfToken(t, "/settings")
	e.post(t, "/settings/admin-auth", url.Values{
		"csrf_token":            {token2},
		"admin_auth_method":     {"jwk"},
		"admin_jwk_subject":     {"step"},
		"admin_jwk_provisioner": {"admin-jwk"},
		"admin_jwk_password":    {"some-password-1234"},
	})

	viewAfterJWK, _, _ := e.settingsRepo.Get(context.Background())
	if viewAfterJWK.HasAdminKey {
		t.Fatal("HasAdminKey should be cleared after switching to JWK (FR-5)")
	}
	if viewAfterJWK.AdminCertPEM != "" {
		t.Fatal("AdminCertPEM should be cleared after switching to JWK (FR-5)")
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
