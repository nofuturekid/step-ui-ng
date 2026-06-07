package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/nofuturekid/step-ui-ng/internal/settings"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// --- Mock CA wiring ----------------------------------------------------------
//
// adminCAFixture is a TLS mock CA serving /roots (pinned trust), GET
// /provisioners, and admin POST/DELETE that verify a correctly-signed x5c admin
// token against the CA root — the same checks step-ca performs. It returns the
// pieces the app tests need to seed settings and assert behaviour.
type adminCAFixture struct {
	url          string
	fingerprint  string
	adminCert    string // PEM chain (leaf+root) for the app's admin credential
	adminKey     string // PEM private key matching the leaf
	provisioners string // JSON body for GET /provisioners (mutable per test)
}

func startAppAdminCA(t *testing.T, provisionersJSON string) *adminCAFixture {
	t.Helper()

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "App Admin Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "step-admin@app.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	f := &adminCAFixture{provisioners: provisionersJSON}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsCert := srv.Certificate()
	f.url = srv.URL
	sum := sha256.Sum256(tlsCert.Raw)
	f.fingerprint = hex.EncodeToString(sum[:])

	rootsBody := `{"crts":["` + strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Raw})), "\n", `\n`) + `"]}`

	verify := func(r *http.Request) bool {
		tok := r.Header.Get("Authorization")
		if tok == "" {
			return false
		}
		jwt, err := jose.ParseSigned(tok)
		if err != nil {
			return false
		}
		chains, err := jwt.Headers[0].Certificates(x509.VerifyOptions{
			Roots:     rootPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return false
		}
		l := chains[0][0]
		if l.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return false
		}
		var claims jose.Claims
		if err := jwt.Claims(l.PublicKey, &claims); err != nil {
			return false
		}
		if err := claims.ValidateWithLeeway(jose.Expected{
			Audience: jose.Audience{f.url + "/admin/provisioners"},
			Time:     time.Now().UTC(),
		}, time.Minute); err != nil {
			return false
		}
		return claims.Issuer == "step-admin-client/1.0" && claims.Subject != ""
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsBody))
	})
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.provisioners))
	})
	mux.HandleFunc("POST /admin/provisioners", func(w http.ResponseWriter, r *http.Request) {
		if !verify(r) {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("DELETE /admin/provisioners/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !verify(r) {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	srv.Config.Handler = mux

	f.adminCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	f.adminKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return f
}

// seedCA saves CA settings pointing at the fixture and, if withAdmin, stores the
// admin credential so create/delete can sign tokens.
func (e *testEnv) seedCA(t *testing.T, f *adminCAFixture, withAdmin bool) {
	t.Helper()
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: f.url, RootFingerprint: f.fingerprint,
	}); err != nil {
		t.Fatalf("seed CA settings: %v", err)
	}
	if withAdmin {
		if err := e.settingsRepo.SaveAdminCredential(context.Background(), f.adminCert, f.adminKey); err != nil {
			t.Fatalf("seed admin credential: %v", err)
		}
	}
}

// getBody fetches a page and returns status + body.
func (e *testEnv) getBody(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, body := e.get(t, path)
	return resp.StatusCode, body
}

// --- Acceptance: list shows provisioners with types (FR-1) ------------------

func TestProvisionersListShowsTypes(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"admin-jwk"},
		{"type":"ACME","name":"acme-prov"}
	]}`)
	e.seedCA(t, f, false)

	status, body := e.getBody(t, "/provisioners")
	if status != http.StatusOK {
		t.Fatalf("GET /provisioners = %d, want 200; body:\n%s", status, body)
	}
	for _, want := range []string{"admin-jwk", "JWK", "acme-prov", "ACME"} {
		if !strings.Contains(body, want) {
			t.Fatalf("provisioners page missing %q; body:\n%s", want, body)
		}
	}
}

// --- Acceptance: select a JWK provisioner with password (FR-2) ---------------

func TestProvisionersSelectPersistsSealed(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"admin-jwk"}]}`)
	e.seedCA(t, f, false)
	const secret = "select-me-secret-9999"

	token := e.csrfToken(t, "/provisioners")
	resp := e.post(t, "/provisioners/select", url.Values{
		"csrf_token": {token},
		"name":       {"admin-jwk"},
		"secret":     {secret},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("select status = %d, want 303", resp.StatusCode)
	}

	got, _, _ := e.settingsRepo.Get(context.Background())
	if got.SelectedProvisioner != "admin-jwk" || !got.HasSelectedSecret {
		t.Fatalf("selection not persisted: %+v", got)
	}

	// The plaintext secret must not appear on the page, and the active marker must.
	_, body := e.getBody(t, "/provisioners")
	if strings.Contains(body, secret) {
		t.Fatal("plaintext selected secret leaked into the provisioners page")
	}
	if !strings.Contains(strings.ToLower(body), "active") {
		t.Fatalf("expected an 'active' marker for the selected provisioner; body:\n%s", body)
	}

	// Defence in depth: the column is sealed.
	var sealed string
	if err := e.db.QueryRowContext(context.Background(),
		"SELECT selected_provisioner_secret_sealed FROM ca_settings WHERE id = 1").Scan(&sealed); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if sealed == "" || sealed == secret {
		t.Fatalf("selected secret not sealed (got %q)", sealed)
	}
}

// --- Acceptance: valid admin creds → create → appears (FR-3) ----------------

func TestProvisionersCreateSucceeds(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, true)

	token := e.csrfToken(t, "/provisioners")
	resp := e.post(t, "/provisioners", url.Values{
		"csrf_token": {token},
		"name":       {"new-jwk"},
		"type":       {"JWK"},
		"secret":     {"create-secret-1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create status = %d, want 303", resp.StatusCode)
	}
	_, body := e.getBody(t, "/provisioners")
	if !strings.Contains(strings.ToLower(body), "created") {
		t.Fatalf("expected a success flash after create; body:\n%s", body)
	}
}

// --- Acceptance: invalid admin creds → create → clear error (FR-3) ----------

func TestProvisionersCreateUnauthorized(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	// Seed a base setting but store an admin credential whose key does NOT match
	// the x5c leaf so the mock rejects the token (401).
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: f.url, RootFingerprint: f.fingerprint,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	badKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badKeyDER, _ := x509.MarshalPKCS8PrivateKey(badKey)
	badKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: badKeyDER}))
	if err := e.settingsRepo.SaveAdminCredential(context.Background(), f.adminCert, badKeyPEM); err != nil {
		t.Fatalf("seed bad admin cred: %v", err)
	}

	token := e.csrfToken(t, "/provisioners")
	resp := e.post(t, "/provisioners", url.Values{
		"csrf_token": {token},
		"name":       {"new-jwk"},
		"type":       {"JWK"},
		"secret":     {"create-secret-1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create status = %d, want 303 (flash error)", resp.StatusCode)
	}
	_, body := e.getBody(t, "/provisioners")
	if !strings.Contains(strings.ToLower(body), "unauthor") && !strings.Contains(strings.ToLower(body), "admin cred") {
		t.Fatalf("expected an unauthorized error flash; body:\n%s", body)
	}
}

// Create without an admin credential configured → clear error, no CA call.
func TestProvisionersCreateNoAdminCredential(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, false) // no admin credential

	token := e.csrfToken(t, "/provisioners")
	resp := e.post(t, "/provisioners", url.Values{
		"csrf_token": {token},
		"name":       {"new-jwk"},
		"type":       {"JWK"},
		"secret":     {"create-secret-1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	_, body := e.getBody(t, "/provisioners")
	if !strings.Contains(strings.ToLower(body), "admin cred") {
		t.Fatalf("expected an 'admin credential' error flash; body:\n%s", body)
	}
}

// --- Acceptance: cannot delete the active provisioner (FR-4) ----------------

func TestProvisionersDeleteActiveRefused(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"active-one"}]}`)
	e.seedCA(t, f, true)

	// Select it first.
	if err := e.settingsRepo.SelectProvisioner(context.Background(), "active-one", "sel-secret-aaaa"); err != nil {
		t.Fatalf("select: %v", err)
	}

	token := e.csrfToken(t, "/provisioners")
	resp := e.post(t, "/provisioners/active-one", url.Values{
		"csrf_token": {token},
		"action":     {"delete"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete status = %d, want 303 (flash error)", resp.StatusCode)
	}
	_, body := e.getBody(t, "/provisioners")
	low := strings.ToLower(body)
	// The specific "cannot delete the active provisioner" error must be shown.
	if !strings.Contains(low, "cannot delete the active provisioner") {
		t.Fatalf("expected a 'cannot delete the active provisioner' error; body:\n%s", body)
	}
	// And the delete must NOT have happened: no success flash. If the guard were
	// removed, the request would reach the (accepting) mock CA and flash "deleted".
	if strings.Contains(low, "provisioner deleted") {
		t.Fatalf("delete of the active provisioner was not blocked; body:\n%s", body)
	}
	// It must still be selected (not cleared).
	got, _, _ := e.settingsRepo.Get(context.Background())
	if got.SelectedProvisioner != "active-one" {
		t.Fatalf("active provisioner selection changed: %+v", got)
	}
}

// TestProvisionerSecretIndicator: the page shows whether a secret is stored for the
// active provisioner (set/none) so the operator can tell — without echoing the value.
func TestProvisionerSecretIndicator(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"p1"}]}`)
	e.seedCA(t, f, true)

	// No provisioner secret stored yet → "none".
	_, body := e.getBody(t, "/provisioners")
	if !strings.Contains(body, ">none<") {
		t.Fatalf("expected a 'none' provisioner-secret badge; body:\n%s", body)
	}

	// Store a secret for the active provisioner → "set", and never echo the value.
	if err := e.settingsRepo.SelectProvisioner(context.Background(), "p1", "prov-secret-aaaa"); err != nil {
		t.Fatalf("select: %v", err)
	}
	_, body = e.getBody(t, "/provisioners")
	if !strings.Contains(body, ">set<") {
		t.Fatalf("expected a 'set' provisioner-secret badge; body:\n%s", body)
	}
	if strings.Contains(body, "prov-secret-aaaa") {
		t.Fatal("provisioner secret value leaked into the rendered page")
	}
}

// A non-active provisioner deletes fine.
func TestProvisionersDeleteNonActive(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"keep"},{"type":"JWK","name":"drop"}]}`)
	e.seedCA(t, f, true)
	if err := e.settingsRepo.SelectProvisioner(context.Background(), "keep", ""); err != nil {
		t.Fatalf("select: %v", err)
	}

	token := e.csrfToken(t, "/provisioners")
	resp := e.post(t, "/provisioners/drop", url.Values{
		"csrf_token": {token},
		"action":     {"delete"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete status = %d, want 303", resp.StatusCode)
	}
	_, body := e.getBody(t, "/provisioners")
	if !strings.Contains(strings.ToLower(body), "deleted") {
		t.Fatalf("expected a delete success flash; body:\n%s", body)
	}
}

// --- Validation (FR-3): name/type/secret length, table-driven ---------------

func TestProvisionersCreateValidation(t *testing.T) {
	cases := []struct {
		name   string
		form   url.Values
		expect string // substring expected in the error flash
	}{
		{"bad name", url.Values{"name": {"bad name!"}, "type": {"JWK"}, "secret": {"longenough"}}, "name"},
		{"bad type", url.Values{"name": {"ok"}, "type": {"X5C"}, "secret": {"longenough"}}, "type"},
		{"short jwk secret", url.Values{"name": {"ok"}, "type": {"JWK"}, "secret": {"short"}}, "secret"},
		{"empty name", url.Values{"name": {""}, "type": {"JWK"}, "secret": {"longenough"}}, "name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			e.completeSetup(t, "root")
			f := startAppAdminCA(t, `{"provisioners":[]}`)
			e.seedCA(t, f, true)

			token := e.csrfToken(t, "/provisioners")
			form := url.Values{"csrf_token": {token}}
			for k, v := range tc.form {
				form[k] = v
			}
			resp := e.post(t, "/provisioners", form)
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("%s: status = %d, want 303", tc.name, resp.StatusCode)
			}
			_, body := e.getBody(t, "/provisioners")
			if !strings.Contains(strings.ToLower(body), tc.expect) {
				t.Fatalf("%s: expected error containing %q; body:\n%s", tc.name, tc.expect, body)
			}
		})
	}
}

// --- RBAC: provisioners is admin+ -------------------------------------------

func TestProvisionersViewerForbidden(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "viewer1", users.RoleViewer)

	logoutToken := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})
	token := e.csrfToken(t, "/login")
	e.loginAs(t, "viewer1")

	if resp, _ := e.get(t, "/provisioners"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer GET /provisioners = %d, want 403", resp.StatusCode)
	}
	resp := e.post(t, "/provisioners", url.Values{
		"csrf_token": {token}, "name": {"x"}, "type": {"JWK"}, "secret": {"longenough"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST /provisioners = %d, want 403", resp.StatusCode)
	}
}

// List when no CA settings exist → a clear message, not a crash.
func TestProvisionersNoSettings(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	status, body := e.getBody(t, "/provisioners")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !strings.Contains(strings.ToLower(body), "ca") {
		t.Fatalf("expected a 'configure CA' style message; body:\n%s", body)
	}
}
