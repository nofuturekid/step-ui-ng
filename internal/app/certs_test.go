package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/nofuturekid/step-ui-ng/internal/settings"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// --- Mock CA for the issue/sign OTT flow ------------------------------------
//
// signCAFixture is a TLS mock CA serving /roots (pinned trust), GET /provisioners
// (publishing a JWK provisioner whose encryptedKey the fixture controls), and
// POST /1.0/sign which VERIFIES the OTT signature + claims against the published
// public JWK before issuing a certificate — the same checks step-ca's JWK
// provisioner performs. It does NOT exercise a live CA.
type signCAFixture struct {
	url         string
	fingerprint string
	provName    string
	password    string
	root        *x509.Certificate
	rootKey     *ecdsa.PrivateKey
}

func startSignCAFixture(t *testing.T) *signCAFixture {
	t.Helper()
	const provName = "ui-jwk"
	const password = "issuance-pass-1234"

	pubKey, jwe, err := jose.GenerateDefaultKeyPair([]byte(password))
	if err != nil {
		t.Fatalf("gen provisioner keypair: %v", err)
	}
	encKey, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize encrypted key: %v", err)
	}

	// Issuing root used to sign requested CSRs.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Issue Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	f := &signCAFixture{provName: provName, password: password, root: rootCert, rootKey: rootKey}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsCert := srv.Certificate()
	f.url = srv.URL
	sum := sha256.Sum256(tlsCert.Raw)
	f.fingerprint = hex.EncodeToString(sum[:])
	rootsBody := `{"crts":["` + strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Raw})), "\n", `\n`) + `"]}`
	wantAud := f.url + "/1.0/sign"

	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsBody))
	})
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		pubBytes, _ := pubKey.MarshalJSON()
		body := `{"provisioners":[{"type":"JWK","name":"` + provName + `","key":` +
			string(pubBytes) + `,"encryptedKey":"` + encKey + `"}]}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			CSR string `json:"csr"`
			OTT string `json:"ott"`
		}
		_ = json.Unmarshal(body, &req)

		jwt, perr := jose.ParseSigned(req.OTT)
		if perr != nil {
			http.Error(w, `{"message":"bad token"}`, http.StatusUnauthorized)
			return
		}
		var claims struct {
			jose.Claims
			SANs []string `json:"sans"`
		}
		if perr := jwt.Claims(pubKey.Public(), &claims); perr != nil {
			http.Error(w, `{"message":"invalid token signature"}`, http.StatusUnauthorized)
			return
		}
		if perr := claims.ValidateWithLeeway(jose.Expected{
			Issuer:   provName,
			Audience: jose.Audience{wantAud},
			Time:     time.Now().UTC(),
		}, time.Minute); perr != nil {
			http.Error(w, `{"message":"invalid claims"}`, http.StatusUnauthorized)
			return
		}
		if claims.Subject == "" {
			http.Error(w, `{"message":"empty subject"}`, http.StatusUnauthorized)
			return
		}

		csr, perr := pemutil.ParseCertificateRequest([]byte(req.CSR))
		if perr != nil || csr.CheckSignature() != nil {
			http.Error(w, `{"message":"bad csr"}`, http.StatusBadRequest)
			return
		}

		leafTmpl := &x509.Certificate{
			SerialNumber:   big.NewInt(time.Now().UnixNano() + 99),
			Subject:        csr.Subject,
			NotBefore:      time.Now().Add(-time.Minute),
			NotAfter:       time.Now().Add(24 * time.Hour),
			KeyUsage:       x509.KeyUsageDigitalSignature,
			ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:       csr.DNSNames,
			IPAddresses:    csr.IPAddresses,
			EmailAddresses: csr.EmailAddresses,
			URIs:           csr.URIs,
		}
		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, csr.PublicKey, rootKey)
		leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
		caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"crt": leafPEM, "ca": caPEM, "certChain": []string{leafPEM, caPEM},
		})
	})
	srv.Config.Handler = mux
	return f
}

// seedSignCA points settings at the fixture and selects the JWK provisioner with
// its password, so the issue/sign handlers have everything they need.
func (e *testEnv) seedSignCA(t *testing.T, f *signCAFixture) {
	t.Helper()
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: f.url, RootFingerprint: f.fingerprint,
	}); err != nil {
		t.Fatalf("seed CA settings: %v", err)
	}
	if err := e.settingsRepo.SelectProvisioner(context.Background(), f.provName, f.password); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}
}

// postForm sends a same-origin form POST and returns the status + body. Unlike
// testEnv.post (which discards the body), the issue/sign handlers render their
// result/errors inline, so the body must be inspected.
func (e *testEnv) postForm(t *testing.T, path string, form url.Values) (int, string) {
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
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body)
}

// postFormResp is like postForm but returns the whole response (headers + body),
// so tests can assert on response headers such as Cache-Control.
func (e *testEnv) postFormResp(t *testing.T, path string, form url.Values) (*http.Response, string) {
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
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

// auditWho returns the who of the newest audit row for the given action.
func (e *testEnv) auditWho(t *testing.T, action string) string {
	t.Helper()
	var who string
	err := e.db.QueryRowContext(context.Background(),
		`SELECT who FROM audit_events WHERE action = ? ORDER BY id DESC LIMIT 1`, action).Scan(&who)
	if err != nil {
		t.Fatalf("read audit who for %q: %v", action, err)
	}
	return who
}

// --- Acceptance: issue for example.test + a SAN → stored (FR-1) -------------

func TestIssueCreatesAndStoresCertificate(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	token := e.csrfToken(t, "/issue")
	status, _ := e.postForm(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"example.test"},
		"sans":       {"www.example.test"},
		"validity":   {"30"},
		"format":     {"pem"},
	})
	if status != http.StatusOK {
		t.Fatalf("POST /issue = %d, want 200 (result page)", status)
	}

	// Persisted in the certificates inventory.
	var (
		cn, strategy string
		n            int
	)
	if err := e.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM certificates`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("certificates rows = %d, want 1", n)
	}
	if err := e.db.QueryRowContext(context.Background(),
		`SELECT cn, key_strategy FROM certificates WHERE id = 1`).Scan(&cn, &strategy); err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if cn != "example.test" || strategy != "server" {
		t.Fatalf("stored cert cn/strategy = %q/%q, want example.test/server", cn, strategy)
	}

	// Audit actor is the session user (FR-4), not "system".
	if who := e.auditWho(t, "issue"); who != "root" {
		t.Fatalf("audit who = %q, want root", who)
	}
}

// --- SECURITY: PEM mode delivers the key, no PFX, and is non-cacheable -------
//
// The issue result carries freshly-generated key material; it is shown exactly
// once. The response MUST carry Cache-Control: no-store so the private key is not
// retained by the browser/back-forward cache/intermediary, and MUST NOT also
// produce a PFX bundle.
func TestIssuePEMResultIsNoStoreAndDeliversKey(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	token := e.csrfToken(t, "/issue")
	resp, body := e.postFormResp(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"pem.test"},
		"validity":   {"30"},
		"format":     {"pem"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /issue = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store (key-bearing response must not be cached)", cc)
	}
	// The PEM private key is delivered (textarea shows it once).
	if !strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("PEM mode must deliver the private key in the result; body:\n%s", body)
	}
	// No PFX in PEM mode.
	if strings.Contains(body, "x-pkcs12") || strings.Contains(strings.ToLower(body), ".pfx") {
		t.Fatalf("PEM mode must not produce a PFX bundle; body:\n%s", body)
	}
	// A visible save-now warning is present.
	if !strings.Contains(strings.ToLower(body), "not retrievable later") {
		t.Fatalf("expected a 'save this now — not retrievable later' warning; body:\n%s", body)
	}
}

// --- SECURITY: PFX mode delivers a usable .pfx and NEVER the plaintext key ----
//
// In PFX mode the password-protected PKCS#12 bundle is the ONLY key payload: the
// rendered result must offer the .pfx as a download whose bytes decode as PKCS#12
// with the chosen password, and must NOT contain the unprotected PEM private key.
// This test FAILS if the certs.go format-conditional assignment is reverted.
func TestIssuePFXResultDeliversBundleAndHidesPlaintextKey(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	const pfxPass = "bundle-pass-9876"
	token := e.csrfToken(t, "/issue")
	resp, body := e.postFormResp(t, "/issue", url.Values{
		"csrf_token":   {token},
		"cn":           {"pfx.test"},
		"validity":     {"30"},
		"format":       {"pfx"},
		"pfx_password": {pfxPass},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /issue (pfx) = %d, want 200", resp.StatusCode)
	}
	// The plaintext PEM private key must NOT appear anywhere in the response.
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("PFX mode leaked the plaintext PEM private key into the result page; body:\n%s", body)
	}
	// The PFX must be offered as a download via a data: URL.
	pfx := extractPFXFromDataURI(t, body)
	if len(pfx) == 0 {
		t.Fatalf("PFX mode must deliver a downloadable PKCS#12 bundle; body:\n%s", body)
	}
	// The delivered bytes must be a usable .pfx: decode with the chosen password.
	if _, _, _, err := pkcs12.DecodeChain(pfx, pfxPass); err != nil {
		t.Fatalf("delivered PFX does not decode as PKCS#12 with its password: %v", err)
	}
	if _, _, _, err := pkcs12.DecodeChain(pfx, "wrong-pass"); err == nil {
		t.Fatal("delivered PFX decoded with the wrong password (must be password-protected)")
	}
	// Cache-Control: no-store also applies to the PFX-bearing response.
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store for the PFX-bearing response", cc)
	}
}

// extractPFXFromDataURI pulls the base64 payload out of the first
// data:application/x-pkcs12;base64,... href in the HTML and decodes it.
func extractPFXFromDataURI(t *testing.T, html string) []byte {
	t.Helper()
	m := pfxDataURIRe.FindStringSubmatch(html)
	if m == nil {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("PFX data URI base64 did not decode: %v", err)
	}
	return raw
}

var pfxDataURIRe = regexp.MustCompile(`data:application/x-pkcs12;base64,([A-Za-z0-9+/=]+)`)

// --- Acceptance: validity over the provisioner max → rejected (FR-5) --------
//
// The fixture's /1.0/sign always issues, so to exercise the validity-bound
// rejection path through the handler we use a provisioner max smaller than the
// requested validity, surfaced as the CA's 4xx → a clear error.

func TestIssueValidityOverMaxRejected(t *testing.T) {
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
	if status != http.StatusBadRequest {
		t.Fatalf("POST /issue over max = %d, want 400", status)
	}
	if !strings.Contains(strings.ToLower(body), "maximum") &&
		!strings.Contains(strings.ToLower(body), "rejected") {
		t.Fatalf("expected a clear validity error; body:\n%s", body)
	}
	var n int
	_ = e.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM certificates`).Scan(&n)
	if n != 0 {
		t.Fatalf("a rejected issue must not persist a certificate (got %d rows)", n)
	}
}

// --- Acceptance: sign a valid CSR → CN/SANs from CSR, no key (FR-2) ---------

func TestSignCSRStoresCertificateNoKey(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	csrPEM := makeCSR(t, "client.test", []string{"alt.client.test"})

	token := e.csrfToken(t, "/sign-csr")
	status, _ := e.postForm(t, "/sign-csr", url.Values{
		"csrf_token": {token},
		"csr":        {csrPEM},
		"validity":   {"10"},
	})
	if status != http.StatusOK {
		t.Fatalf("POST /sign-csr = %d, want 200", status)
	}

	var (
		cn, strategy string
		privSealed   sql.NullString
	)
	if err := e.db.QueryRowContext(context.Background(),
		`SELECT cn, key_strategy, privkey_sealed FROM certificates WHERE id = 1`).
		Scan(&cn, &strategy, &privSealed); err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if cn != "client.test" || strategy != "csr" {
		t.Fatalf("stored cn/strategy = %q/%q, want client.test/csr", cn, strategy)
	}
	if privSealed.Valid {
		t.Fatalf("a CSR-signed cert must store no private key, got %q", privSealed.String)
	}
	if who := e.auditWho(t, "sign"); who != "root" {
		t.Fatalf("audit who = %q, want root", who)
	}
}

// --- Acceptance: garbled CSR → rejected (FR-2/FR-5) -------------------------

func TestSignCSRGarbledRejected(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	e.seedSignCA(t, f)

	token := e.csrfToken(t, "/sign-csr")
	status, body := e.postForm(t, "/sign-csr", url.Values{
		"csrf_token": {token},
		"csr":        {"-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----"},
		"validity":   {"30"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("garbled CSR = %d, want 400", status)
	}
	if !strings.Contains(strings.ToLower(body), "csr") {
		t.Fatalf("expected a CSR error; body:\n%s", body)
	}
}

// --- Missing/unselected provisioner → clear error (FR-5) --------------------

func TestIssueNoProvisionerSelected(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startSignCAFixture(t)
	// Save CA settings but do NOT select a provisioner.
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: f.url, RootFingerprint: f.fingerprint,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	token := e.csrfToken(t, "/issue")
	status, body := e.postForm(t, "/issue", url.Values{
		"csrf_token": {token},
		"cn":         {"x.test"},
		"validity":   {"7"},
		"format":     {"pem"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("issue with no provisioner = %d, want 400", status)
	}
	if !strings.Contains(strings.ToLower(body), "provisioner") {
		t.Fatalf("expected a 'provisioner' error; body:\n%s", body)
	}
}

// --- RBAC: issue/sign are admin+ --------------------------------------------

func TestIssueSignViewerForbidden(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "viewer1", users.RoleViewer)
	e.switchTo(t, "viewer1")

	for _, path := range []string{"/issue", "/sign-csr"} {
		if resp, _ := e.get(t, path); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer GET %s = %d, want 403", path, resp.StatusCode)
		}
	}
}

// --- helpers ----------------------------------------------------------------

// signCAFixtureMax wraps signCAFixture with a provisioner validity cap enforced
// by /1.0/sign.
type signCAFixtureMax struct {
	*signCAFixture
}

func startSignCAFixtureMax(t *testing.T, maxDays int) *signCAFixtureMax {
	t.Helper()
	const provName = "ui-jwk"
	const password = "issuance-pass-1234"

	pubKey, jwe, err := jose.GenerateDefaultKeyPair([]byte(password))
	if err != nil {
		t.Fatalf("gen provisioner keypair: %v", err)
	}
	encKey, _ := jwe.CompactSerialize()

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Issue Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	f := &signCAFixture{provName: provName, password: password, root: rootCert, rootKey: rootKey}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsCert := srv.Certificate()
	f.url = srv.URL
	sum := sha256.Sum256(tlsCert.Raw)
	f.fingerprint = hex.EncodeToString(sum[:])
	rootsBody := `{"crts":["` + strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Raw})), "\n", `\n`) + `"]}`
	wantAud := f.url + "/1.0/sign"

	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsBody))
	})
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		pubBytes, _ := pubKey.MarshalJSON()
		_, _ = w.Write([]byte(`{"provisioners":[{"type":"JWK","name":"` + provName + `","key":` +
			string(pubBytes) + `,"encryptedKey":"` + encKey + `"}]}`))
	})
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			OTT      string `json:"ott"`
			CSR      string `json:"csr"`
			NotAfter string `json:"notAfter"`
		}
		_ = json.Unmarshal(body, &req)
		jwt, perr := jose.ParseSigned(req.OTT)
		if perr != nil {
			http.Error(w, `{"message":"bad token"}`, http.StatusUnauthorized)
			return
		}
		var claims struct {
			jose.Claims
			SANs []string `json:"sans"`
		}
		if perr := jwt.Claims(pubKey.Public(), &claims); perr != nil {
			http.Error(w, `{"message":"invalid token signature"}`, http.StatusUnauthorized)
			return
		}
		if perr := claims.ValidateWithLeeway(jose.Expected{
			Issuer: provName, Audience: jose.Audience{wantAud}, Time: time.Now().UTC(),
		}, time.Minute); perr != nil {
			http.Error(w, `{"message":"invalid claims"}`, http.StatusUnauthorized)
			return
		}
		// Enforce the provisioner max.
		if req.NotAfter != "" {
			if na, e := time.Parse(time.RFC3339, req.NotAfter); e == nil {
				if na.After(time.Now().Add(time.Duration(maxDays)*24*time.Hour + time.Minute)) {
					http.Error(w, `{"message":"requested duration exceeds the provisioner's maximum"}`, http.StatusForbidden)
					return
				}
			}
		}
		csr, _ := pemutil.ParseCertificateRequest([]byte(req.CSR))
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano() + 5),
			Subject:      csr.Subject, NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(time.Duration(maxDays) * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: csr.DNSNames,
		}
		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, csr.PublicKey, rootKey)
		leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"crt": leafPEM, "certChain": []string{leafPEM}})
	})
	srv.Config.Handler = mux
	return &signCAFixtureMax{signCAFixture: f}
}

// makeCSR builds a PEM CSR with the given CN + DNS SANs.
func makeCSR(t *testing.T, cn string, dns []string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
