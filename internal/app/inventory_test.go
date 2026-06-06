package app_test

// spec/0007 — inventory & encrypted re-download handler acceptance tests.
//
// Acceptance criteria tested here:
//   - GET /inventory renders the cert list (auth required; any role may browse).
//   - Filter by status and search text narrows the list.
//   - GET /certificates/{id} renders the detail view.
//   - GET /certificates/{id}/download is admin+ only (RBAC, FR-4).
//   - Download response: Content-Type=application/zip, Content-Disposition=attachment,
//     Cache-Control=no-store (FR-4 + security headers).
//   - Server-issued cert download → ZIP contains privkey.pem (asserting key PEM).
//   - CSR-signed cert download → ZIP omits privkey.pem.
//   - Download with pfx_password includes cert.p12.
//   - Unauthenticated GET /inventory → redirect to /login.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/audit"
	"github.com/nofuturekid/step-ui-ng/internal/ca"
	"github.com/nofuturekid/step-ui-ng/internal/certs"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// --- Acceptance: auth & RBAC ------------------------------------------------

// Unauthenticated request → redirect to /login.
func TestInventoryRequiresAuth(t *testing.T) {
	e := newTestEnv(t)
	e.seedUser(t, "root", users.RoleSuperadmin)

	resp, _ := e.get(t, "/inventory")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("unauthenticated GET /inventory = %d %q, want 303 /login",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

// Any authenticated role can browse /inventory (read-only).
func TestInventoryAccessibleToAllRoles(t *testing.T) {
	for _, role := range []users.Role{users.RoleViewer, users.RoleAdmin, users.RoleSuperadmin} {
		t.Run(string(role), func(t *testing.T) {
			e := newTestEnv(t)
			e.completeSetup(t, "root")
			e.seedUser(t, "testuser", role)
			e.switchTo(t, "testuser")

			resp, _ := e.get(t, "/inventory")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("role %s GET /inventory = %d, want 200", role, resp.StatusCode)
			}
		})
	}
}

// Viewer cannot download (admin+ required).
func TestDownloadRequiresAdmin(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "viewer1xx", users.RoleViewer)
	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "rbac-viewer.test", now.Add(30*24*time.Hour).Unix())

	e.switchTo(t, "viewer1xx")
	// The viewer can access /inventory (read-only), so we can get a valid CSRF
	// token from there and use it for the POST attempt.
	token := e.csrfToken(t, "/inventory")
	resp, _ := e.postResp(t, fmt.Sprintf("/certificates/%d/download", id), url.Values{
		"csrf_token": {token},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer download = %d, want 403", resp.StatusCode)
	}
}

// --- Acceptance: inventory list & filters -----------------------------------

// GET /inventory lists all certificates in the response body.
func TestInventoryListShowsCerts(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertMinimalCert(t, e.db, "list-alpha.test", now.Add(30*24*time.Hour).Unix())
	invInsertMinimalCert(t, e.db, "list-beta.test", now.Add(-24*time.Hour).Unix())

	_, body := e.get(t, "/inventory")
	if !strings.Contains(body, "list-alpha.test") {
		t.Errorf("inventory missing list-alpha.test")
	}
	if !strings.Contains(body, "list-beta.test") {
		t.Errorf("inventory missing list-beta.test")
	}
}

// ?status=active shows only non-expired, non-revoked certs.
func TestInventoryFilterByStatus(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertMinimalCert(t, e.db, "filter-active.test", now.Add(30*24*time.Hour).Unix())
	invInsertMinimalCert(t, e.db, "filter-expired.test", now.Add(-24*time.Hour).Unix())

	_, body := e.get(t, "/inventory?status=active")
	if !strings.Contains(body, "filter-active.test") {
		t.Errorf("active filter: missing filter-active.test in body")
	}
	if strings.Contains(body, "filter-expired.test") {
		t.Errorf("active filter: unexpected filter-expired.test in body")
	}
}

// ?q=<text> narrows the list to matching CN/SAN.
func TestInventoryFilterBySearch(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	invInsertMinimalCert(t, e.db, "search-foo.test", now.Add(30*24*time.Hour).Unix())
	invInsertMinimalCert(t, e.db, "search-bar.test", now.Add(30*24*time.Hour).Unix())

	_, body := e.get(t, "/inventory?q=foo")
	if !strings.Contains(body, "search-foo.test") {
		t.Errorf("search filter: missing search-foo.test")
	}
	if strings.Contains(body, "search-bar.test") {
		t.Errorf("search filter: unexpected search-bar.test")
	}
}

// --- Acceptance: detail view ------------------------------------------------

// GET /certificates/{id} renders the detail view with the cert's CN.
func TestCertDetailView(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "detail-view.test", now.Add(30*24*time.Hour).Unix())

	_, body := e.get(t, fmt.Sprintf("/certificates/%d", id))
	if !strings.Contains(body, "detail-view.test") {
		t.Errorf("detail view missing CN; body snippet: %q", truncate(body, 200))
	}
}

// GET /certificates/{id} for a non-existent ID returns 404.
func TestCertDetailNotFound(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	resp, _ := e.get(t, "/certificates/99999")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing cert = %d, want 404", resp.StatusCode)
	}
}

// --- Acceptance: download response headers ----------------------------------

// Admin can download via POST; response carries the required headers and is a valid ZIP.
func TestDownloadResponseHeaders(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root") // superadmin = admin+

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "headers.test", now.Add(30*24*time.Hour).Unix())
	path := fmt.Sprintf("/certificates/%d/download", id)
	token := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))

	resp, body := e.postResp(t, path, url.Values{"csrf_token": {token}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d, want 200; body: %q", resp.StatusCode, truncate(body, 200))
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/zip") {
		t.Errorf("Content-Type = %q, want application/zip", ct)
	}
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", cd)
	}
	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// --- Acceptance: bundle contents per key strategy ---------------------------

// Server-issued cert download (POST) includes privkey.pem; key PEM is parseable.
func TestDownloadServerCertIncludesKey(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Issue a real server cert so its sealed key is in the DB.
	id := invSeedServerCert(t, e, "server-dl.test")
	path := fmt.Sprintf("/certificates/%d/download", id)
	token := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))

	resp, rawBody := e.postResp(t, path, url.Values{"csrf_token": {token}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download = %d: %s", resp.StatusCode, truncate(rawBody, 300))
	}

	zr := invMustOpenZip(t, []byte(rawBody))
	invMustHaveEntry(t, zr, "privkey.pem")
	invMustHaveEntry(t, zr, "cert.pem")
	invMustHaveEntry(t, zr, "chain.pem")
	invMustHaveEntry(t, zr, "fullchain.pem")

	// The key PEM must parse as a PKCS#8 private key.
	keyBytes := invZipEntry(t, zr, "privkey.pem")
	if !strings.Contains(string(keyBytes), "PRIVATE KEY") {
		t.Fatalf("privkey.pem does not look like a PEM key: %q", string(keyBytes))
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("privkey.pem: expected PRIVATE KEY PEM block")
	}
}

// CSR-signed cert download (POST) omits privkey.pem.
func TestDownloadCSRCertOmitsKey(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "csr-download.test", now.Add(30*24*time.Hour).Unix())
	path := fmt.Sprintf("/certificates/%d/download", id)
	token := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))

	resp, rawBody := e.postResp(t, path, url.Values{"csrf_token": {token}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download = %d", resp.StatusCode)
	}
	zr := invMustOpenZip(t, []byte(rawBody))
	invMustHaveEntry(t, zr, "cert.pem")
	invMustNoEntry(t, zr, "privkey.pem")
}

// TestDownloadIsPostNotGet asserts that the download endpoint is registered as
// POST (not GET). A GET to the old URL path must NOT succeed (405 or 404 — not
// 200). This test fails if the route is reverted to GET.
func TestDownloadIsPostNotGet(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "get-is-gone.test", now.Add(30*24*time.Hour).Unix())

	resp, _ := e.get(t, fmt.Sprintf("/certificates/%d/download", id))
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("GET /certificates/%d/download = 200; download must be POST only, not GET", id)
	}
}

// TestDownloadPasswordFromPostBody asserts that the PFX password is read from
// the POST body (r.PostFormValue) and not from the URL query string. A POST with
// the password in the form body must succeed (cert.p12 in ZIP), while a POST
// with the password only in the query string must produce a ZIP without cert.p12
// (password is not read from the URL). This test fails if the handler reads the
// query string instead of the form body.
func TestDownloadPasswordFromPostBody(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	id := invSeedServerCert(t, e, "postbody-pfx.test")
	path := fmt.Sprintf("/certificates/%d/download", id)

	// POST with password in form body → cert.p12 must be in the ZIP.
	token := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))
	resp, rawBody := e.postResp(t, path, url.Values{
		"csrf_token":   {token},
		"pfx_password": {"test-pass"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST download with body password = %d: %s", resp.StatusCode, truncate(rawBody, 300))
	}
	zr := invMustOpenZip(t, []byte(rawBody))
	invMustHaveEntry(t, zr, "cert.p12")

	// POST with password only in query string → cert.p12 must NOT be in the ZIP
	// (the handler reads the body, not the URL).
	token2 := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))
	resp2, rawBody2 := e.postResp(t, path+"?pfx_password=test-pass", url.Values{
		"csrf_token": {token2},
		// no pfx_password in body
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("POST download (query only) = %d: %s", resp2.StatusCode, truncate(rawBody2, 300))
	}
	zr2 := invMustOpenZip(t, []byte(rawBody2))
	invMustNoEntry(t, zr2, "cert.p12")
}

// TestDownloadPOSTResponseHeaders asserts that a POST download carries the
// required security headers (Content-Type, Content-Disposition, Cache-Control).
func TestDownloadPOSTResponseHeaders(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	now := time.Now()
	id := invInsertMinimalCert(t, e.db, "postheaders.test", now.Add(30*24*time.Hour).Unix())
	path := fmt.Sprintf("/certificates/%d/download", id)
	token := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))

	resp, body := e.postResp(t, path, url.Values{
		"csrf_token": {token},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST download = %d: %s", resp.StatusCode, truncate(body, 200))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/zip") {
		t.Errorf("Content-Type = %q, want application/zip", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", cd)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// Download with pfx_password in POST body includes cert.p12 in the ZIP.
func TestDownloadWithPFXPasswordIncludesP12(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	id := invSeedServerCert(t, e, "pfx-dl.test")
	path := fmt.Sprintf("/certificates/%d/download", id)
	token := e.csrfToken(t, fmt.Sprintf("/certificates/%d", id))
	resp, rawBody := e.postResp(t, path, url.Values{
		"csrf_token":   {token},
		"pfx_password": {"my-pass"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download = %d: %s", resp.StatusCode, truncate(rawBody, 300))
	}
	zr := invMustOpenZip(t, []byte(rawBody))
	invMustHaveEntry(t, zr, "cert.p12")
}

// --- helpers ----------------------------------------------------------------

// postResp sends a same-origin form POST and returns the full response + body.
// This is separate from the shared postBody helper (which returns only the
// status code) so download tests can inspect response headers and ZIP bytes.
func (e *testEnv) postResp(t *testing.T, path string, form url.Values) (*http.Response, string) {
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

// invInsertMinimalCert inserts a CSR-strategy cert row (no sealed key) and
// returns its ID.  Used when key material is not needed for the test.
func invInsertMinimalCert(t *testing.T, db *sql.DB, cn string, notAfter int64) int64 {
	t.Helper()
	ts := time.Now().Unix()
	res, err := db.Exec(`INSERT INTO certificates
		(cn, sans_json, serial, not_before, not_after, status, key_strategy,
		 cert_pem, chain_pem, fullchain_pem, privkey_sealed, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'valid', 'csr', 'certpem', 'chainpem', 'fullchainpem',
		        NULL, 'test', ?, ?)`,
		cn, `["`+cn+`"]`, "serial-"+cn, ts, notAfter, ts, ts)
	if err != nil {
		t.Fatalf("invInsertMinimalCert %s: %v", cn, err)
	}
	id, _ := res.LastInsertId()
	return id
}

// invSeedServerCert issues a real server cert via a fake signer, storing its
// sealed private key in the env's DB (same crypto.Box as the live handler).
// Returns the cert ID.
func invSeedServerCert(t *testing.T, e *testEnv, cn string) int64 {
	t.Helper()
	// Build a certs.Service wired to the same DB + box as the handler so the
	// sealed key can be opened during download.
	svc := certs.NewService(e.db, e.box, audit.NewRecorder(e.db), invFakeSigner(t))
	cert, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor: "root", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CN: cn, ValidityDays: 30, Format: certs.FormatPEM,
	})
	if err != nil {
		t.Fatalf("invSeedServerCert %q: %v", cn, err)
	}
	return cert.ID
}

// invFakeSigner returns a certs.Signer backed by an in-memory self-signed CA.
func invFakeSigner(t *testing.T) certs.Signer {
	t.Helper()
	return invFakeSignerVal(t)
}

// invMustOpenZip parses raw bytes as a ZIP archive, failing the test on error.
func invMustOpenZip(t *testing.T, data []byte) *zip.Reader {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse ZIP: %v (first 64 bytes: %q)", err, truncate(string(data), 64))
	}
	return zr
}

// invMustHaveEntry asserts that name is present in the ZIP.
func invMustHaveEntry(t *testing.T, zr *zip.Reader, name string) {
	t.Helper()
	for _, f := range zr.File {
		if f.Name == name {
			return
		}
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	t.Fatalf("ZIP missing %q; entries: %v", name, names)
}

// invMustNoEntry asserts that name is NOT present in the ZIP.
func invMustNoEntry(t *testing.T, zr *zip.Reader, name string) {
	t.Helper()
	for _, f := range zr.File {
		if f.Name == name {
			t.Fatalf("ZIP unexpectedly contains %q", name)
		}
	}
}

// invZipEntry reads all bytes from a named ZIP entry.
func invZipEntry(t *testing.T, zr *zip.Reader, name string) []byte {
	t.Helper()
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open zip entry %q: %v", name, err)
			}
			defer rc.Close()
			b, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("read zip entry %q: %v", name, err)
			}
			return b
		}
	}
	t.Fatalf("ZIP entry %q not found", name)
	return nil
}

// truncate returns the first n bytes of s (as a string) for safe diagnostic
// output in test failures.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// invFakeSignerVal returns a certs.Signer backed by a self-signed in-memory CA.
// It is used exclusively by inventory tests that need to seed real sealed keys.
func invFakeSignerVal(t *testing.T) certs.Signer {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Inv Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &caKey.PublicKey, caKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	return &invFakeCA{root: rootCert, rootKey: caKey, rootDER: rootDER}
}

type invFakeCA struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	rootDER []byte
}

func (f *invFakeCA) SignCSR(_ context.Context, p ca.SignParams) (ca.SignResult, error) {
	csrBlock, _ := pem.Decode([]byte(p.CSRPEM))
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return ca.SignResult{}, err
	}
	notAfter := time.Now().Add(time.Duration(p.ValidityDays) * 24 * time.Hour)
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        csr.Subject,
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, f.root, csr.PublicKey, f.rootKey)
	if err != nil {
		return ca.SignResult{}, err
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	chainPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.rootDER}))
	return ca.SignResult{
		Certificate:  leaf,
		CertPEM:      leafPEM,
		ChainPEM:     chainPEM,
		FullchainPEM: leafPEM + chainPEM,
	}, nil
}
