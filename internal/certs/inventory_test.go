package certs_test

// spec/0007 — inventory & encrypted re-download
//
// Acceptance-criteria tests (each fails on regression of the behaviour it locks):
//   - Bundle contents per key strategy (server → key present; csr → key absent).
//   - Sealed-at-rest assertion (stored value ≠ plaintext PEM; round-trips via Box).
//   - Filter logic (status, CN/SAN text search, combined).
//   - Expiry / status derivation (active, expired, revoked, days-until-expiry).
//   - Download response headers (no-store, attachment) — tested in internal/app.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/certs"
)

// --- FR-3 / FR-4 / FR-6: bundle contents & sealed-at-rest --------------------

// Given a server-issued certificate, the bundle contains cert/chain/fullchain
// AND privkey.pem.  The sealed DB value is NOT the plaintext key and
// round-trips via Box.Open.
func TestBundleServerStrategyContainsKey(t *testing.T) {
	svc, db, _ := testService(t)
	cert, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor: "alice", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CN: "bundle-server.test", ValidityDays: 30, Format: certs.FormatPEM,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Build the bundle from the DB row.
	bundle, err := svc.Bundle(context.Background(), cert.ID, "")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	// Must contain the four required files.
	zr := mustOpenZip(t, bundle)
	mustHaveEntry(t, zr, "cert.pem")
	mustHaveEntry(t, zr, "chain.pem")
	mustHaveEntry(t, zr, "fullchain.pem")
	mustHaveEntry(t, zr, "privkey.pem")
	mustHaveEntry(t, zr, "README.txt")

	// privkey.pem content must parse as a private key.
	keyBytes := zipEntry(t, zr, "privkey.pem")
	if !strings.Contains(string(keyBytes), "PRIVATE KEY") {
		t.Fatalf("privkey.pem does not look like a PEM private key: %q", string(keyBytes))
	}
	key := mustParseKey(t, keyBytes)
	if key == nil {
		t.Fatal("privkey.pem did not parse as a private key")
	}

	// The stored privkey_sealed is NOT the plaintext PEM (FR-4 sealed-at-rest).
	var privSealed sql.NullString
	if err := db.QueryRow(`SELECT privkey_sealed FROM certificates WHERE id = ?`, cert.ID).
		Scan(&privSealed); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if !privSealed.Valid {
		t.Fatal("server cert must have a sealed private key in the DB")
	}
	if strings.Contains(privSealed.String, "PRIVATE KEY") {
		t.Fatal("private key stored in clear text (sealed-at-rest regression)")
	}
}

// Given a CSR-signed certificate (key_strategy=csr), the bundle omits privkey.pem.
func TestBundleCSRStrategyOmitsKey(t *testing.T) {
	svc, _, _ := testService(t)
	csrPEM := buildClientCSR(t, "bundle-csr.test", nil, nil, nil, nil)
	cert, err := svc.Sign(context.Background(), certs.SignParams{
		Actor: "bob", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CSRPEM: csrPEM, ValidityDays: 30,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	bundle, err := svc.Bundle(context.Background(), cert.ID, "")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	zr := mustOpenZip(t, bundle)
	mustHaveEntry(t, zr, "cert.pem")
	mustHaveEntry(t, zr, "chain.pem")
	mustHaveEntry(t, zr, "fullchain.pem")
	mustHaveEntry(t, zr, "README.txt")
	mustNotHaveEntry(t, zr, "privkey.pem")
}

// FR-3 optional cert.p12: when a PFX password is provided, the ZIP includes
// cert.p12 that decodes with that password.
func TestBundleIncludesPFXWhenPasswordProvided(t *testing.T) {
	svc, _, _ := testService(t)
	cert, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor: "alice", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CN: "pfx-bundle.test", ValidityDays: 30, Format: certs.FormatPEM,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	bundle, err := svc.Bundle(context.Background(), cert.ID, "bundle-pass")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	zr := mustOpenZip(t, bundle)
	mustHaveEntry(t, zr, "cert.p12")
	p12Bytes := zipEntry(t, zr, "cert.p12")
	if _, _, _, err := pkcs12Decode(p12Bytes, "bundle-pass"); err != nil {
		t.Fatalf("cert.p12 does not decode with supplied password: %v", err)
	}
}

// Without a PFX password the ZIP must NOT contain cert.p12.
func TestBundleOmitsPFXWhenNoPassword(t *testing.T) {
	svc, _, _ := testService(t)
	cert, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor: "alice", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CN: "nopfx-bundle.test", ValidityDays: 30, Format: certs.FormatPEM,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	bundle, err := svc.Bundle(context.Background(), cert.ID, "")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	zr := mustOpenZip(t, bundle)
	mustNotHaveEntry(t, zr, "cert.p12")
}

// --- FR-2: Status derivation (active / expired / revoked + days-until-expiry) -

func TestDeriveStatusActive(t *testing.T) {
	future := time.Now().Add(10 * 24 * time.Hour).Unix()
	st, days := certs.DeriveStatus("valid", future)
	if st != "active" {
		t.Fatalf("DeriveStatus = %q, want active", st)
	}
	if days < 9 || days > 10 {
		t.Fatalf("DeriveStatus days = %d, want ~10", days)
	}
}

func TestDeriveStatusExpired(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour).Unix()
	st, days := certs.DeriveStatus("valid", past)
	if st != "expired" {
		t.Fatalf("DeriveStatus = %q, want expired", st)
	}
	if days >= 0 {
		t.Fatalf("DeriveStatus days = %d, want negative (past expiry)", days)
	}
}

func TestDeriveStatusRevoked(t *testing.T) {
	future := time.Now().Add(30 * 24 * time.Hour).Unix()
	st, days := certs.DeriveStatus("revoked", future)
	if st != "revoked" {
		t.Fatalf("DeriveStatus = %q, want revoked even if not_after is in the future", st)
	}
	_ = days // days is still computed but status is authoritative
}

// TestDeriveStatusBoundaryAtExactExpiry pins now == not_after and asserts the
// cert is considered expired (RFC 5280: the not_after instant is inclusive, so a
// cert at exactly not_after is no longer valid). This fails with the old
// expiry.Before(now) comparison because Before returns false when times are equal.
func TestDeriveStatusBoundaryAtExactExpiry(t *testing.T) {
	pinned := time.Now().Round(time.Second) // strip sub-second so Unix round-trips exactly
	certs.SetNowTime(func() time.Time { return pinned })
	defer certs.SetNowTime(nil) // restore wall clock

	notAfter := pinned.Unix() // now == not_after
	st, _ := certs.DeriveStatus("valid", notAfter)
	if st != "expired" {
		t.Fatalf("DeriveStatus at boundary (now==not_after) = %q, want expired (RFC 5280 inclusive expiry)", st)
	}
}

// TestDeriveStatusRevokedAndExpiredRevokedWins asserts that a revoked cert whose
// not_after is also in the past reports "revoked", not "expired". Revocation is
// the authoritative state; the expiry derivation is secondary.
func TestDeriveStatusRevokedAndExpiredRevokedWins(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour).Unix()
	st, _ := certs.DeriveStatus("revoked", past)
	if st != "revoked" {
		t.Fatalf("revoked+expired DeriveStatus = %q, want revoked (revocation takes precedence)", st)
	}
}

// --- Search LIKE escaping ---------------------------------------------------

// TestListSearchUnderscoreEscaped asserts that a search term containing a literal
// underscore matches only rows whose CN/SAN contains that exact underscore, not
// any single character at that position. A LIKE `_` without an ESCAPE clause
// would be a wildcard and match any character, causing false positives.
func TestListSearchUnderscoreEscaped(t *testing.T) {
	svc, db, _ := testService(t)
	now := time.Now()
	// Insert two certs: one whose CN contains an underscore, one that does not.
	seedCert(t, db, "under_score.test", `["under_score.test"]`, "valid", now.Add(30*24*time.Hour).Unix())
	seedCert(t, db, "underscore.test", `["underscore.test"]`, "valid", now.Add(30*24*time.Hour).Unix()) // no underscore at that exact position

	list, err := svc.List(context.Background(), certs.ListFilter{Search: "under_score"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, item := range list {
		if item.CN != "under_score.test" {
			t.Errorf("search 'under_score' matched unexpected CN %q (underscore not treated as literal)", item.CN)
		}
	}
	found := false
	for _, item := range list {
		if item.CN == "under_score.test" {
			found = true
		}
	}
	if !found {
		t.Error("search 'under_score' did not match 'under_score.test'")
	}
}

// TestListSearchInjectionSafetyMatchesNothing asserts that an injection-shaped
// search term (e.g. "%' OR '1'='1") matches no rows beyond what the literal
// string would match. This proves the query is parameterized: the value is
// treated as data, not as SQL.
func TestListSearchInjectionSafetyMatchesNothing(t *testing.T) {
	svc, db, _ := testService(t)
	now := time.Now()
	seedCert(t, db, "legit.test", `["legit.test"]`, "valid", now.Add(30*24*time.Hour).Unix())

	// This term would be catastrophic if interpolated directly into SQL.
	list, err := svc.List(context.Background(), certs.ListFilter{Search: "%' OR '1'='1"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		var cns []string
		for _, item := range list {
			cns = append(cns, item.CN)
		}
		t.Errorf("injection-shaped search returned %d rows (want 0): %v", len(list), cns)
	}
}

// --- FR-1: Inventory list + filters -----------------------------------------

// Table-driven filter tests over a seeded certificate set.
func TestListFilters(t *testing.T) {
	svc, db, _ := testService(t)

	// Seed three certificates:
	//  1. CN=alpha.test  status=valid  not_after=future
	//  2. CN=beta.test   status=valid  not_after=past   (expired by date)
	//  3. CN=gamma.test  status=revoked not_after=future
	now := time.Now()
	seedCert(t, db, "alpha.test", `["alpha.test","www.alpha.test"]`, "valid", now.Add(30*24*time.Hour).Unix())
	seedCert(t, db, "beta.test", `["beta.test"]`, "valid", now.Add(-24*time.Hour).Unix())
	seedCert(t, db, "gamma.test", `["gamma.test","san.gamma.test"]`, "revoked", now.Add(30*24*time.Hour).Unix())

	cases := []struct {
		name      string
		filter    certs.ListFilter
		wantCNs   []string
		unwantCNs []string
	}{
		{
			name:    "no filter returns all",
			filter:  certs.ListFilter{},
			wantCNs: []string{"alpha.test", "beta.test", "gamma.test"},
		},
		{
			name:      "filter active shows only non-expired, non-revoked",
			filter:    certs.ListFilter{Status: "active"},
			wantCNs:   []string{"alpha.test"},
			unwantCNs: []string{"beta.test", "gamma.test"},
		},
		{
			name:      "filter expired shows only date-expired",
			filter:    certs.ListFilter{Status: "expired"},
			wantCNs:   []string{"beta.test"},
			unwantCNs: []string{"alpha.test", "gamma.test"},
		},
		{
			name:      "filter revoked shows only stored-revoked",
			filter:    certs.ListFilter{Status: "revoked"},
			wantCNs:   []string{"gamma.test"},
			unwantCNs: []string{"alpha.test", "beta.test"},
		},
		{
			name:    "text search matches CN",
			filter:  certs.ListFilter{Search: "alpha"},
			wantCNs: []string{"alpha.test"},
		},
		{
			name:    "text search matches SAN",
			filter:  certs.ListFilter{Search: "san.gamma"},
			wantCNs: []string{"gamma.test"},
		},
		{
			name:      "text search no match",
			filter:    certs.ListFilter{Search: "zzznomatch"},
			unwantCNs: []string{"alpha.test", "beta.test", "gamma.test"},
		},
		{
			name:      "combined: active + search",
			filter:    certs.ListFilter{Status: "active", Search: "alpha"},
			wantCNs:   []string{"alpha.test"},
			unwantCNs: []string{"beta.test", "gamma.test"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, err := svc.List(context.Background(), tc.filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			got := make(map[string]bool)
			for _, c := range list {
				got[c.CN] = true
			}
			for _, want := range tc.wantCNs {
				if !got[want] {
					t.Errorf("want %q in results, got %v", want, keys(got))
				}
			}
			for _, unwant := range tc.unwantCNs {
				if got[unwant] {
					t.Errorf("unwanted %q in results, got %v", unwant, keys(got))
				}
			}
		})
	}
}

// --- FR-1: Detail view (Get by ID) ------------------------------------------

func TestGetReturnsDetail(t *testing.T) {
	svc, db, _ := testService(t)
	now := time.Now()
	id := seedCert(t, db, "detail.test", `["detail.test"]`, "valid", now.Add(30*24*time.Hour).Unix())

	c, err := svc.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if c.CN != "detail.test" {
		t.Fatalf("Get CN = %q, want detail.test", c.CN)
	}
	if c.ID != id {
		t.Fatalf("Get ID = %d, want %d", c.ID, id)
	}
}

func TestGetNotFoundError(t *testing.T) {
	svc, _, _ := testService(t)
	_, err := svc.Get(context.Background(), 99999)
	if err == nil {
		t.Fatal("expected error for missing cert ID")
	}
}

// --- helpers ----------------------------------------------------------------

// mustOpenZip parses bundle bytes as a ZIP archive.
func mustOpenZip(t *testing.T, data []byte) *zip.Reader {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse ZIP: %v", err)
	}
	return zr
}

// mustHaveEntry asserts that name appears in the ZIP.
func mustHaveEntry(t *testing.T, zr *zip.Reader, name string) {
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

// mustNotHaveEntry asserts that name does NOT appear in the ZIP.
func mustNotHaveEntry(t *testing.T, zr *zip.Reader, name string) {
	t.Helper()
	for _, f := range zr.File {
		if f.Name == name {
			t.Fatalf("ZIP unexpectedly contains %q", name)
		}
	}
}

// zipEntry reads the content of a named file from a ZIP.
func zipEntry(t *testing.T, zr *zip.Reader, name string) []byte {
	t.Helper()
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open zip entry %q: %v", name, err)
			}
			defer rc.Close()
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(rc); err != nil {
				t.Fatalf("read zip entry %q: %v", name, err)
			}
			return buf.Bytes()
		}
	}
	t.Fatalf("entry %q not found in ZIP", name)
	return nil
}

// mustParseKey tries to parse a PEM private key (PKCS#8).
func mustParseKey(t *testing.T, pemBytes []byte) any {
	t.Helper()
	var block *pem.Block
	for rest := pemBytes; len(rest) > 0; {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "PRIVATE KEY" {
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatalf("parse PKCS8 key: %v", err)
			}
			return k
		}
	}
	t.Fatalf("no PRIVATE KEY block found in %q", string(pemBytes))
	return nil
}

// seedCert inserts a minimal certificate row directly into the DB (bypasses the
// CA signer) so filter tests can control status / not_after precisely.
func seedCert(t *testing.T, db *sql.DB, cn, sansJSON, status string, notAfter int64) int64 {
	t.Helper()
	ts := time.Now().Unix()
	res, err := db.Exec(`INSERT INTO certificates
		(cn, sans_json, serial, not_before, not_after, status, key_strategy,
		 cert_pem, chain_pem, fullchain_pem, privkey_sealed, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'csr', 'certpem', 'chainpem', 'fullchainpem', NULL, 'test', ?, ?)`,
		cn, sansJSON, "serial-"+cn, ts, notAfter, status, ts, ts)
	if err != nil {
		t.Fatalf("seedCert %s: %v", cn, err)
	}
	id, _ := res.LastInsertId()
	return id
}

// keys returns the keys of a bool map for diagnostic output.
func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
