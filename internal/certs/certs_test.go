package certs_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/nofuturekid/step-ui-ng/internal/audit"
	"github.com/nofuturekid/step-ui-ng/internal/ca"
	"github.com/nofuturekid/step-ui-ng/internal/certs"
	"github.com/nofuturekid/step-ui-ng/internal/crypto"
)

// pkcs12Decode decodes a PFX bundle with the given password, returning the key,
// leaf and CA certs so the test can assert the bundle round-trips.
func pkcs12Decode(pfx []byte, password string) (any, *x509.Certificate, []*x509.Certificate, error) {
	return pkcs12.DecodeChain(pfx, password)
}

// --- Test harness -----------------------------------------------------------

// fakeSigner stands in for the live CA: it records what it was asked to sign and
// returns a self-signed leaf built from the CSR, so the certs domain logic
// (keygen, CSR build, persistence, sealing, audit) is tested deterministically.
// The real OTT flow is proven in internal/ca against an httptest CA.
type fakeSigner struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	lastCSR  *x509.CertificateRequest
	lastDays int
	err      error
}

func newFakeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return &fakeSigner{root: cert, rootKey: key}
}

func (f *fakeSigner) SignCSR(_ context.Context, p ca.SignParams) (ca.SignResult, error) {
	if f.err != nil {
		return ca.SignResult{}, f.err
	}
	csr, err := x509.ParseCertificateRequest(decodePEM(p.CSRPEM))
	if err != nil {
		return ca.SignResult{}, err
	}
	f.lastCSR = csr
	f.lastDays = p.ValidityDays

	notAfter := time.Now().Add(time.Duration(maxInt(p.ValidityDays, 1)) * 24 * time.Hour)
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
	leafPEM := pemString(leafDER)
	chainPEM := pemString(f.root.Raw)
	return ca.SignResult{
		Certificate:  leaf,
		CertPEM:      leafPEM,
		ChainPEM:     chainPEM,
		FullchainPEM: leafPEM + chainPEM,
	}, nil
}

func decodePEM(s string) []byte {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil
	}
	return b.Bytes
}

func pemString(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// fakeRevoker stands in for the live CA revoke flow: it records the params it was
// called with and returns a configurable error so the domain's revoke logic
// (already-revoked guard, status-only-on-success, audit) is tested
// deterministically. The real OTT revoke flow is proven in internal/ca against
// an httptest CA.
type fakeRevoker struct {
	calls      int
	lastSerial string
	lastReason string
	err        error
}

func (f *fakeRevoker) RevokeCert(_ context.Context, p ca.RevokeParams) error {
	f.calls++
	f.lastSerial = p.Serial
	f.lastReason = p.Reason
	return f.err
}

// testService builds a certs.Service over an in-memory DB, a real crypto.Box, an
// audit.Recorder, the fake signer and the fake revoker.
func testService(t *testing.T) (*certs.Service, *sql.DB, *fakeSigner, *fakeRevoker) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mustExec(t, db, certsSchema)
	mustExec(t, db, auditSchema)

	box, err := crypto.NewBox(t.TempDir())
	if err != nil {
		t.Fatalf("new box: %v", err)
	}
	signer := newFakeSigner(t)
	revoker := &fakeRevoker{}
	svc := certs.NewService(db, box, audit.NewRecorder(db), signer, revoker)
	return svc, db, signer, revoker
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("exec schema: %v", err)
	}
}

const certsSchema = `CREATE TABLE certificates (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	cn TEXT NOT NULL, sans_json TEXT NOT NULL, serial TEXT NOT NULL,
	not_before INTEGER NOT NULL, not_after INTEGER NOT NULL, status TEXT NOT NULL,
	key_strategy TEXT NOT NULL CHECK (key_strategy IN ('server','csr')),
	cert_pem TEXT NOT NULL, chain_pem TEXT NOT NULL, fullchain_pem TEXT NOT NULL,
	privkey_sealed TEXT, created_by TEXT NOT NULL,
	created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
	provisioner TEXT
) STRICT;`

const auditSchema = `CREATE TABLE audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT NOT NULL, action TEXT NOT NULL,
	target TEXT NOT NULL, details TEXT NOT NULL, created_at INTEGER NOT NULL
) STRICT;`

// --- Acceptance: Issue for example.test + a SAN → stored (FR-1) -------------

func TestIssueStoresCertificateAndKey(t *testing.T) {
	svc, db, signer, _ := testService(t)

	cert, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor:           "alice",
		ProvisionerName: "ui-jwk",
		Password:        "pass",
		CAURL:           "https://ca.test",
		Fingerprint:     "fp",
		CN:              "example.test",
		SANs:            []string{"www.example.test"},
		ValidityDays:    30,
		Format:          certs.FormatPEM,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cert.CN != "example.test" || cert.KeyStrategy != "server" {
		t.Fatalf("cert = %+v, want CN example.test / server", cert)
	}

	// The CSR the signer saw must carry the CN as a DNS SAN plus the extra SAN.
	if !containsStr(signer.lastCSR.DNSNames, "example.test") ||
		!containsStr(signer.lastCSR.DNSNames, "www.example.test") {
		t.Fatalf("signed CSR DNSNames = %v, want example.test + www.example.test", signer.lastCSR.DNSNames)
	}

	// Stored in the inventory with a sealed private key (server strategy).
	var (
		cn, serial, keyStrategy, sansJSON string
		privSealed                        sql.NullString
		certPEM, fullchain                string
	)
	if err := db.QueryRow(`SELECT cn, serial, key_strategy, sans_json, privkey_sealed, cert_pem, fullchain_pem
		FROM certificates WHERE id = ?`, cert.ID).
		Scan(&cn, &serial, &keyStrategy, &sansJSON, &privSealed, &certPEM, &fullchain); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if cn != "example.test" || keyStrategy != "server" {
		t.Fatalf("stored cn/strategy = %q/%q", cn, keyStrategy)
	}
	if !privSealed.Valid || privSealed.String == "" {
		t.Fatal("server-generated key must be stored sealed")
	}
	// The sealed value must not be the raw PEM (defence in depth).
	if strings.Contains(privSealed.String, "PRIVATE KEY") {
		t.Fatal("private key stored in clear text")
	}
	var sans []string
	_ = json.Unmarshal([]byte(sansJSON), &sans)
	if !containsStr(sans, "example.test") {
		t.Fatalf("sans_json = %s, missing the CN", sansJSON)
	}
	if certPEM == "" || fullchain == "" {
		t.Fatal("PEM material not stored")
	}
}

// --- Acceptance: audit actor recorded for issue (FR-4) ----------------------

func TestIssueRecordsAuditActor(t *testing.T) {
	svc, db, _, _ := testService(t)
	if _, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor: "alice", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CN: "audit.test", ValidityDays: 1, Format: certs.FormatPEM,
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	var who, action, target string
	if err := db.QueryRow(`SELECT who, action, target FROM audit_events WHERE action = 'issue'`).
		Scan(&who, &action, &target); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if who != "alice" {
		t.Fatalf("audit who = %q, want alice (the session user, not system)", who)
	}
	if target != "audit.test" {
		t.Fatalf("audit target = %q, want audit.test", target)
	}
}

// --- Issue rejects an empty CN (FR-5) ---------------------------------------

func TestIssueRejectsEmptyCN(t *testing.T) {
	svc, _, _, _ := testService(t)
	_, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor: "alice", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CN: "  ", ValidityDays: 1, Format: certs.FormatPEM,
	})
	if !errors.Is(err, certs.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput for empty CN", err)
	}
}

// --- Issue PFX format produces a PKCS#12 bundle -----------------------------

func TestIssuePFXReturnsBundle(t *testing.T) {
	svc, _, _, _ := testService(t)
	cert, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor: "alice", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CN: "pfx.test", ValidityDays: 1,
		Format: certs.FormatPFX, PFXPassword: "bundle-pass",
	})
	if err != nil {
		t.Fatalf("Issue PFX: %v", err)
	}
	if len(cert.PFX) == 0 {
		t.Fatal("expected a non-empty PFX bundle")
	}
	// The bundle must decode with the given password and round-trip the key+cert.
	if _, _, _, err := pkcs12Decode(cert.PFX, "bundle-pass"); err != nil {
		t.Fatalf("PFX does not decode with its password: %v", err)
	}
	if _, _, _, err := pkcs12Decode(cert.PFX, "wrong"); err == nil {
		t.Fatal("PFX decoded with the wrong password")
	}
}

// --- SECURITY: PFX mode must NOT also expose the plaintext PEM private key ----
//
// The PFX format is chosen precisely so the key travels password-protected.
// Returning PrivateKeyPEM as well would render the unprotected key in the result
// page's textarea, defeating the point. This test FAILS if the format-conditional
// assignment is reverted to unconditionally setting PrivateKeyPEM.
func TestIssuePFXDoesNotLeakPlaintextKey(t *testing.T) {
	svc, _, _, _ := testService(t)
	cert, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor: "alice", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CN: "pfx-noleak.test", ValidityDays: 1,
		Format: certs.FormatPFX, PFXPassword: "bundle-pass",
	})
	if err != nil {
		t.Fatalf("Issue PFX: %v", err)
	}
	if len(cert.PFX) == 0 {
		t.Fatal("expected a non-empty PFX bundle in PFX mode")
	}
	if cert.PrivateKeyPEM != "" {
		t.Fatalf("PFX mode leaked the plaintext PEM private key (len=%d): the password-protected PFX is the ONLY key payload", len(cert.PrivateKeyPEM))
	}
}

// --- PEM mode delivers the PEM key and NO PFX --------------------------------
//
// The two key payloads are mutually exclusive by format: exactly one is set.
func TestIssuePEMDeliversKeyAndNoPFX(t *testing.T) {
	svc, _, _, _ := testService(t)
	cert, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor: "alice", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CN: "pem-only.test", ValidityDays: 1,
		Format: certs.FormatPEM,
	})
	if err != nil {
		t.Fatalf("Issue PEM: %v", err)
	}
	if !strings.Contains(cert.PrivateKeyPEM, "PRIVATE KEY") {
		t.Fatalf("PEM mode must deliver the PEM private key, got %q", cert.PrivateKeyPEM)
	}
	if len(cert.PFX) != 0 {
		t.Fatalf("PEM mode must not produce a PFX bundle, got %d bytes", len(cert.PFX))
	}
}

// --- Acceptance: Sign a valid CSR → CN/SANs from the CSR (FR-2) -------------

func TestSignCSRTakesCNAndSANsFromCSR(t *testing.T) {
	svc, db, signer, _ := testService(t)

	csrPEM := buildClientCSR(t, "client.test",
		[]string{"alt.client.test"},
		[]string{"10.0.0.5"},
		[]string{"admin@client.test"},
		[]string{"spiffe://client.test/svc"})

	cert, err := svc.Sign(context.Background(), certs.SignParams{
		Actor: "bob", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CSRPEM: csrPEM, ValidityDays: 10,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if cert.CN != "client.test" || cert.KeyStrategy != "csr" {
		t.Fatalf("cert = %+v, want client.test / csr", cert)
	}
	// SANs must come from the CSR (DNS/IP/email/URI).
	for _, want := range []string{"alt.client.test", "10.0.0.5", "admin@client.test", "spiffe://client.test/svc"} {
		if !containsStr(cert.SANs, want) {
			t.Fatalf("cert SANs %v missing %q (must be taken from the CSR)", cert.SANs, want)
		}
	}
	// The signer must have received exactly the CSR (CN from the CSR subject).
	if signer.lastCSR.Subject.CommonName != "client.test" {
		t.Fatalf("signer CN = %q, want client.test", signer.lastCSR.Subject.CommonName)
	}

	// Stored with NO private key (csr strategy).
	var keyStrategy string
	var privSealed sql.NullString
	if err := db.QueryRow(`SELECT key_strategy, privkey_sealed FROM certificates WHERE id = ?`, cert.ID).
		Scan(&keyStrategy, &privSealed); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if keyStrategy != "csr" {
		t.Fatalf("key_strategy = %q, want csr", keyStrategy)
	}
	if privSealed.Valid {
		t.Fatal("a CSR-signed certificate must store no private key")
	}
}

// --- Acceptance: invalid/garbled CSR → rejected (FR-2/FR-5) -----------------

func TestSignRejectsGarbledCSR(t *testing.T) {
	svc, _, _, _ := testService(t)
	_, err := svc.Sign(context.Background(), certs.SignParams{
		Actor: "bob", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\ngarbage\n-----END CERTIFICATE REQUEST-----\n",
	})
	if !errors.Is(err, certs.ErrInvalidCSR) {
		t.Fatalf("err = %v, want ErrInvalidCSR for a garbled CSR", err)
	}
}

// --- CSR signature verification: a CSR whose signature is invalid is rejected
// BEFORE any CA call (FR-2 "verify the CSR signature"). -----------------------

func TestSignRejectsBadSignatureCSR(t *testing.T) {
	svc, _, signer, _ := testService(t)
	csrPEM := tamperedCSR(t, "evil.test")
	_, err := svc.Sign(context.Background(), certs.SignParams{
		Actor: "bob", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp",
		CSRPEM: csrPEM,
	})
	if !errors.Is(err, certs.ErrInvalidCSR) {
		t.Fatalf("err = %v, want ErrInvalidCSR for a CSR with a broken signature", err)
	}
	if signer.lastCSR != nil {
		t.Fatal("a CSR with a bad signature must never reach the CA")
	}
}

// --- Sign records the audit actor (FR-4) ------------------------------------

func TestSignRecordsAuditActor(t *testing.T) {
	svc, db, _, _ := testService(t)
	csrPEM := buildClientCSR(t, "sign-audit.test", nil, nil, nil, nil)
	if _, err := svc.Sign(context.Background(), certs.SignParams{
		Actor: "carol", ProvisionerName: "p", Password: "x",
		CAURL: "https://ca.test", Fingerprint: "fp", CSRPEM: csrPEM,
	}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var who, action string
	if err := db.QueryRow(`SELECT who, action FROM audit_events WHERE action = 'sign'`).
		Scan(&who, &action); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if who != "carol" {
		t.Fatalf("audit who = %q, want carol", who)
	}
}

// --- ParseCSR extracts CN + SANs incl. IP/email/URI -------------------------

func TestParseCSRExtractsAllSANTypes(t *testing.T) {
	csrPEM := buildClientCSR(t, "parse.test",
		[]string{"a.parse.test"}, []string{"192.168.1.1"},
		[]string{"u@parse.test"}, []string{"https://parse.test/x"})
	info, err := certs.ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	if info.CN != "parse.test" {
		t.Fatalf("CN = %q", info.CN)
	}
	for _, want := range []string{"a.parse.test", "192.168.1.1", "u@parse.test", "https://parse.test/x"} {
		if !containsStr(info.SANs, want) {
			t.Fatalf("SANs %v missing %q", info.SANs, want)
		}
	}
}

// A CSR with a tampered signature is rejected by ParseCSR's signature check.
func TestParseCSRRejectsBadSignature(t *testing.T) {
	if _, err := certs.ParseCSR(tamperedCSR(t, "x.test")); !errors.Is(err, certs.ErrInvalidCSR) {
		t.Fatalf("err = %v, want ErrInvalidCSR", err)
	}
}

// --- helpers ----------------------------------------------------------------

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// buildClientCSR builds a properly self-signed CSR with the given CN + SANs.
func buildClientCSR(t *testing.T, cn string, dns, ips, emails, uris []string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cn},
		DNSNames:       dns,
		EmailAddresses: emails,
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	for _, u := range uris {
		parsed, _ := url.Parse(u)
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// tamperedCSR builds a valid CSR then flips a byte in its signature so
// CheckSignature fails, but the DER still parses.
func tamperedCSR(t *testing.T, cn string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	// Flip the last byte (part of the signature) to break the signature while
	// keeping the structure parseable.
	der[len(der)-1] ^= 0xFF
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
