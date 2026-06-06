// Package certs is the certificate domain (spec/0006): issue a server-generated
// certificate, or sign a client-supplied CSR, via the CA's active provisioner,
// then persist the result and emit an audit event.
//
// Two key strategies (spec/0006 data model):
//   - "server": the UI generates the keypair, builds the CSR, and stores the
//     private key SEALED at rest (AES-256-GCM via internal/crypto). The plaintext
//     key is returned to the requesting user EXACTLY ONCE, inline on the issue
//     result response, and never logged. The format selects a single payload:
//     PEM mode returns the unprotected PEM key; PFX mode returns ONLY the
//     password-protected PKCS#12 bundle (never the plaintext key as well). The
//     handler marks any key-bearing response no-store so it is not cached; there
//     is no persistent re-download here (that is spec/0007).
//   - "csr": the client kept its private key; the UI only stores the issued
//     certificate (privkey_sealed is NULL).
//
// Handlers stay thin — all of this logic lives here (AGENTS.md). The CA call is
// behind the Signer interface so the domain is unit-testable without a live CA;
// the real OTT signing flow is proven in internal/ca against an httptest CA.
package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"go.step.sm/crypto/pemutil"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
	appcrypto "github.com/nofuturekid/step-ui-ng/internal/crypto"
)

// Domain errors, matchable via errors.Is so handlers map them to user-facing
// messages (FR-5).
var (
	// ErrInvalidInput means a required field (e.g. CN) is missing or invalid.
	ErrInvalidInput = errors.New("certs: invalid input")
	// ErrInvalidCSR means the supplied CSR could not be parsed or its signature
	// did not verify (FR-2).
	ErrInvalidCSR = errors.New("certs: invalid CSR")
)

// Format selects the download bundle produced for a server-generated key.
type Format string

const (
	// FormatPEM bundles the cert/chain/key as PEM.
	FormatPEM Format = "pem"
	// FormatPFX bundles the cert/chain/key as PKCS#12 (PFX), password-protected.
	FormatPFX Format = "pfx"
)

// Signer obtains a certificate for a CSR from the CA. It matches ca.SignCSR so
// the production wiring passes ca.SignCSR directly; tests substitute a fake.
type Signer interface {
	SignCSR(ctx context.Context, p ca.SignParams) (ca.SignResult, error)
}

// caSignerFunc adapts ca.SignCSR (a plain func) to the Signer interface.
type caSignerFunc func(ctx context.Context, p ca.SignParams) (ca.SignResult, error)

func (f caSignerFunc) SignCSR(ctx context.Context, p ca.SignParams) (ca.SignResult, error) {
	return f(ctx, p)
}

// LiveSigner returns a Signer backed by the real ca.SignCSR.
func LiveSigner() Signer { return caSignerFunc(ca.SignCSR) }

// Recorder is the audit sink (internal/audit.Recorder satisfies it).
type Recorder interface {
	Record(ctx context.Context, who, action, target, details string) error
}

// Service issues and signs certificates and persists them.
type Service struct {
	db     *sql.DB
	box    *appcrypto.Box
	audit  Recorder
	signer Signer
}

// NewService wires the persistence, sealing box, audit recorder and CA signer.
func NewService(db *sql.DB, box *appcrypto.Box, audit Recorder, signer Signer) *Service {
	return &Service{db: db, box: box, audit: audit, signer: signer}
}

// now is overridable in tests; defaults to wall-clock unix seconds.
var now = func() int64 { return time.Now().Unix() }

// Certificate is the stored/returned view of an issued or signed certificate.
// PrivateKeyPEM and PFX are populated only for a freshly server-generated key and
// are MUTUALLY EXCLUSIVE: exactly one is set per the requested Format (PEM →
// PrivateKeyPEM, PFX → PFX). They are the one-shot download payload delivered
// inline on the result response; they are never persisted in clear text or logged.
type Certificate struct {
	ID            int64
	CN            string
	SANs          []string
	Serial        string
	NotBefore     int64
	NotAfter      int64
	Status        string
	KeyStrategy   string // "server" | "csr"
	CertPEM       string
	ChainPEM      string
	FullchainPEM  string
	PrivateKeyPEM string // server strategy + FormatPEM only; one-shot payload, not persisted
	PFX           []byte // server strategy + FormatPFX only; one-shot payload, not persisted
}

// IssueParams are the inputs to Issue (FR-1).
type IssueParams struct {
	Actor           string // the authenticated session user (audit who, FR-4)
	ProvisionerName string
	Password        string // selected provisioner secret (from sealed settings)
	CAURL           string
	Fingerprint     string
	CN              string
	SANs            []string
	ValidityDays    int
	Format          Format
	PFXPassword     string // required for FormatPFX
}

// Issue generates a keypair server-side, builds a CSR for CN + SANs (the CN is
// also added as a SAN so the leaf is valid for it), obtains the certificate from
// the CA, seals the private key, persists everything with key_strategy=server,
// and records an audit event attributed to Actor.
func (s *Service) Issue(ctx context.Context, p IssueParams) (Certificate, error) {
	cn := strings.TrimSpace(p.CN)
	if cn == "" {
		return Certificate{}, fmt.Errorf("%w: common name is required", ErrInvalidInput)
	}
	if p.Format == FormatPFX && p.PFXPassword == "" {
		return Certificate{}, fmt.Errorf("%w: a PFX password is required for the PKCS#12 format", ErrInvalidInput)
	}

	sans := normalizeSANs(cn, p.SANs)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Certificate{}, fmt.Errorf("certs: generate key: %w", err)
	}
	csrPEM, err := buildCSR(cn, sans, key)
	if err != nil {
		return Certificate{}, err
	}

	res, err := s.signer.SignCSR(ctx, ca.SignParams{
		CAURL:           p.CAURL,
		Fingerprint:     p.Fingerprint,
		ProvisionerName: p.ProvisionerName,
		Password:        p.Password,
		CSRPEM:          csrPEM,
		ValidityDays:    p.ValidityDays,
	})
	if err != nil {
		return Certificate{}, err
	}

	keyPEM, err := marshalKeyPEM(key)
	if err != nil {
		return Certificate{}, err
	}
	sealed, err := s.box.Seal([]byte(keyPEM))
	if err != nil {
		return Certificate{}, fmt.Errorf("certs: seal private key: %w", err)
	}

	cert, err := s.persist(ctx, res, sans, "server", sql.NullString{String: sealed, Valid: true}, p.Actor)
	if err != nil {
		return Certificate{}, err
	}

	// Attach exactly ONE download payload, selected by format, never persisted in
	// clear. PEM mode returns the unprotected PEM key; PFX mode returns ONLY the
	// password-protected PKCS#12 bundle — never the plaintext key as well.
	switch p.Format {
	case FormatPFX:
		pfx, perr := buildPFX(key, res.Certificate, res.ChainPEM, p.PFXPassword)
		if perr != nil {
			return Certificate{}, perr
		}
		cert.PFX = pfx
	default:
		cert.PrivateKeyPEM = keyPEM
	}

	if err := s.audit.Record(ctx, p.Actor, "issue", cn, auditDetails(cert)); err != nil {
		return Certificate{}, fmt.Errorf("certs: audit issue: %w", err)
	}
	return cert, nil
}

// SignParams are the inputs to Sign (FR-2).
type SignParams struct {
	Actor           string
	ProvisionerName string
	Password        string
	CAURL           string
	Fingerprint     string
	CSRPEM          string
	ValidityDays    int
}

// Sign parses and verifies a client CSR, takes the CN + SANs from it, obtains the
// certificate from the CA, persists it with key_strategy=csr (no private key),
// and records an audit event attributed to Actor.
func (s *Service) Sign(ctx context.Context, p SignParams) (Certificate, error) {
	info, err := ParseCSR(p.CSRPEM)
	if err != nil {
		return Certificate{}, err
	}

	res, err := s.signer.SignCSR(ctx, ca.SignParams{
		CAURL:           p.CAURL,
		Fingerprint:     p.Fingerprint,
		ProvisionerName: p.ProvisionerName,
		Password:        p.Password,
		CSRPEM:          p.CSRPEM,
		ValidityDays:    p.ValidityDays,
	})
	if err != nil {
		return Certificate{}, err
	}

	cert, err := s.persist(ctx, res, info.SANs, "csr", sql.NullString{}, p.Actor)
	if err != nil {
		return Certificate{}, err
	}

	if err := s.audit.Record(ctx, p.Actor, "sign", info.CN, auditDetails(cert)); err != nil {
		return Certificate{}, fmt.Errorf("certs: audit sign: %w", err)
	}
	return cert, nil
}

// CSRInfo is the subject material extracted from a CSR (FR-2).
type CSRInfo struct {
	CN   string
	SANs []string
}

// ParseCSR parses a PEM CSR with crypto/x509 and VERIFIES its self-signature,
// rejecting on failure (FR-2). It extracts the CN and all SAN types (DNS/IP/
// email/URI). A malformed PEM, a non-CSR block, or a bad signature all yield
// ErrInvalidCSR.
func ParseCSR(csrPEM string) (CSRInfo, error) {
	csr, err := pemutil.ParseCertificateRequest([]byte(csrPEM))
	if err != nil {
		return CSRInfo{}, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return CSRInfo{}, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidCSR, err)
	}
	return CSRInfo{CN: csr.Subject.CommonName, SANs: csrSANs(csr)}, nil
}

// persist inserts a certificate row and returns the stored Certificate. serial,
// not_before and not_after are parsed from the issued leaf.
func (s *Service) persist(ctx context.Context, res ca.SignResult, sans []string, strategy string, privSealed sql.NullString, actor string) (Certificate, error) {
	leaf := res.Certificate
	if leaf == nil {
		return Certificate{}, fmt.Errorf("certs: CA returned no certificate")
	}
	sansJSON, err := json.Marshal(sans)
	if err != nil {
		return Certificate{}, fmt.Errorf("certs: marshal sans: %w", err)
	}
	ts := now()
	serial := leaf.SerialNumber.String()
	notBefore := leaf.NotBefore.Unix()
	notAfter := leaf.NotAfter.Unix()

	result, err := s.db.ExecContext(ctx,
		`INSERT INTO certificates
		   (cn, sans_json, serial, not_before, not_after, status, key_strategy,
		    cert_pem, chain_pem, fullchain_pem, privkey_sealed, created_by,
		    created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 'valid', ?, ?, ?, ?, ?, ?, ?, ?)`,
		leaf.Subject.CommonName, string(sansJSON), serial, notBefore, notAfter,
		strategy, res.CertPEM, res.ChainPEM, res.FullchainPEM, privSealed,
		actor, ts, ts)
	if err != nil {
		return Certificate{}, fmt.Errorf("certs: insert: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Certificate{}, fmt.Errorf("certs: last insert id: %w", err)
	}
	return Certificate{
		ID:           id,
		CN:           leaf.Subject.CommonName,
		SANs:         sans,
		Serial:       serial,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		Status:       "valid",
		KeyStrategy:  strategy,
		CertPEM:      res.CertPEM,
		ChainPEM:     res.ChainPEM,
		FullchainPEM: res.FullchainPEM,
	}, nil
}

// normalizeSANs ensures the CN is present as a SAN (so the leaf is valid for it)
// and de-duplicates the list while preserving order.
func normalizeSANs(cn string, extra []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(cn)
	for _, s := range extra {
		add(s)
	}
	return out
}

// buildCSR builds a PEM CSR for cn + sans (classifying each SAN as IP, email,
// URI or DNS) signed by key.
func buildCSR(cn string, sans []string, key crypto.Signer) (string, error) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	for _, s := range sans {
		classifySAN(tmpl, s)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", fmt.Errorf("certs: create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// classifySAN routes a SAN string into the right CSR field: an IP literal →
// IPAddresses, a value with "@" and no scheme → EmailAddresses, a value with a
// URL scheme → URIs, otherwise → DNSNames.
func classifySAN(tmpl *x509.CertificateRequest, s string) {
	if ip := net.ParseIP(s); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		return
	}
	if u := parseURI(s); u != nil {
		tmpl.URIs = append(tmpl.URIs, u)
		return
	}
	if strings.Contains(s, "@") {
		tmpl.EmailAddresses = append(tmpl.EmailAddresses, s)
		return
	}
	tmpl.DNSNames = append(tmpl.DNSNames, s)
}

// parseURI returns a parsed URL when s looks like a URI (has a scheme and an
// authority or opaque part), or nil otherwise. It is used to classify a SAN as a
// URI rather than a DNS name or email. A bare "host:port" or plain hostname has
// no scheme and is not treated as a URI.
func parseURI(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return nil
	}
	if u.Host == "" && u.Opaque == "" {
		return nil
	}
	return u
}

// csrSANs returns a CSR's SANs as strings (DNS, IP, email, URI).
func csrSANs(csr *x509.CertificateRequest) []string {
	var sans []string
	sans = append(sans, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, csr.EmailAddresses...)
	for _, u := range csr.URIs {
		sans = append(sans, u.String())
	}
	return sans
}

// marshalKeyPEM PKCS#8-encodes a private key as PEM.
func marshalKeyPEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("certs: marshal private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// buildPFX produces a PKCS#12 bundle from the key, leaf and chain, encrypted with
// password, using the modern (AES) encoder for better compatibility/security.
func buildPFX(key crypto.PrivateKey, leaf *x509.Certificate, chainPEM, password string) ([]byte, error) {
	var caCerts []*x509.Certificate
	if chainPEM != "" {
		certs, err := pemutil.ParseCertificateBundle([]byte(chainPEM))
		if err != nil {
			return nil, fmt.Errorf("certs: parse chain for PFX: %w", err)
		}
		caCerts = certs
	}
	pfx, err := pkcs12.Modern.Encode(key, leaf, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("certs: encode PFX: %w", err)
	}
	return pfx, nil
}

// auditDetails is a compact, secret-free summary stored in the audit event.
func auditDetails(c Certificate) string {
	return fmt.Sprintf("serial=%s strategy=%s sans=%s", c.Serial, c.KeyStrategy, strings.Join(c.SANs, ","))
}
