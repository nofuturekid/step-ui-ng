package ca_test

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
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
)

// validFP is a syntactically valid 64-hex fingerprint placeholder (all zeroes),
// used where the value must not match the server's real fingerprint.
const validFP = "0000000000000000000000000000000000000000000000000000000000000000"

// mockCA mimics Step-CA's GET /roots endpoint over TLS. The server's own TLS
// leaf certificate is served as the "root", so the pinned fingerprint (SHA-256
// of that cert's DER) both identifies the root AND validates the TLS chain —
// exactly the steady-state pin the client builds.
type mockCA struct {
	url         string
	cert        *x509.Certificate
	fingerprint string
}

// newMockCA starts a TLS test server whose /roots handler is produced by body,
// which receives the server's own certificate (so the response can embed it).
func newMockCA(t *testing.T, body func(cert *x509.Certificate) (int, string)) *mockCA {
	t.Helper()

	// Two-phase start: NewUnstartedServer so we can read the auto-generated TLS
	// certificate, then install a handler closing over it, then start.
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cert := srv.Certificate()
	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		status, b := body(cert)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(b))
	})
	srv.Config.Handler = mux

	sum := sha256.Sum256(cert.Raw)
	return &mockCA{
		url:         srv.URL,
		cert:        cert,
		fingerprint: hex.EncodeToString(sum[:]),
	}
}

// pemOf encodes a certificate as PEM (Step-CA serialises each cert in the roots
// response as a PEM string).
func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// rootsJSON builds the {"crts":[...]} body Step-CA returns for GET /roots.
func rootsJSON(certs ...*x509.Certificate) string {
	pems := make([]string, len(certs))
	for i, c := range certs {
		pems[i] = pemOf(c)
	}
	b, _ := json.Marshal(struct {
		Crts []string `json:"crts"`
	}{Crts: pems})
	return string(b)
}

// Acceptance: valid CA URL + correct fingerprint → success and roots load.
func TestConnectionSuccess(t *testing.T) {
	m := newMockCA(t, func(cert *x509.Certificate) (int, string) {
		return http.StatusOK, rootsJSON(cert)
	})

	roots, err := ca.TestConnection(context.Background(), m.url, m.fingerprint)
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if len(roots) == 0 {
		t.Fatal("no roots returned on success")
	}
	if !roots[0].Equal(m.cert) {
		t.Fatal("returned root does not match the served root")
	}
}

// The fingerprint compare must be case-insensitive (Step-CA lowercases it).
func TestConnectionSuccessUppercaseFingerprint(t *testing.T) {
	m := newMockCA(t, func(cert *x509.Certificate) (int, string) {
		return http.StatusOK, rootsJSON(cert)
	})
	upper := hexUpper(m.fingerprint)
	if _, err := ca.TestConnection(context.Background(), m.url, upper); err != nil {
		t.Fatalf("uppercase fingerprint should verify: %v", err)
	}
}

// Acceptance: wrong fingerprint → fails with a clear (typed) message.
func TestConnectionWrongFingerprint(t *testing.T) {
	m := newMockCA(t, func(cert *x509.Certificate) (int, string) {
		return http.StatusOK, rootsJSON(cert)
	})
	_, err := ca.TestConnection(context.Background(), m.url, validFP)
	if !errors.Is(err, ca.ErrFingerprintMismatch) {
		t.Fatalf("err = %v, want ErrFingerprintMismatch", err)
	}
}

// Unreachable CA → ErrUnreachable.
func TestConnectionUnreachable(t *testing.T) {
	_, err := ca.TestConnection(context.Background(), "https://127.0.0.1:1", validFP)
	if !errors.Is(err, ca.ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

// Malformed roots body → ErrMalformedResponse. The fingerprint passed is the
// real one so the failure is unambiguously the body, not the pin.
func TestConnectionMalformedResponse(t *testing.T) {
	m := newMockCA(t, func(_ *x509.Certificate) (int, string) {
		return http.StatusOK, "not json {{{"
	})
	_, err := ca.TestConnection(context.Background(), m.url, m.fingerprint)
	if !errors.Is(err, ca.ErrMalformedResponse) {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
}

// An empty crts array → ErrMalformedResponse (no root to pin against).
func TestConnectionEmptyRoots(t *testing.T) {
	m := newMockCA(t, func(_ *x509.Certificate) (int, string) {
		return http.StatusOK, `{"crts":[]}`
	})
	_, err := ca.TestConnection(context.Background(), m.url, m.fingerprint)
	if !errors.Is(err, ca.ErrMalformedResponse) {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
}

// A non-2xx status from the CA → error (clear failure, not a silent success).
func TestConnectionBadStatus(t *testing.T) {
	m := newMockCA(t, func(_ *x509.Certificate) (int, string) {
		return http.StatusInternalServerError, "boom"
	})
	_, err := ca.TestConnection(context.Background(), m.url, m.fingerprint)
	if err == nil {
		t.Fatal("expected an error on 500 from the CA")
	}
}

// A short/invalid fingerprint is rejected before any network call.
func TestConnectionInvalidFingerprintInput(t *testing.T) {
	_, err := ca.TestConnection(context.Background(), "https://ca.example", "abc")
	if !errors.Is(err, ca.ErrInvalidFingerprint) {
		t.Fatalf("err = %v, want ErrInvalidFingerprint", err)
	}
}

// An already-expired context surfaces an error rather than hanging.
func TestConnectionContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	_, err := ca.TestConnection(ctx, "https://127.0.0.1:1", validFP)
	if err == nil {
		t.Fatal("expected an error with an already-expired context")
	}
}

// hexUpper uppercases a hex string.
func hexUpper(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'a' && c <= 'f' {
			out[i] = c - 32
		}
	}
	return string(out)
}

// --- Two-cert topology: a real leaf→root chain (proves Phase 2 is exercised) ---
//
// The existing mockCA collapses the TLS leaf and the served /roots root into one
// self-signed cert, so Phase 1 (pin match) and Phase 2 (chain validation against
// a pool built from the matched root) coincide. The helpers below let a test
// build a genuine CA root and a distinct leaf signed by it, so that deleting the
// Phase-2 block in ca.go is observable.

// keyPair is a generated certificate plus its private key.
type keyPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

// fp returns the hex SHA-256 of the certificate's DER (the pin format).
func (k *keyPair) fp() string {
	sum := sha256.Sum256(k.der)
	return hex.EncodeToString(sum[:])
}

// genRootCA produces a self-signed CA root (IsCA, KeyUsageCertSign).
func genRootCA(t *testing.T, cn string) *keyPair {
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
	return &keyPair{cert: cert, key: key, der: der}
}

// genLeaf produces a server leaf signed by root, with SANs for 127.0.0.1 and
// localhost so hostname verification passes against an httptest server.
func genLeaf(t *testing.T, root *keyPair, cn string) *keyPair {
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
	return &keyPair{cert: cert, key: key, der: der}
}

// genIntermediate produces a CA intermediate (IsCA, KeyUsageCertSign) signed by
// parent — used to model a real Step-CA topology (root -> intermediate -> leaf).
func genIntermediate(t *testing.T, parent *keyPair, cn string) *keyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen intermediate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("create intermediate cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate cert: %v", err)
	}
	return &keyPair{cert: cert, key: key, der: der}
}

// tlsCertChain builds a tls.Certificate presenting leaf then the given chain
// (intermediates/root), backed by the leaf's private key.
func tlsCertChain(leaf *keyPair, chain ...*keyPair) tls.Certificate {
	c := tls.Certificate{PrivateKey: leaf.key, Leaf: leaf.cert}
	c.Certificate = append(c.Certificate, leaf.der)
	for _, k := range chain {
		c.Certificate = append(c.Certificate, k.der)
	}
	return c
}

// startTLSServerWith stands up an httptest TLS server presenting the given
// tls.Certificate and serving /roots from the supplied body.
func startTLSServerWith(t *testing.T, leaf tls.Certificate, rootsBody string) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsBody))
	})
	srv.Config.Handler = mux
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

// Phase-2 positive: a genuine leaf→root chain. The TLS leaf is signed by the
// root, and /roots serves the root whose fingerprint is the pin. Phase 1 matches
// the root in the presented chain; Phase 2 builds a pool from that root and
// validates the live chain against it. This only succeeds if the leaf truly
// chains to the pinned root — a collapsed self-signed cert cannot reach here.
func TestConnectionTwoCertChainSuccess(t *testing.T) {
	root := genRootCA(t, "Test Root CA")
	leaf := genLeaf(t, root, "ca.test")

	// Present leaf + root in the TLS chain so Phase 1 (which scans presented
	// peer certs for the pin) can find the root.
	url := startTLSServerWith(t, tlsCertChain(leaf, root), rootsJSON(root.cert))

	roots, err := ca.TestConnection(context.Background(), url, root.fp())
	if err != nil {
		t.Fatalf("TestConnection over a real leaf->root chain: %v", err)
	}
	if len(roots) == 0 {
		t.Fatal("no roots returned on success")
	}
	if !roots[0].Equal(root.cert) {
		t.Fatal("returned root does not match the served root")
	}
}

// TestConnectionRealStepCATopology reproduces a real Step-CA: root -> intermediate
// -> leaf, where the TLS handshake presents ONLY leaf + intermediate (NOT the root,
// as servers conventionally do), and /roots serves the root. The pin is the ROOT
// fingerprint. This MUST succeed: the root is found via /roots (not the presented
// chain), and Phase 2 verifies the live leaf->intermediate->root chain anchors in
// the pinned root.
//
// Regression guard: this fails with ErrFingerprintMismatch if Phase 1 requires the
// pinned cert to appear in the *presented* TLS chain — which real Step-CA never does
// (it sends leaf + intermediate, never the root). See the 2026-06 prod report.
func TestConnectionRealStepCATopology(t *testing.T) {
	root := genRootCA(t, "Homelab Root CA")
	inter := genIntermediate(t, root, "Homelab Intermediate CA")
	leaf := genLeaf(t, inter, "ca.test") // signed by the intermediate

	// Present leaf + intermediate only — the root is deliberately NOT in the chain.
	url := startTLSServerWith(t, tlsCertChain(leaf, inter), rootsJSON(root.cert))

	roots, err := ca.TestConnection(context.Background(), url, root.fp())
	if err != nil {
		t.Fatalf("TestConnection (leaf+intermediate presented, root only in /roots): %v", err)
	}
	if len(roots) == 0 || !roots[0].Equal(root.cert) {
		t.Fatal("expected the served root to be returned")
	}
}

// Phase-2 negative (the MITM scenario): Phase 1 passes but Phase 2 must fail.
//
// The TLS leaf is signed by root B, and the presented chain contains BOTH root A
// (the pinned root) and root B. Phase 1 scans the presented peer certs and finds
// root A → the pin matches. /roots serves root A. Phase 2 then builds a pool from
// root A and re-validates the live TLS chain against it; because the leaf is
// signed by B (not A), that validation fails → ErrBadTLS.
//
// This is the authoritative anchor gate: it must pass today and FAIL (go green
// for the wrong reason) if the Phase-2 block in ca.go is removed.
func TestConnectionPhase2ChainNotAnchored(t *testing.T) {
	rootA := genRootCA(t, "Pinned Root A")
	rootB := genRootCA(t, "Impostor Root B")
	leaf := genLeaf(t, rootB, "ca.test") // signed by B, NOT the pinned A

	// Present leaf + B (the real signer) + A (so Phase 1's pin scan finds A).
	url := startTLSServerWith(t, tlsCertChain(leaf, rootB, rootA), rootsJSON(rootA.cert))

	_, err := ca.TestConnection(context.Background(), url, rootA.fp())
	if !errors.Is(err, ca.ErrBadTLS) {
		t.Fatalf("err = %v, want ErrBadTLS (live chain does not anchor in the pinned root)", err)
	}
}

// Scheme guard: a non-https CA URL is rejected before any network call. The
// connection test requires TLS to the CA (FR-3 / rootsEndpoint).
func TestConnectionRequiresHTTPS(t *testing.T) {
	_, err := ca.TestConnection(context.Background(), "http://ca.example:9000", validFP)
	if !errors.Is(err, ca.ErrBadTLS) {
		t.Fatalf("err = %v, want ErrBadTLS for an http:// URL", err)
	}
}
