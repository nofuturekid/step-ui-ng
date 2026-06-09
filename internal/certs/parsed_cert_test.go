package certs_test

// Unit tests for ParseLeafPEM (parsed_cert.go).
//
// Why these tests matter:
//   - They verify that the fingerprint is the correct SHA-256 of the DER bytes
//     in plain lowercase hex (no separators), matching the default output of
//     "step certificate fingerprint".
//   - They verify that issuer CN, public-key type, key usage and EKU are
//     extracted correctly from a known certificate.
//   - They verify graceful degradation (empty ParsedCert + error) when the PEM
//     is invalid — so the handler can degrade without panicking.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/certs"
)

// buildTestCert creates a cert signed by a fresh ECDSA CA with the given subject
// key usage, EKU bits, and issuerCN for the signing CA. Returns the leaf PEM.
// _ (first key parameter) is the leaf private key — unused here since we sign
// directly with the CA key via x509.CreateCertificate.
func buildTestCert(
	t *testing.T,
	_ any,
	leafPub any,
	ku x509.KeyUsage,
	eku []x509.ExtKeyUsage,
	issuerCN string,
) string {
	t.Helper()

	// Generate a dedicated CA key for this test cert so the issuer CN is
	// distinct from the subject CN.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "test.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafPub, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestParseLeafPEM_ECDSAFingerprint verifies that ParseLeafPEM returns the
// correct SHA-256 fingerprint for an ECDSA P-256 leaf certificate. The
// fingerprint must match sha256(DER) formatted as plain lowercase hex (no
// separators), matching the default output of "step certificate fingerprint".
func TestParseLeafPEM_ECDSAFingerprint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM := buildTestCert(t, key, &key.PublicKey,
		x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, "Test Root CA")

	parsed, err := certs.ParseLeafPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseLeafPEM error: %v", err)
	}

	// Compute expected fingerprint independently from the DER bytes.
	block, _ := pem.Decode([]byte(certPEM))
	sum := sha256.Sum256(block.Bytes)
	want := hex.EncodeToString(sum[:])

	if parsed.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q", parsed.Fingerprint, want)
	}
	// Plain hex: 64 lowercase hex chars, no colons.
	if len(parsed.Fingerprint) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(parsed.Fingerprint))
	}
	if strings.ContainsRune(parsed.Fingerprint, ':') {
		t.Errorf("Fingerprint must not contain colons, got %q", parsed.Fingerprint)
	}
}

// TestParseLeafPEM_IssuerCN verifies that Issuer is the issuing CA's CN.
func TestParseLeafPEM_IssuerCN(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM := buildTestCert(t, key, &key.PublicKey,
		x509.KeyUsageDigitalSignature, nil, "My Internal CA")

	parsed, err := certs.ParseLeafPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseLeafPEM error: %v", err)
	}
	if parsed.Issuer != "My Internal CA" {
		t.Errorf("Issuer = %q, want %q", parsed.Issuer, "My Internal CA")
	}
}

// TestParseLeafPEM_PublicKeyType_ECDSA verifies the public-key description for
// an ECDSA P-256 key.
func TestParseLeafPEM_PublicKeyType_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM := buildTestCert(t, key, &key.PublicKey, 0, nil, "Root")

	parsed, err := certs.ParseLeafPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseLeafPEM error: %v", err)
	}
	if parsed.PublicKeyType != "ECDSA P-256" {
		t.Errorf("PublicKeyType = %q, want %q", parsed.PublicKeyType, "ECDSA P-256")
	}
}

// TestParseLeafPEM_PublicKeyType_RSA verifies the public-key description for an
// RSA 2048 key.
func TestParseLeafPEM_PublicKeyType_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certPEM := buildTestCert(t, key, &key.PublicKey, 0, nil, "Root")

	parsed, err := certs.ParseLeafPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseLeafPEM error: %v", err)
	}
	if parsed.PublicKeyType != "RSA 2048" {
		t.Errorf("PublicKeyType = %q, want %q", parsed.PublicKeyType, "RSA 2048")
	}
}

// TestParseLeafPEM_PublicKeyType_Ed25519 verifies the public-key description
// for an Ed25519 key.
func TestParseLeafPEM_PublicKeyType_Ed25519(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	certPEM := buildTestCert(t, key, pub, 0, nil, "Root")

	parsed, err := certs.ParseLeafPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseLeafPEM error: %v", err)
	}
	if parsed.PublicKeyType != "Ed25519" {
		t.Errorf("PublicKeyType = %q, want %q", parsed.PublicKeyType, "Ed25519")
	}
}

// TestParseLeafPEM_KeyUsages verifies that the expected key usage strings are
// returned for a cert with DigitalSignature + KeyEncipherment bits set.
func TestParseLeafPEM_KeyUsages(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ku := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	certPEM := buildTestCert(t, key, &key.PublicKey, ku, nil, "Root")

	parsed, err := certs.ParseLeafPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseLeafPEM error: %v", err)
	}
	must := []string{"digitalSignature", "keyEncipherment"}
	for _, want := range must {
		found := false
		for _, got := range parsed.KeyUsages {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("KeyUsages %v missing %q", parsed.KeyUsages, want)
		}
	}
	// Must NOT contain bits that weren't set.
	for _, got := range parsed.KeyUsages {
		if got == "keyCertSign" || got == "cRLSign" {
			t.Errorf("KeyUsages %v unexpectedly contains %q", parsed.KeyUsages, got)
		}
	}
}

// TestParseLeafPEM_ExtKeyUsages verifies that the EKU strings (serverAuth,
// clientAuth) are extracted correctly.
func TestParseLeafPEM_ExtKeyUsages(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	certPEM := buildTestCert(t, key, &key.PublicKey, 0, eku, "Root")

	parsed, err := certs.ParseLeafPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseLeafPEM error: %v", err)
	}
	want := map[string]bool{"serverAuth": true, "clientAuth": true}
	for _, got := range parsed.ExtKeyUsages {
		delete(want, got)
	}
	if len(want) > 0 {
		t.Errorf("ExtKeyUsages %v missing: %v", parsed.ExtKeyUsages, want)
	}
}

// TestParseLeafPEM_EmptyKeyUsages verifies that when no key usages or EKUs
// are set, the slices are empty (not nil-but-non-empty or panicking).
func TestParseLeafPEM_EmptyKeyUsages(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM := buildTestCert(t, key, &key.PublicKey, 0, nil, "Root")

	parsed, err := certs.ParseLeafPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseLeafPEM error: %v", err)
	}
	if len(parsed.KeyUsages) != 0 {
		t.Errorf("KeyUsages = %v, want empty", parsed.KeyUsages)
	}
	if len(parsed.ExtKeyUsages) != 0 {
		t.Errorf("ExtKeyUsages = %v, want empty", parsed.ExtKeyUsages)
	}
}

// TestParseLeafPEM_InvalidPEM verifies that bad input returns a non-nil error
// and an empty (zero) ParsedCert — callers must be able to degrade gracefully
// without panicking.
func TestParseLeafPEM_InvalidPEM(t *testing.T) {
	parsed, err := certs.ParseLeafPEM("not a PEM")
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
	if parsed.Fingerprint != "" || parsed.Issuer != "" || parsed.PublicKeyType != "" {
		t.Errorf("expected empty ParsedCert on error, got %+v", parsed)
	}
}

// TestParseLeafPEM_FingerprintFormat verifies that the fingerprint format is
// exactly 64 lowercase hex characters with no separators (SHA-256 = 32 bytes =
// 64 hex chars). This matches the default output of "step certificate fingerprint".
func TestParseLeafPEM_FingerprintFormat(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM := buildTestCert(t, key, &key.PublicKey, 0, nil, "Root")

	parsed, err := certs.ParseLeafPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseLeafPEM error: %v", err)
	}

	fp := parsed.Fingerprint

	// Must be exactly 64 characters (32 bytes × 2 hex digits each).
	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64: %q", len(fp), fp)
	}

	// Must contain no colons (plain hex, no separators).
	if strings.ContainsRune(fp, ':') {
		t.Errorf("Fingerprint must not contain colons, got %q", fp)
	}

	// Every character must be a lowercase hex digit.
	for i, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("Fingerprint[%d] = %c is not a lowercase hex digit: %q", i, c, fp)
		}
	}
}
