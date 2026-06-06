package ca

// White-box tests for the admin-token security crux (package ca, not ca_test).
//
// These tests require access to unexported types and functions (AdminCredential
// struct fields, generateAdminToken) so they live in the internal package
// alongside the production code rather than the external ca_test package.
//
// TestMockRejectsForgedJWSSignature is the restored "mock is non-vacuous"
// test. It proves that the mock admin API in provisioners_test.go genuinely
// checks the JWS signature — mirroring step-ca's AuthorizeAdminToken:
//   - a forged token whose x5c chain is valid (leaf signed by the CA root)
//     but whose JWS is signed by a DIFFERENT private key must be rejected.
//   - if the mock's jwt.Claims(leaf.PublicKey, ...) check were removed, this
//     test would fail (the mock would accept the forged token).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
)

// genRootWB produces a self-signed CA root for the white-box test.
// (Cannot reuse genRootCA from ca_test.go — different package declaration.)
func genRootWB(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genRootWB key: %v", err)
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
		t.Fatalf("genRootWB cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("genRootWB parse: %v", err)
	}
	return cert, key
}

// genAdminLeafWB produces a leaf cert signed by root with digitalSignature +
// clientAuth — the shape the mock's x5c chain check requires.
func genAdminLeafWB(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genAdminLeafWB key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 7),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("genAdminLeafWB cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("genAdminLeafWB parse: %v", err)
	}
	return cert, key
}

// forgedSigCASkipSigCheck is a package-level toggle used exclusively by
// TestMockRejectsForgedJWSSignature to prove the mock is non-vacuous:
// when true the handler skips step (3) (JWS signature verification) and
// the forged token must then be ACCEPTED — causing the test to fail.
var forgedSigCASkipSigCheck bool

// startForgedSigCA stands up a mock admin CA whose token verifier mirrors
// step-ca's AuthorizeAdminToken. rootPool is the pool used to verify the x5c
// admin chain (distinct from the TLS cert). The handler reads
// forgedSigCASkipSigCheck so the non-vacuousness assertion can be exercised.
func startForgedSigCA(t *testing.T, rootPool *x509.CertPool) (caURL, caFP string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tlsCert := srv.Certificate()
	sum := sha256.Sum256(tlsCert.Raw)
	caFP = hex.EncodeToString(sum[:])
	caURL = srv.URL

	// /roots body: {"crts":["<TLS cert PEM>"]} — satisfies pinnedClientFor's
	// two-phase trust: phase-1 pin matches the TLS cert FP, phase-2 chain
	// validates against that same cert as the root.
	// Use json.Marshal so the PEM newlines are properly escaped inside the
	// JSON string (bare newlines inside a JSON string literal are invalid).
	rootsPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Raw}))
	rootsBodyBytes, _ := json.Marshal(struct {
		Crts []string `json:"crts"`
	}{Crts: []string{rootsPEM}})
	rootsBody := string(rootsBodyBytes)

	wantAud := caURL + adminURLPath
	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsBody))
	})
	mux.HandleFunc("POST /admin/provisioners", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("Authorization")
		if tok == "" {
			http.Error(w, `{"message":"missing authorization"}`, http.StatusUnauthorized)
			return
		}
		jwt, err := jose.ParseSigned(tok)
		if err != nil {
			http.Error(w, `{"message":"parse error"}`, http.StatusUnauthorized)
			return
		}
		// (1) Verify the x5c chain to the admin root with clientAuth EKU.
		chains, err := jwt.Headers[0].Certificates(x509.VerifyOptions{
			Roots:     rootPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			http.Error(w, `{"message":"x5c chain invalid"}`, http.StatusUnauthorized)
			return
		}
		leaf := chains[0][0]
		// (2) Leaf must carry the digital-signature key usage.
		if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			http.Error(w, `{"message":"leaf lacks digital signature"}`, http.StatusUnauthorized)
			return
		}
		// (3) Verify the JWS signature using the leaf's PUBLIC KEY.
		// THIS IS THE CHECK UNDER TEST. The forgedSigCASkipSigCheck toggle lets
		// TestMockRejectsForgedJWSSignature confirm that removing this check
		// causes the mock to accept a forged token → the test fails → proof
		// that the check is necessary (the mock is non-vacuous).
		if forgedSigCASkipSigCheck {
			// Signature check deliberately bypassed for the non-vacuousness probe.
			// Accept any token whose x5c chain is valid (steps 1/2 already passed).
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"type":"JWK","name":"x"}`))
			return
		}
		var claims jose.Claims
		if err := jwt.Claims(leaf.PublicKey, &claims); err != nil {
			http.Error(w, `{"message":"invalid token signature"}`, http.StatusUnauthorized)
			return
		}
		// (4) Validate audience and issuer.
		if err := claims.ValidateWithLeeway(jose.Expected{
			Audience: jose.Audience{wantAud},
			Time:     time.Now().UTC(),
		}, time.Minute); err != nil {
			http.Error(w, `{"message":"claims invalid"}`, http.StatusUnauthorized)
			return
		}
		if claims.Issuer != adminIssuer {
			http.Error(w, `{"message":"unexpected issuer"}`, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"type":"JWK","name":"x"}`))
	})
	srv.Config.Handler = mux
	return caURL, caFP
}

// TestMockRejectsForgedJWSSignature is the restored end-to-end coverage that
// the mock admin API genuinely verifies the JWS signature (the "mock is not
// vacuous" guarantee on the admin-token security crux).
//
// Strategy: build a valid x5c chain (leaf signed by the admin root) but sign
// the JWS with a DIFFERENT private key (the "forger"). By constructing
// AdminCredential directly — bypassing NewAdminCredential's key-match guard,
// which is tested separately by TestNewAdminCredentialRejectsMismatchedKey —
// the token reaches the mock's verifyAdminToken. Step (3) there,
// jwt.Claims(leaf.PublicKey, &claims), then fails: the leaf's public key does
// not match the forger's signature → 401.
//
// Non-vacuousness guarantee: if step (3) in startForgedSigCA were commented
// out, CreateProvisioner would return nil (success) and this test would FAIL
// at the errors.Is(err, ErrAdminUnauthorized) assertion.
func TestMockRejectsForgedJWSSignature(t *testing.T) {
	// Build the admin cert chain: root CA + leaf signed by that root.
	rootCert, rootKey := genRootWB(t, "Forged-Sig Root CA")
	leafCert, _ := genAdminLeafWB(t, rootCert, rootKey, "admin@ca.test")

	// The mock uses this pool to verify the x5c chain (separate from TLS trust).
	adminRootPool := x509.NewCertPool()
	adminRootPool.AddCert(rootCert)

	caURL, caFP := startForgedSigCA(t, adminRootPool)

	// Generate a DIFFERENT key — the "forger". Its public half does NOT match
	// the leaf certificate's public key.
	forgerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen forger key: %v", err)
	}
	if forgerKey.PublicKey.Equal(leafCert.PublicKey) {
		t.Fatal("test setup error: forger key matches leaf — key generation is broken")
	}

	// Construct the forged credential directly, bypassing NewAdminCredential:
	//   chain  = [leafCert, rootCert]  → x5c chain verification PASSES
	//   signer = forgerKey             → JWS signature will NOT verify against leaf.PublicKey
	forgedCred := AdminCredential{
		chain:  []*x509.Certificate{leafCert, rootCert},
		signer: forgerKey,
	}

	// Main assertion: with the JWS-signature check in place, the forged token
	// must be rejected. CreateProvisioner calls generateAdminToken(forgedCred):
	//   - x5c header carries leafCert (valid chain → passes mock's (1)/(2))
	//   - JWS is signed by forgerKey  → fails mock's (3): jwt.Claims(leaf.PublicKey,…)
	// Expected: HTTP 401 → ErrAdminUnauthorized.
	_, err = CreateProvisioner(
		context.Background(), caURL, caFP, forgedCred,
		NewProvisionerSpec{Name: "x", Type: "JWK", JWKSecret: "passphrase123"},
	)
	if !errors.Is(err, ErrAdminUnauthorized) {
		t.Fatalf("forged JWS: err = %v, want ErrAdminUnauthorized\n"+
			"(if err is nil the mock's JWS-signature check is not enforced — the mock is vacuous)", err)
	}

	// Non-vacuousness probe: disable the mock's signature check and confirm the
	// SAME forged token is now ACCEPTED (returns nil). This proves that the
	// check above is the specific guard that makes the mock non-vacuous.
	// If this sub-test passes, removing step (3) from startForgedSigCA would
	// break TestMockRejectsForgedJWSSignature — exactly the guarantee we want.
	t.Run("mock_is_non_vacuous", func(t *testing.T) {
		forgedSigCASkipSigCheck = true
		defer func() { forgedSigCASkipSigCheck = false }()

		_, err := CreateProvisioner(
			context.Background(), caURL, caFP, forgedCred,
			NewProvisionerSpec{Name: "x", Type: "JWK", JWKSecret: "passphrase123"},
		)
		if err != nil {
			t.Fatalf("with sig check disabled the forged token should be accepted, got: %v\n"+
				"(this means the JWS-signature check is NOT the only guard — review mock logic)", err)
		}
	})
}
