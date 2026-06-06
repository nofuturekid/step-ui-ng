package ca

// White-box tests for the OTT sign crux (package ca, not ca_test). These need
// the unexported buildSignToken/postSign/pinnedClientFor and the signClaims
// shape, so they live alongside the production code.
//
// TestSignOTTSignatureIsVerified proves the sign mock is non-vacuous: a token
// whose JWS is signed by a DIFFERENT key than the published provisioner JWK must
// be rejected by /1.0/sign. With the signature check disabled (the toggle), the
// same forged token is accepted — so the check is the specific guard that makes
// the mock meaningful.

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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
)

// wbKeyPair is a cert + key for the white-box helpers.
type wbKeyPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// genRootKP makes a self-signed CA root for the white-box sign mock.
func genRootKP(t *testing.T) *wbKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "WB Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &wbKeyPair{cert: cert, key: key}
}

// selfIssue signs a leaf from the CSR with root and returns the leaf PEM.
func selfIssue(t *testing.T, csr *x509.CertificateRequest, root *wbKeyPair) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 5),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     csr.DNSNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, csr.PublicKey, root.key)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// wbCSR builds a PEM CSR with the given CN.
func wbCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen csr key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

const wbProvName = "wb-jwk"
const wbProvPassword = "wb-provisioner-pass"

// wbSkipOTTSigCheck disables the mock's OTT signature verification so the
// non-vacuousness probe can confirm the forged token is otherwise accepted.
var wbSkipOTTSigCheck bool

// startWBSignCA stands up a sign CA that publishes a JWK provisioner and verifies
// the OTT against the published public JWK (unless wbSkipOTTSigCheck is set).
func startWBSignCA(t *testing.T) (caURL, caFP, encryptedKey string, pub *jose.JSONWebKey) {
	t.Helper()
	pubKey, jwe, err := jose.GenerateDefaultKeyPair([]byte(wbProvPassword))
	if err != nil {
		t.Fatalf("gen provisioner keypair: %v", err)
	}
	encKey, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize encrypted key: %v", err)
	}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsCert := srv.Certificate()
	caURL = srv.URL
	sum := sha256.Sum256(tlsCert.Raw)
	caFP = hex.EncodeToString(sum[:])
	rootsPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Raw}))
	rootsBodyBytes, _ := json.Marshal(struct {
		Crts []string `json:"crts"`
	}{Crts: []string{rootsPEM}})
	wantAud := caURL + "/1.0/sign"

	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rootsBodyBytes)
	})
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		pubBytes, _ := pubKey.MarshalJSON()
		body := `{"provisioners":[{"type":"JWK","name":"` + wbProvName + `","key":` +
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
		jwt, err := jose.ParseSigned(req.OTT)
		if err != nil {
			http.Error(w, `{"message":"bad token"}`, http.StatusUnauthorized)
			return
		}
		if wbSkipOTTSigCheck {
			// Signature verification deliberately bypassed: accept and issue.
			issueWB(t, w, req.CSR)
			return
		}
		var claims signClaims
		if err := jwt.Claims(pubKey.Public(), &claims); err != nil {
			http.Error(w, `{"message":"invalid token signature"}`, http.StatusUnauthorized)
			return
		}
		if err := claims.ValidateWithLeeway(jose.Expected{
			Issuer:   wbProvName,
			Audience: jose.Audience{wantAud},
			Time:     time.Now().UTC(),
		}, time.Minute); err != nil {
			http.Error(w, `{"message":"invalid claims"}`, http.StatusUnauthorized)
			return
		}
		issueWB(t, w, req.CSR)
	})
	srv.Config.Handler = mux
	return caURL, caFP, encKey, pubKey
}

// issueWB self-signs a leaf from the CSR so the client gets a parseable cert.
func issueWB(t *testing.T, w http.ResponseWriter, csrPEM string) {
	t.Helper()
	csr, err := pemutil.ParseCertificateRequest([]byte(csrPEM))
	if err != nil {
		http.Error(w, `{"message":"bad csr"}`, http.StatusBadRequest)
		return
	}
	root := genRootKP(t)
	leafPEM := selfIssue(t, csr, root)
	resp := map[string]any{"crt": leafPEM, "ca": leafPEM, "certChain": []string{leafPEM}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// TestSignOTTSignatureIsVerified proves the mock enforces the OTT signature.
func TestSignOTTSignatureIsVerified(t *testing.T) {
	caURL, caFP, _, pubKey := startWBSignCA(t)

	ctx := context.Background()
	client, err := pinnedClientFor(ctx, caURL, caFP)
	if err != nil {
		t.Fatalf("pinnedClientFor: %v", err)
	}
	base, _ := baseURL(caURL)

	// Generate a DIFFERENT signing key (the forger) — NOT the provisioner key.
	forger, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "forger-kid", 0)
	if err != nil {
		t.Fatalf("gen forger jwk: %v", err)
	}
	if forger.KeyID == pubKey.KeyID {
		t.Fatal("test setup error: forger kid collides with provisioner kid")
	}

	csrPEM := wbCSR(t, "wb.test")
	ott := wbToken(t, forger, base)

	// With the signature check on, the forged OTT must be rejected (401 → 4xx).
	_, err = postSign(ctx, base, client, csrPEM, ott, 0)
	if !errors.Is(err, ErrSignRejected) {
		t.Fatalf("forged OTT: err = %v, want ErrSignRejected (mock must verify the JWS)", err)
	}

	// Non-vacuousness: disable the mock's signature check and confirm the SAME
	// forged token is now accepted.
	t.Run("mock_is_non_vacuous", func(t *testing.T) {
		wbSkipOTTSigCheck = true
		defer func() { wbSkipOTTSigCheck = false }()
		res, err := postSign(ctx, base, client, csrPEM, ott, 0)
		if err != nil {
			t.Fatalf("with sig check disabled the forged token should be accepted, got: %v", err)
		}
		if res.Certificate == nil {
			t.Fatal("expected a certificate when the sig check is bypassed")
		}
	})
}

// wbToken signs an OTT with the given key for the sign audience.
func wbToken(t *testing.T, key *jose.JSONWebKey, base string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key.Key}, opts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	jti, _ := randutil.Hex(64)
	now := time.Now()
	claims := signClaims{
		Claims: jose.Claims{
			ID:        jti,
			Issuer:    wbProvName,
			Subject:   "wb.test",
			Audience:  jose.Audience{base + "/1.0/sign"},
			NotBefore: jose.NewNumericDate(now),
			IssuedAt:  jose.NewNumericDate(now),
			Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
		},
		SANs: []string{"wb.test"},
	}
	tok, err := jose.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}
