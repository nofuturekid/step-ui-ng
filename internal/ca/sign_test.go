package ca_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
)

// --- Provisioner OTT signing (the crux, FR-1/FR-2) --------------------------
//
// The mock CA publishes a JWK provisioner at GET /provisioners whose public key
// the test controls and whose encryptedKey is a JWE the test built with a known
// password. The /1.0/sign endpoint re-implements step-ca's JWK authorizeToken:
// it parses the OTT, verifies the JWS signature against the PUBLISHED PUBLIC JWK,
// and checks iss == provisioner name, aud == {ca}/1.0/sign, and a non-empty sub.
// Only then does it issue a certificate. This proves the client signs correctly,
// not merely that the request has the right shape. It does NOT exercise a live
// CA (remote management, real validity policy) — see signCA's doc.

const signProvName = "ui-jwk"
const signProvPassword = "provisioner-pass-1234"

// signCA is a mock CA for the OTT sign flow.
type signCA struct {
	url         string
	fingerprint string
	caRoot      *x509.Certificate // issuing root the mock embeds in the chain
	pubJWK      jose.JSONWebKey   // the provisioner's public signing key
	// lastOTTSANs/lastOTTSub capture the claims the mock saw, so tests can assert
	// the client put the right CN/SANs into the token.
	lastOTTSub  string
	lastOTTSANs []string
	maxDays     int // provisioner max validity in days the mock enforces (0 = none)
}

// buildSignProvisioner generates a JWK keypair, encrypts the private half with
// signProvPassword (a JWE compact string, exactly the encryptedKey shape step-ca
// publishes), and returns the public JWK plus the encryptedKey string and the
// private key (kept so the mock could sign, though it only verifies).
func buildSignProvisioner(t *testing.T) (pub jose.JSONWebKey, encryptedKey string) {
	t.Helper()
	pubKey, jwe, err := jose.GenerateDefaultKeyPair([]byte(signProvPassword))
	if err != nil {
		t.Fatalf("generate provisioner keypair: %v", err)
	}
	compact, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize encrypted key: %v", err)
	}
	return *pubKey, compact
}

// startSignCA stands up the mock CA: GET /roots (pinned trust), GET /provisioners
// (publishes the JWK provisioner), and POST /1.0/sign (verifies the OTT, issues a
// cert). maxDays, if > 0, makes /1.0/sign reject a requested notAfter beyond the
// bound (mimicking the provisioner's claimer max).
func startSignCA(t *testing.T, maxDays int) *signCA {
	t.Helper()
	pub, encKey := buildSignProvisioner(t)

	// The issuing root/leaf the mock uses to sign requested CSRs.
	root := genRootCA(t, "Sign Root CA")
	intermediate := genIntermediateCA(t, root, "Sign Intermediate CA")

	c := &signCA{caRoot: root.cert, pubJWK: pub, maxDays: maxDays}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsCert := srv.Certificate()
	c.url = srv.URL
	sum := sha256.Sum256(tlsCert.Raw)
	c.fingerprint = hex.EncodeToString(sum[:])

	wantAud := c.url + "/1.0/sign"

	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsJSON(tlsCert)))
	})
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		pubBytes, _ := pub.MarshalJSON()
		body := `{"provisioners":[{"type":"JWK","name":"` + signProvName + `","key":` +
			string(pubBytes) + `,"encryptedKey":"` + encKey + `"}]}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			CsrPEM   string `json:"csr"`
			OTT      string `json:"ott"`
			NotAfter string `json:"notAfter"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"message":"bad request"}`, http.StatusBadRequest)
			return
		}

		// (1) Parse + verify the OTT against the published public JWK.
		jwt, err := jose.ParseSigned(req.OTT)
		if err != nil {
			http.Error(w, `{"message":"bad token"}`, http.StatusUnauthorized)
			return
		}
		var claims struct {
			jose.Claims
			SANs []string `json:"sans"`
		}
		if err := jwt.Claims(pub.Public(), &claims); err != nil {
			http.Error(w, `{"message":"invalid token signature"}`, http.StatusUnauthorized)
			return
		}
		// (2) iss == provisioner name, aud == sign URL, sub non-empty.
		if err := claims.ValidateWithLeeway(jose.Expected{
			Issuer:   signProvName,
			Audience: jose.Audience{wantAud},
			Time:     time.Now().UTC(),
		}, time.Minute); err != nil {
			http.Error(w, `{"message":"invalid claims"}`, http.StatusUnauthorized)
			return
		}
		if claims.Subject == "" {
			http.Error(w, `{"message":"empty subject"}`, http.StatusUnauthorized)
			return
		}
		c.lastOTTSub = claims.Subject
		c.lastOTTSANs = claims.SANs

		// (3) Parse the CSR and verify its self-signature, like the CA does.
		csr, err := pemutil.ParseCertificateRequest([]byte(req.CsrPEM))
		if err != nil {
			http.Error(w, `{"message":"bad csr"}`, http.StatusBadRequest)
			return
		}
		if err := csr.CheckSignature(); err != nil {
			http.Error(w, `{"message":"csr signature invalid"}`, http.StatusBadRequest)
			return
		}

		// (4) Validity bound (claimer max). The client requests notAfter.
		notAfter := time.Now().Add(24 * time.Hour)
		if req.NotAfter != "" {
			if parsed, perr := time.Parse(time.RFC3339, req.NotAfter); perr == nil {
				notAfter = parsed
			}
		}
		if c.maxDays > 0 {
			maxAllowed := time.Now().Add(time.Duration(c.maxDays)*24*time.Hour + time.Minute)
			if notAfter.After(maxAllowed) {
				http.Error(w,
					`{"message":"requested duration exceeds the provisioner's maximum"}`,
					http.StatusForbidden)
				return
			}
		}

		// (5) Issue: sign a leaf from the CSR's public key + subject.
		leafPEM, chainPEM := issueFromCSR(t, csr, root, intermediate, notAfter)
		resp := map[string]any{
			"crt":       leafPEM,
			"ca":        pemOfCertString(intermediate.cert),
			"certChain": []string{leafPEM, chainPEM},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv.Config.Handler = mux
	return c
}

// pemOfCertString PEM-encodes a cert to a string.
func pemOfCertString(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// --- Acceptance: issue for example.test + a SAN -----------------------------

func TestSignCSRIssuesCertificate(t *testing.T) {
	c := startSignCA(t, 0)

	// Build a CSR the way internal/certs will: CN repeated as a DNS SAN, plus an
	// extra SAN.
	csrPEM, _ := makeTestCSR(t, "example.test", []string{"example.test", "www.example.test"}, nil, nil, nil)

	res, err := ca.SignCSR(context.Background(), ca.SignParams{
		CAURL:           c.url,
		Fingerprint:     c.fingerprint,
		ProvisionerName: signProvName,
		Password:        signProvPassword,
		CSRPEM:          csrPEM,
		ValidityDays:    7,
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if len(res.Certificate.Raw) == 0 {
		t.Fatal("no certificate returned")
	}
	if res.Certificate.Subject.CommonName != "example.test" {
		t.Fatalf("issued CN = %q, want example.test", res.Certificate.Subject.CommonName)
	}
	if res.CertPEM == "" || res.ChainPEM == "" || res.FullchainPEM == "" {
		t.Fatalf("PEM material incomplete: cert=%d chain=%d full=%d",
			len(res.CertPEM), len(res.ChainPEM), len(res.FullchainPEM))
	}
	// The mock verified the OTT: it must have seen the CN as the subject.
	if c.lastOTTSub != "example.test" {
		t.Fatalf("OTT sub seen by CA = %q, want example.test", c.lastOTTSub)
	}
	// And the SANs claim must carry both the CN and the extra SAN.
	if !contains(c.lastOTTSANs, "example.test") || !contains(c.lastOTTSANs, "www.example.test") {
		t.Fatalf("OTT sans = %v, want example.test + www.example.test", c.lastOTTSANs)
	}
}

// --- Acceptance: validity over the provisioner max → rejected ---------------

func TestSignCSRValidityOverMaxRejected(t *testing.T) {
	c := startSignCA(t, 30) // provisioner max = 30 days
	csrPEM, _ := makeTestCSR(t, "example.test", nil, nil, nil, nil)

	_, err := ca.SignCSR(context.Background(), ca.SignParams{
		CAURL:           c.url,
		Fingerprint:     c.fingerprint,
		ProvisionerName: signProvName,
		Password:        signProvPassword,
		CSRPEM:          csrPEM,
		ValidityDays:    365, // over the 30-day max
	})
	if !errors.Is(err, ca.ErrSignRejected) {
		t.Fatalf("err = %v, want ErrSignRejected for validity over max", err)
	}
}

// --- The wrong provisioner password cannot decrypt the signing key ----------

func TestSignCSRWrongPassword(t *testing.T) {
	c := startSignCA(t, 0)
	csrPEM, _ := makeTestCSR(t, "example.test", nil, nil, nil, nil)

	_, err := ca.SignCSR(context.Background(), ca.SignParams{
		CAURL:           c.url,
		Fingerprint:     c.fingerprint,
		ProvisionerName: signProvName,
		Password:        "wrong-password",
		CSRPEM:          csrPEM,
		ValidityDays:    7,
	})
	if !errors.Is(err, ca.ErrProvisionerKey) {
		t.Fatalf("err = %v, want ErrProvisionerKey for the wrong password", err)
	}
}

// --- A missing/unknown provisioner name → clear error -----------------------

func TestSignCSRUnknownProvisioner(t *testing.T) {
	c := startSignCA(t, 0)
	csrPEM, _ := makeTestCSR(t, "example.test", nil, nil, nil, nil)

	_, err := ca.SignCSR(context.Background(), ca.SignParams{
		CAURL:           c.url,
		Fingerprint:     c.fingerprint,
		ProvisionerName: "does-not-exist",
		Password:        signProvPassword,
		CSRPEM:          csrPEM,
		ValidityDays:    7,
	})
	if !errors.Is(err, ca.ErrProvisionerNotFound) {
		t.Fatalf("err = %v, want ErrProvisionerNotFound", err)
	}
}

// A CSR whose self-signature does not verify must be rejected by the exported
// SignCSR entry point itself (defense in depth), BEFORE any CA round-trip. We
// point CAURL at an unreachable address: if the signature check were missing we
// would see a connection error, not ErrInvalidCSR.
func TestSignCSRRejectsBadSignatureCSR(t *testing.T) {
	csrPEM, _ := makeTestCSR(t, "example.test", []string{"example.test"}, nil, nil, nil)
	tampered := tamperCSRSignature(t, csrPEM)

	_, err := ca.SignCSR(context.Background(), ca.SignParams{
		CAURL:           "https://127.0.0.1:1", // would fail to connect if reached
		Fingerprint:     "deadbeef",
		ProvisionerName: "ui-jwk",
		Password:        signProvPassword,
		CSRPEM:          tampered,
		ValidityDays:    7,
	})
	if !errors.Is(err, ca.ErrInvalidCSR) {
		t.Fatalf("err = %v, want ErrInvalidCSR (CSR signature must be verified before any CA call)", err)
	}
}

// tamperCSRSignature decodes a CSR PEM, flips the last DER byte (part of the
// signature) so CheckSignature fails while the structure still parses, and
// re-encodes it.
func tamperCSRSignature(t *testing.T, csrPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("decode CSR PEM")
	}
	der := append([]byte(nil), block.Bytes...)
	der[len(der)-1] ^= 0xFF
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// The OTT-signature-verification crux (a token signed by the WRONG key must be
// rejected by the mock) is proven in the white-box TestSignOTTSignatureIsVerified
// (sign_wb_test.go), which also includes the non-vacuousness probe.

// contains reports whether s contains v.
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// makeTestCSR builds a PEM CSR with the given CN and SANs, returning the PEM and
// the private key PEM.
func makeTestCSR(t *testing.T, cn string, dns []string, ips, emails, uris []string) (csrPEM string, keyPEM string) {
	t.Helper()
	return buildCSR(t, cn, dns, ips, emails, uris)
}
