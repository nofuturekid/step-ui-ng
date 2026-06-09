package ca_test

// Tests for the AdminAuth credential-source abstraction (ADR-0018, spec/0012 FR-4).
//
// TDD strategy:
//   - TestX5CStoredCredential: x5cStored passes through a pre-built AdminCredential
//     unchanged; its token is accepted by the mock admin endpoint.
//   - TestJWKMintedCredential: jwkMinted mints a cert from the JWK provisioner
//     (OTT → /1.0/sign) and the resulting token is accepted by the mock admin endpoint.
//   - TestJWKMintedWrongPassword: wrong password → ErrProvisionerKey (typed error,
//     never leaking the password).
//   - TestJWKMintedEmptySubject: empty subject → ErrInvalidAdminCredential.
//   - TestDeleteProvisionerViaJWKMinted: Delete works end-to-end through the
//     JWK-minted credential source.

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

	"github.com/nofuturekid/step-ui-ng/internal/ca"
)

// --- Combined mock CA for AdminAuth tests -----------------------------------
//
// dualMockCA serves:
//   - GET /roots               (pinned trust for both sign and admin paths)
//   - GET /provisioners        (JWK provisioner with encryptedKey)
//   - POST /1.0/sign           (verifies OTT, issues a leaf with clientAuth EKU)
//   - POST /admin/provisioners (verifies x5c admin token; accepts tokens whose
//     x5c chain verifies to the mock's issuing root)
//   - DELETE /admin/provisioners/{name} (same)

type dualMockCA struct {
	url         string
	fingerprint string
	rootPool    *x509.CertPool
}

func startDualMockCA(t *testing.T) *dualMockCA {
	t.Helper()

	const provName = signProvName

	pub, encKey := buildSignProvisioner(t)
	root := genRootCA(t, "Dual Root CA")
	intermediate := genIntermediateCA(t, root, "Dual Intermediate CA")

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.cert)

	d := &dualMockCA{rootPool: rootPool}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsCert := srv.Certificate()
	d.url = srv.URL
	sum := sha256.Sum256(tlsCert.Raw)
	d.fingerprint = hex.EncodeToString(sum[:])

	wantSignAud := d.url + "/1.0/sign"
	wantAdminAud := d.url + "/admin/provisioners"

	requireAdminToken := func(w http.ResponseWriter, r *http.Request) bool {
		tok := r.Header.Get("Authorization")
		if tok == "" {
			http.Error(w, `{"message":"missing authorization"}`, http.StatusUnauthorized)
			return false
		}
		jwt, err := jose.ParseSigned(tok)
		if err != nil {
			http.Error(w, `{"message":"bad token"}`, http.StatusUnauthorized)
			return false
		}
		chains, err := jwt.Headers[0].Certificates(x509.VerifyOptions{
			Roots:     rootPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			http.Error(w, `{"message":"x5c chain invalid"}`, http.StatusUnauthorized)
			return false
		}
		leaf := chains[0][0]
		if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			http.Error(w, `{"message":"leaf lacks digital signature"}`, http.StatusUnauthorized)
			return false
		}
		var claims jose.Claims
		if err := jwt.Claims(leaf.PublicKey, &claims); err != nil {
			http.Error(w, `{"message":"signature invalid"}`, http.StatusUnauthorized)
			return false
		}
		if err := claims.ValidateWithLeeway(jose.Expected{
			Audience: jose.Audience{wantAdminAud},
			Time:     time.Now().UTC(),
		}, time.Minute); err != nil {
			http.Error(w, `{"message":"claims invalid"}`, http.StatusUnauthorized)
			return false
		}
		return claims.Issuer == "step-admin-client/1.0" && claims.Subject != ""
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsJSON(tlsCert)))
	})

	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		pubBytes, _ := pub.MarshalJSON()
		body := `{"provisioners":[{"type":"JWK","name":"` + provName + `","key":` +
			string(pubBytes) + `,"encryptedKey":"` + encKey + `"}]}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	// POST /1.0/sign: verify OTT, issue a leaf with digitalSignature + clientAuth.
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			CsrPEM string `json:"csr"`
			OTT    string `json:"ott"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"message":"bad request"}`, http.StatusBadRequest)
			return
		}
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
		if err := claims.ValidateWithLeeway(jose.Expected{
			Issuer:   provName,
			Audience: jose.Audience{wantSignAud},
			Time:     time.Now().UTC(),
		}, time.Minute); err != nil {
			http.Error(w, `{"message":"invalid claims"}`, http.StatusUnauthorized)
			return
		}
		if claims.Subject == "" {
			http.Error(w, `{"message":"empty subject"}`, http.StatusUnauthorized)
			return
		}

		// Parse the CSR and verify its self-signature.
		block, _ := pem.Decode([]byte(req.CsrPEM))
		if block == nil {
			http.Error(w, `{"message":"bad csr pem"}`, http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, `{"message":"parse csr: `+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		if err := csr.CheckSignature(); err != nil {
			http.Error(w, `{"message":"csr signature invalid"}`, http.StatusBadRequest)
			return
		}

		// Issue the leaf with clientAuth EKU + digitalSignature so it is usable
		// as an admin credential in the admin endpoint above.
		leafPEM, chainPEM := issueFromCSR(t, csr, root, intermediate, time.Now().Add(time.Hour))
		resp := map[string]any{
			"crt":       leafPEM,
			"ca":        pemOfCertString(intermediate.cert),
			"certChain": []string{leafPEM, chainPEM},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("POST /admin/provisioners", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdminToken(w, r) {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	mux.HandleFunc("DELETE /admin/provisioners/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdminToken(w, r) {
			return
		}
		_, _ = w.Write([]byte(`{"status":"deleted"}`))
	})

	srv.Config.Handler = mux
	return d
}

// --- Acceptance: x5cStored passes the pre-built credential through unchanged ---

// TestX5CStoredCredential: an x5cStored AdminAuth returns the same credential
// and its token is accepted by the mock admin endpoint.
func TestX5CStoredCredential(t *testing.T) {
	f := startAdminCA(t, nil)

	cred := f.cred(t)
	auth := ca.X5CStored(cred)

	got, err := auth.Credential(context.Background())
	if err != nil {
		t.Fatalf("X5CStored.Credential: %v", err)
	}

	_, err = ca.CreateProvisioner(context.Background(), f.caURL, f.caFP, got,
		ca.NewProvisionerSpec{Name: "x5c-test", Type: "JWK", JWKSecret: "s3cr3tPass"})
	if err != nil {
		t.Fatalf("CreateProvisioner via x5cStored: %v", err)
	}
}

// --- Acceptance: jwkMinted mints a valid admin cert; token accepted ----------

// TestJWKMintedCredential: JWKMinted.Credential mints an ephemeral cert via the
// JWK provisioner and the resulting x5c admin token is accepted by the mock
// admin endpoint.
func TestJWKMintedCredential(t *testing.T) {
	d := startDualMockCA(t)

	auth := ca.JWKMinted(ca.JWKMintedParams{
		CAURL:           d.url,
		Fingerprint:     d.fingerprint,
		ProvisionerName: signProvName,
		Password:        signProvPassword,
		Subject:         "step",
	})

	cred, err := auth.Credential(context.Background())
	if err != nil {
		t.Fatalf("JWKMinted.Credential: %v", err)
	}

	// The minted credential must produce an admin token the mock accepts.
	_, err = ca.CreateProvisioner(context.Background(), d.url, d.fingerprint, cred,
		ca.NewProvisionerSpec{Name: "jwk-minted-test", Type: "JWK", JWKSecret: "s3cr3tPass"})
	if err != nil {
		t.Fatalf("CreateProvisioner via jwkMinted credential: %v", err)
	}
}

// --- Acceptance: wrong password → ErrProvisionerKey, password never leaked --

func TestJWKMintedWrongPassword(t *testing.T) {
	d := startDualMockCA(t)

	const badPass = "wrong-password-xyz"
	auth := ca.JWKMinted(ca.JWKMintedParams{
		CAURL:           d.url,
		Fingerprint:     d.fingerprint,
		ProvisionerName: signProvName,
		Password:        badPass,
		Subject:         "step",
	})

	_, err := auth.Credential(context.Background())
	if !errors.Is(err, ca.ErrProvisionerKey) {
		t.Fatalf("err = %v, want ErrProvisionerKey for wrong password", err)
	}
	// The password text must never appear in the error.
	if containsSubstr(err.Error(), badPass) {
		t.Fatal("wrong password text leaked into the error message")
	}
}

// --- Acceptance: empty subject → ErrInvalidAdminCredential ------------------

func TestJWKMintedEmptySubject(t *testing.T) {
	d := startDualMockCA(t)

	auth := ca.JWKMinted(ca.JWKMintedParams{
		CAURL:           d.url,
		Fingerprint:     d.fingerprint,
		ProvisionerName: signProvName,
		Password:        signProvPassword,
		Subject:         "",
	})

	_, err := auth.Credential(context.Background())
	if !errors.Is(err, ca.ErrInvalidAdminCredential) {
		t.Fatalf("err = %v, want ErrInvalidAdminCredential for empty subject", err)
	}
}

// --- Acceptance: Delete provisioner via jwkMinted credential source ---------

func TestDeleteProvisionerViaJWKMinted(t *testing.T) {
	d := startDualMockCA(t)

	auth := ca.JWKMinted(ca.JWKMintedParams{
		CAURL:           d.url,
		Fingerprint:     d.fingerprint,
		ProvisionerName: signProvName,
		Password:        signProvPassword,
		Subject:         "step",
	})

	cred, err := auth.Credential(context.Background())
	if err != nil {
		t.Fatalf("JWKMinted.Credential: %v", err)
	}

	if err := ca.DeleteProvisioner(context.Background(), d.url, d.fingerprint, cred, "old-prov"); err != nil {
		t.Fatalf("DeleteProvisioner via jwkMinted credential: %v", err)
	}
}

// containsSubstr reports whether s contains substr.
func containsSubstr(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
