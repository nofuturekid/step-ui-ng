package ca_test

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
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
)

// --- List provisioners (FR-1) -----------------------------------------------

// startProvisionerListCA stands up a TLS CA serving GET /roots (so the pinned
// trust flow succeeds) and GET /provisioners returning the given pages keyed by
// the incoming ?cursor= value. pages[""] is the first page. It returns the URL
// and the pinned root fingerprint.
func startProvisionerListCA(t *testing.T, pages map[string]string) (caURL, fingerprint string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cert := srv.Certificate()
	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsJSON(cert)))
	})
	mux.HandleFunc("/provisioners", func(w http.ResponseWriter, r *http.Request) {
		body, ok := pages[r.URL.Query().Get("cursor")]
		if !ok {
			http.Error(w, "no such page", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	srv.Config.Handler = mux

	sum := sha256.Sum256(cert.Raw)
	return srv.URL, hex.EncodeToString(sum[:])
}

// Acceptance: reachable CA → list shows provisioners with types.
func TestListProvisioners(t *testing.T) {
	caURL, fp := startProvisionerListCA(t, map[string]string{
		"": `{"provisioners":[
			{"type":"JWK","name":"admin-jwk"},
			{"type":"ACME","name":"acme"},
			{"type":"SSHPOP","name":"sshpop"}
		]}`,
	})

	got, err := ca.ListProvisioners(context.Background(), caURL, fp)
	if err != nil {
		t.Fatalf("ListProvisioners: %v", err)
	}
	want := []ca.Provisioner{
		{Type: "JWK", Name: "admin-jwk"},
		{Type: "ACME", Name: "acme"},
		{Type: "SSHPOP", Name: "sshpop"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d provisioners, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("provisioner[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Pagination: the CA returns a nextCursor; the client follows it and concatenates.
func TestListProvisionersPaginates(t *testing.T) {
	caURL, fp := startProvisionerListCA(t, map[string]string{
		"":      `{"provisioners":[{"type":"JWK","name":"p1"}],"nextCursor":"page2"}`,
		"page2": `{"provisioners":[{"type":"ACME","name":"p2"}],"nextCursor":""}`,
	})

	got, err := ca.ListProvisioners(context.Background(), caURL, fp)
	if err != nil {
		t.Fatalf("ListProvisioners: %v", err)
	}
	if len(got) != 2 || got[0].Name != "p1" || got[1].Name != "p2" {
		t.Fatalf("pagination did not concatenate pages: %+v", got)
	}
}

// A wrong fingerprint must fail the pinned trust even for the list endpoint.
func TestListProvisionersWrongFingerprint(t *testing.T) {
	caURL, _ := startProvisionerListCA(t, map[string]string{
		"": `{"provisioners":[]}`,
	})
	_, err := ca.ListProvisioners(context.Background(), caURL, validFP)
	if !errors.Is(err, ca.ErrFingerprintMismatch) {
		t.Fatalf("err = %v, want ErrFingerprintMismatch", err)
	}
}

// --- Admin credential + token signing (the crux, FR-3/FR-4) -----------------
//
// adminFixture is a CA root, the admin leaf signed by that root (with the key
// usages the server requires: digital signature + clientAuth EKU), and the
// admin private key. It mirrors what step-ca's AuthorizeAdminToken verifies:
//  1. the x5c chain verifies to the CA root (ExtKeyUsageClientAuth),
//  2. the leaf has KeyUsageDigitalSignature,
//  3. the JWT signature verifies with the leaf's public key,
//  4. claims: aud matches the request URL, iss == "step-admin-client/1.0",
//     sub is non-empty, and the token is within its validity window.
type adminFixture struct {
	root     *keyPair
	leaf     *keyPair
	leafKey  *ecdsa.PrivateKey
	caCert   *x509.Certificate // the TLS leaf the mock serves
	caURL    string
	caFP     string
	rootPool *x509.CertPool
}

// genAdminLeaf builds an admin leaf signed by root with digitalSignature +
// clientAuth, returning the cert and its key.
func genAdminLeaf(t *testing.T, root *keyPair, cn string) *keyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen admin leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 7),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &key.PublicKey, root.key)
	if err != nil {
		t.Fatalf("create admin leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse admin leaf: %v", err)
	}
	return &keyPair{cert: cert, key: key, der: der}
}

// pemCert / pemKey encode a cert / EC key as PEM.
func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// verifyAdminToken replicates step-ca's AuthorizeAdminToken so the mock proves
// the client signed correctly. Returns the verified claims or an error.
func verifyAdminToken(t *testing.T, tok string, rootPool *x509.CertPool, wantAud string) (jose.Claims, error) {
	t.Helper()
	jwt, err := jose.ParseSigned(tok)
	if err != nil {
		return jose.Claims{}, err
	}
	// (1) Verify the x5c chain to the CA root with clientAuth EKU.
	chains, err := jwt.Headers[0].Certificates(x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return jose.Claims{}, err
	}
	leaf := chains[0][0]
	// (2) Leaf must allow digital signature.
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return jose.Claims{}, errors.New("leaf lacks digital signature key usage")
	}
	// (3) Verify the JWT signature with the leaf public key.
	var claims jose.Claims
	if err := jwt.Claims(leaf.PublicKey, &claims); err != nil {
		return jose.Claims{}, err
	}
	// (4) Validate time, audience, issuer, subject.
	if err := claims.ValidateWithLeeway(jose.Expected{
		Audience: jose.Audience{wantAud},
		Time:     time.Now().UTC(),
	}, time.Minute); err != nil {
		return jose.Claims{}, err
	}
	if claims.Issuer != "step-admin-client/1.0" {
		return jose.Claims{}, errors.New("unexpected issuer: " + claims.Issuer)
	}
	if claims.Subject == "" {
		return jose.Claims{}, errors.New("empty subject")
	}
	return claims, nil
}

// startAdminCA stands up a mock admin CA. It serves GET /roots (pinned trust),
// and POST/DELETE /admin/provisioners which require a correctly-signed admin
// token verified against the CA root. capture, if non-nil, receives the parsed
// create body. The handler echoes back the provisioner on create.
func startAdminCA(t *testing.T, capture *map[string]any) *adminFixture {
	t.Helper()
	root := genRootCA(t, "Admin Root CA")
	leaf := genAdminLeaf(t, root, "step-admin@ca.test")

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.cert)

	f := &adminFixture{root: root, leaf: leaf, leafKey: leaf.key, rootPool: rootPool}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	f.caCert = srv.Certificate()
	f.caURL = srv.URL
	sum := sha256.Sum256(f.caCert.Raw)
	f.caFP = hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsJSON(f.caCert)))
	})
	requireToken := func(w http.ResponseWriter, r *http.Request) bool {
		tok := r.Header.Get("Authorization")
		if tok == "" {
			http.Error(w, `{"message":"missing authorization"}`, http.StatusUnauthorized)
			return false
		}
		wantAud := f.caURL + "/admin/provisioners"
		if _, err := verifyAdminToken(t, tok, rootPool, wantAud); err != nil {
			http.Error(w, `{"message":"invalid admin token"}`, http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("POST /admin/provisioners", func(w http.ResponseWriter, r *http.Request) {
		if !requireToken(w, r) {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)
		if capture != nil {
			*capture = parsed
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) // echo it back as the created provisioner
	})
	mux.HandleFunc("DELETE /admin/provisioners/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !requireToken(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"deleted"}`))
	})
	srv.Config.Handler = mux
	return f
}

// cred builds an AdminCredential from the fixture (cert chain PEM + key PEM).
func (f *adminFixture) cred(t *testing.T) ca.AdminCredential {
	t.Helper()
	chain := append(pemCert(f.leaf.der), pemCert(f.root.der)...)
	c, err := ca.NewAdminCredential(chain, pemKey(t, f.leafKey))
	if err != nil {
		t.Fatalf("NewAdminCredential: %v", err)
	}
	return c
}

// Acceptance: valid admin creds → create → the provisioner appears (the mock
// admin API accepts a correctly-signed token and returns the created provisioner).
func TestCreateProvisionerSignedToken(t *testing.T) {
	var captured map[string]any
	f := startAdminCA(t, &captured)

	prov, err := ca.CreateProvisioner(context.Background(), f.caURL, f.caFP, f.cred(t),
		ca.NewProvisionerSpec{Name: "ci-jwk", Type: "JWK", JWKSecret: "s3cr3t-pass"})
	if err != nil {
		t.Fatalf("CreateProvisioner: %v", err)
	}
	if prov.Name != "ci-jwk" || prov.Type != "JWK" {
		t.Fatalf("created provisioner = %+v, want ci-jwk/JWK", prov)
	}
	// The mock parsed the body: assert the type/name and that a JWK detail with a
	// public key + encrypted private key was sent (not the raw password).
	if captured["type"] != "JWK" || captured["name"] != "ci-jwk" {
		t.Fatalf("create body type/name = %v/%v", captured["type"], captured["name"])
	}
	details, _ := captured["details"].(map[string]any)
	jwk, _ := details["JWK"].(map[string]any)
	if jwk == nil {
		t.Fatalf("create body missing details.JWK: %+v", captured)
	}
	if _, ok := jwk["publicKey"]; !ok {
		t.Fatalf("create body missing publicKey: %+v", jwk)
	}
	if _, ok := jwk["encryptedPrivateKey"]; !ok {
		t.Fatalf("create body missing encryptedPrivateKey: %+v", jwk)
	}
	// The plaintext password must never appear in the request body.
	raw, _ := json.Marshal(captured)
	if strings.Contains(string(raw), "s3cr3t-pass") {
		t.Fatal("plaintext JWK password leaked into the create request body")
	}
}

// NewAdminCredential: a mismatched cert/key pair (real leaf cert, different private
// key) must be rejected fast — before any network call — so the mismatch surfaces
// locally rather than as a remote 401.
func TestNewAdminCredentialRejectsMismatchedKey(t *testing.T) {
	root := genRootCA(t, "Test Root CA")
	leaf := genAdminLeaf(t, root, "admin@ca.test")

	// A different key whose public half does NOT match the leaf certificate.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen other key: %v", err)
	}
	chain := append(pemCert(leaf.der), pemCert(root.der)...)
	_, err = ca.NewAdminCredential(chain, pemKey(t, otherKey))
	if !errors.Is(err, ca.ErrInvalidAdminCredential) {
		t.Fatalf("err = %v, want ErrInvalidAdminCredential for a mismatched cert/key pair", err)
	}
}

// Acceptance: invalid admin creds → create → clear error (mock returns 401).
func TestCreateProvisionerUnauthorized(t *testing.T) {
	f := startAdminCA(t, nil)

	// A leaf NOT signed by the CA root: the x5c chain verification on the server
	// fails → 401. Use a self-signed leaf as an impostor admin cert.
	impostor := genRootCA(t, "Impostor")
	impostorLeaf := genAdminLeaf(t, impostor, "evil@ca.test")
	chain := append(pemCert(impostorLeaf.der), pemCert(impostor.der)...)
	cred, err := ca.NewAdminCredential(chain, pemKey(t, impostorLeaf.key))
	if err != nil {
		t.Fatalf("NewAdminCredential: %v", err)
	}

	_, err = ca.CreateProvisioner(context.Background(), f.caURL, f.caFP, cred,
		ca.NewProvisionerSpec{Name: "x", Type: "JWK", JWKSecret: "passphrase"})
	if !errors.Is(err, ca.ErrAdminUnauthorized) {
		t.Fatalf("err = %v, want ErrAdminUnauthorized", err)
	}
}

// Delete: a correctly-signed token deletes the named provisioner.
func TestDeleteProvisionerSignedToken(t *testing.T) {
	f := startAdminCA(t, nil)
	if err := ca.DeleteProvisioner(context.Background(), f.caURL, f.caFP, f.cred(t), "old-prov"); err != nil {
		t.Fatalf("DeleteProvisioner: %v", err)
	}
}

// Delete with bad creds → ErrAdminUnauthorized.
func TestDeleteProvisionerUnauthorized(t *testing.T) {
	f := startAdminCA(t, nil)
	impostor := genRootCA(t, "Impostor")
	impostorLeaf := genAdminLeaf(t, impostor, "evil@ca.test")
	chain := append(pemCert(impostorLeaf.der), pemCert(impostor.der)...)
	cred, err := ca.NewAdminCredential(chain, pemKey(t, impostorLeaf.key))
	if err != nil {
		t.Fatalf("NewAdminCredential: %v", err)
	}
	err = ca.DeleteProvisioner(context.Background(), f.caURL, f.caFP, cred, "p")
	if !errors.Is(err, ca.ErrAdminUnauthorized) {
		t.Fatalf("err = %v, want ErrAdminUnauthorized", err)
	}
}

// Create ACME and SSHPOP provisioners build the right detail envelope (no JWK
// secret needed).
func TestCreateProvisionerACMEAndSSHPOP(t *testing.T) {
	for _, typ := range []string{"ACME", "SSHPOP"} {
		t.Run(typ, func(t *testing.T) {
			var captured map[string]any
			f := startAdminCA(t, &captured)
			_, err := ca.CreateProvisioner(context.Background(), f.caURL, f.caFP, f.cred(t),
				ca.NewProvisionerSpec{Name: "p-" + typ, Type: typ})
			if err != nil {
				t.Fatalf("CreateProvisioner %s: %v", typ, err)
			}
			details, _ := captured["details"].(map[string]any)
			if _, ok := details[typ]; !ok {
				t.Fatalf("create body for %s missing details.%s: %+v", typ, typ, captured)
			}
		})
	}
}
