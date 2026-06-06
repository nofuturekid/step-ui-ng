package ca_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
)

// --- ACME + EAB mock admin CA (spec/0010) -----------------------------------
//
// startACMEAdminCA stands up a TLS mock CA serving GET /roots (pinned trust) plus
// the ACME admin surface: POST/PUT /admin/provisioners (verified admin token),
// and the EAB endpoints POST/GET /admin/acme/eab/{prov} and DELETE
// /admin/acme/eab/{prov}/{id}. Each EAB request requires a correctly-signed admin
// token whose audience is the EAB collection endpoint — proving the token machine
// is exercised for EAB, not just provisioner CRUD. It keeps an in-memory store of
// EAB keys keyed by provisioner so create→list→delete behave end to end.
type acmeAdminCA struct {
	*adminFixture
	created    *map[string]any // last create/update provisioner body
	deleted    *[]string       // keyIDs the CA was asked to delete
	hmacB64    string          // base64 HMAC the CA returns on create
	store      map[string][]map[string]any
	skipEABTok bool // when true the CA skips EAB token verification (non-vacuous probe)
}

func startACMEAdminCA(t *testing.T) *acmeAdminCA {
	t.Helper()
	var created map[string]any
	var deleted []string
	c := &acmeAdminCA{
		created: &created,
		deleted: &deleted,
		// 32 random-ish bytes, base64-encoded — the shape step-ca returns.
		hmacB64: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		store:   map[string][]map[string]any{},
	}

	root := genRootCA(t, "ACME Admin Root CA")
	leaf := genAdminLeaf(t, root, "step-admin@acme.test")
	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.cert)
	c.adminFixture = &adminFixture{root: root, leaf: leaf, leafKey: leaf.key, rootPool: rootPool}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c.caCert = srv.Certificate()
	c.caURL = srv.URL
	sum := sha256.Sum256(c.caCert.Raw)
	c.caFP = hex.EncodeToString(sum[:])

	// requireToken verifies the admin token against the given audience, mirroring
	// step-ca's AuthorizeAdminToken (chain → leaf usage → JWS sig → claims).
	requireToken := func(w http.ResponseWriter, r *http.Request, wantAud string) bool {
		tok := r.Header.Get("Authorization")
		if tok == "" {
			http.Error(w, `{"message":"missing authorization"}`, http.StatusUnauthorized)
			return false
		}
		if _, err := verifyAdminToken(t, tok, rootPool, wantAud); err != nil {
			http.Error(w, `{"message":"invalid admin token"}`, http.StatusUnauthorized)
			return false
		}
		return true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsJSON(c.caCert)))
	})
	provAud := func() string { return c.caURL + "/admin/provisioners" }
	mux.HandleFunc("POST /admin/provisioners", func(w http.ResponseWriter, r *http.Request) {
		if !requireToken(w, r, provAud()) {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = json.Unmarshal(body, &created)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("PUT /admin/provisioners/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !requireToken(w, r, provAud()) {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = json.Unmarshal(body, &created)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	eabAud := func(prov string) string { return c.caURL + "/admin/acme/eab/" + prov }
	mux.HandleFunc("POST /admin/acme/eab/{prov}", func(w http.ResponseWriter, r *http.Request) {
		prov := r.PathValue("prov")
		if !c.skipEABTok && !requireToken(w, r, eabAud(prov)) {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var req struct {
			Reference string `json:"reference"`
		}
		_ = json.Unmarshal(body, &req)
		id := "eab-" + prov + "-" + req.Reference
		if req.Reference == "" {
			id = "eab-" + prov + "-auto"
		}
		key := map[string]any{
			"id":          id,
			"provisioner": prov,
			"reference":   req.Reference,
			"createdAt":   "2026-06-06T00:00:00Z",
		}
		// Store WITHOUT the hmac so list never echoes it (matches step-ca: the
		// HMAC is only ever returned at create time).
		c.store[prov] = append(c.store[prov], key)
		// The create response DOES include the hmac.
		resp := map[string]any{}
		for k, v := range key {
			resp[k] = v
		}
		resp["hmacKey"] = c.hmacB64
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("GET /admin/acme/eab/{prov}", func(w http.ResponseWriter, r *http.Request) {
		prov := r.PathValue("prov")
		if !requireToken(w, r, eabAud(prov)) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"eaks":       c.store[prov],
			"nextCursor": "",
		})
	})
	mux.HandleFunc("DELETE /admin/acme/eab/{prov}/{id}", func(w http.ResponseWriter, r *http.Request) {
		prov := r.PathValue("prov")
		id := r.PathValue("id")
		if !requireToken(w, r, eabAud(prov)) {
			return
		}
		deleted = append(deleted, id)
		kept := c.store[prov][:0]
		for _, k := range c.store[prov] {
			if k["id"] != id {
				kept = append(kept, k)
			}
		}
		c.store[prov] = kept
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"deleted"}`))
	})
	srv.Config.Handler = mux
	return c
}

// Acceptance: create an ACME provisioner with dns-01 + requireEAB → the CA
// receives the correct linkedca-shaped body (challenges as protojson enum names,
// requireEab true), and the directory URL is derived correctly.
func TestCreateACMEProvisionerOptions(t *testing.T) {
	c := startACMEAdminCA(t)
	_, err := ca.CreateProvisioner(context.Background(), c.caURL, c.caFP, c.cred(t),
		ca.NewProvisionerSpec{
			Name:           "acme1",
			Type:           "ACME",
			ACMEChallenges: []string{"dns-01"},
			ACMERequireEAB: true,
		})
	if err != nil {
		t.Fatalf("CreateProvisioner ACME: %v", err)
	}
	details, _ := (*c.created)["details"].(map[string]any)
	acme, _ := details["ACME"].(map[string]any)
	if acme == nil {
		t.Fatalf("create body missing details.ACME: %+v", *c.created)
	}
	if acme["requireEab"] != true {
		t.Fatalf("requireEab not set: %+v", acme)
	}
	ch, _ := acme["challenges"].([]any)
	if len(ch) != 1 || ch[0] != "DNS_01" {
		t.Fatalf("challenges = %+v, want [DNS_01] (protojson enum name)", acme["challenges"])
	}

	want := c.caURL + "/acme/acme1/directory"
	if got := ca.DirectoryURL(c.caURL, "acme1"); got != want {
		t.Fatalf("DirectoryURL = %q, want %q", got, want)
	}
}

// UpdateProvisioner edits the ACME options via PUT (admin token verified).
//
// requireEab is sent EXPLICITLY — including false — so an update that turns EAB
// off is unambiguously applied at the CA rather than being silently dropped by an
// omitempty. (Earlier this asserted omission-when-false, which made a destructive
// edit that clears requireEAB indistinguishable from one that leaves it; see the
// app-layer merge-on-edit fix in spec/0010.)
func TestUpdateACMEProvisioner(t *testing.T) {
	c := startACMEAdminCA(t)
	_, err := ca.UpdateProvisioner(context.Background(), c.caURL, c.caFP, c.cred(t),
		ca.NewProvisionerSpec{
			Name:           "acme1",
			Type:           "ACME",
			ACMEChallenges: []string{"http-01", "tls-alpn-01"},
			ACMERequireEAB: false,
		})
	if err != nil {
		t.Fatalf("UpdateProvisioner: %v", err)
	}
	details, _ := (*c.created)["details"].(map[string]any)
	acme, _ := details["ACME"].(map[string]any)
	if v, has := acme["requireEab"]; !has || v != false {
		t.Fatalf("requireEab must be sent explicitly as false, got has=%v v=%v: %+v", has, v, acme)
	}
	ch, _ := acme["challenges"].([]any)
	if len(ch) != 2 || ch[0] != "HTTP_01" || ch[1] != "TLS_ALPN_01" {
		t.Fatalf("challenges = %+v, want [HTTP_01 TLS_ALPN_01]", acme["challenges"])
	}
}

// ListACMEProvisioners parses each ACME provisioner's current details from the
// public GET /provisioners list — the friendly challenge names and requireEAB —
// so the app layer can pre-fill the edit form and merge updates rather than
// silently dropping fields. Non-ACME provisioners are excluded.
func TestListACMEProvisionersParsesDetails(t *testing.T) {
	caURL, fp := startProvisionerListCA(t, map[string]string{
		"": `{"provisioners":[
			{"type":"JWK","name":"admin-jwk"},
			{"type":"ACME","name":"eab-required","requireEAB":true,"challenges":["dns-01"]},
			{"type":"ACME","name":"open","challenges":["http-01","tls-alpn-01"]}
		]}`,
	})

	got, err := ca.ListACMEProvisioners(context.Background(), caURL, fp)
	if err != nil {
		t.Fatalf("ListACMEProvisioners: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d ACME provisioners, want 2: %+v", len(got), got)
	}
	byName := map[string]ca.ACMEProvisioner{}
	for _, p := range got {
		byName[p.Name] = p
	}
	if p := byName["eab-required"]; !p.RequireEAB ||
		len(p.Challenges) != 1 || p.Challenges[0] != "dns-01" {
		t.Fatalf("eab-required parsed wrong: %+v", p)
	}
	if p := byName["open"]; p.RequireEAB ||
		len(p.Challenges) != 2 || p.Challenges[0] != "http-01" || p.Challenges[1] != "tls-alpn-01" {
		t.Fatalf("open parsed wrong: %+v", p)
	}
}

// Acceptance: create an EAB key → keyID + HMAC returned ONCE on create.
func TestCreateEABKeyReturnsHMACOnce(t *testing.T) {
	c := startACMEAdminCA(t)
	key, err := ca.CreateEABKey(context.Background(), c.caURL, c.caFP, c.cred(t), "acme1", "laptop")
	if err != nil {
		t.Fatalf("CreateEABKey: %v", err)
	}
	if key.KeyID == "" {
		t.Fatalf("create returned empty keyID: %+v", key)
	}
	if key.HMAC != c.hmacB64 {
		t.Fatalf("create HMAC = %q, want %q (the one-time secret)", key.HMAC, c.hmacB64)
	}
	if key.Reference != "laptop" {
		t.Fatalf("reference = %q, want laptop", key.Reference)
	}
}

// Acceptance: after create, the key is LISTED without the HMAC (the list view can
// never leak the secret). The HMAC string must be absent from every list row.
func TestListEABKeysNeverIncludesHMAC(t *testing.T) {
	c := startACMEAdminCA(t)
	created, err := ca.CreateEABKey(context.Background(), c.caURL, c.caFP, c.cred(t), "acme1", "server")
	if err != nil {
		t.Fatalf("CreateEABKey: %v", err)
	}
	list, err := ca.ListEABKeys(context.Background(), c.caURL, c.caFP, c.cred(t), "acme1")
	if err != nil {
		t.Fatalf("ListEABKeys: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1: %+v", len(list), list)
	}
	if list[0].KeyID != created.KeyID {
		t.Fatalf("listed keyID = %q, want %q", list[0].KeyID, created.KeyID)
	}
	if list[0].HMAC != "" {
		t.Fatalf("list row carried the HMAC %q — it must be stripped", list[0].HMAC)
	}
	// Defence in depth: the create HMAC must not appear anywhere in the listed
	// keys, even via another field.
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), created.HMAC) {
		t.Fatalf("the create HMAC leaked into the EAB list: %s", raw)
	}
}

// Acceptance: revoke (delete) an EAB key → the CA receives the delete and the key
// is removed from the list.
func TestDeleteEABKeyRemovesFromList(t *testing.T) {
	c := startACMEAdminCA(t)
	created, err := ca.CreateEABKey(context.Background(), c.caURL, c.caFP, c.cred(t), "acme1", "old")
	if err != nil {
		t.Fatalf("CreateEABKey: %v", err)
	}
	if err := ca.DeleteEABKey(context.Background(), c.caURL, c.caFP, c.cred(t), "acme1", created.KeyID); err != nil {
		t.Fatalf("DeleteEABKey: %v", err)
	}
	if len(*c.deleted) != 1 || (*c.deleted)[0] != created.KeyID {
		t.Fatalf("CA did not receive the delete by keyID: %+v", *c.deleted)
	}
	list, err := ca.ListEABKeys(context.Background(), c.caURL, c.caFP, c.cred(t), "acme1")
	if err != nil {
		t.Fatalf("ListEABKeys: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("key still listed after delete: %+v", list)
	}
}

// EAB operations with an impostor admin credential → ErrAdminUnauthorized (the
// EAB endpoints genuinely verify the token).
func TestEABUnauthorized(t *testing.T) {
	c := startACMEAdminCA(t)
	impostor := genRootCA(t, "Impostor")
	impostorLeaf := genAdminLeaf(t, impostor, "evil@acme.test")
	chain := append(pemCert(impostorLeaf.der), pemCert(impostor.der)...)
	cred, err := ca.NewAdminCredential(chain, pemKey(t, impostorLeaf.key))
	if err != nil {
		t.Fatalf("NewAdminCredential: %v", err)
	}
	if _, err := ca.CreateEABKey(context.Background(), c.caURL, c.caFP, cred, "acme1", "x"); !errors.Is(err, ca.ErrAdminUnauthorized) {
		t.Fatalf("CreateEABKey err = %v, want ErrAdminUnauthorized", err)
	}
	if _, err := ca.ListEABKeys(context.Background(), c.caURL, c.caFP, cred, "acme1"); !errors.Is(err, ca.ErrAdminUnauthorized) {
		t.Fatalf("ListEABKeys err = %v, want ErrAdminUnauthorized", err)
	}
	if err := ca.DeleteEABKey(context.Background(), c.caURL, c.caFP, cred, "acme1", "k"); !errors.Is(err, ca.ErrAdminUnauthorized) {
		t.Fatalf("DeleteEABKey err = %v, want ErrAdminUnauthorized", err)
	}
}

// Non-vacuousness: with the EAB-create token check disabled, the SAME impostor
// credential is accepted — proving the token verification above is the guard that
// rejects it (the mock is not vacuous on the EAB create path).
func TestEABMockNonVacuous(t *testing.T) {
	c := startACMEAdminCA(t)
	c.skipEABTok = true
	impostor := genRootCA(t, "Impostor")
	impostorLeaf := genAdminLeaf(t, impostor, "evil@acme.test")
	chain := append(pemCert(impostorLeaf.der), pemCert(impostor.der)...)
	cred, err := ca.NewAdminCredential(chain, pemKey(t, impostorLeaf.key))
	if err != nil {
		t.Fatalf("NewAdminCredential: %v", err)
	}
	if _, err := ca.CreateEABKey(context.Background(), c.caURL, c.caFP, cred, "acme1", "x"); err != nil {
		t.Fatalf("with EAB token check disabled the impostor should be accepted, got: %v", err)
	}
}

// Invalid ACME challenge → ErrInvalidProvisioner before any CA call.
func TestCreateACMEInvalidChallenge(t *testing.T) {
	c := startACMEAdminCA(t)
	_, err := ca.CreateProvisioner(context.Background(), c.caURL, c.caFP, c.cred(t),
		ca.NewProvisionerSpec{Name: "acme1", Type: "ACME", ACMEChallenges: []string{"bogus-01"}})
	if !errors.Is(err, ca.ErrInvalidProvisioner) {
		t.Fatalf("err = %v, want ErrInvalidProvisioner", err)
	}
}
