package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/nofuturekid/step-ui-ng/internal/audit"
	"github.com/nofuturekid/step-ui-ng/internal/settings"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// --- ACME + EAB mock CA (spec/0010) -----------------------------------------
//
// acmeCAFixture is a TLS mock CA serving /roots (pinned trust), GET /provisioners,
// the admin provisioner endpoints (POST/PUT/DELETE), and the EAB endpoints
// (POST/GET/DELETE /admin/acme/eab/{prov}). Every admin request requires a
// correctly-signed x5c admin token verified against the CA root — the same checks
// step-ca performs — so the mock is non-vacuous. The EAB store keeps keys per
// provisioner so create→list→revoke behave end to end. The HMAC is returned ONLY
// on create and never stored, mirroring step-ca.
type acmeCAFixture struct {
	url         string
	fingerprint string
	adminCert   string
	adminKey    string
	provJSON    string // GET /provisioners body (mutable)
	hmacB64     string
	store       map[string][]map[string]any
	createBody  map[string]any // last create/update provisioner body
	deletedEAB  []string       // EAB keyIDs deleted
}

func startACMECA(t *testing.T, provJSON string) *acmeCAFixture {
	t.Helper()

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "ACME Admin Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "step-admin@acme.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	f := &acmeCAFixture{
		provJSON: provJSON,
		hmacB64:  base64.StdEncoding.EncodeToString([]byte("abcdefabcdefabcdefabcdefabcdef01")),
		store:    map[string][]map[string]any{},
	}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsCert := srv.Certificate()
	f.url = srv.URL
	sum := sha256.Sum256(tlsCert.Raw)
	f.fingerprint = hex.EncodeToString(sum[:])

	rootsBody := `{"crts":["` + strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Raw})), "\n", `\n`) + `"]}`

	// verify checks the admin token's signature/chain/claims for the given
	// audience — the exact step-ca AuthorizeAdminToken checks. A wrong audience or
	// a forged signature is rejected, so the mock is non-vacuous.
	verify := func(r *http.Request, wantAud string) bool {
		tok := r.Header.Get("Authorization")
		if tok == "" {
			return false
		}
		jwt, err := jose.ParseSigned(tok)
		if err != nil {
			return false
		}
		chains, err := jwt.Headers[0].Certificates(x509.VerifyOptions{
			Roots:     rootPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return false
		}
		l := chains[0][0]
		if l.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return false
		}
		var claims jose.Claims
		if err := jwt.Claims(l.PublicKey, &claims); err != nil {
			return false
		}
		if err := claims.ValidateWithLeeway(jose.Expected{
			Audience: jose.Audience{wantAud},
			Time:     time.Now().UTC(),
		}, time.Minute); err != nil {
			return false
		}
		return claims.Issuer == "step-admin-client/1.0" && claims.Subject != ""
	}
	provAud := func() string { return f.url + "/admin/provisioners" }
	eabAud := func(prov string) string { return f.url + "/admin/acme/eab/" + prov }

	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsBody))
	})
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.provJSON))
	})
	mux.HandleFunc("POST /admin/provisioners", func(w http.ResponseWriter, r *http.Request) {
		if !verify(r, provAud()) {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = json.Unmarshal(body, &f.createBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("PUT /admin/provisioners/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !verify(r, provAud()) {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = json.Unmarshal(body, &f.createBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("DELETE /admin/provisioners/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !verify(r, provAud()) {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /admin/acme/eab/{prov}", func(w http.ResponseWriter, r *http.Request) {
		prov := r.PathValue("prov")
		if !verify(r, eabAud(prov)) {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var req struct {
			Reference string `json:"reference"`
		}
		_ = json.Unmarshal(body, &req)
		id := "eab-" + req.Reference
		if req.Reference == "" {
			id = "eab-auto"
		}
		key := map[string]any{"id": id, "provisioner": prov, "reference": req.Reference, "createdAt": "2026-06-06T00:00:00Z"}
		f.store[prov] = append(f.store[prov], key) // stored WITHOUT hmac
		resp := map[string]any{"hmacKey": f.hmacB64}
		for k, v := range key {
			resp[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("GET /admin/acme/eab/{prov}", func(w http.ResponseWriter, r *http.Request) {
		prov := r.PathValue("prov")
		if !verify(r, eabAud(prov)) {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"eaks": f.store[prov], "nextCursor": ""})
	})
	mux.HandleFunc("DELETE /admin/acme/eab/{prov}/{id}", func(w http.ResponseWriter, r *http.Request) {
		prov := r.PathValue("prov")
		id := r.PathValue("id")
		if !verify(r, eabAud(prov)) {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		f.deletedEAB = append(f.deletedEAB, id)
		kept := f.store[prov][:0]
		for _, k := range f.store[prov] {
			if k["id"] != id {
				kept = append(kept, k)
			}
		}
		f.store[prov] = kept
		_, _ = w.Write([]byte(`{"status":"deleted"}`))
	})
	srv.Config.Handler = mux

	f.adminCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	f.adminKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return f
}

// seedACMECA saves CA settings + admin credential pointing at the ACME fixture.
func (e *testEnv) seedACMECA(t *testing.T, f *acmeCAFixture) {
	t.Helper()
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: f.url, RootFingerprint: f.fingerprint,
	}); err != nil {
		t.Fatalf("seed CA settings: %v", err)
	}
	if err := e.settingsRepo.SaveAdminCredential(context.Background(), f.adminCert, f.adminKey); err != nil {
		t.Fatalf("seed admin credential: %v", err)
	}
}

// auditActions returns the recorded audit actions+targets+details for assertions.
func (e *testEnv) auditEvents(t *testing.T) []audit.Event {
	t.Helper()
	evs, err := e.auditRec.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	return evs
}

// --- Acceptance: create ACME provisioner with dns-01 + requireEAB (FR-1) -----

func TestACMECreateProvisionerWithOptions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[]}`)
	e.seedACMECA(t, f)

	token := e.csrfToken(t, "/acme")
	resp := e.post(t, "/acme/provisioners", url.Values{
		"csrf_token":  {token},
		"name":        {"acme1"},
		"challenge":   {"dns-01"},
		"require_eab": {"on"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create ACME status = %d, want 303", resp.StatusCode)
	}

	// The CA received the correct linkedca-shaped body.
	details, _ := f.createBody["details"].(map[string]any)
	acme, _ := details["ACME"].(map[string]any)
	if acme == nil || acme["requireEab"] != true {
		t.Fatalf("CA did not receive requireEab=true: %+v", f.createBody)
	}
	ch, _ := acme["challenges"].([]any)
	if len(ch) != 1 || ch[0] != "DNS_01" {
		t.Fatalf("CA challenges = %+v, want [DNS_01]", acme["challenges"])
	}

	// The provisioner now appears with its directory URL on the list page.
	f.provJSON = `{"provisioners":[{"type":"ACME","name":"acme1"}]}`
	_, body := e.getBody(t, "/acme")
	if !strings.Contains(body, "acme1") {
		t.Fatalf("ACME list missing acme1; body:\n%s", body)
	}
	if !strings.Contains(body, f.url+"/acme/acme1/directory") {
		t.Fatalf("ACME list missing directory URL; body:\n%s", body)
	}

	// Audit event recorded, attributed to the session user, with no secret.
	found := false
	for _, ev := range e.auditEvents(t) {
		if ev.Action == "acme.provisioner.create" && ev.Target == "acme1" {
			found = true
			if ev.Who != "root" {
				t.Fatalf("audit who = %q, want root", ev.Who)
			}
			if !strings.Contains(ev.Details, "requireEAB=true") || !strings.Contains(ev.Details, "dns-01") {
				t.Fatalf("audit details missing options: %q", ev.Details)
			}
		}
	}
	if !found {
		t.Fatal("no acme.provisioner.create audit event")
	}
}

// --- Acceptance: EAB create shows HMAC ONCE, then listed without it (FR-2) ----

func TestACMEEABCreateShowsHMACOnceThenHidden(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme1"}]}`)
	e.seedACMECA(t, f)

	token := e.csrfToken(t, "/acme/eab/acme1")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/acme/eab/acme1",
		strings.NewReader(url.Values{"csrf_token": {token}, "reference": {"laptop"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Referer", e.srv.URL+"/acme/eab/acme1")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("create EAB: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create EAB status = %d, want 200 (one-time display); body:\n%s", resp.StatusCode, body)
	}
	// The one-time display shows the HMAC.
	if !strings.Contains(string(body), f.hmacB64) {
		t.Fatalf("create response missing the one-time HMAC; body:\n%s", body)
	}
	// And carries no-store so it is never cached.
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("create response Cache-Control = %q, want no-store", cc)
	}

	// Thereafter the list view must NOT contain the HMAC.
	_, listBody := e.getBody(t, "/acme/eab/acme1")
	if strings.Contains(listBody, f.hmacB64) {
		t.Fatalf("the HMAC leaked into the EAB list view; body:\n%s", listBody)
	}
	// The keyID is still listed.
	if !strings.Contains(listBody, "eab-laptop") {
		t.Fatalf("EAB list missing the created keyID; body:\n%s", listBody)
	}

	// Audit: an acme.eab.create event with NO HMAC anywhere in the row.
	found := false
	for _, ev := range e.auditEvents(t) {
		if ev.Action == "acme.eab.create" {
			found = true
			if ev.Who != "root" {
				t.Fatalf("audit who = %q, want root", ev.Who)
			}
			raw, _ := json.Marshal(ev)
			if strings.Contains(string(raw), f.hmacB64) {
				t.Fatalf("the HMAC leaked into an audit row: %s", raw)
			}
		}
	}
	if !found {
		t.Fatal("no acme.eab.create audit event")
	}
}

// --- Acceptance: revoke an EAB key → removed from the list (FR-2) ------------

func TestACMEEABRevokeRemovesFromList(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme1"}]}`)
	e.seedACMECA(t, f)

	// Create one via the handler.
	token := e.csrfToken(t, "/acme/eab/acme1")
	e.post(t, "/acme/eab/acme1", url.Values{"csrf_token": {token}, "reference": {"old"}})

	// Revoke it.
	token2 := e.csrfToken(t, "/acme/eab/acme1")
	resp := e.post(t, "/acme/eab/acme1", url.Values{
		"csrf_token": {token2},
		"action":     {"delete"},
		"key_id":     {"eab-old"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke status = %d, want 303", resp.StatusCode)
	}
	// The mock CA received the revoke by keyID.
	gotDelete := false
	for _, id := range f.deletedEAB {
		if id == "eab-old" {
			gotDelete = true
		}
	}
	if !gotDelete {
		t.Fatalf("CA did not receive the EAB revoke: %+v", f.deletedEAB)
	}
	// And it is gone from the list.
	_, body := e.getBody(t, "/acme/eab/acme1")
	if strings.Contains(body, "eab-old") {
		t.Fatalf("revoked key still listed; body:\n%s", body)
	}

	// Audit: a revoke event with the session user.
	found := false
	for _, ev := range e.auditEvents(t) {
		if ev.Action == "acme.eab.revoke" && ev.Who == "root" {
			found = true
		}
	}
	if !found {
		t.Fatal("no acme.eab.revoke audit event with who=root")
	}
}

// --- Acceptance: client snippets include directory URL + EAB params (FR-4) ----

func TestACMESnippetsIncludeDirectoryAndEAB(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme1"}]}`)
	e.seedACMECA(t, f)

	// On the EAB page (no keys yet), snippets show the directory URL and EAB
	// placeholders are present in all clients.
	_, body := e.getBody(t, "/acme/eab/acme1")
	wantDir := f.url + "/acme/acme1/directory"
	if !strings.Contains(body, wantDir) {
		t.Fatalf("snippets missing directory URL %q; body:\n%s", wantDir, body)
	}
	// The directory URL must appear INSIDE the rendered snippet text, not merely in
	// the page-level copy field: assert the certbot --server line embeds it.
	if !strings.Contains(body, "--server "+wantDir) {
		t.Fatalf("directory URL not embedded in the certbot snippet (--server %s); body:\n%s", wantDir, body)
	}
	for _, client := range []string{"certbot", "acme.sh", "Caddy", "Traefik"} {
		if !strings.Contains(body, client) {
			t.Fatalf("snippets missing client %q; body:\n%s", client, body)
		}
	}

	// After creating an EAB key, the one-time display snippets carry the REAL
	// keyID + HMAC values (FR-4: parameterized with EAB params when required).
	token := e.csrfToken(t, "/acme/eab/acme1")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/acme/eab/acme1",
		strings.NewReader(url.Values{"csrf_token": {token}, "reference": {"snip"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Referer", e.srv.URL+"/acme/eab/acme1")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("create EAB: %v", err)
	}
	created, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(created), "eab-snip") {
		t.Fatalf("snippets after create missing the real keyID; body:\n%s", created)
	}
	if !strings.Contains(string(created), f.hmacB64) {
		t.Fatalf("snippets after create missing the real HMAC; body:\n%s", created)
	}
	// The EAB flags appear in the snippets (e.g. certbot --eab-kid).
	if !strings.Contains(string(created), "--eab-kid") {
		t.Fatalf("certbot snippet missing --eab-kid EAB param; body:\n%s", created)
	}
}

// --- ACME provisioner edit (update options) ---------------------------------

func TestACMEEditProvisionerOptions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme1"}]}`)
	e.seedACMECA(t, f)

	token := e.csrfToken(t, "/acme")
	resp := e.post(t, "/acme/provisioners/acme1", url.Values{
		"csrf_token": {token},
		"action":     {"edit"},
		"challenge":  {"http-01", "tls-alpn-01"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("edit status = %d, want 303", resp.StatusCode)
	}
	details, _ := f.createBody["details"].(map[string]any)
	acme, _ := details["ACME"].(map[string]any)
	ch, _ := acme["challenges"].([]any)
	if len(ch) != 2 || ch[0] != "HTTP_01" || ch[1] != "TLS_ALPN_01" {
		t.Fatalf("update challenges = %+v, want [HTTP_01 TLS_ALPN_01]", acme["challenges"])
	}
	found := false
	for _, ev := range e.auditEvents(t) {
		if ev.Action == "acme.provisioner.update" && ev.Target == "acme1" && ev.Who == "root" {
			found = true
		}
	}
	if !found {
		t.Fatal("no acme.provisioner.update audit event")
	}
}

// --- Regression lock: edit must NOT silently drop requireEAB + challenges -----
//
// An admin editing ONE option (here: adding a challenge) must not clear the other
// ACME options. The provisioner has requireEAB=true + dns-01; the edit submits an
// extra challenge but does NOT touch requireEAB. The PUT to the CA must still
// carry requireEab=true and retain DNS_01 — otherwise an EAB-required directory is
// silently turned open. This FAILS if the handler stops merging the current state
// (e.g. defaults requireEAB to false when the form omits it).
func TestACMEEditPreservesUntouchedOptions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"acme1","requireEAB":true,"challenges":["dns-01"]}]}`)
	e.seedACMECA(t, f)

	// The inline edit form is pre-filled from the real current state: the EAB box
	// is checked and the dns-01 challenge is checked.
	_, page := e.getBody(t, "/acme")
	if !strings.Contains(page, `name="require_eab" checked`) {
		t.Fatalf("edit form did not pre-fill requireEAB from current state; body:\n%s", page)
	}
	if !strings.Contains(page, `value="dns-01" checked`) {
		t.Fatalf("edit form did not pre-fill the dns-01 challenge from current state; body:\n%s", page)
	}

	// Edit: add http-01. The submission carries challenges but NOTHING about
	// requireEAB (the admin did not touch it) — the handler must preserve it.
	token := e.csrfToken(t, "/acme")
	resp := e.post(t, "/acme/provisioners/acme1", url.Values{
		"csrf_token": {token},
		"action":     {"edit"},
		"challenge":  {"dns-01", "http-01"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("edit status = %d, want 303", resp.StatusCode)
	}

	details, _ := f.createBody["details"].(map[string]any)
	acme, _ := details["ACME"].(map[string]any)
	if acme == nil {
		t.Fatalf("CA did not receive details.ACME on edit: %+v", f.createBody)
	}
	if acme["requireEab"] != true {
		t.Fatalf("edit silently dropped requireEAB: %+v", acme)
	}
	ch, _ := acme["challenges"].([]any)
	hasDNS := false
	for _, c := range ch {
		if c == "DNS_01" {
			hasDNS = true
		}
	}
	if !hasDNS {
		t.Fatalf("edit silently dropped the existing dns-01 challenge: %+v", acme["challenges"])
	}
}

// --- Regression lock: snippet RequireEAB tracks the real provisioner option ----
//
// The spec criterion is "client snippets including EAB parameters when required".
// EAB params must be driven by the provisioner's REAL requireEAB, not by whether
// any EAB keys happen to exist. A requireEAB provisioner with ZERO keys must still
// render --eab-kid and the per-client EAB params; a non-EAB provisioner must not.
// This FAILS if RequireEAB is derived from len(keys)>0.
func TestACMESnippetEABParamsFollowRequireEAB(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[
		{"type":"ACME","name":"needeab","requireEAB":true},
		{"type":"ACME","name":"openacme"}
	]}`)
	e.seedACMECA(t, f)

	// requireEAB provisioner, NO keys yet → EAB params present in every client:
	// certbot (--eab-kid/--eab-hmac-key), acme.sh (--eab-kid), Caddy (eab line)
	// and Traefik (hmacEncoded). The EAB key-id placeholder stands in for the
	// not-yet-created key.
	_, eabBody := e.getBody(t, "/acme/eab/needeab")
	for _, want := range []string{"--eab-kid", "--eab-hmac-key", "eab &lt;EAB_KEY_ID&gt;", "hmacEncoded:"} {
		if !strings.Contains(eabBody, want) {
			t.Fatalf("requireEAB snippet (zero keys) missing %q; body:\n%s", want, eabBody)
		}
	}
	// The directory URL must actually appear INSIDE a snippet (not just the
	// page-level copy field): assert the certbot --server line carries it.
	wantServerLine := "--server " + f.url + "/acme/needeab/directory"
	if !strings.Contains(eabBody, wantServerLine) {
		t.Fatalf("directory URL not embedded in the certbot snippet; want %q; body:\n%s", wantServerLine, eabBody)
	}

	// Non-EAB provisioner → NO EAB params anywhere in the snippets.
	_, openBody := e.getBody(t, "/acme/eab/openacme")
	if strings.Contains(openBody, "--eab-kid") {
		t.Fatalf("non-EAB provisioner snippet wrongly includes --eab-kid; body:\n%s", openBody)
	}
}

// --- ACME provisioner delete -------------------------------------------------

func TestACMEDeleteProvisioner(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[{"type":"ACME","name":"gone"}]}`)
	e.seedACMECA(t, f)

	token := e.csrfToken(t, "/acme")
	resp := e.post(t, "/acme/provisioners/gone", url.Values{
		"csrf_token": {token},
		"action":     {"delete"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete status = %d, want 303", resp.StatusCode)
	}
	_, body := e.getBody(t, "/acme")
	if !strings.Contains(strings.ToLower(body), "deleted") {
		t.Fatalf("expected a delete success flash; body:\n%s", body)
	}
}

// --- RBAC: ACME is admin+ ----------------------------------------------------

func TestACMEViewerForbidden(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "viewer1", users.RoleViewer)

	logoutToken := e.csrfToken(t, "/users")
	e.post(t, "/logout", url.Values{"csrf_token": {logoutToken}})
	token := e.csrfToken(t, "/login")
	e.loginAs(t, "viewer1")

	if resp, _ := e.get(t, "/acme"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer GET /acme = %d, want 403", resp.StatusCode)
	}
	if resp, _ := e.get(t, "/acme/eab/acme1"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer GET /acme/.../eab = %d, want 403", resp.StatusCode)
	}
	resp := e.post(t, "/acme/provisioners", url.Values{
		"csrf_token": {token}, "name": {"x"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST /acme/provisioners = %d, want 403", resp.StatusCode)
	}
}

// Create without an admin credential → clear error, no CA call.
func TestACMECreateNoAdminCredential(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startACMECA(t, `{"provisioners":[]}`)
	// CA settings only, no admin credential.
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: f.url, RootFingerprint: f.fingerprint,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	token := e.csrfToken(t, "/acme")
	resp := e.post(t, "/acme/provisioners", url.Values{
		"csrf_token": {token}, "name": {"acme1"}, "challenge": {"http-01"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	_, body := e.getBody(t, "/acme")
	if !strings.Contains(strings.ToLower(body), "admin cred") {
		t.Fatalf("expected an 'admin credential' error flash; body:\n%s", body)
	}
}
