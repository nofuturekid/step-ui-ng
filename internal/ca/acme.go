package ca

// ACME provisioner options and External Account Binding (EAB) management against
// Step-CA's admin API (spec/0010, ADR-0004). Everything here reuses the
// two-phase pinned-trust client (no blanket skip-verify) and the SDK-signed x5c
// admin token from provisioners.go — no `step` CLI.
//
// # Admin API shapes (researched against smallstep/certificates + smallstep/linkedca)
//
//   - ACME provisioner: a linkedca.Provisioner of type "ACME" whose
//     details.ACME (an ACMEProvisioner message, protojson) carries the camelCase
//     fields "requireEab" (bool) and "challenges" (a repeated enum). protojson
//     serialises enum values by their proto names, so the wire values are
//     "HTTP_01", "DNS_01", "TLS_ALPN_01", "DEVICE_ATTEST_01" — NOT the friendly
//     "http-01" form. We accept the friendly forms from the UI and translate.
//   - Create/edit/delete: POST /admin/provisioners, PUT /admin/provisioners/{name},
//     DELETE /admin/provisioners/{name} — all with an x5c admin token.
//   - EAB: POST /admin/acme/eab/{provisioner} {"reference":"..."} returns a single
//     protojson linkedca.EABKey {id, hmacKey(base64 bytes), provisioner, reference,
//     account, createdAt, boundAt}; GET /admin/acme/eab/{provisioner} returns
//     {"eaks":[<EABKey>...],"nextCursor":""}; DELETE
//     /admin/acme/eab/{provisioner}/{id} removes one. (The OSS step-ca stubs these
//     EAB endpoints — they are a Certificate Manager feature — but the wire shapes
//     and routes are fixed by smallstep/certificates' ca.AdminClient, which is what
//     a live CA's EAB-enabled build serves; we target those shapes.)
//
// # EAB HMAC handling (the crux)
//
// The EAB HMAC is a secret. CreateEABKey returns it ONCE in the create result;
// callers must show it exactly once and never persist, log, or audit it.
// ListEABKeys deliberately DROPS the HMAC from every returned row so the list
// view can never leak it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// acmeChallengeWire maps the UI/friendly challenge names to the protojson enum
// names Step-CA's ACMEProvisioner expects on the wire.
var acmeChallengeWire = map[string]string{
	"http-01":          "HTTP_01",
	"dns-01":           "DNS_01",
	"tls-alpn-01":      "TLS_ALPN_01",
	"device-attest-01": "DEVICE_ATTEST_01",
}

// acmeDetails builds the details.ACME protojson object for an ACME provisioner
// from the spec's challenge list and requireEAB flag. Unknown challenge strings
// are skipped (validateSpec rejects them earlier); the resulting map omits an
// empty challenges list so the CA applies its default (all challenges allowed).
//
// requireEab is ALWAYS sent — including false — because a PUT replaces the
// provisioner's details wholesale: omitting it on a false intent would let the CA
// keep a previous requireEAB=true (or, on a re-create, silently default), turning
// a destructive edit into a security regression. The caller is responsible for
// passing the COMPLETE intended state (see the app merge-on-edit path).
func acmeDetails(spec NewProvisionerSpec) map[string]any {
	d := map[string]any{"requireEab": spec.ACMERequireEAB}
	var challenges []string
	for _, c := range spec.ACMEChallenges {
		if wire, ok := acmeChallengeWire[strings.ToLower(strings.TrimSpace(c))]; ok {
			challenges = append(challenges, wire)
		}
	}
	if len(challenges) > 0 {
		d["challenges"] = challenges
	}
	return d
}

// validACMEChallenge reports whether c is one of the challenge types the UI may
// request (FR-1). device-attest-01 is accepted for completeness but the UI only
// offers the three spec'd challenges.
func validACMEChallenge(c string) bool {
	_, ok := acmeChallengeWire[strings.ToLower(strings.TrimSpace(c))]
	return ok
}

// UpdateProvisioner edits an existing provisioner via PUT
// {caURL}/admin/provisioners/{name} with an SDK-signed admin token (FR-1). It is
// used to change an ACME provisioner's options (challenges, requireEAB). The body
// is the same linkedca-shaped JSON as create; Step-CA replaces the provisioner's
// details with it.
func UpdateProvisioner(ctx context.Context, caURL, fingerprint string, cred AdminCredential, spec NewProvisionerSpec) (Provisioner, error) {
	if err := validateSpec(spec); err != nil {
		return Provisioner{}, err
	}
	base, err := baseURL(caURL)
	if err != nil {
		return Provisioner{}, err
	}
	body, err := buildCreateBody(spec)
	if err != nil {
		return Provisioner{}, err
	}
	// The token audience is the collection endpoint (matching Step-CA, which
	// derives the audience from the request path's prefix).
	endpoint := base + adminURLPath
	target := endpoint + "/" + url.PathEscape(spec.Name)
	client, err := pinnedClientFor(ctx, caURL, fingerprint)
	if err != nil {
		return Provisioner{}, err
	}
	tok, err := generateAdminToken(cred, endpoint)
	if err != nil {
		return Provisioner{}, err
	}
	if _, err := adminRequest(ctx, client, http.MethodPut, target, tok, body); err != nil {
		return Provisioner{}, err
	}
	return Provisioner{Type: spec.Type, Name: spec.Name}, nil
}

// EABKey is one ACME External Account Binding key as returned by the admin API.
// HMAC is the base64-encoded HMAC secret and is populated ONLY by CreateEABKey
// (the one-time create result). ListEABKeys always leaves it empty so a list
// render can never expose it.
type EABKey struct {
	KeyID       string
	HMAC        string // base64 secret; non-empty only on create, never on list
	Provisioner string
	Reference   string
	Account     string // bound ACME account id, empty until bound
	CreatedAt   string // RFC3339 timestamp from the CA, best-effort
	BoundAt     string // RFC3339 timestamp from the CA, empty until bound
}

// Bound reports whether the key has been bound to an ACME account yet.
func (k EABKey) Bound() bool { return strings.TrimSpace(k.Account) != "" }

// eabKeyWire mirrors the protojson linkedca.EABKey on the wire. hmacKey is a
// bytes field, so protojson base64-encodes it; createdAt/boundAt are RFC3339.
type eabKeyWire struct {
	ID          string `json:"id"`
	HmacKey     string `json:"hmacKey"`
	Provisioner string `json:"provisioner"`
	Reference   string `json:"reference"`
	Account     string `json:"account"`
	CreatedAt   string `json:"createdAt"`
	BoundAt     string `json:"boundAt"`
}

func (w eabKeyWire) toEABKey(withHMAC bool) EABKey {
	k := EABKey{
		KeyID:       w.ID,
		Provisioner: w.Provisioner,
		Reference:   w.Reference,
		Account:     w.Account,
		CreatedAt:   w.CreatedAt,
		BoundAt:     w.BoundAt,
	}
	if withHMAC {
		k.HMAC = w.HmacKey
	}
	return k
}

// eabBasePath returns the admin EAB collection path for a provisioner, e.g.
// "/admin/acme/eab/my-acme". The provisioner name is path-escaped.
func eabBasePath(provisioner string) string {
	return "/admin/acme/eab/" + url.PathEscape(provisioner)
}

// CreateEABKey creates an EAB key for the named ACME provisioner via POST
// {caURL}/admin/acme/eab/{provisioner} (FR-2). The returned EABKey carries the
// one-time HMAC; the caller MUST show it exactly once and never persist, log, or
// audit it.
func CreateEABKey(ctx context.Context, caURL, fingerprint string, cred AdminCredential, provisioner, reference string) (EABKey, error) {
	provisioner = strings.TrimSpace(provisioner)
	if provisioner == "" {
		return EABKey{}, fmt.Errorf("%w: empty provisioner name", ErrInvalidProvisioner)
	}
	base, err := baseURL(caURL)
	if err != nil {
		return EABKey{}, err
	}
	endpoint := base + eabBasePath(provisioner)
	client, err := pinnedClientFor(ctx, caURL, fingerprint)
	if err != nil {
		return EABKey{}, err
	}
	tok, err := generateAdminToken(cred, endpoint)
	if err != nil {
		return EABKey{}, err
	}
	body, err := json.Marshal(map[string]any{"reference": reference})
	if err != nil {
		return EABKey{}, fmt.Errorf("%w: encode request: %v", ErrInvalidProvisioner, err)
	}
	respBody, err := adminRequest(ctx, client, http.MethodPost, endpoint, tok, body)
	if err != nil {
		return EABKey{}, err
	}
	var w eabKeyWire
	if err := json.Unmarshal(respBody, &w); err != nil {
		return EABKey{}, fmt.Errorf("%w: decode EAB key: %v", ErrMalformedResponse, err)
	}
	if w.ID == "" || w.HmacKey == "" {
		return EABKey{}, fmt.Errorf("%w: EAB key response missing id or hmac", ErrMalformedResponse)
	}
	return w.toEABKey(true), nil
}

// ListEABKeys lists the EAB keys for the named ACME provisioner via GET
// {caURL}/admin/acme/eab/{provisioner} (FR-2), following nextCursor pagination.
// The HMAC is deliberately stripped from every row so the list view can never
// leak it; only keyID + reference + bound-account/status are returned.
func ListEABKeys(ctx context.Context, caURL, fingerprint string, cred AdminCredential, provisioner string) ([]EABKey, error) {
	provisioner = strings.TrimSpace(provisioner)
	if provisioner == "" {
		return nil, fmt.Errorf("%w: empty provisioner name", ErrInvalidProvisioner)
	}
	base, err := baseURL(caURL)
	if err != nil {
		return nil, err
	}
	endpoint := base + eabBasePath(provisioner)
	client, err := pinnedClientFor(ctx, caURL, fingerprint)
	if err != nil {
		return nil, err
	}

	var out []EABKey
	cursor := ""
	for {
		u := endpoint
		if cursor != "" {
			u += "?cursor=" + url.QueryEscape(cursor)
		}
		// The token audience is the collection endpoint WITHOUT the cursor query:
		// Step-CA's ca.AdminClient.generateAdminToken explicitly drops the query
		// string from the audience (scheme://host/path only), so a paginated GET
		// signs the same audience as the first page.
		tok, err := generateAdminToken(cred, endpoint)
		if err != nil {
			return nil, err
		}
		respBody, err := adminRequest(ctx, client, http.MethodGet, u, tok, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			EAKs       []eabKeyWire `json:"eaks"`
			NextCursor string       `json:"nextCursor"`
		}
		if err := json.Unmarshal(respBody, &page); err != nil {
			return nil, fmt.Errorf("%w: decode EAB keys: %v", ErrMalformedResponse, err)
		}
		for _, w := range page.EAKs {
			out = append(out, w.toEABKey(false)) // never carry the HMAC into a list row
		}
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}

// DeleteEABKey revokes (removes) an EAB key by keyID via DELETE
// {caURL}/admin/acme/eab/{provisioner}/{keyID} with an SDK-signed admin token
// (FR-2). After this the key can no longer be used to bind an ACME account.
func DeleteEABKey(ctx context.Context, caURL, fingerprint string, cred AdminCredential, provisioner, keyID string) error {
	provisioner = strings.TrimSpace(provisioner)
	keyID = strings.TrimSpace(keyID)
	if provisioner == "" || keyID == "" {
		return fmt.Errorf("%w: provisioner and keyID are required", ErrInvalidProvisioner)
	}
	base, err := baseURL(caURL)
	if err != nil {
		return err
	}
	endpoint := base + eabBasePath(provisioner)
	target := endpoint + "/" + url.PathEscape(keyID)
	client, err := pinnedClientFor(ctx, caURL, fingerprint)
	if err != nil {
		return err
	}
	tok, err := generateAdminToken(cred, endpoint)
	if err != nil {
		return err
	}
	if _, err := adminRequest(ctx, client, http.MethodDelete, target, tok, nil); err != nil {
		return err
	}
	return nil
}

// DirectoryURL returns the ACME directory URL for a provisioner (FR-3):
// {caURL}/acme/{provisioner}/directory. It trims a trailing slash from caURL but
// does not validate the scheme — the caller already holds a verified CA URL.
func DirectoryURL(caURL, provisioner string) string {
	base := strings.TrimRight(strings.TrimSpace(caURL), "/")
	return base + "/acme/" + url.PathEscape(strings.TrimSpace(provisioner)) + "/directory"
}
