package ca

// Provisioner management against Step-CA over its HTTP API (ADR-0004): list,
// create and delete, with admin operations authenticated by an SDK-signed x5c
// admin token (spec/0005). No `step` CLI is used.
//
// # Admin-token format (the crux)
//
// Create/delete hit Step-CA's admin API, which authenticates each request with
// an x5c-signed JWT placed verbatim in the Authorization header (no "Bearer "
// prefix). The token is a compact JWS whose protected header carries:
//
//   - typ: "JWT"
//   - x5c: the admin certificate chain (leaf first), each entry the base64
//     std-encoding of the certificate DER — the format go-jose's
//     Header.Certificates parses and Step-CA's AuthorizeAdminToken verifies.
//
// and whose claims are:
//
//   - iss: "step-admin-client/1.0"  (the value Step-CA expects, see below)
//   - sub: the admin leaf certificate's Common Name (non-empty)
//   - aud: the FULL request URL of the endpoint, e.g.
//     "https://ca:9000/admin/provisioners" — Step-CA matches aud against the
//     request path's audience
//   - jti: a random 256-bit hex nonce (one-time-use protection)
//   - iat/nbf/exp: a short validity window (5 min)
//
// The JWS is signed with the admin private key, whose public half is the leaf in
// the x5c chain. Step-CA's authority.AuthorizeAdminToken (authority/authorize.go)
// then: (1) verifies the x5c chain to the CA root with the clientAuth EKU,
// (2) requires the leaf to have the digital-signature key usage, (3) verifies the
// JWS signature with the leaf's public key (proving the signer holds the matching
// private key), and (4) validates the time window, the audience, iss and a
// non-empty sub. This mechanism (and the exact iss/aud/x5c shape) was taken from
// the smallstep/certificates and go.step.sm/crypto sources.
//
// IMPORTANT — validation scope: the token is exercised against an httptest mock
// (internal/ca/provisioners_test.go) that re-implements the four checks above
// using the public key, so the tests prove the token is signed and shaped
// correctly. They do NOT prove behaviour against a live Step-CA; remote
// management config, admin enrolment and DB-backed token reuse are only
// observable against a real CA.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
)

// Admin-token constants, taken verbatim from Step-CA so a live CA accepts the
// tokens we sign (authority/authorize.go, ca/adminClient.go).
const (
	// adminIssuer is the iss claim Step-CA's AuthorizeAdminToken accepts for the
	// modern admin-client flow.
	adminIssuer = "step-admin-client/1.0"
	// adminURLPath is the admin provisioners endpoint path.
	adminURLPath = "/admin/provisioners"
	// adminTokenValidity is the token's validity window. Step-CA allows a small
	// leeway; a few minutes is the recommended skew.
	adminTokenValidity = 5 * time.Minute
)

// Provisioner-related errors, matchable via errors.Is.
var (
	// ErrAdminUnauthorized means the CA rejected the admin token (bad/expired
	// signature, untrusted x5c chain, or insufficient privileges): HTTP 401/403.
	ErrAdminUnauthorized = errors.New("ca: admin request unauthorized")
	// ErrAdminRequestFailed means the admin API returned another non-2xx status.
	ErrAdminRequestFailed = errors.New("ca: admin request failed")
	// ErrInvalidAdminCredential means the supplied admin cert/key could not be
	// parsed, do not match, or the leaf is unusable for token signing.
	ErrInvalidAdminCredential = errors.New("ca: invalid admin credential")
	// ErrInvalidProvisioner means a create spec failed validation (name/type or a
	// missing/short JWK secret).
	ErrInvalidProvisioner = errors.New("ca: invalid provisioner spec")
)

// nameRE is the provisioner name rule from FR-3.
var nameRE = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// validTypes are the provisioner types this UI can create (FR-3). Stored
// upper-cased to match Step-CA's linkedca type names.
var validTypes = map[string]bool{"JWK": true, "ACME": true, "SSHPOP": true}

// minJWKSecretLen is the minimum JWK provisioner password length (FR-3).
const minJWKSecretLen = 8

// Provisioner is a CA provisioner as listed by GET /provisioners: just the name
// and type the UI needs (FR-1).
type Provisioner struct {
	Type string
	Name string
}

// NewProvisionerSpec describes a provisioner to create (FR-3). JWKSecret is the
// passphrase used to encrypt the generated JWK private key; it is required for
// type JWK and ignored otherwise. The plaintext secret never leaves this package
// in the request body — only the public JWK and the JWE-encrypted private key
// are sent.
//
// ACMEChallenges and ACMERequireEAB carry the ACME-provisioner options (spec/0010
// FR-1): the allowed challenge types and whether External Account Binding is
// required. They are only consulted when Type is "ACME".
type NewProvisionerSpec struct {
	Name           string
	Type           string
	JWKSecret      string
	ACMEChallenges []string // allowed ACME challenges, e.g. "http-01","dns-01","tls-alpn-01"
	ACMERequireEAB bool     // require External Account Binding for ACME
}

// AdminCredential is the x5c admin certificate chain plus its private key, used
// to sign admin tokens. The private key never leaves the process; only the
// public chain is embedded (x5c) in tokens.
type AdminCredential struct {
	chain  []*x509.Certificate // leaf first
	signer crypto.Signer       // private key matching the leaf
}

// NewAdminCredential parses a PEM certificate chain (leaf first) and a PEM
// private key into an AdminCredential, validating that the leaf is usable for
// token signing (has the digital-signature key usage and a public key matching
// the private key). It does NOT verify the chain to the CA root — that is the
// CA's job at token-authorization time.
func NewAdminCredential(certChainPEM, keyPEM []byte) (AdminCredential, error) {
	chain, err := pemutil.ParseCertificateBundle(certChainPEM)
	if err != nil || len(chain) == 0 {
		return AdminCredential{}, fmt.Errorf("%w: parse certificate chain: %v", ErrInvalidAdminCredential, err)
	}
	key, err := pemutil.ParseKey(keyPEM)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("%w: parse private key: %v", ErrInvalidAdminCredential, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return AdminCredential{}, fmt.Errorf("%w: private key is not a signer", ErrInvalidAdminCredential)
	}
	leaf := chain[0]
	// Fast-fail: verify the leaf's public key matches the private key so a
	// mismatched cert/key pair is caught here rather than as a remote 401.
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if eq, ok := signer.Public().(equaler); !ok || !eq.Equal(leaf.PublicKey) {
		return AdminCredential{}, fmt.Errorf("%w: leaf certificate public key does not match the private key", ErrInvalidAdminCredential)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return AdminCredential{}, fmt.Errorf("%w: leaf certificate lacks the digital-signature key usage", ErrInvalidAdminCredential)
	}
	if leaf.Subject.CommonName == "" {
		return AdminCredential{}, fmt.Errorf("%w: leaf certificate has no common name (token subject)", ErrInvalidAdminCredential)
	}
	return AdminCredential{chain: chain, signer: signer}, nil
}

// ListProvisioners fetches GET {caURL}/provisioners over the pinned-trust client
// (FR-1), following the CA's nextCursor pagination, and returns the parsed
// name+type pairs. No admin token is required.
func ListProvisioners(ctx context.Context, caURL, fingerprint string) ([]Provisioner, error) {
	base, err := baseURL(caURL)
	if err != nil {
		return nil, err
	}
	client, err := pinnedClientFor(ctx, caURL, fingerprint)
	if err != nil {
		return nil, err
	}

	var out []Provisioner
	cursor := ""
	for {
		u := base + "/provisioners"
		if cursor != "" {
			u += "?cursor=" + url.QueryEscape(cursor)
		}
		body, err := fetch(ctx, u, client)
		if err != nil {
			return nil, err
		}
		var page provisionersResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("%w: decode provisioners: %v", ErrMalformedResponse, err)
		}
		for _, p := range page.Provisioners {
			out = append(out, Provisioner{Type: p.Type, Name: p.Name})
		}
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}

// provisionersResponse mirrors Step-CA's GET /provisioners body.
type provisionersResponse struct {
	Provisioners []struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"provisioners"`
	NextCursor string `json:"nextCursor"`
}

// ACMEProvisioner is one ACME provisioner with the current options the edit form
// needs to pre-fill and the update path needs to merge (spec/0010): the allowed
// challenges (friendly names, e.g. "dns-01") and whether EAB is required. These
// come from the public GET /provisioners list, which marshals the in-memory
// provisioner.ACME objects directly — so the wire fields are the friendly
// "challenges" names and "requireEAB" (NOT the linkedca protojson enum/camelCase
// the admin API uses for create/update bodies).
type ACMEProvisioner struct {
	Name       string
	Challenges []string // friendly names; empty means the CA's default (all allowed)
	RequireEAB bool
}

// acmeProvisionerWire mirrors the ACME fields of GET /provisioners. Both fields
// are omitempty on the CA side, so an absent "requireEAB" is false and absent
// "challenges" means the CA applies its default — we preserve that distinction by
// leaving Challenges nil rather than inventing a default set.
type acmeProvisionerWire struct {
	Type       string   `json:"type"`
	Name       string   `json:"name"`
	RequireEAB bool     `json:"requireEAB"`
	Challenges []string `json:"challenges"`
}

// ListACMEProvisioners fetches GET {caURL}/provisioners and returns only the ACME
// provisioners with their current options parsed (challenges + requireEAB), so the
// app layer can pre-fill the edit form and merge updates instead of clobbering the
// unspecified fields (spec/0010). No admin token is required; pagination is
// followed like ListProvisioners.
func ListACMEProvisioners(ctx context.Context, caURL, fingerprint string) ([]ACMEProvisioner, error) {
	base, err := baseURL(caURL)
	if err != nil {
		return nil, err
	}
	client, err := pinnedClientFor(ctx, caURL, fingerprint)
	if err != nil {
		return nil, err
	}

	var out []ACMEProvisioner
	cursor := ""
	for {
		u := base + "/provisioners"
		if cursor != "" {
			u += "?cursor=" + url.QueryEscape(cursor)
		}
		body, err := fetch(ctx, u, client)
		if err != nil {
			return nil, err
		}
		var page struct {
			Provisioners []acmeProvisionerWire `json:"provisioners"`
			NextCursor   string                `json:"nextCursor"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("%w: decode provisioners: %v", ErrMalformedResponse, err)
		}
		for _, p := range page.Provisioners {
			if p.Type != "ACME" {
				continue
			}
			out = append(out, ACMEProvisioner{
				Name:       p.Name,
				Challenges: p.Challenges,
				RequireEAB: p.RequireEAB,
			})
		}
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}

// CreateProvisioner creates a provisioner via POST {caURL}/admin/provisioners
// with an SDK-signed admin token (FR-3). It validates the spec, builds the
// linkedca-shaped JSON body (for JWK it generates a keypair and encrypts the
// private key with the supplied secret), signs the admin token, and returns the
// created provisioner echoed by the CA.
func CreateProvisioner(ctx context.Context, caURL, fingerprint string, cred AdminCredential, spec NewProvisionerSpec) (Provisioner, error) {
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
	endpoint := base + adminURLPath
	client, err := pinnedClientFor(ctx, caURL, fingerprint)
	if err != nil {
		return Provisioner{}, err
	}
	tok, err := generateAdminToken(cred, endpoint)
	if err != nil {
		return Provisioner{}, err
	}

	respBody, err := adminRequest(ctx, client, http.MethodPost, endpoint, tok, body)
	if err != nil {
		return Provisioner{}, err
	}
	// The CA echoes the created provisioner; fall back to the spec if it omits
	// the fields (the create succeeded either way).
	var created struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	_ = json.Unmarshal(respBody, &created)
	if created.Name == "" {
		created.Name = spec.Name
	}
	if created.Type == "" {
		created.Type = spec.Type
	}
	return Provisioner{Type: created.Type, Name: created.Name}, nil
}

// DeleteProvisioner deletes a provisioner via DELETE
// {caURL}/admin/provisioners/{name} with an SDK-signed admin token (FR-4). The
// "cannot delete the active provisioner" guard is enforced one layer up (in the
// settings/handler layer) where the selected provisioner is known.
func DeleteProvisioner(ctx context.Context, caURL, fingerprint string, cred AdminCredential, name string) error {
	base, err := baseURL(caURL)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("%w: empty provisioner name", ErrInvalidProvisioner)
	}
	// The token audience is the collection endpoint (matching Step-CA, which
	// derives the audience from the request path's prefix).
	endpoint := base + adminURLPath
	target := endpoint + "/" + url.PathEscape(name)
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

// validateSpec enforces the FR-3 rules: name pattern, allowed type, and a JWK
// secret of at least minJWKSecretLen for JWK provisioners.
func validateSpec(spec NewProvisionerSpec) error {
	if !nameRE.MatchString(spec.Name) {
		return fmt.Errorf("%w: name must match %s", ErrInvalidProvisioner, nameRE.String())
	}
	if !validTypes[spec.Type] {
		return fmt.Errorf("%w: type must be one of JWK, ACME, SSHPOP", ErrInvalidProvisioner)
	}
	if spec.Type == "JWK" && len(spec.JWKSecret) < minJWKSecretLen {
		return fmt.Errorf("%w: JWK secret must be at least %d characters", ErrInvalidProvisioner, minJWKSecretLen)
	}
	if spec.Type == "ACME" {
		for _, c := range spec.ACMEChallenges {
			if !validACMEChallenge(c) {
				return fmt.Errorf("%w: unknown ACME challenge %q", ErrInvalidProvisioner, c)
			}
		}
	}
	return nil
}

// buildCreateBody builds the linkedca.Provisioner JSON (protojson shape) for the
// create request. The details oneof is keyed by the type name (JWK/ACME/SSHPOP);
// bytes fields are base64-encoded as protojson requires.
func buildCreateBody(spec NewProvisionerSpec) ([]byte, error) {
	details := map[string]any{}
	switch spec.Type {
	case "JWK":
		pub, encPriv, err := jwkProvisionerKeys(spec.JWKSecret)
		if err != nil {
			return nil, err
		}
		details["JWK"] = map[string]any{
			"publicKey":           base64.StdEncoding.EncodeToString(pub),
			"encryptedPrivateKey": base64.StdEncoding.EncodeToString(encPriv),
		}
	case "ACME":
		details["ACME"] = acmeDetails(spec)
	case "SSHPOP":
		details["SSHPOP"] = map[string]any{}
	default:
		return nil, fmt.Errorf("%w: unsupported type %q", ErrInvalidProvisioner, spec.Type)
	}
	payload := map[string]any{
		"type":    spec.Type,
		"name":    spec.Name,
		"details": details,
	}
	return json.Marshal(payload)
}

// jwkProvisionerKeys generates a JWK keypair encrypted with secret, returning the
// public JWK JSON bytes and the JWE-compact encrypted private key bytes — the two
// byte fields of linkedca.JWKProvisioner. This mirrors how Step-CA itself builds
// a JWK provisioner (jose.GenerateDefaultKeyPair). The plaintext secret is only
// used to encrypt the private key; it is never sent to the CA.
func jwkProvisionerKeys(secret string) (publicJWK, encryptedPrivateKey []byte, err error) {
	pub, jwe, err := jose.GenerateDefaultKeyPair([]byte(secret))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generate JWK: %v", ErrInvalidProvisioner, err)
	}
	publicJWK, err = pub.MarshalJSON()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: marshal public JWK: %v", ErrInvalidProvisioner, err)
	}
	compact, err := jwe.CompactSerialize()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: serialize encrypted key: %v", ErrInvalidProvisioner, err)
	}
	return publicJWK, []byte(compact), nil
}

// generateAdminToken builds and signs the x5c admin JWT for the given endpoint
// (used as the audience). See the package-level doc for the exact format. The
// returned string goes verbatim into the Authorization header.
func generateAdminToken(cred AdminCredential, endpoint string) (string, error) {
	if cred.signer == nil || len(cred.chain) == 0 {
		return "", fmt.Errorf("%w: credential not initialised", ErrInvalidAdminCredential)
	}

	// The x5c header: each cert as base64(DER), leaf first.
	x5c := make([]string, len(cred.chain))
	for i, c := range cred.chain {
		x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}

	opts := (&jose.SignerOptions{}).
		WithType("JWT").
		WithHeader("x5c", x5c)
	// Leaving Algorithm empty lets jose.NewSigner derive it from the key type
	// (ES256/384/512 for ECDSA, EdDSA for Ed25519, RS256 for RSA).
	signer, err := jose.NewSigner(jose.SigningKey{Key: cred.signer}, opts)
	if err != nil {
		return "", fmt.Errorf("%w: build signer: %v", ErrInvalidAdminCredential, err)
	}

	jti, err := randutil.Hex(64)
	if err != nil {
		return "", fmt.Errorf("%w: generate jti: %v", ErrInvalidAdminCredential, err)
	}
	now := time.Now()
	claims := jose.Claims{
		ID:        jti,
		Issuer:    adminIssuer,
		Subject:   cred.chain[0].Subject.CommonName,
		Audience:  jose.Audience{endpoint},
		NotBefore: jose.NewNumericDate(now),
		IssuedAt:  jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(adminTokenValidity)),
	}
	tok, err := jose.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("%w: sign token: %v", ErrInvalidAdminCredential, err)
	}
	return tok, nil
}

// adminRequest performs an admin API call with the token in the Authorization
// header (verbatim, no Bearer prefix — matching Step-CA's AdminClient) and maps
// the response status to typed errors. It never logs or returns the token.
func adminRequest(ctx context.Context, client *http.Client, method, urlStr, token string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, rdr)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrUnreachable, err)
	}
	req.Header.Set("Authorization", token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, classifyDoError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return respBody, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%w: %s", ErrAdminUnauthorized, adminErrorMessage(respBody))
	default:
		return nil, fmt.Errorf("%w: status %d: %s", ErrAdminRequestFailed, resp.StatusCode, adminErrorMessage(respBody))
	}
}

// adminErrorMessage extracts a {"message":"..."} field from a CA error body, or
// returns a short fallback. It never returns request material.
func adminErrorMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		return e.Message
	}
	if s := strings.TrimSpace(string(body)); s != "" && len(s) < 200 {
		return s
	}
	return "no detail"
}
