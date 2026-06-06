package ca

// Certificate signing against Step-CA via a JWK provisioner one-time token (OTT),
// over the existing two-phase pinned-trust client (ADR-0004): no `step` CLI.
//
// # OTT (one-time token) flow — the crux
//
// To sign a CSR, Step-CA's JWK provisioner requires a short-lived JWT (the OTT)
// signed by the provisioner's private JWK. The UI never holds that key in clear:
// it is published encrypted. The flow is:
//
//  1. Fetch the active JWK provisioner from GET {ca}/provisioners (matched by
//     name). The entry carries the public JWK ("key") and the JWE-encrypted
//     private key ("encryptedKey").
//  2. Decrypt encryptedKey with the selected provisioner password (jose.Decrypt
//     + WithPassword) to recover the signing JWK. The password comes from sealed
//     settings; it is never logged.
//  3. Build the OTT: a JWS whose claims are
//       - sub : the certificate CN (Step-CA requires a non-empty subject)
//       - sans: the SAN list (DNS/IP/email/URI), JSON key "sans"
//       - aud : "{ca}/1.0/sign" (the audience Step-CA's JWK provisioner expects)
//       - iss : the provisioner name (Step-CA matches iss == provisioner name)
//       - iat/nbf/exp: a short validity window
//       - jti: a random nonce (one-time-use protection)
//     signed with the provisioner JWK via go.step.sm/crypto/jose. The header's
//     kid is the JWK key id (Step-CA selects the key by kid when present).
//  4. POST {ca}/1.0/sign with {"csr": <PEM>, "ott": <token>, "notAfter": <RFC3339>}.
//     notAfter requests the validity; the CA enforces the provisioner's max and
//     returns 403 when the request exceeds it. Parse the returned cert + chain.
//
// These claim names and the aud/iss rules were taken from smallstep/cli's token
// package (SANSClaim = "sans", aud == sign URL) and smallstep/certificates'
// JWK provisioner authorizeToken (iss == provisioner name, non-empty sub, JWS
// verified against the public JWK).
//
// IMPORTANT — validation scope: the OTT is exercised against an httptest mock
// (internal/ca/sign_test.go) that publishes a JWK provisioner whose encryptedKey
// the test controls and whose /1.0/sign endpoint VERIFIES the OTT signature and
// claims against the published public JWK before issuing — so the tests prove the
// token is signed and shaped correctly. They do NOT prove behaviour against a
// live Step-CA: remote management config, the real provisioner validity policy,
// templates and DB-backed token reuse are only observable against a real CA.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
)

// Sign-flow errors, matchable via errors.Is.
var (
	// ErrProvisionerNotFound means no JWK provisioner with the requested name was
	// listed by the CA.
	ErrProvisionerNotFound = errors.New("ca: provisioner not found")
	// ErrProvisionerKey means the provisioner's encrypted key could not be
	// decrypted (wrong password) or parsed.
	ErrProvisionerKey = errors.New("ca: cannot decrypt provisioner key")
	// ErrInvalidCSR means the supplied CSR PEM could not be parsed.
	ErrInvalidCSR = errors.New("ca: invalid CSR")
	// ErrSignRejected means the CA rejected the sign request (e.g. validity over
	// the provisioner max, or a policy violation): a non-auth 4xx.
	ErrSignRejected = errors.New("ca: CA rejected the sign request")
	// ErrSignFailed means the sign request failed for another reason (5xx or an
	// unexpected response shape).
	ErrSignFailed = errors.New("ca: sign request failed")
)

// signTokenValidity is the OTT's validity window; it only needs to outlive the
// single round-trip to /1.0/sign.
const signTokenValidity = 5 * time.Minute

// SignParams are the inputs to SignCSR. Password is the selected provisioner's
// passphrase (from sealed settings); it is used only to decrypt the signing key
// and is never logged or returned.
type SignParams struct {
	CAURL           string
	Fingerprint     string
	ProvisionerName string
	Password        string
	CSRPEM          string
	ValidityDays    int // requested validity; 0 lets the CA apply its default
}

// SignResult is the outcome of a successful sign: the parsed leaf certificate and
// the PEM material (leaf, the chain above it, and the leaf+chain fullchain).
type SignResult struct {
	Certificate  *x509.Certificate
	CertPEM      string
	ChainPEM     string
	FullchainPEM string
}

// SignCSR obtains a certificate for the given CSR PEM by signing a JWK
// provisioner OTT and POSTing it with the CSR to {ca}/1.0/sign. The CN and SANs
// carried in the OTT are taken from the CSR (parsed by the caller), so this
// function works for both server-generated issuance and client-supplied CSRs.
// See the package doc for the exact token format and the no-live-CA limitation.
func SignCSR(ctx context.Context, p SignParams) (SignResult, error) {
	base, err := baseURL(p.CAURL)
	if err != nil {
		return SignResult{}, err
	}
	csr, err := pemutil.ParseCertificateRequest([]byte(p.CSRPEM))
	if err != nil {
		return SignResult{}, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	// Verify the CSR self-signature at the exported CA entry point too, so this
	// holds regardless of caller. The domain layer (internal/certs) already checks
	// it one layer up; making it idempotent here is cheap defense-in-depth and
	// avoids sending an unverifiable CSR to the CA.
	if err := csr.CheckSignature(); err != nil {
		return SignResult{}, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidCSR, err)
	}

	client, err := pinnedClientFor(ctx, p.CAURL, p.Fingerprint)
	if err != nil {
		return SignResult{}, err
	}

	signingKey, err := provisionerSigningKey(ctx, base, client, p.ProvisionerName, p.Password)
	if err != nil {
		return SignResult{}, err
	}

	ott, err := buildSignToken(signingKey, p.ProvisionerName, base, csr)
	if err != nil {
		return SignResult{}, err
	}

	return postSign(ctx, base, client, p.CSRPEM, ott, p.ValidityDays)
}

// jwkProvisionerEntry mirrors a JWK provisioner in GET /provisioners: the type,
// name, public key and the JWE-encrypted private key.
type jwkProvisionerEntry struct {
	Type         string          `json:"type"`
	Name         string          `json:"name"`
	Key          json.RawMessage `json:"key"`
	EncryptedKey string          `json:"encryptedKey"`
}

// provisionerSigningKey fetches the named JWK provisioner, decrypts its
// encryptedKey with the password, and returns the signing JWK. It follows the
// CA's nextCursor pagination so the provisioner is found regardless of page.
func provisionerSigningKey(ctx context.Context, base string, client *http.Client, name, password string) (*jose.JSONWebKey, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: no provisioner selected", ErrProvisionerNotFound)
	}
	cursor := ""
	for {
		u := base + "/provisioners"
		if cursor != "" {
			u += "?cursor=" + cursor
		}
		body, err := fetch(ctx, u, client)
		if err != nil {
			return nil, err
		}
		var page struct {
			Provisioners []jwkProvisionerEntry `json:"provisioners"`
			NextCursor   string                `json:"nextCursor"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("%w: decode provisioners: %v", ErrMalformedResponse, err)
		}
		for _, e := range page.Provisioners {
			if e.Name != name {
				continue
			}
			if e.Type != "JWK" || e.EncryptedKey == "" {
				return nil, fmt.Errorf("%w: provisioner %q is not a usable JWK provisioner", ErrProvisionerNotFound, name)
			}
			return decryptSigningKey(e.EncryptedKey, password)
		}
		if page.NextCursor == "" {
			return nil, fmt.Errorf("%w: %q", ErrProvisionerNotFound, name)
		}
		cursor = page.NextCursor
	}
}

// decryptSigningKey decrypts the JWE encryptedKey with the password and parses
// the recovered private JWK.
func decryptSigningKey(encryptedKey, password string) (*jose.JSONWebKey, error) {
	plain, err := jose.Decrypt([]byte(encryptedKey), jose.WithPassword([]byte(password)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProvisionerKey, err)
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(plain); err != nil {
		return nil, fmt.Errorf("%w: parse decrypted key: %v", ErrProvisionerKey, err)
	}
	if jwk.IsPublic() || !jwk.Valid() {
		return nil, fmt.Errorf("%w: decrypted key is not a valid private key", ErrProvisionerKey)
	}
	return &jwk, nil
}

// signClaims is the OTT payload: the standard registered claims plus the "sans"
// claim Step-CA's JWK provisioner reads.
type signClaims struct {
	jose.Claims
	SANs []string `json:"sans"`
}

// buildSignToken builds and signs the OTT for the CSR's CN + SANs against the
// {ca}/1.0/sign audience, signed with the provisioner JWK. The header carries the
// key's kid (and the algorithm is derived from the key).
func buildSignToken(key *jose.JSONWebKey, provisionerName, base string, csr *x509.CertificateRequest) (string, error) {
	opts := (&jose.SignerOptions{}).
		WithType("JWT").
		WithHeader("kid", key.KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key.Key}, opts)
	if err != nil {
		return "", fmt.Errorf("%w: build signer: %v", ErrProvisionerKey, err)
	}

	jti, err := randutil.Hex(64)
	if err != nil {
		return "", fmt.Errorf("%w: generate jti: %v", ErrProvisionerKey, err)
	}
	now := time.Now()
	claims := signClaims{
		Claims: jose.Claims{
			ID:        jti,
			Issuer:    provisionerName,
			Subject:   csr.Subject.CommonName,
			Audience:  jose.Audience{base + "/1.0/sign"},
			NotBefore: jose.NewNumericDate(now),
			IssuedAt:  jose.NewNumericDate(now),
			Expiry:    jose.NewNumericDate(now.Add(signTokenValidity)),
		},
		SANs: csrSANs(csr),
	}
	tok, err := jose.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("%w: sign token: %v", ErrProvisionerKey, err)
	}
	return tok, nil
}

// csrSANs returns the CSR's SANs as strings (DNS, IP, email, URI). If the CSR has
// no SANs but a CN, the CN is used so the leaf has at least one SAN — mirroring
// Step-CA's "default to subject" behaviour and keeping the issued cert usable.
func csrSANs(csr *x509.CertificateRequest) []string {
	var sans []string
	sans = append(sans, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, csr.EmailAddresses...)
	for _, u := range csr.URIs {
		sans = append(sans, u.String())
	}
	if len(sans) == 0 && csr.Subject.CommonName != "" {
		sans = append(sans, csr.Subject.CommonName)
	}
	return sans
}

// signRequest is the POST /1.0/sign body.
type signRequest struct {
	CSR      string `json:"csr"`
	OTT      string `json:"ott"`
	NotAfter string `json:"notAfter,omitempty"`
}

// signResponse mirrors Step-CA's /1.0/sign response: the leaf ("crt"), the CA
// cert ("ca") and the full chain ("certChain", leaf first).
type signResponse struct {
	Crt       string   `json:"crt"`
	CA        string   `json:"ca"`
	CertChain []string `json:"certChain"`
}

// postSign sends the sign request and parses the returned certificate + chain.
func postSign(ctx context.Context, base string, client *http.Client, csrPEM, ott string, validityDays int) (SignResult, error) {
	reqBody := signRequest{CSR: csrPEM, OTT: ott}
	if validityDays > 0 {
		reqBody.NotAfter = time.Now().Add(time.Duration(validityDays) * 24 * time.Hour).UTC().Format(time.RFC3339)
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return SignResult{}, fmt.Errorf("%w: marshal request: %v", ErrSignFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/1.0/sign", bytes.NewReader(raw))
	if err != nil {
		return SignResult{}, fmt.Errorf("%w: build request: %v", ErrUnreachable, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return SignResult{}, classifyDoError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return parseSignResponse(body)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// Validity over max, bad CSR per the CA, or token rejected → a clear,
		// caller-actionable rejection.
		return SignResult{}, fmt.Errorf("%w: %s", ErrSignRejected, adminErrorMessage(body))
	default:
		return SignResult{}, fmt.Errorf("%w: status %d: %s", ErrSignFailed, resp.StatusCode, adminErrorMessage(body))
	}
}

// parseSignResponse turns the /1.0/sign body into a SignResult: it parses the
// leaf, builds the chain PEM (everything above the leaf) and the fullchain.
func parseSignResponse(body []byte) (SignResult, error) {
	var sr signResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return SignResult{}, fmt.Errorf("%w: decode response: %v", ErrSignFailed, err)
	}
	if sr.Crt == "" {
		return SignResult{}, fmt.Errorf("%w: response had no certificate", ErrSignFailed)
	}
	leaf, err := pemutil.ParseCertificate([]byte(sr.Crt))
	if err != nil {
		return SignResult{}, fmt.Errorf("%w: parse leaf: %v", ErrSignFailed, err)
	}

	// The chain is everything in certChain after the leaf, falling back to the
	// "ca" field when certChain is absent.
	var chainPEM string
	switch {
	case len(sr.CertChain) > 1:
		for _, c := range sr.CertChain[1:] {
			chainPEM += ensureTrailingNewline(c)
		}
	case sr.CA != "":
		chainPEM = ensureTrailingNewline(sr.CA)
	}

	certPEM := ensureTrailingNewline(sr.Crt)
	return SignResult{
		Certificate:  leaf,
		CertPEM:      certPEM,
		ChainPEM:     chainPEM,
		FullchainPEM: certPEM + chainPEM,
	}, nil
}

// ensureTrailingNewline guarantees the PEM ends with a newline so concatenated
// blocks are valid.
func ensureTrailingNewline(pem string) string {
	if pem == "" || pem[len(pem)-1] == '\n' {
		return pem
	}
	return pem + "\n"
}
