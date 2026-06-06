package ca

// Certificate revocation against Step-CA via a JWK provisioner one-time token
// (OTT), over the existing two-phase pinned-trust client (ADR-0004): no `step`
// CLI.
//
// # Revoke OTT flow — the crux
//
// Revocation reuses the JWK provisioner OTT machinery of the sign flow, with two
// differences that step-ca's revoke authorization enforces:
//
//   - The OTT's audience is "{ca}/1.0/revoke" (not /1.0/sign).
//   - The OTT's SUBJECT is the certificate SERIAL being revoked. step-ca's
//     authorizeRevoke checks that the token subject equals the serial in the
//     request body and rejects the call otherwise ("token subject and serial
//     number do not match"). This binds the signed token to one specific cert.
//
// The request body is POST {ca}/1.0/revoke with
//
//	{ "serial": <serial>, "ott": <token>, "reasonCode": <int>,
//	  "reason": <text>, "passive": true }
//
// Step-CA only implements PASSIVE revocation (it marks the cert revoked in its
// DB so OCSP/CRL report it; "non-passive" CRL-only revocation is not
// implemented), so passive must be true. These field names and the
// subject==serial rule were taken from smallstep/certificates' api/revoke.go
// (RevokeRequest, Validate: passive must be true) and smallstep/cli's revoke
// token flow (RevokeType audience = /1.0/revoke, token subject = serial).
//
// IMPORTANT — validation scope: like the sign flow, this is exercised against an
// httptest mock (revoke_test.go) that publishes a JWK provisioner and verifies
// the OTT signature, the aud/iss claims and subject==serial before reporting
// success. It does NOT prove behaviour against a live Step-CA (real revocation
// DB, OCSP/CRL propagation, provisioner policy).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
)

// Revoke-flow errors, matchable via errors.Is. The provisioner-key/not-found
// errors are shared with the sign flow (ErrProvisionerNotFound,
// ErrProvisionerKey) since they resolve the same JWK provisioner.
var (
	// ErrRevokeInvalid means a required input was missing or malformed (e.g. an
	// empty serial); rejected before any CA round-trip.
	ErrRevokeInvalid = errors.New("ca: invalid revoke request")
	// ErrRevokeFailed means the CA rejected or failed the revoke request (any
	// non-2xx response). The local status MUST be left unchanged in this case.
	ErrRevokeFailed = errors.New("ca: revoke request failed")
)

// RevokeParams are the inputs to RevokeCert. Password is the selected
// provisioner's passphrase (from sealed settings); it is used only to decrypt
// the signing key and is never logged or returned.
type RevokeParams struct {
	CAURL           string
	Fingerprint     string
	ProvisionerName string
	Password        string
	Serial          string // the certificate serial to revoke (decimal or 0x hex)
	Reason          string // free-text revocation reason
	ReasonCode      int    // OCSP reason code (0 = unspecified)
}

// RevokeCert revokes the certificate with the given serial at the CA by signing
// a JWK provisioner OTT whose subject is the serial and whose audience is
// {ca}/1.0/revoke, then POSTing it with the serial/reason to {ca}/1.0/revoke.
// It returns nil only when the CA reports success; any non-2xx is ErrRevokeFailed
// so the caller can keep local state unchanged. See the package doc for the
// exact token format and the no-live-CA limitation.
func RevokeCert(ctx context.Context, p RevokeParams) error {
	serial := strings.TrimSpace(p.Serial)
	if serial == "" {
		return fmt.Errorf("%w: a serial number is required", ErrRevokeInvalid)
	}

	base, err := baseURL(p.CAURL)
	if err != nil {
		return err
	}

	client, err := pinnedClientFor(ctx, p.CAURL, p.Fingerprint)
	if err != nil {
		return err
	}

	signingKey, err := provisionerSigningKey(ctx, base, client, p.ProvisionerName, p.Password)
	if err != nil {
		return err
	}

	ott, err := buildRevokeToken(signingKey, p.ProvisionerName, base, serial)
	if err != nil {
		return err
	}

	return postRevoke(ctx, base, client, serial, ott, p.Reason, p.ReasonCode)
}

// buildRevokeToken builds and signs the OTT for revoking serial against the
// {ca}/1.0/revoke audience, signed with the provisioner JWK. The subject is the
// serial (step-ca requires token.sub == serial); the header carries the key's
// kid. Mirrors buildSignToken but with the revoke audience + serial subject.
func buildRevokeToken(key *jose.JSONWebKey, provisionerName, base, serial string) (string, error) {
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
	claims := jose.Claims{
		ID:        jti,
		Issuer:    provisionerName,
		Subject:   serial,
		Audience:  jose.Audience{base + "/1.0/revoke"},
		NotBefore: jose.NewNumericDate(now),
		IssuedAt:  jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(signTokenValidity)),
	}
	tok, err := jose.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("%w: sign token: %v", ErrProvisionerKey, err)
	}
	return tok, nil
}

// revokeRequest is the POST /1.0/revoke body. passive is always true: step-ca
// only implements passive revocation.
type revokeRequest struct {
	Serial     string `json:"serial"`
	OTT        string `json:"ott"`
	ReasonCode int    `json:"reasonCode"`
	Reason     string `json:"reason"`
	Passive    bool   `json:"passive"`
}

// postRevoke sends the revoke request and maps any non-2xx to ErrRevokeFailed so
// the caller leaves local state untouched on failure.
func postRevoke(ctx context.Context, base string, client *http.Client, serial, ott, reason string, reasonCode int) error {
	raw, err := json.Marshal(revokeRequest{
		Serial:     serial,
		OTT:        ott,
		ReasonCode: reasonCode,
		Reason:     reason,
		Passive:    true,
	})
	if err != nil {
		return fmt.Errorf("%w: marshal request: %v", ErrRevokeFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/1.0/revoke", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrUnreachable, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return classifyDoError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// Any non-2xx (already revoked at the CA, unknown serial, policy, 5xx) is a
	// failure: the caller must NOT mutate local state.
	return fmt.Errorf("%w: %s", ErrRevokeFailed, adminErrorMessage(body))
}
