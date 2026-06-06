// Package ca talks to a Smallstep Step-CA over its HTTPS API (ADR-0004): no
// shelling out to the `step` CLI. Its job for spec/0004 is the "Test connection"
// action — fetch the CA roots and verify the configured root fingerprint.
//
// # TLS-pinning trust flow (FR-3)
//
// We never blanket-trust the CA's TLS certificate. Trust is anchored to the
// operator-supplied root fingerprint in two phases:
//
//  1. Pinned bootstrap fetch. On first contact we do not yet hold the root
//     certificate, so we cannot use a normal RootCAs pool. We connect with a
//     tls.Config whose VerifyConnection callback enforces the pin: it computes
//     SHA-256 over each presented peer certificate's DER and fails unless one
//     equals the configured fingerprint. InsecureSkipVerify is set only to
//     suppress the default chain check (we have no anchor yet) — the callback
//     never returns nil unconditionally, so an attacker-presented certificate
//     whose fingerprint differs is rejected. We then GET /roots and locate the
//     root whose SHA-256(DER) matches the fingerprint.
//
//  2. Steady-state verification. Using the now-verified root we build a real
//     RootCAs pool and re-establish the TLS connection with
//     InsecureSkipVerify:false, so the CA's TLS chain is validated against the
//     pinned root by Go's standard verifier. Only if that succeeds do we report
//     the connection good. This proves the CA actually serves a chain anchored
//     in the pinned root, not merely that some presented cert matched the pin.
package ca

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.step.sm/crypto/pemutil"
)

// Typed errors let callers (and tests) branch on the failure kind without
// inspecting wrapped network/TLS detail. They are wrapped with %w so the
// underlying cause is preserved for logs while staying matchable via errors.Is.
var (
	// ErrInvalidFingerprint means the supplied fingerprint is not 40–64 hex
	// chars; rejected before any network call.
	ErrInvalidFingerprint = errors.New("ca: invalid root fingerprint")
	// ErrUnreachable means the CA could not be contacted (dial/timeout/DNS).
	ErrUnreachable = errors.New("ca: unreachable")
	// ErrBadTLS means the TLS handshake failed during steady-state verification
	// against the pinned root.
	ErrBadTLS = errors.New("ca: TLS verification failed")
	// ErrFingerprintMismatch means no fetched root matched the pinned
	// fingerprint (the security crux of "Test connection").
	ErrFingerprintMismatch = errors.New("ca: root fingerprint does not match")
	// ErrMalformedResponse means the /roots body was not the expected JSON/PEM
	// shape, or contained no certificates.
	ErrMalformedResponse = errors.New("ca: malformed CA response")
)

// fingerprint bounds: a hex SHA-1 is 40 chars, a hex SHA-256 is 64; Step-CA's
// bootstrap fingerprint is the hex SHA-256 of the root's DER. We accept the
// 40–64 range (FR-4) but only SHA-256 (64) can ever match in practice.
const (
	minFingerprintLen = 40
	maxFingerprintLen = 64
)

// defaultTimeout caps the whole Test-connection round-trip.
const defaultTimeout = 10 * time.Second

// TestConnection fetches the CA's roots over HTTPS and verifies that one of them
// matches the pinned fingerprint, returning the parsed roots on success. See the
// package doc for the two-phase TLS-pinning trust flow.
//
// caURL is the CA base URL (e.g. https://ca.example:9000); the /roots path is
// appended. fingerprint is the hex SHA-256 of the root certificate's DER bytes
// (case-insensitive), as produced by `step ca root` / the bootstrap flow.
func TestConnection(ctx context.Context, caURL, fingerprint string) ([]*x509.Certificate, error) {
	want, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	rootsURL, err := rootsEndpoint(caURL)
	if err != nil {
		return nil, err
	}

	// Phase 1: pinned bootstrap fetch (no trust anchor yet).
	body, err := fetch(ctx, rootsURL, pinnedClient(want))
	if err != nil {
		return nil, err
	}

	roots, err := parseRoots(body)
	if err != nil {
		return nil, err
	}

	pinned := matchFingerprint(roots, want)
	if pinned == nil {
		return nil, ErrFingerprintMismatch
	}

	// Phase 2: steady-state verification against a real pool built from the
	// verified root, with InsecureSkipVerify:false.
	pool := x509.NewCertPool()
	pool.AddCert(pinned)
	if _, err := fetch(ctx, rootsURL, pooledClient(pool)); err != nil {
		// A failure here means the CA's TLS chain does not actually anchor in the
		// pinned root even though a presented cert matched the fingerprint.
		return nil, fmt.Errorf("%w: %v", ErrBadTLS, err)
	}

	return roots, nil
}

// baseURL trims trailing slashes/whitespace and validates the https scheme,
// returning the CA base URL ready for path joining. It shares the scheme guard
// with rootsEndpoint.
func baseURL(caURL string) (string, error) {
	u := strings.TrimRight(strings.TrimSpace(caURL), "/")
	if !strings.HasPrefix(u, "https://") {
		return "", fmt.Errorf("%w: CA URL must be https", ErrBadTLS)
	}
	return u, nil
}

// pinnedClientFor establishes the two-phase pinned trust to caURL/fingerprint
// (see the package doc) and returns an *http.Client whose transport trusts ONLY
// the verified pinned root (RootCAs pool, InsecureSkipVerify:false). Every CA
// operation beyond Test connection (list/create/delete provisioners, spec/0005)
// reuses this so they share the same anchored-trust guarantee — no blanket
// skip-verify. caURL must be https. Returns ErrUnreachable/ErrBadTLS/
// ErrFingerprintMismatch/ErrMalformedResponse as appropriate.
func pinnedClientFor(ctx context.Context, caURL, fingerprint string) (*http.Client, error) {
	want, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	rootsURL, err := rootsEndpoint(caURL)
	if err != nil {
		return nil, err
	}

	// Phase 1: pinned bootstrap fetch of /roots (no trust anchor yet).
	body, err := fetch(ctx, rootsURL, pinnedClient(want))
	if err != nil {
		return nil, err
	}
	roots, err := parseRoots(body)
	if err != nil {
		return nil, err
	}
	pinned := matchFingerprint(roots, want)
	if pinned == nil {
		return nil, ErrFingerprintMismatch
	}

	// Phase 2: build the steady-state client anchored in the verified root and
	// prove the live chain anchors there before handing it back.
	pool := x509.NewCertPool()
	pool.AddCert(pinned)
	client := pooledClient(pool)
	if _, err := fetch(ctx, rootsURL, client); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadTLS, err)
	}
	return client, nil
}

// normalizeFingerprint lower-cases and strips separators, then validates the
// 40–64 hex-character rule (FR-4).
func normalizeFingerprint(fp string) (string, error) {
	fp = strings.ToLower(strings.TrimSpace(fp))
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, "-", "")
	if !ValidFingerprint(fp) {
		return "", ErrInvalidFingerprint
	}
	return fp, nil
}

// ValidFingerprint reports whether fp is 40–64 lowercase/uppercase hex chars
// (FR-4). It is exported so the settings repo can reuse the same rule.
func ValidFingerprint(fp string) bool {
	fp = strings.ToLower(strings.TrimSpace(fp))
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, "-", "")
	if l := len(fp); l < minFingerprintLen || l > maxFingerprintLen {
		return false
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return false
	}
	return true
}

// rootsEndpoint returns caURL with a /roots path, validating the scheme is
// https (Test connection requires TLS to the CA; FR-3).
func rootsEndpoint(caURL string) (string, error) {
	u := strings.TrimRight(strings.TrimSpace(caURL), "/")
	if !strings.HasPrefix(u, "https://") {
		return "", fmt.Errorf("%w: CA URL must be https for the connection test", ErrBadTLS)
	}
	return u + "/roots", nil
}

// fetch performs GET url with the given client and returns the body, mapping
// transport failures to ErrUnreachable and non-2xx to ErrMalformedResponse.
func fetch(ctx context.Context, url string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, classifyDoError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the body; a roots bundle is small.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrUnreachable, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: CA returned status %d", ErrMalformedResponse, resp.StatusCode)
	}
	return body, nil
}

// classifyDoError maps an http.Client.Do error to a typed sentinel. A TLS
// verification failure (wrong pin in phase 1, or chain failure in phase 2) is
// ErrFingerprintMismatch/ErrBadTLS; everything else (dial, timeout, DNS) is
// ErrUnreachable.
func classifyDoError(err error) error {
	// The pinned bootstrap client returns ErrFingerprintMismatch from its
	// VerifyConnection callback; preserve it through the url.Error wrapper.
	if errors.Is(err, ErrFingerprintMismatch) {
		return ErrFingerprintMismatch
	}
	var certErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &certInvalid) {
		return fmt.Errorf("%w: %v", ErrBadTLS, err)
	}
	return fmt.Errorf("%w: %v", ErrUnreachable, err)
}

// pinnedClient builds the phase-1 client: it suppresses the default chain check
// (we hold no anchor yet) but enforces the fingerprint pin in VerifyConnection,
// which NEVER returns nil unconditionally.
func pinnedClient(wantFP string) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// We have no trust anchor on the very first contact, so the default
		// verifier cannot run; the VerifyConnection pin below is the real check.
		InsecureSkipVerify: true, //nolint:gosec // pin enforced in VerifyConnection
		// This callback is only a cheap pre-check: it proves *some* presented
		// cert matches the pinned fingerprint, not that the live chain anchors in
		// it. Phase 2 (pooledClient, InsecureSkipVerify:false) is the
		// authoritative MITM/anchor gate — DO NOT DELETE the Phase-2 block in
		// TestConnection in favour of this. See TestConnectionPhase2ChainNotAnchored.
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, cert := range cs.PeerCertificates {
				sum := sha256.Sum256(cert.Raw)
				if hex.EncodeToString(sum[:]) == wantFP {
					return nil
				}
			}
			return ErrFingerprintMismatch
		},
	}
	return newClient(tlsCfg)
}

// pooledClient builds the phase-2 client: standard verification against the
// pinned-root pool, with InsecureSkipVerify:false.
func pooledClient(pool *x509.CertPool) *http.Client {
	return newClient(&tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	})
}

// newClient returns an http.Client with the given TLS config and a bounded
// timeout, not sharing the default transport (so our TLS config is isolated).
func newClient(tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: defaultTimeout,
			DisableKeepAlives:   true,
		},
	}
}

// rootsResponse mirrors Step-CA's GET /roots body: {"crts":[<PEM>, ...]}.
type rootsResponse struct {
	Crts []string `json:"crts"`
}

// parseRoots decodes the /roots JSON and parses every embedded PEM certificate.
func parseRoots(body []byte) ([]*x509.Certificate, error) {
	var rr rootsResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return nil, fmt.Errorf("%w: decode JSON: %v", ErrMalformedResponse, err)
	}
	if len(rr.Crts) == 0 {
		return nil, fmt.Errorf("%w: no certificates in response", ErrMalformedResponse)
	}

	var out []*x509.Certificate
	for _, p := range rr.Crts {
		certs, err := pemutil.ParseCertificateBundle([]byte(p))
		if err != nil {
			return nil, fmt.Errorf("%w: parse PEM: %v", ErrMalformedResponse, err)
		}
		out = append(out, certs...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no certificates parsed", ErrMalformedResponse)
	}
	return out, nil
}

// matchFingerprint returns the first certificate whose SHA-256(DER) equals
// wantFP, or nil.
func matchFingerprint(certs []*x509.Certificate, wantFP string) *x509.Certificate {
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) == wantFP {
			return c
		}
	}
	return nil
}
