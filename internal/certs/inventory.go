package certs

// spec/0007 — inventory & encrypted re-download
//
// This file adds the inventory query layer (List, Get) and the in-memory ZIP
// bundle assembly (Bundle).  It deliberately avoids any disk writes or logging
// of plaintext key material (FR-4).

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ErrNotFound is returned by Get when no certificate row matches the id.
var ErrNotFound = errors.New("certs: not found")

// nowTime is overridable in tests; defaults to wall-clock time.
var nowTime = time.Now

// ListFilter carries the optional filter parameters for List.
type ListFilter struct {
	// Status restricts results to certs whose derived status equals this value.
	// Allowed values: "active", "expired", "revoked".  Empty means no filter.
	Status string
	// Search restricts results to rows where cn or sans_json contains the
	// substring (case-insensitive).  Empty means no filter.
	Search string
}

// InventoryItem is the projected row returned by List (a subset of Certificate
// enriched with the derived status and days-until-expiry).
type InventoryItem struct {
	ID           int64
	CN           string
	SANs         []string
	Serial       string
	NotAfter     int64
	StoredStatus string // the value in the DB status column
	Status       string // derived: active | expired | revoked
	DaysLeft     int    // positive = days until expiry; negative = days past expiry
	KeyStrategy  string
}

// DeriveStatus derives the display status and days-until-expiry from the
// stored status column and not_after (Unix seconds).
//
//   - "revoked" in the DB → status "revoked" (authoritative; spec/0008 will set
//     this; the days-left calculation is still returned but ignored for display).
//   - not_after in the past → "expired".
//   - otherwise → "active".
func DeriveStatus(storedStatus string, notAfter int64) (status string, daysLeft int) {
	now := nowTime()
	expiry := time.Unix(notAfter, 0)
	diff := expiry.Sub(now)
	// Truncate to whole days, rounding toward zero.
	daysLeft = int(diff.Hours() / 24)

	switch storedStatus {
	case "revoked":
		return "revoked", daysLeft
	}
	// RFC 5280: not_after is inclusive — a cert at exactly not_after is expired.
	// Use !After (i.e. <=) so now == not_after is treated as expired.
	if !expiry.After(now) {
		return "expired", daysLeft
	}
	return "active", daysLeft
}

// List queries the certificate inventory with optional filters.
// Status filtering is performed in Go (not SQL) because it mixes DB state with
// derived status (expired = not_after in the past, which is not stored in the
// DB status column — spec/0008 will update status on revoke but not on expiry).
func (s *Service) List(ctx context.Context, f ListFilter) ([]InventoryItem, error) {
	// Base query: all rows, optional CN/SAN substring filter (case-insensitive).
	// SQLite LIKE is case-insensitive for ASCII by default.
	var (
		rows *sql.Rows
		err  error
	)
	if f.Search == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, cn, sans_json, serial, not_after, status, key_strategy
			   FROM certificates ORDER BY created_at DESC`)
	} else {
		// Escape the LIKE special characters in the search term so they are
		// treated as literals. The ESCAPE clause uses '\' as the escape
		// character, so we must also escape any literal '\' in the input.
		escaped := f.Search
		escaped = strings.ReplaceAll(escaped, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `%`, `\%`)
		escaped = strings.ReplaceAll(escaped, `_`, `\_`)
		like := "%" + escaped + "%"
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, cn, sans_json, serial, not_after, status, key_strategy
			   FROM certificates
			  WHERE cn LIKE ? ESCAPE '\' OR sans_json LIKE ? ESCAPE '\'
			  ORDER BY created_at DESC`,
			like, like)
	}
	if err != nil {
		return nil, fmt.Errorf("certs: list: %w", err)
	}
	defer rows.Close()

	var out []InventoryItem
	for rows.Next() {
		var it InventoryItem
		var sansJSON string
		if err := rows.Scan(&it.ID, &it.CN, &sansJSON, &it.Serial,
			&it.NotAfter, &it.StoredStatus, &it.KeyStrategy); err != nil {
			return nil, fmt.Errorf("certs: list scan: %w", err)
		}
		_ = json.Unmarshal([]byte(sansJSON), &it.SANs)
		it.Status, it.DaysLeft = DeriveStatus(it.StoredStatus, it.NotAfter)

		// Apply status filter (derived, not stored).
		if f.Status != "" && it.Status != f.Status {
			continue
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("certs: list rows: %w", err)
	}
	return out, nil
}

// Get returns the full certificate row for id, or ErrNotFound.
func (s *Service) Get(ctx context.Context, id int64) (Certificate, error) {
	var (
		c          Certificate
		sansJSON   string
		privSealed sql.NullString
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, cn, sans_json, serial, not_before, not_after, status,
		        key_strategy, cert_pem, chain_pem, fullchain_pem, privkey_sealed
		   FROM certificates WHERE id = ?`, id).
		Scan(&c.ID, &c.CN, &sansJSON, &c.Serial, &c.NotBefore, &c.NotAfter,
			&c.Status, &c.KeyStrategy, &c.CertPEM, &c.ChainPEM, &c.FullchainPEM,
			&privSealed)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	if err != nil {
		return Certificate{}, fmt.Errorf("certs: get: %w", err)
	}
	_ = json.Unmarshal([]byte(sansJSON), &c.SANs)
	// privkey_sealed is intentionally not exposed on Certificate (never logs it).
	_ = privSealed
	return c, nil
}

// Bundle assembles an in-memory ZIP containing:
//
//   - cert.pem        — the leaf certificate
//   - chain.pem       — the issuer chain
//   - fullchain.pem   — leaf + chain concatenated
//   - privkey.pem     — the private key (ONLY if key_strategy=server; FR-6)
//   - cert.p12        — PKCS#12 bundle (ONLY when pfxPassword is non-empty; FR-3)
//   - README.txt      — file descriptions
//
// The private key is decrypted in-memory only; it is never written to disk or
// logged (FR-4).
func (s *Service) Bundle(ctx context.Context, id int64, pfxPassword string) ([]byte, error) {
	// Load the full row including the sealed key.
	var (
		cn, certPEM, chainPEM, fullchainPEM, keyStrategy string
		privSealed                                       sql.NullString
		notAfter                                         int64
		serial                                           string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT cn, serial, not_after, key_strategy,
		        cert_pem, chain_pem, fullchain_pem, privkey_sealed
		   FROM certificates WHERE id = ?`, id).
		Scan(&cn, &serial, &notAfter, &keyStrategy,
			&certPEM, &chainPEM, &fullchainPEM, &privSealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("certs: bundle: %w", err)
	}

	// Unseal the private key in-memory (FR-4: never write to disk, never log).
	var keyPEM string
	if keyStrategy == "server" && privSealed.Valid && privSealed.String != "" {
		plain, err := s.box.Open(privSealed.String)
		if err != nil {
			return nil, fmt.Errorf("certs: bundle: unseal key: %w", err)
		}
		keyPEM = string(plain)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	addFile := func(name, content string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(content))
		return err
	}
	addBytes := func(name string, content []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(content)
		return err
	}

	if err := addFile("cert.pem", certPEM); err != nil {
		return nil, fmt.Errorf("certs: bundle: write cert.pem: %w", err)
	}
	if err := addFile("chain.pem", chainPEM); err != nil {
		return nil, fmt.Errorf("certs: bundle: write chain.pem: %w", err)
	}
	if err := addFile("fullchain.pem", fullchainPEM); err != nil {
		return nil, fmt.Errorf("certs: bundle: write fullchain.pem: %w", err)
	}

	// privkey.pem — only for server-generated certificates (FR-6).
	if keyPEM != "" {
		if err := addFile("privkey.pem", keyPEM); err != nil {
			return nil, fmt.Errorf("certs: bundle: write privkey.pem: %w", err)
		}
	}

	// cert.p12 — optional; only when a PFX password is provided (FR-3).
	if pfxPassword != "" && keyPEM != "" {
		p12, err := buildBundlePFX(keyPEM, certPEM, chainPEM, pfxPassword)
		if err != nil {
			return nil, fmt.Errorf("certs: bundle: build p12: %w", err)
		}
		if err := addBytes("cert.p12", p12); err != nil {
			return nil, fmt.Errorf("certs: bundle: write cert.p12: %w", err)
		}
	}

	readme := buildReadme(cn, serial, keyStrategy, keyPEM != "", pfxPassword != "" && keyPEM != "")
	if err := addFile("README.txt", readme); err != nil {
		return nil, fmt.Errorf("certs: bundle: write README.txt: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("certs: bundle: close zip: %w", err)
	}
	return buf.Bytes(), nil
}

// buildBundlePFX builds a PKCS#12 bundle from a PEM key, PEM leaf cert, and PEM
// chain, encrypted with password.
func buildBundlePFX(keyPEM, certPEM, chainPEM, password string) ([]byte, error) {
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("parse key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key DER: %w", err)
	}

	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("parse cert PEM")
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert DER: %w", err)
	}

	var caCerts []*x509.Certificate
	if chainPEM != "" {
		rest := []byte(chainPEM)
		for len(rest) > 0 {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			ca, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse chain cert: %w", err)
			}
			caCerts = append(caCerts, ca)
		}
	}

	return pkcs12.Modern.Encode(key, leaf, caCerts, password)
}

// buildReadme returns the README.txt content describing the bundle files.
func buildReadme(cn, serial, keyStrategy string, hasKey, hasPFX bool) string {
	var sb strings.Builder
	sb.WriteString("step-ui-ng certificate bundle\n")
	sb.WriteString("==============================\n\n")
	fmt.Fprintf(&sb, "Common name : %s\n", cn)
	fmt.Fprintf(&sb, "Serial      : %s\n", serial)
	fmt.Fprintf(&sb, "Key strategy: %s\n\n", keyStrategy)
	sb.WriteString("Files\n-----\n")
	sb.WriteString("  cert.pem      — leaf certificate (PEM)\n")
	sb.WriteString("  chain.pem     — issuer chain (PEM, may be empty for self-signed)\n")
	sb.WriteString("  fullchain.pem — leaf + issuer chain concatenated (PEM)\n")
	if hasKey {
		sb.WriteString("  privkey.pem   — private key (PKCS#8 PEM, unencrypted)\n")
	}
	if hasPFX {
		sb.WriteString("  cert.p12      — PKCS#12 bundle (password-protected)\n")
	}
	sb.WriteString("\nSecurity notes\n--------------\n")
	sb.WriteString("  Store this bundle in a secure location.\n")
	if hasKey {
		sb.WriteString("  privkey.pem is unencrypted — restrict access (chmod 0600).\n")
	}
	return sb.String()
}
