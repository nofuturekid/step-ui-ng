package certs

// spec/0008 — revoke & renew (domain layer).
//
// Revoke is REAL: it calls the CA (by serial, with a reason) and only marks the
// local row revoked when the CA reports success — so a CA failure never silently
// diverges the local state from the CA's (the predecessor's bug). Renew re-issues
// for the SAME CN/SANs with a chosen validity, sealing the new server key, and
// stores it as a new inventory row.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
)

// Revoke/renew domain errors, matchable via errors.Is so handlers map them to
// user-facing messages.
var (
	// ErrAlreadyRevoked means the certificate is already revoked locally; the
	// revoke action is refused without a CA call (FR-3 guard rail).
	ErrAlreadyRevoked = errors.New("certs: certificate is already revoked")
	// ErrReasonRequired means no revocation reason was supplied (FR-3).
	ErrReasonRequired = errors.New("certs: a revocation reason is required")
)

// RevokeParams are the inputs to Revoke (FR-1).
type RevokeParams struct {
	Actor           string // the authenticated session user (audit who, FR-4)
	ID              int64  // the local certificate row to revoke
	ProvisionerName string
	Password        string // selected provisioner secret (from sealed settings)
	CAURL           string
	Fingerprint     string
	Reason          string // required (FR-3)
	ReasonCode      int    // OCSP reason code (0 = unspecified)
}

// Revoke revokes the certificate at the CA by its serial and, ONLY on CA
// success, sets the local status to "revoked" and records an audit event
// (FR-1). It refuses an already-revoked cert (FR-3) and requires a reason
// (FR-3). On any CA failure the local row is left UNCHANGED and the CA error is
// returned (atomicity w.r.t. the CA) — so the inventory never claims a cert is
// revoked when the CA still considers it valid.
func (s *Service) Revoke(ctx context.Context, p RevokeParams) error {
	reason := strings.TrimSpace(p.Reason)
	if reason == "" {
		return ErrReasonRequired
	}

	// Load the current row: we need the serial for the CA call and the stored
	// status for the already-revoked guard.
	var (
		serial string
		status string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT serial, status FROM certificates WHERE id = ?`, p.ID).
		Scan(&serial, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("certs: revoke: load: %w", err)
	}
	if status == "revoked" {
		return ErrAlreadyRevoked
	}

	// Call the CA FIRST. If this fails, return without touching local state.
	if err := s.revoker.RevokeCert(ctx, ca.RevokeParams{
		CAURL:           p.CAURL,
		Fingerprint:     p.Fingerprint,
		ProvisionerName: p.ProvisionerName,
		Password:        p.Password,
		Serial:          serial,
		Reason:          reason,
		ReasonCode:      p.ReasonCode,
	}); err != nil {
		return err
	}

	// CA succeeded: mark the local row revoked and audit. Only here do we mutate.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE certificates SET status = 'revoked', updated_at = ? WHERE id = ?`,
		now(), p.ID); err != nil {
		return fmt.Errorf("certs: revoke: update status: %w", err)
	}
	if err := s.audit.Record(ctx, p.Actor, "revoke", serial,
		fmt.Sprintf("serial=%s reasonCode=%d reason=%s", serial, p.ReasonCode, reason)); err != nil {
		return fmt.Errorf("certs: audit revoke: %w", err)
	}
	return nil
}

// RenewParams are the inputs to Renew (FR-2).
type RenewParams struct {
	Actor           string
	ID              int64 // the local certificate row to renew
	ProvisionerName string
	Password        string
	CAURL           string
	Fingerprint     string
	ValidityDays    int // chosen validity; bounded by the provisioner max at the CA
}

// Renew re-issues a certificate for the SAME CN and SANs as the row identified
// by ID, with a freshly generated server keypair and the chosen validity
// (FR-2). It reuses the issue path (keygen → CSR → CA sign → seal → persist), so
// the renewed certificate appears in the inventory as a new server-strategy row
// with its sealed key, and records an audit event attributed to Actor. The
// provisioner's own max validity still bounds the request at the CA (an
// over-max request surfaces as ca.ErrSignRejected). The original row is left
// untouched (it may still be valid until separately revoked/expired).
func (s *Service) Renew(ctx context.Context, p RenewParams) (Certificate, error) {
	// Load the original CN/SANs.
	var (
		cn       string
		sansJSON string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT cn, sans_json FROM certificates WHERE id = ?`, p.ID).
		Scan(&cn, &sansJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	if err != nil {
		return Certificate{}, fmt.Errorf("certs: renew: load: %w", err)
	}
	sans := decodeSANs(sansJSON)

	// Re-issue for the same CN/SANs. Issue normalizes the CN into the SAN list
	// and de-dups, so passing the stored SANs (which already include the CN) is
	// idempotent. The renewed material is sealed and stored by Issue; it also
	// emits an "issue" audit event for the new row. We add a "renew" event below
	// so the renew action itself is attributable (FR-4) and links the source row.
	cert, err := s.Issue(ctx, IssueParams{
		Actor:           p.Actor,
		ProvisionerName: p.ProvisionerName,
		Password:        p.Password,
		CAURL:           p.CAURL,
		Fingerprint:     p.Fingerprint,
		CN:              cn,
		SANs:            sans,
		ValidityDays:    p.ValidityDays,
		Format:          FormatPEM,
	})
	if err != nil {
		return Certificate{}, err
	}

	if err := s.audit.Record(ctx, p.Actor, "renew", cn,
		fmt.Sprintf("from_id=%d new_serial=%s validity_days=%d", p.ID, cert.Serial, p.ValidityDays)); err != nil {
		return Certificate{}, fmt.Errorf("certs: audit renew: %w", err)
	}
	return cert, nil
}

// decodeSANs parses the stored sans_json column into a slice (nil on any error,
// which Issue will then backfill from the CN).
func decodeSANs(sansJSON string) []string {
	var sans []string
	_ = json.Unmarshal([]byte(sansJSON), &sans)
	return sans
}
