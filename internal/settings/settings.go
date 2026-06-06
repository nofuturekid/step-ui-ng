// Package settings owns the single-row CA connection configuration (spec/0004):
// the CA URL, root fingerprint, optional admin identity and the admin secret.
//
// The admin secret is sealed with internal/crypto (AES-256-GCM, ADR-0006) before
// storage and is NEVER decrypted toward the client: callers read a View, which
// carries only a HasAdminSecret bool, never the plaintext (FR-5). All validation
// (URL scheme, fingerprint shape; FR-4) lives here so handlers stay thin.
package settings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
	"github.com/nofuturekid/step-ui-ng/internal/crypto"
)

// Validation errors, matchable via errors.Is so handlers can map them to
// user-facing messages.
var (
	ErrInvalidURL         = errors.New("settings: ca_url must be http(s)")
	ErrInvalidFingerprint = errors.New("settings: root_fingerprint must be 40–64 hex chars")
)

// Input is the write model: it carries the plaintext admin secret (optional).
// An empty AdminSecret on Save leaves the existing sealed value unchanged
// (write-only field semantics, FR-5).
type Input struct {
	CAURL            string
	RootFingerprint  string
	AdminProvisioner string
	AdminSubject     string
	AdminSecret      string // plaintext; sealed before storage, never persisted as-is
}

// View is the read model returned to callers/templates. It deliberately omits
// any secret value: HasAdminSecret only reports whether one is set (FR-5).
type View struct {
	CAURL            string
	RootFingerprint  string
	AdminProvisioner string
	AdminSubject     string
	HasAdminSecret   bool
	CreatedAt        int64
	UpdatedAt        int64
}

// Repo is the SQLite-backed CA-settings repository. It holds the crypto.Box so
// it can seal the admin secret on write; the Box is never used to decrypt toward
// a caller.
type Repo struct {
	db  *sql.DB
	box *crypto.Box
}

// NewRepo returns a Repo over an already-migrated DB and a sealing Box.
func NewRepo(db *sql.DB, box *crypto.Box) *Repo { return &Repo{db: db, box: box} }

// now is overridable in tests; defaults to wall-clock unix seconds.
var now = func() int64 { return time.Now().Unix() }

// Get loads the single settings row. ok is false when no settings exist yet.
// The admin secret is never decrypted: only HasAdminSecret is reported.
func (r *Repo) Get(ctx context.Context) (View, bool, error) {
	var (
		v      View
		sealed sql.NullString
		prov   sql.NullString
		subj   sql.NullString
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT ca_url, root_fingerprint, admin_provisioner, admin_subject,
		        admin_secret_sealed, created_at, updated_at
		 FROM ca_settings WHERE id = 1`).
		Scan(&v.CAURL, &v.RootFingerprint, &prov, &subj, &sealed, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, false, nil
	}
	if err != nil {
		return View{}, false, fmt.Errorf("settings: get: %w", err)
	}
	v.AdminProvisioner = prov.String
	v.AdminSubject = subj.String
	v.HasAdminSecret = sealed.Valid && sealed.String != ""
	return v, true, nil
}

// Save validates and upserts the single settings row. The admin secret is sealed
// before storage; an empty AdminSecret preserves the existing sealed value
// (FR-5). The upsert targets the fixed id=1, so there is only ever one row.
func (r *Repo) Save(ctx context.Context, in Input) error {
	caURL, err := validateURL(in.CAURL)
	if err != nil {
		return err
	}
	fp, err := validateFingerprint(in.RootFingerprint)
	if err != nil {
		return err
	}

	var sealed sql.NullString
	if in.AdminSecret != "" {
		s, err := r.box.Seal([]byte(in.AdminSecret))
		if err != nil {
			return fmt.Errorf("settings: seal admin secret: %w", err)
		}
		sealed = sql.NullString{String: s, Valid: true}
	}

	ts := now()
	// Upsert on the fixed primary key. On conflict we update the non-secret
	// fields always, but only overwrite the sealed secret when a new one was
	// supplied (excluded.admin_secret_sealed is NULL otherwise) — COALESCE keeps
	// the existing value. created_at is preserved on update.
	_, err = r.db.ExecContext(ctx,
		`INSERT INTO ca_settings
		   (id, ca_url, root_fingerprint, admin_provisioner, admin_subject,
		    admin_secret_sealed, created_at, updated_at)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   ca_url              = excluded.ca_url,
		   root_fingerprint    = excluded.root_fingerprint,
		   admin_provisioner   = excluded.admin_provisioner,
		   admin_subject       = excluded.admin_subject,
		   admin_secret_sealed = COALESCE(excluded.admin_secret_sealed, ca_settings.admin_secret_sealed),
		   updated_at          = excluded.updated_at`,
		caURL, fp, nullable(in.AdminProvisioner), nullable(in.AdminSubject),
		sealed, ts, ts)
	if err != nil {
		return fmt.Errorf("settings: save: %w", err)
	}
	return nil
}

// validateURL enforces the http(s) scheme rule (FR-4) and normalises trailing
// whitespace. It does not strip a trailing slash so the stored value matches
// what the operator entered; the ca package handles path joining.
func validateURL(raw string) (string, error) {
	u := strings.TrimSpace(raw)
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return "", ErrInvalidURL
	}
	// Reject a scheme with no host (e.g. "https://").
	if rest := strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://"); rest == "" {
		return "", ErrInvalidURL
	}
	return u, nil
}

// validateFingerprint enforces the 40–64 hex rule (FR-4), reusing the ca
// package's canonical check, and returns the trimmed value.
func validateFingerprint(raw string) (string, error) {
	fp := strings.TrimSpace(raw)
	if !ca.ValidFingerprint(fp) {
		return "", ErrInvalidFingerprint
	}
	return fp, nil
}

// nullable maps an empty string to a NULL column value, keeping optional fields
// truly absent rather than empty strings.
func nullable(s string) sql.NullString {
	s = strings.TrimSpace(s)
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
