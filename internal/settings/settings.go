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
// any secret value: the Has* bools only report whether a secret/key is set
// (FR-5 of 0004; spec/0005). The admin certificate chain is public, so it is
// carried verbatim; the admin private key is never exposed, only HasAdminKey.
type View struct {
	CAURL            string
	RootFingerprint  string
	AdminProvisioner string
	AdminSubject     string
	HasAdminSecret   bool
	// Provisioner management (spec/0005).
	SelectedProvisioner string
	HasSelectedSecret   bool
	AdminCertPEM        string // the x5c chain (public)
	HasAdminKey         bool   // an admin signing key is configured
	CreatedAt           int64
	UpdatedAt           int64
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
		v         View
		sealed    sql.NullString
		prov      sql.NullString
		subj      sql.NullString
		selProv   sql.NullString
		selSecret sql.NullString
		adminCert sql.NullString
		adminKey  sql.NullString
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT ca_url, root_fingerprint, admin_provisioner, admin_subject,
		        admin_secret_sealed, selected_provisioner,
		        selected_provisioner_secret_sealed, admin_cert_pem, admin_key_sealed,
		        created_at, updated_at
		 FROM ca_settings WHERE id = 1`).
		Scan(&v.CAURL, &v.RootFingerprint, &prov, &subj, &sealed,
			&selProv, &selSecret, &adminCert, &adminKey, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return View{}, false, nil
	}
	if err != nil {
		return View{}, false, fmt.Errorf("settings: get: %w", err)
	}
	v.AdminProvisioner = prov.String
	v.AdminSubject = subj.String
	v.HasAdminSecret = sealed.Valid && sealed.String != ""
	v.SelectedProvisioner = selProv.String
	v.HasSelectedSecret = selSecret.Valid && selSecret.String != ""
	v.AdminCertPEM = adminCert.String
	v.HasAdminKey = adminKey.Valid && adminKey.String != ""
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

// ErrNoSettings means an operation needs the CA settings row to exist first.
var ErrNoSettings = errors.New("settings: no CA settings saved yet")

// SelectProvisioner persists the active provisioner for issuance (FR-2): its
// name and an optional sealed secret. An empty secret clears any stored secret
// (the secret belongs to the provisioner, so it must not linger when switching).
// The CA settings row must already exist.
func (r *Repo) SelectProvisioner(ctx context.Context, name, secret string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("settings: select provisioner: empty name")
	}

	var sealed sql.NullString
	if secret != "" {
		s, err := r.box.Seal([]byte(secret))
		if err != nil {
			return fmt.Errorf("settings: seal provisioner secret: %w", err)
		}
		sealed = sql.NullString{String: s, Valid: true}
	}

	res, err := r.db.ExecContext(ctx,
		`UPDATE ca_settings
		    SET selected_provisioner = ?,
		        selected_provisioner_secret_sealed = ?,
		        updated_at = ?
		  WHERE id = 1`,
		name, sealed, now())
	if err != nil {
		return fmt.Errorf("settings: select provisioner: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoSettings
	}
	return nil
}

// SaveAdminCredential stores the admin certificate chain (PEM, public) and seals
// the admin private key (PEM) used to sign x5c admin tokens (FR-3/FR-4,
// ADR-0012). The CA settings row must already exist. The private key is
// write-only: it is sealed before storage and never returned toward the client.
func (r *Repo) SaveAdminCredential(ctx context.Context, certPEM, keyPEM string) error {
	if strings.TrimSpace(certPEM) == "" || strings.TrimSpace(keyPEM) == "" {
		return fmt.Errorf("settings: admin credential: cert and key are required")
	}
	sealedKey, err := r.box.Seal([]byte(keyPEM))
	if err != nil {
		return fmt.Errorf("settings: seal admin key: %w", err)
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE ca_settings
		    SET admin_cert_pem = ?, admin_key_sealed = ?, updated_at = ?
		  WHERE id = 1`,
		certPEM, sealedKey, now())
	if err != nil {
		return fmt.Errorf("settings: save admin credential: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoSettings
	}
	return nil
}

// AdminCredential returns the stored admin certificate chain and the decrypted
// private key for use by the CA admin operations. ok is false when no admin
// credential is configured. The plaintext key is returned ONLY here, for
// internal signing use — never toward the client (callers must not render it).
func (r *Repo) AdminCredential(ctx context.Context) (certPEM, keyPEM string, ok bool, err error) {
	var cert, sealedKey sql.NullString
	qErr := r.db.QueryRowContext(ctx,
		`SELECT admin_cert_pem, admin_key_sealed FROM ca_settings WHERE id = 1`).
		Scan(&cert, &sealedKey)
	if errors.Is(qErr, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if qErr != nil {
		return "", "", false, fmt.Errorf("settings: admin credential: %w", qErr)
	}
	if !cert.Valid || cert.String == "" || !sealedKey.Valid || sealedKey.String == "" {
		return "", "", false, nil
	}
	plain, oErr := r.box.Open(sealedKey.String)
	if oErr != nil {
		return "", "", false, fmt.Errorf("settings: open admin key: %w", oErr)
	}
	return cert.String, string(plain), true, nil
}

// SelectedSecret returns the decrypted secret of the selected provisioner for
// internal issuance use. ok is false when no secret is stored. Never expose the
// returned value toward the client.
func (r *Repo) SelectedSecret(ctx context.Context) (secret string, ok bool, err error) {
	var sealed sql.NullString
	qErr := r.db.QueryRowContext(ctx,
		`SELECT selected_provisioner_secret_sealed FROM ca_settings WHERE id = 1`).
		Scan(&sealed)
	if errors.Is(qErr, sql.ErrNoRows) {
		return "", false, nil
	}
	if qErr != nil {
		return "", false, fmt.Errorf("settings: selected secret: %w", qErr)
	}
	if !sealed.Valid || sealed.String == "" {
		return "", false, nil
	}
	plain, oErr := r.box.Open(sealed.String)
	if oErr != nil {
		return "", false, fmt.Errorf("settings: open selected secret: %w", oErr)
	}
	return string(plain), true, nil
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
