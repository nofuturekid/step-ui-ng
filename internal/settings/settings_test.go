package settings_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/crypto"
	"github.com/nofuturekid/step-ui-ng/internal/settings"
	"github.com/nofuturekid/step-ui-ng/internal/store"
)

const validFP = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" // 64 hex

// newRepo opens a fresh migrated store and a Box over a temp data dir, returning
// a settings repo plus the underlying DB and Box for assertions.
func newRepo(t *testing.T) (*settings.Repo, *store.Store, *crypto.Box) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	box, err := crypto.NewBox(dir)
	if err != nil {
		t.Fatalf("crypto.NewBox: %v", err)
	}
	return settings.NewRepo(st.DB(), box), st, box
}

// Empty store: Get returns ok=false (no settings yet).
func TestGetEmpty(t *testing.T) {
	repo, _, _ := newRepo(t)
	_, ok, err := repo.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("Get on empty store returned ok=true")
	}
}

// CRUD: save then load round-trips the non-secret fields and exposes "secret
// set" without revealing the value.
func TestSaveAndGet(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()

	in := settings.Input{
		CAURL:            "https://ca.example:9000",
		RootFingerprint:  validFP,
		AdminProvisioner: "admin-jwk",
		AdminSubject:     "step@example.com",
		AdminSecret:      "super-secret-password",
	}
	if err := repo.Save(ctx, in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get after Save returned ok=false")
	}
	if got.CAURL != in.CAURL || got.RootFingerprint != in.RootFingerprint {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.AdminProvisioner != in.AdminProvisioner || got.AdminSubject != in.AdminSubject {
		t.Fatalf("admin identity round-trip mismatch: %+v", got)
	}
	if !got.HasAdminSecret {
		t.Fatal("HasAdminSecret = false after saving a secret")
	}
}

// FR-5: the Settings view exposes a "secret set" bool but never the plaintext
// — there must be no field carrying the clear-text secret.
func TestGetNeverExposesPlaintextSecret(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()
	const secret = "do-not-leak-me-1234567890"

	if err := repo.Save(ctx, settings.Input{
		CAURL: "https://ca.example", RootFingerprint: validFP, AdminSecret: secret,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, _, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Reflectively render the struct and assert the secret is absent.
	if strings.Contains(renderAllFields(got), secret) {
		t.Fatal("Get result contains the plaintext admin secret")
	}
}

// Sealing: the stored admin_secret_sealed column must NOT equal the plaintext
// and must round-trip back through the Box to the original secret.
func TestAdminSecretSealedAtRest(t *testing.T) {
	repo, st, box := newRepo(t)
	ctx := context.Background()
	const secret = "plaintext-secret-value-xyz"

	if err := repo.Save(ctx, settings.Input{
		CAURL: "https://ca.example", RootFingerprint: validFP, AdminSecret: secret,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var sealed string
	if err := st.DB().QueryRowContext(ctx,
		"SELECT admin_secret_sealed FROM ca_settings WHERE id = 1").Scan(&sealed); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if sealed == "" {
		t.Fatal("admin_secret_sealed is empty after saving a secret")
	}
	if sealed == secret {
		t.Fatal("admin_secret_sealed stored as PLAINTEXT")
	}
	opened, err := box.Open(sealed)
	if err != nil {
		t.Fatalf("Box.Open stored value: %v", err)
	}
	if string(opened) != secret {
		t.Fatalf("sealed value did not round-trip: got %q", opened)
	}
}

// An empty AdminSecret on a subsequent Save must leave the existing sealed value
// untouched (write-only field semantics, FR-5).
func TestEmptySecretLeavesExistingUntouched(t *testing.T) {
	repo, st, _ := newRepo(t)
	ctx := context.Background()
	const secret = "keep-me-secret-abcdef"

	if err := repo.Save(ctx, settings.Input{
		CAURL: "https://ca.example", RootFingerprint: validFP, AdminSecret: secret,
	}); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	var first string
	_ = st.DB().QueryRowContext(ctx,
		"SELECT admin_secret_sealed FROM ca_settings WHERE id = 1").Scan(&first)

	// Re-save without a secret; the sealed value must be unchanged.
	if err := repo.Save(ctx, settings.Input{
		CAURL: "https://ca2.example", RootFingerprint: validFP, AdminSecret: "",
	}); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	var second string
	_ = st.DB().QueryRowContext(ctx,
		"SELECT admin_secret_sealed FROM ca_settings WHERE id = 1").Scan(&second)

	if second != first {
		t.Fatalf("empty secret changed the sealed value: %q -> %q", first, second)
	}
	got, _, _ := repo.Get(ctx)
	if got.CAURL != "https://ca2.example" {
		t.Fatalf("non-secret fields should still update: %+v", got)
	}
	if !got.HasAdminSecret {
		t.Fatal("HasAdminSecret should remain true after a no-secret update")
	}
}

// Save is an upsert against the single row: a second Save updates rather than
// erroring on the PK.
func TestSaveUpserts(t *testing.T) {
	repo, st, _ := newRepo(t)
	ctx := context.Background()

	for _, url := range []string{"https://a.example", "https://b.example"} {
		if err := repo.Save(ctx, settings.Input{CAURL: url, RootFingerprint: validFP}); err != nil {
			t.Fatalf("Save %s: %v", url, err)
		}
	}
	var n int
	_ = st.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM ca_settings").Scan(&n)
	if n != 1 {
		t.Fatalf("row count = %d, want 1 (single-row upsert)", n)
	}
	got, _, _ := repo.Get(ctx)
	if got.CAURL != "https://b.example" {
		t.Fatalf("upsert did not update CAURL: %+v", got)
	}
}

// Validation: ca_url must be http(s) (FR-4).
func TestSaveRejectsInvalidURL(t *testing.T) {
	repo, _, _ := newRepo(t)
	for _, url := range []string{"", "ftp://ca", "ca.example", "javascript:alert(1)", "  "} {
		err := repo.Save(context.Background(), settings.Input{CAURL: url, RootFingerprint: validFP})
		if !errors.Is(err, settings.ErrInvalidURL) {
			t.Fatalf("Save url=%q err = %v, want ErrInvalidURL", url, err)
		}
	}
}

// Validation: fingerprint must be 40–64 hex (FR-4), table-driven.
func TestSaveFingerprintValidation(t *testing.T) {
	repo, _, _ := newRepo(t)
	cases := []struct {
		name string
		fp   string
		ok   bool
	}{
		{"too short", "abcd", false},
		{"39 hex (below min)", strings.Repeat("a", 39), false},
		{"40 hex (sha1 min)", strings.Repeat("a", 40), true},
		{"64 hex (sha256)", validFP, true},
		{"65 hex (above max)", strings.Repeat("a", 65), false},
		{"non-hex", strings.Repeat("z", 64), false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := repo.Save(context.Background(), settings.Input{
				CAURL: "https://ca.example", RootFingerprint: tc.fp,
			})
			if tc.ok && err != nil {
				t.Fatalf("fp=%q: unexpected error %v", tc.fp, err)
			}
			if !tc.ok && !errors.Is(err, settings.ErrInvalidFingerprint) {
				t.Fatalf("fp=%q: err = %v, want ErrInvalidFingerprint", tc.fp, err)
			}
		})
	}
}

// renderAllFields concatenates every exported string field of a View so a leak
// of the plaintext secret into any field is caught.
func renderAllFields(v settings.View) string {
	return strings.Join([]string{
		v.CAURL, v.RootFingerprint, v.AdminProvisioner, v.AdminSubject,
		v.SelectedProvisioner, v.AdminCertPEM,
	}, "\x00")
}
