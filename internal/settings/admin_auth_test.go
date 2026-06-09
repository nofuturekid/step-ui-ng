package settings_test

// Tests for the admin-auth configuration (spec/0012 FR-5, migration 0006).
//
// TDD checklist:
//   - TestSaveAdminJWKSealsPassword: password is sealed at rest; HasAdminJWK = true;
//     plaintext never in View.
//   - TestSaveAdminJWKLeaveBlankKeepsPassword: blank password on re-save leaves the
//     stored sealed value unchanged.
//   - TestSaveAdminJWKClearsX5CMaterial: switching to JWK clears admin_cert_pem and
//     admin_key_sealed (FR-5).
//   - TestSetAdminAuthNoneClearsAll: SetAdminAuthNone clears all admin material.
//   - TestAdminJWKPasswordRoundTrip: AdminJWKPassword decrypts and returns the password.
//   - TestAdminJWKPasswordNeverInView: the JWK password is not present in any View field.
//   - TestSaveAdminCredentialClearsJWK: switching to x5c (SaveAdminCredential) clears
//     the JWK password (FR-5 complementary direction).

import (
	"context"
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/settings"
)

// --- TestSaveAdminJWKSealsPassword ------------------------------------------

func TestSaveAdminJWKSealsPassword(t *testing.T) {
	repo, st, box := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	const subject = "step"
	const provisioner = "admin"
	const password = "jwk-admin-password-9876"

	if err := repo.SaveAdminJWK(ctx, subject, provisioner, password); err != nil {
		t.Fatalf("SaveAdminJWK: %v", err)
	}

	view, _, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if view.AdminAuthMethod != settings.AdminAuthJWK {
		t.Fatalf("AdminAuthMethod = %q, want %q", view.AdminAuthMethod, settings.AdminAuthJWK)
	}
	if view.AdminJWKSubject != subject {
		t.Fatalf("AdminJWKSubject = %q, want %q", view.AdminJWKSubject, subject)
	}
	if view.AdminJWKProvisioner != provisioner {
		t.Fatalf("AdminJWKProvisioner = %q, want %q", view.AdminJWKProvisioner, provisioner)
	}
	if !view.HasAdminJWK {
		t.Fatal("HasAdminJWK = false after SaveAdminJWK with a password")
	}

	// The plaintext password must not appear in any View field.
	if strings.Contains(renderAllFields(view), password) {
		t.Fatal("JWK password leaked into the View")
	}

	// The column is sealed and round-trips.
	var sealed string
	if err := st.DB().QueryRowContext(ctx,
		"SELECT admin_jwk_password_sealed FROM ca_settings WHERE id = 1").Scan(&sealed); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if sealed == "" || sealed == password {
		t.Fatalf("JWK password not sealed at rest (got %q)", sealed)
	}
	opened, err := box.Open(sealed)
	if err != nil {
		t.Fatalf("Box.Open: %v", err)
	}
	if string(opened) != password {
		t.Fatalf("sealed JWK password did not round-trip: got %q", opened)
	}
}

// --- TestSaveAdminJWKLeaveBlankKeepsPassword ---------------------------------

func TestSaveAdminJWKLeaveBlankKeepsPassword(t *testing.T) {
	repo, st, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.SaveAdminJWK(ctx, "step", "admin", "first-password-aaaa"); err != nil {
		t.Fatalf("SaveAdminJWK: %v", err)
	}
	var first string
	if err := st.DB().QueryRowContext(ctx,
		"SELECT admin_jwk_password_sealed FROM ca_settings WHERE id = 1").Scan(&first); err != nil {
		t.Fatalf("read first: %v", err)
	}

	// Re-save with a blank password: sealed value must be unchanged.
	if err := repo.SaveAdminJWK(ctx, "step", "admin", ""); err != nil {
		t.Fatalf("SaveAdminJWK blank: %v", err)
	}
	var second string
	if err := st.DB().QueryRowContext(ctx,
		"SELECT admin_jwk_password_sealed FROM ca_settings WHERE id = 1").Scan(&second); err != nil {
		t.Fatalf("read second: %v", err)
	}
	if second != first {
		t.Fatalf("blank password changed the sealed value: %q -> %q", first, second)
	}
}

// --- TestSaveAdminJWKClearsX5CMaterial (FR-5 switching) ---------------------

func TestSaveAdminJWKClearsX5CMaterial(t *testing.T) {
	repo, st, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Store x5c material first.
	if err := repo.SaveAdminCredential(ctx, "CERTCHAIN", "PRIVATEKEY"); err != nil {
		t.Fatalf("SaveAdminCredential: %v", err)
	}

	// Now switch to JWK: x5c material must be cleared.
	if err := repo.SaveAdminJWK(ctx, "step", "admin", "jwk-pass-aaaa"); err != nil {
		t.Fatalf("SaveAdminJWK: %v", err)
	}

	var certPEM, keySealed string
	if err := st.DB().QueryRowContext(ctx,
		"SELECT COALESCE(admin_cert_pem,''), COALESCE(admin_key_sealed,'') FROM ca_settings WHERE id = 1").
		Scan(&certPEM, &keySealed); err != nil {
		t.Fatalf("read x5c columns: %v", err)
	}
	if certPEM != "" {
		t.Fatal("admin_cert_pem not cleared after switching to JWK")
	}
	if keySealed != "" {
		t.Fatal("admin_key_sealed not cleared after switching to JWK")
	}
	view, _, _ := repo.Get(ctx)
	if view.HasAdminKey {
		t.Fatal("HasAdminKey should be false after switching to JWK")
	}
}

// --- TestSetAdminAuthNoneClearsAll ------------------------------------------

func TestSetAdminAuthNoneClearsAll(t *testing.T) {
	repo, st, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.SaveAdminJWK(ctx, "step", "admin", "some-password"); err != nil {
		t.Fatalf("SaveAdminJWK: %v", err)
	}

	if err := repo.SetAdminAuthNone(ctx); err != nil {
		t.Fatalf("SetAdminAuthNone: %v", err)
	}

	view, _, _ := repo.Get(ctx)
	if view.AdminAuthMethod != settings.AdminAuthNone {
		t.Fatalf("AdminAuthMethod = %q, want none", view.AdminAuthMethod)
	}
	if view.HasAdminJWK {
		t.Fatal("HasAdminJWK should be false after SetAdminAuthNone")
	}
	if view.HasAdminKey {
		t.Fatal("HasAdminKey should be false after SetAdminAuthNone")
	}

	// Columns must be NULL.
	var jwkPass, certPEM, keySealed string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COALESCE(admin_jwk_password_sealed,''),
		        COALESCE(admin_cert_pem,''),
		        COALESCE(admin_key_sealed,'')
		   FROM ca_settings WHERE id = 1`).
		Scan(&jwkPass, &certPEM, &keySealed); err != nil {
		t.Fatalf("read columns: %v", err)
	}
	if jwkPass != "" || certPEM != "" || keySealed != "" {
		t.Fatalf("secret material not cleared: jwk=%q cert=%q key=%q", jwkPass, certPEM, keySealed)
	}
}

// --- TestAdminJWKPasswordRoundTrip ------------------------------------------

func TestAdminJWKPasswordRoundTrip(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// No password stored → ok=false.
	if _, ok, err := repo.AdminJWKPassword(ctx); err != nil || ok {
		t.Fatalf("AdminJWKPassword with none stored: ok=%v err=%v, want ok=false", ok, err)
	}

	const password = "secret-jwk-pass-xyz"
	if err := repo.SaveAdminJWK(ctx, "step", "admin", password); err != nil {
		t.Fatalf("SaveAdminJWK: %v", err)
	}
	got, ok, err := repo.AdminJWKPassword(ctx)
	if err != nil || !ok {
		t.Fatalf("AdminJWKPassword: ok=%v err=%v", ok, err)
	}
	if got != password {
		t.Fatalf("AdminJWKPassword returned %q, want %q", got, password)
	}
}

// --- TestAdminJWKPasswordNeverInView ----------------------------------------

func TestAdminJWKPasswordNeverInView(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	const password = "do-not-leak-jwk-pass-1234"
	if err := repo.SaveAdminJWK(ctx, "step", "admin", password); err != nil {
		t.Fatalf("SaveAdminJWK: %v", err)
	}
	view, _, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Contains(renderAllFields(view), password) {
		t.Fatal("JWK password leaked into the View fields")
	}
}

// --- TestSaveAdminCredentialClearsJWK (FR-5 x5c direction) ------------------

// Switching to x5c (SaveAdminCredential) sets method=x5c and clears any stored
// JWK password.  Note: SaveAdminCredential does NOT automatically set the method
// (it was written before the method column existed), so this test only verifies
// that the application layer (postAdminAuth) should handle this.  We test that
// the existing SaveAdminCredential call does NOT spontaneously leak JWK material,
// and that the manual SetAdminAuthNone then SaveAdminCredential path works.
// FR-5 symmetry: switching to x5c via SaveAdminCredential must clear the stored
// JWK material (no stale sealed password lingering) AND never leak it into the View.
func TestSaveAdminCredentialClearsAndDoesNotLeakJWK(t *testing.T) {
	repo, st, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	const pass = "jwk-secret-aaaa"
	if err := repo.SaveAdminJWK(ctx, "step", "admin", pass); err != nil {
		t.Fatalf("SaveAdminJWK: %v", err)
	}

	// Switch to x5c: the JWK material must be cleared (FR-5), not just hidden.
	if err := repo.SaveAdminCredential(ctx, "CERTCHAIN", "PRIVATEKEY"); err != nil {
		t.Fatalf("SaveAdminCredential: %v", err)
	}

	var subj, prov, sealed string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COALESCE(admin_jwk_subject,''), COALESCE(admin_jwk_provisioner,''),
		        COALESCE(admin_jwk_password_sealed,'') FROM ca_settings WHERE id = 1`).
		Scan(&subj, &prov, &sealed); err != nil {
		t.Fatalf("read jwk columns: %v", err)
	}
	if sealed != "" {
		t.Fatal("admin_jwk_password_sealed not cleared after switching to x5c (stale secret lingers)")
	}
	if subj != "" || prov != "" {
		t.Fatalf("jwk subject/provisioner not cleared after switching to x5c: subj=%q prov=%q", subj, prov)
	}

	view, _, _ := repo.Get(ctx)
	if view.HasAdminJWK {
		t.Fatal("HasAdminJWK should be false after switching to x5c")
	}
	if view.AdminAuthMethod != settings.AdminAuthX5C {
		t.Fatalf("method = %q, want x5c", view.AdminAuthMethod)
	}
	if strings.Contains(renderAllFields(view), pass) {
		t.Fatal("JWK password leaked into the View after SaveAdminCredential")
	}
}
