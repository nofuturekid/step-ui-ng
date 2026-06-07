package settings_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/settings"
)

// Acceptance: select a JWK provisioner with password → persisted (sealed) and
// marked active; the sealed secret round-trips and plaintext is never exposed.
func TestSelectProvisionerSealsSecret(t *testing.T) {
	repo, st, box := newRepo(t)
	ctx := context.Background()
	const secret = "jwk-provisioner-password-123"

	// A base CA setting must exist first (select extends it).
	if err := repo.Save(ctx, settings.Input{
		CAURL: "https://ca.example", RootFingerprint: validFP,
	}); err != nil {
		t.Fatalf("Save base: %v", err)
	}

	if err := repo.SelectProvisioner(ctx, "admin-jwk", secret); err != nil {
		t.Fatalf("SelectProvisioner: %v", err)
	}

	// The view marks it active without exposing the secret.
	got, _, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SelectedProvisioner != "admin-jwk" {
		t.Fatalf("SelectedProvisioner = %q, want admin-jwk", got.SelectedProvisioner)
	}
	if !got.HasSelectedSecret {
		t.Fatal("HasSelectedSecret = false after selecting with a password")
	}
	if strings.Contains(renderAllFields(got), secret) {
		t.Fatal("the plaintext selected-provisioner secret leaked into the View")
	}

	// Defence in depth: the column is sealed and round-trips via the Box.
	var sealed string
	if err := st.DB().QueryRowContext(ctx,
		"SELECT selected_provisioner_secret_sealed FROM ca_settings WHERE id = 1").Scan(&sealed); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if sealed == "" || sealed == secret {
		t.Fatalf("selected secret not sealed at rest (got %q)", sealed)
	}
	opened, err := box.Open(sealed)
	if err != nil {
		t.Fatalf("Box.Open: %v", err)
	}
	if string(opened) != secret {
		t.Fatalf("sealed secret did not round-trip: %q", opened)
	}
}

// Selecting a provisioner without a secret (e.g. ACME) is allowed; the secret
// column is cleared.
func TestSelectProvisionerNoSecret(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.SelectProvisioner(ctx, "acme", ""); err != nil {
		t.Fatalf("SelectProvisioner: %v", err)
	}
	got, _, _ := repo.Get(ctx)
	if got.SelectedProvisioner != "acme" || got.HasSelectedSecret {
		t.Fatalf("got %+v, want acme with no secret", got)
	}
}

// Re-selecting with a new secret replaces the previous sealed value; selecting a
// different provisioner with an empty secret clears the old secret (the secret
// belongs to the provisioner, so it must not linger).
func TestSelectProvisionerReplacesSecret(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.SelectProvisioner(ctx, "p1", "first-secret-aaaa"); err != nil {
		t.Fatalf("select p1: %v", err)
	}
	if err := repo.SelectProvisioner(ctx, "p2", ""); err != nil {
		t.Fatalf("select p2: %v", err)
	}
	got, _, _ := repo.Get(ctx)
	if got.SelectedProvisioner != "p2" {
		t.Fatalf("SelectedProvisioner = %q, want p2", got.SelectedProvisioner)
	}
	if got.HasSelectedSecret {
		t.Fatal("old secret lingered after switching provisioners with an empty secret")
	}
}

// Re-selecting the SAME provisioner with a blank secret keeps the stored secret
// (mirrors the admin-secret "leave blank to keep" semantics). Only switching to a
// different provisioner clears it (TestSelectProvisionerReplacesSecret).
func TestSelectProvisionerKeepsSecretOnSameName(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.SelectProvisioner(ctx, "p1", "keep-me-secret-aaaa"); err != nil {
		t.Fatalf("select p1 with secret: %v", err)
	}
	// Re-select the same provisioner, leaving the secret blank.
	if err := repo.SelectProvisioner(ctx, "p1", ""); err != nil {
		t.Fatalf("re-select p1 blank: %v", err)
	}
	got, _, _ := repo.Get(ctx)
	if got.SelectedProvisioner != "p1" {
		t.Fatalf("SelectedProvisioner = %q, want p1", got.SelectedProvisioner)
	}
	if !got.HasSelectedSecret {
		t.Fatal("blank secret on the same provisioner must keep the stored secret")
	}
}

// SelectProvisioner requires an existing CA settings row (it extends it).
func TestSelectProvisionerRequiresSettings(t *testing.T) {
	repo, _, _ := newRepo(t)
	if err := repo.SelectProvisioner(context.Background(), "p", "secret"); err == nil {
		t.Fatal("SelectProvisioner without saved CA settings should error")
	}
}

// SaveAdminCredential seals the admin private key and stores the public cert
// chain in clear (it is public); the View reports HasAdminKey without exposing
// either the key or chain text where it would leak a secret.
func TestSaveAdminCredentialSealsKey(t *testing.T) {
	repo, st, box := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	const certPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	const keyPEM = "-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n"

	if err := repo.SaveAdminCredential(ctx, certPEM, keyPEM); err != nil {
		t.Fatalf("SaveAdminCredential: %v", err)
	}

	got, _, _ := repo.Get(ctx)
	if !got.HasAdminKey {
		t.Fatal("HasAdminKey = false after saving an admin key")
	}

	// The private key is sealed and round-trips; the column is not plaintext.
	var sealed, storedCert string
	if err := st.DB().QueryRowContext(ctx,
		"SELECT admin_key_sealed, admin_cert_pem FROM ca_settings WHERE id = 1").Scan(&sealed, &storedCert); err != nil {
		t.Fatalf("read columns: %v", err)
	}
	if sealed == "" || strings.Contains(sealed, "SECRETKEYMATERIAL") {
		t.Fatalf("admin key not sealed at rest (got %q)", sealed)
	}
	opened, err := box.Open(sealed)
	if err != nil {
		t.Fatalf("Box.Open: %v", err)
	}
	if string(opened) != keyPEM {
		t.Fatalf("admin key did not round-trip")
	}
	if storedCert != certPEM {
		t.Fatalf("admin cert chain not stored verbatim")
	}
}

// AdminCredential loads and decrypts the stored credential for use by the CA
// admin operations. It returns ok=false when none is configured.
func TestLoadAdminCredential(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()
	if err := repo.Save(ctx, settings.Input{CAURL: "https://ca.example", RootFingerprint: validFP}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, _, ok, err := repo.AdminCredential(ctx); err != nil || ok {
		t.Fatalf("AdminCredential with none set: ok=%v err=%v, want ok=false", ok, err)
	}

	const certPEM = "CERTCHAIN"
	const keyPEM = "PRIVATEKEY"
	if err := repo.SaveAdminCredential(ctx, certPEM, keyPEM); err != nil {
		t.Fatalf("SaveAdminCredential: %v", err)
	}
	cert, key, ok, err := repo.AdminCredential(ctx)
	if err != nil || !ok {
		t.Fatalf("AdminCredential: ok=%v err=%v", ok, err)
	}
	if cert != certPEM || key != keyPEM {
		t.Fatalf("AdminCredential returned cert=%q key=%q", cert, key)
	}
}
