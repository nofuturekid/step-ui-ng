package ca

// AdminAuth is the credential-source abstraction (ADR-0018, spec/0012 FR-4):
// a factory that yields a ready-to-use AdminCredential (cert chain + signer)
// regardless of where the credential comes from. Two implementations:
//
//   - x5cStored  — wraps a pre-loaded cert chain + private key (the uploaded PEM
//     material from SaveAdminCredential).
//   - jwkMinted  — mints a short-lived admin cert on demand by decrypting the JWK
//     provisioner's encryptedKey with the sealed password, signing a provisioner
//     OTT, and calling POST /1.0/sign.  The minted cert+key live only in memory.
//
// Both feed the unchanged generateAdminToken (x5c) path.  Callers should obtain
// the credential once per admin operation, not across requests.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// AdminAuth yields a ready AdminCredential for one admin operation.
type AdminAuth interface {
	// Credential returns a usable AdminCredential.  The caller must treat the
	// returned value as short-lived (it may be an ephemeral minted cert).
	Credential(ctx context.Context) (AdminCredential, error)
}

// x5cStored wraps a pre-parsed AdminCredential that was loaded from stored
// (sealed) PEM material.  Credential returns it directly.
type x5cStored struct {
	cred AdminCredential
}

// X5CStored returns an AdminAuth that returns the given AdminCredential directly.
// Use this when the cert chain + key come from SaveAdminCredential.
func X5CStored(cred AdminCredential) AdminAuth {
	return x5cStored{cred: cred}
}

// Credential implements AdminAuth.
func (s x5cStored) Credential(_ context.Context) (AdminCredential, error) {
	return s.cred, nil
}

// JWKMintedParams holds the configuration for the JWK-based credential source.
// Password is the plaintext provisioner password (decrypted from sealed storage
// by the caller); it is used only in memory and never logged.
type JWKMintedParams struct {
	CAURL           string
	Fingerprint     string
	ProvisionerName string
	Password        string // plaintext; never logged or returned
	Subject         string // admin subject (CN + DNS SAN of the minted cert)
}

// jwkMinted mints a short-lived admin certificate on demand.
type jwkMinted struct {
	p JWKMintedParams
}

// JWKMinted returns an AdminAuth that mints an ephemeral admin cert from the
// JWK provisioner password each time Credential is called (ADR-0018 FR-3).
func JWKMinted(p JWKMintedParams) AdminAuth {
	return &jwkMinted{p: p}
}

// Credential mints a short-lived admin certificate via the JWK provisioner:
//  1. Generate an ephemeral EC P-256 key.
//  2. Build a CSR with CN=Subject and DNS SAN=Subject.
//  3. Call SignCSR (OTT → POST /1.0/sign) to obtain the cert.
//  4. Wrap the result into a NewAdminCredential.
//
// Wrong password surfaces as ErrProvisionerKey (from SignCSR → decryptSigningKey).
// The password and ephemeral key are never logged or returned.
func (m *jwkMinted) Credential(ctx context.Context) (AdminCredential, error) {
	if m.p.Subject == "" {
		return AdminCredential{}, fmt.Errorf("%w: JWK minted credential requires a non-empty admin subject", ErrInvalidAdminCredential)
	}

	// 1. Ephemeral P-256 key.
	ephKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("%w: generate ephemeral key: %v", ErrInvalidAdminCredential, err)
	}

	// 2. CSR: CN and DNS SAN both set to the admin subject (step-ca accepts this).
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: m.p.Subject},
		DNSNames: []string{m.p.Subject},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, ephKey)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("%w: create CSR: %v", ErrInvalidAdminCredential, err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// Key PEM for NewAdminCredential.
	keyDER, err := x509.MarshalPKCS8PrivateKey(ephKey)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("%w: marshal ephemeral key: %v", ErrInvalidAdminCredential, err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	// 3. Sign the CSR via the JWK provisioner OTT (reuses the proven sign flow).
	// ValidityDays=0 → let the CA apply its default; the minted cert only lives
	// in memory for one operation anyway.
	res, err := SignCSR(ctx, SignParams{
		CAURL:           m.p.CAURL,
		Fingerprint:     m.p.Fingerprint,
		ProvisionerName: m.p.ProvisionerName,
		Password:        m.p.Password, // never logged inside SignCSR
		CSRPEM:          csrPEM,
		ValidityDays:    0,
	})
	if err != nil {
		// ErrProvisionerKey already surfaces a wrong password; propagate as-is.
		return AdminCredential{}, err
	}

	// 4. Build the AdminCredential from the minted cert chain + ephemeral key.
	cred, err := NewAdminCredential([]byte(res.FullchainPEM), []byte(keyPEM))
	if err != nil {
		return AdminCredential{}, fmt.Errorf("%w: build admin credential from minted cert: %v", ErrInvalidAdminCredential, err)
	}
	return cred, nil
}
