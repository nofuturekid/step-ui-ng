package app

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
	"github.com/nofuturekid/step-ui-ng/internal/settings"
)

// getSettings renders the CA-settings page (admin+). The admin secret is shown
// only as "set"/empty, never as a value (FR-5).
func (s *server) getSettings(w http.ResponseWriter, r *http.Request) {
	view, _, err := s.settings.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	d := s.page(r, "CA settings")
	d.Flash = s.sessions.PopString(r.Context(), flashKey)
	d.Error = s.sessions.PopString(r.Context(), errorKey)
	s.render(w, r, http.StatusOK, settingsPage(d, view))
}

// postSettings validates and saves the CA connection — CA URL + root fingerprint
// (FR-1, FR-4). An audit event is recorded on success (spec/0009 FR-2).
func (s *server) postSettings(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	in := settings.Input{
		CAURL:           r.PostFormValue("ca_url"),
		RootFingerprint: r.PostFormValue("root_fingerprint"),
	}
	if err := s.settings.Save(r.Context(), in); err != nil {
		s.sessions.Put(r.Context(), errorKey, settingsErrorMessage(err))
	} else {
		s.sessions.Put(r.Context(), flashKey, "CA settings saved.")
		// Details carry only non-secret fields; admin_secret is write-only and never logged.
		_ = s.audit.Record(r.Context(), actor.Username, "settings.update", "ca_settings",
			"ca_url="+in.CAURL)
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// postSettingsTest runs ca.TestConnection against the saved settings and renders
// an htmx-friendly result partial (FR-2). It never echoes secrets.
func (s *server) postSettingsTest(w http.ResponseWriter, r *http.Request) {
	view, ok, err := s.settings.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.render(w, r, http.StatusBadRequest,
			testResult(false, "No CA settings saved yet — save the connection first."))
		return
	}

	roots, err := ca.TestConnection(r.Context(), view.CAURL, view.RootFingerprint)
	if err != nil {
		s.render(w, r, http.StatusOK, testResult(false, testFailureMessage(err)))
		return
	}
	s.render(w, r, http.StatusOK, testSuccess(len(roots)))
}

// postAdminAuth saves the admin-authentication method and its material
// (spec/0012 FR-1/FR-2/FR-3). The method field selects "none", "x5c", or "jwk".
// For "jwk": subject, provisioner, and an optional password (leave blank to
// keep). For "x5c": an uploaded admin certificate chain + private key, validated
// (keypair match, digitalSignature, clientAuth EKU, non-empty CN) before the key
// is sealed. For "none": clears all admin credential material. An audit event is
// recorded on success — never with secrets.
func (s *server) postAdminAuth(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	method := strings.TrimSpace(r.PostFormValue("admin_auth_method"))

	var saveErr error
	switch settings.AdminAuthMethod(method) {
	case settings.AdminAuthJWK:
		subject := r.PostFormValue("admin_jwk_subject")
		provisioner := r.PostFormValue("admin_jwk_provisioner")
		password := r.PostFormValue("admin_jwk_password")
		saveErr = s.settings.SaveAdminJWK(r.Context(), subject, provisioner, password)
		if saveErr == nil {
			s.sessions.Put(r.Context(), flashKey, "Admin authentication saved (JWK).")
			// Password is write-only and never logged; only subject/prov are recorded.
			_ = s.audit.Record(r.Context(), actor.Username, "settings.admin_auth", "admin_auth",
				"method=jwk subject="+subject+" provisioner="+provisioner)
		}
	case settings.AdminAuthNone:
		saveErr = s.settings.SetAdminAuthNone(r.Context())
		if saveErr == nil {
			s.sessions.Put(r.Context(), flashKey, "Admin authentication cleared.")
			_ = s.audit.Record(r.Context(), actor.Username, "settings.admin_auth", "admin_auth", "method=none")
		}
	case settings.AdminAuthX5C:
		cert := strings.TrimSpace(r.PostFormValue("admin_x5c_cert"))
		key := strings.TrimSpace(r.PostFormValue("admin_x5c_key"))
		if cert == "" || key == "" {
			s.sessions.Put(r.Context(), errorKey, "Certificate and key are required for x5c authentication.")
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
		// Validate via NewAdminCredential (keypair match, digitalSignature, CN).
		if _, err := ca.NewAdminCredential([]byte(cert), []byte(key)); err != nil {
			s.sessions.Put(r.Context(), errorKey, x5cCredentialErrorMessage(err))
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
		// Additionally require clientAuth EKU (Step-CA's AuthorizeAdminToken checks it).
		if err := requireClientAuth(cert); err != nil {
			s.sessions.Put(r.Context(), errorKey, err.Error())
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
		saveErr = s.settings.SaveAdminCredential(r.Context(), cert, key)
		if saveErr == nil {
			// Audit: non-secret fields only — never log the key.
			leaf, _ := parseLeafCN(cert)
			s.sessions.Put(r.Context(), flashKey, "Admin authentication saved (x5c).")
			_ = s.audit.Record(r.Context(), actor.Username, "settings.admin_auth", "admin_auth",
				"method=x5c subject="+leaf)
		}
	default:
		// Unknown method: reject.
		s.sessions.Put(r.Context(), errorKey, "Unknown admin authentication method.")
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	if saveErr != nil {
		s.sessions.Put(r.Context(), errorKey, adminAuthErrorMessage(saveErr))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// adminAuthErrorMessage maps admin-auth save errors to user-facing text.
func adminAuthErrorMessage(err error) string {
	if errors.Is(err, settings.ErrNoSettings) {
		return "Save the CA connection first, then configure admin authentication."
	}
	msg := err.Error()
	if strings.Contains(msg, "subject and provisioner") {
		return "Both admin subject and provisioner name are required for JWK authentication."
	}
	return "Could not save admin authentication settings."
}

// settingsErrorMessage maps Save's validation errors to user-facing text.
func settingsErrorMessage(err error) string {
	switch {
	case errors.Is(err, settings.ErrInvalidURL):
		return "CA URL must start with http:// or https://."
	case errors.Is(err, settings.ErrInvalidFingerprint):
		return "Root fingerprint must be 40–64 hexadecimal characters."
	default:
		return "Could not save CA settings."
	}
}

// requireClientAuth checks that the leaf certificate in the PEM chain has the
// clientAuth (or any) extended key usage — Step-CA's AuthorizeAdminToken verifies
// the chain with the clientAuth EKU. It parses only the first CERTIFICATE block
// (the leaf).
func requireClientAuth(certChainPEM string) error {
	block, _ := pem.Decode([]byte(certChainPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid admin credential: cannot parse the certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid admin credential: parse leaf: %v", err)
	}
	for _, eku := range leaf.ExtKeyUsage {
		// ExtKeyUsageAny permits all usages (incl. clientAuth), so accept it too.
		if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageAny {
			return nil
		}
	}
	return fmt.Errorf("invalid admin credential: leaf certificate must have the clientAuth (or any) extended key usage (required by Step-CA)")
}

// parseLeafCN returns the Common Name of the first certificate in the PEM chain.
// On any error it returns an empty string (used for audit detail only).
func parseLeafCN(certChainPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certChainPEM))
	if block == nil {
		return "", fmt.Errorf("no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return leaf.Subject.CommonName, nil
}

// x5cCredentialErrorMessage maps a ca.ErrInvalidAdminCredential to a clear,
// secret-free message suitable for the flash error.
func x5cCredentialErrorMessage(err error) string {
	if errors.Is(err, ca.ErrInvalidAdminCredential) {
		return "Invalid admin credential: " + extractInvalidCredentialDetail(err)
	}
	return "Invalid admin credential."
}

// extractInvalidCredentialDetail extracts a human-readable detail from the
// ErrInvalidAdminCredential wrapped error text, without leaking key material.
func extractInvalidCredentialDetail(err error) string {
	msg := err.Error()
	// Strip the sentinel prefix so the user sees the useful part.
	const prefix = "ca: invalid admin credential: "
	if after, ok := strings.CutPrefix(msg, prefix); ok {
		return after
	}
	return "check that the certificate chain and private key match"
}

// testFailureMessage maps a ca.TestConnection error to a clear message (FR-2),
// never leaking secrets or raw internals.
func testFailureMessage(err error) string {
	switch {
	case errors.Is(err, ca.ErrFingerprintMismatch):
		return "The CA's root certificate does not match the configured fingerprint."
	case errors.Is(err, ca.ErrUnreachable):
		return "Could not reach the CA at the configured URL."
	case errors.Is(err, ca.ErrBadTLS):
		return "TLS verification against the pinned root failed."
	case errors.Is(err, ca.ErrMalformedResponse):
		return "The CA returned an unexpected response."
	case errors.Is(err, ca.ErrInvalidFingerprint):
		return "The configured fingerprint is not valid."
	default:
		return "Connection test failed."
	}
}
