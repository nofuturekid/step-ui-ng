package app

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/a-h/templ"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
	"github.com/nofuturekid/step-ui-ng/internal/certs"
)

// issueView carries the issue form's prior input (so a failed submit is
// repopulated) and the rendered result of a successful issue.
type issueView struct {
	CN       string
	SANs     string
	Validity string
	Format   string
	Result   *certs.Certificate
}

// signView carries the sign-csr form's prior input and the result.
type signView struct {
	CSR      string
	Validity string
	Result   *certs.Certificate
}

// getIssue renders the issue form (admin+).
func (s *server) getIssue(w http.ResponseWriter, r *http.Request) {
	d := s.page(r, "Issue certificate")
	d.ActiveSection = "/issue"
	s.render(w, r, http.StatusOK, issuePage(d, issueView{Validity: "30", Format: "pem"}))
}

// postIssue generates a keypair, requests a certificate from the CA via the
// active provisioner OTT, stores it, and renders the result. Validation and CA
// errors are shown clearly (FR-5). The certificate is attributed to the session
// user in the audit log (FR-4).
func (s *server) postIssue(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	view := issueView{
		CN:       strings.TrimSpace(r.PostFormValue("cn")),
		SANs:     r.PostFormValue("sans"),
		Validity: r.PostFormValue("validity"),
		Format:   r.PostFormValue("format"),
	}

	conn, ok := s.issuanceConn(w, r, &view)
	if !ok {
		return
	}

	validity, err := parseValidity(view.Validity)
	if err != nil {
		s.renderIssueError(w, r, view, "Validity must be a positive number of days.")
		return
	}
	format := certs.FormatPEM
	if view.Format == string(certs.FormatPFX) {
		format = certs.FormatPFX
	}

	cert, err := s.certs.Issue(r.Context(), certs.IssueParams{
		Actor:           actor.Username,
		ProvisionerName: conn.provisioner,
		Password:        conn.password,
		CAURL:           conn.caURL,
		Fingerprint:     conn.fingerprint,
		CN:              view.CN,
		SANs:            splitSANs(view.SANs),
		ValidityDays:    validity,
		Format:          format,
		PFXPassword:     r.PostFormValue("pfx_password"),
	})
	if err != nil {
		s.renderIssueError(w, r, view, issueErrorMessage(err))
		return
	}

	d := s.page(r, "Issue certificate")
	d.ActiveSection = "/issue"
	d.Flash = "Certificate issued."
	view.Result = &cert
	// The result carries freshly-generated key material (PEM key or PFX). Mark the
	// response non-cacheable so the private key is not retained by the browser or
	// any intermediary (it is delivered exactly once, never retrievable later).
	if hasKeyMaterial(cert) {
		noStore(w)
	}
	s.render(w, r, http.StatusOK, issuePage(d, view))
}

// hasKeyMaterial reports whether the result carries freshly-generated private key
// material (PEM key or PFX) that must not be cached.
func hasKeyMaterial(c certs.Certificate) bool {
	return c.PrivateKeyPEM != "" || len(c.PFX) > 0
}

// noStore marks a response as non-cacheable so key-bearing pages are never
// retained by the browser, a back/forward cache, or an intermediary.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// getSignCSR renders the sign-csr form (admin+).
func (s *server) getSignCSR(w http.ResponseWriter, r *http.Request) {
	d := s.page(r, "Sign CSR")
	d.ActiveSection = "/sign-csr"
	s.render(w, r, http.StatusOK, signCSRPage(d, signView{Validity: "30"}))
}

// postSignCSR parses + verifies the submitted CSR, requests a certificate via the
// active provisioner OTT, stores it (no private key), and renders the result.
func (s *server) postSignCSR(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	view := signView{
		CSR:      r.PostFormValue("csr"),
		Validity: r.PostFormValue("validity"),
	}

	conn, ok := s.signConn(w, r, &view)
	if !ok {
		return
	}

	validity, err := parseValidity(view.Validity)
	if err != nil {
		s.renderSignError(w, r, view, "Validity must be a positive number of days.")
		return
	}

	cert, err := s.certs.Sign(r.Context(), certs.SignParams{
		Actor:           actor.Username,
		ProvisionerName: conn.provisioner,
		Password:        conn.password,
		CAURL:           conn.caURL,
		Fingerprint:     conn.fingerprint,
		CSRPEM:          view.CSR,
		ValidityDays:    validity,
	})
	if err != nil {
		s.renderSignError(w, r, view, signErrorMessage(err))
		return
	}

	d := s.page(r, "Sign CSR")
	d.ActiveSection = "/sign-csr"
	d.Flash = "Certificate signed."
	view.Result = &cert
	s.render(w, r, http.StatusOK, signCSRPage(d, view))
}

// issuanceConn bundles the CA connection + active provisioner needed to issue.
type issuanceConn struct {
	caURL       string
	fingerprint string
	provisioner string
	password    string
}

// issuanceConn resolves CA settings + the selected provisioner secret, rendering
// a clear 400 on the issue page if anything is missing (FR-5). ok is false when
// the caller should stop.
func (s *server) issuanceConn(w http.ResponseWriter, r *http.Request, view *issueView) (issuanceConn, bool) {
	conn, msg := s.resolveConn(r)
	if msg != "" {
		s.renderIssueError(w, r, *view, msg)
		return issuanceConn{}, false
	}
	return conn, true
}

// signConn is the same as issuanceConn but renders errors on the sign page.
func (s *server) signConn(w http.ResponseWriter, r *http.Request, view *signView) (issuanceConn, bool) {
	conn, msg := s.resolveConn(r)
	if msg != "" {
		s.renderSignError(w, r, *view, msg)
		return issuanceConn{}, false
	}
	return conn, true
}

// resolveConn loads the CA settings and the selected provisioner + its secret.
// It returns a non-empty message when issuance cannot proceed (no settings, no
// provisioner selected, or no secret for it).
func (s *server) resolveConn(r *http.Request) (issuanceConn, string) {
	view, ok, err := s.settings.Get(r.Context())
	if err != nil {
		return issuanceConn{}, "Could not load the CA settings."
	}
	if !ok {
		return issuanceConn{}, "Configure the CA connection first (CA settings)."
	}
	if view.SelectedProvisioner == "" {
		return issuanceConn{}, "Select an active provisioner first (Provisioners)."
	}
	secret, ok, err := s.settings.SelectedSecret(r.Context())
	if err != nil {
		return issuanceConn{}, "Could not load the provisioner secret."
	}
	if !ok {
		return issuanceConn{}, "The active provisioner has no stored secret — set it on the Provisioners page."
	}
	return issuanceConn{
		caURL:       view.CAURL,
		fingerprint: view.RootFingerprint,
		provisioner: view.SelectedProvisioner,
		password:    secret,
	}, ""
}

// renderIssueError re-renders the issue form with the prior input and an error.
func (s *server) renderIssueError(w http.ResponseWriter, r *http.Request, view issueView, msg string) {
	d := s.page(r, "Issue certificate")
	d.ActiveSection = "/issue"
	d.Error = msg
	s.render(w, r, http.StatusBadRequest, issuePage(d, view))
}

// renderSignError re-renders the sign form with the prior input and an error.
func (s *server) renderSignError(w http.ResponseWriter, r *http.Request, view signView, msg string) {
	d := s.page(r, "Sign CSR")
	d.ActiveSection = "/sign-csr"
	d.Error = msg
	s.render(w, r, http.StatusBadRequest, signCSRPage(d, view))
}

// parseValidity parses a positive day count; 0/empty is rejected so the request
// carries an explicit bound.
func parseValidity(raw string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return 0, errors.New("invalid validity")
	}
	return n, nil
}

// joinSANs renders a SAN list for display.
func joinSANs(sans []string) string { return strings.Join(sans, ", ") }

// splitSANs splits a comma/newline/space-separated SAN list into trimmed,
// non-empty entries.
func splitSANs(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	var out []string
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// issueErrorMessage maps an issue failure to a clear, secret-free message (FR-5).
func issueErrorMessage(err error) string {
	switch {
	case errors.Is(err, certs.ErrInvalidInput):
		return "Check the inputs: a common name is required (and a PFX password for the PKCS#12 format)."
	default:
		return caSignErrorMessage(err)
	}
}

// signErrorMessage maps a sign failure to a clear message (FR-5).
func signErrorMessage(err error) string {
	if errors.Is(err, certs.ErrInvalidCSR) {
		return "The CSR could not be parsed or its signature did not verify. Paste a valid PEM CSR."
	}
	return caSignErrorMessage(err)
}

// pfxDataURI returns a trusted data: URL carrying the base64-encoded PFX so the
// binary bundle can be offered as a one-shot download link (a textarea cannot
// hold binary). It is a SafeURL because the content is self-generated, not user
// input — templ's URL sanitizer otherwise rejects the data: scheme.
func pfxDataURI(pfx []byte) templ.SafeURL {
	return templ.SafeURL("data:application/x-pkcs12;base64," + base64.StdEncoding.EncodeToString(pfx))
}

// pemKeyDataURI returns a trusted data: URL carrying the base64-encoded PEM
// private key so it can be saved as a file in addition to the on-page textarea.
func pemKeyDataURI(keyPEM string) templ.SafeURL {
	return templ.SafeURL("data:application/x-pem-file;base64," + base64.StdEncoding.EncodeToString([]byte(keyPEM)))
}

// pfxFilename builds a safe download filename for the PFX bundle from the CN.
func pfxFilename(cn string) string { return downloadName(cn) + ".pfx" }

// keyFilename builds a safe download filename for the PEM private key from the CN.
func keyFilename(cn string) string { return downloadName(cn) + ".key.pem" }

// downloadName sanitizes a CN into a filesystem/header-safe base name, falling
// back to "certificate" when nothing usable remains.
func downloadName(cn string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_':
			return r
		default:
			return '_'
		}
	}, strings.TrimSpace(cn))
	safe = strings.Trim(safe, "._-")
	if safe == "" {
		return "certificate"
	}
	return safe
}

// caSignErrorMessage maps the shared CA-layer sign errors to messages.
func caSignErrorMessage(err error) string {
	switch {
	case errors.Is(err, ca.ErrSignRejected):
		return "The CA rejected the request — the validity may exceed the provisioner's maximum, or the request violates a policy."
	case errors.Is(err, ca.ErrProvisionerNotFound):
		return "The active provisioner was not found on the CA. Re-check the selection."
	case errors.Is(err, ca.ErrProvisionerKey):
		return "Could not use the provisioner key — the stored provisioner secret is likely wrong."
	case errors.Is(err, ca.ErrFingerprintMismatch):
		return "The CA's root certificate does not match the configured fingerprint."
	case errors.Is(err, ca.ErrUnreachable):
		return "Could not reach the CA at the configured URL."
	case errors.Is(err, ca.ErrBadTLS):
		return "TLS verification against the pinned root failed."
	case errors.Is(err, ca.ErrInvalidCSR):
		return "The CSR was rejected as invalid."
	default:
		return "The certificate operation failed."
	}
}
