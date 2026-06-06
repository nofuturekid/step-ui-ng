package app

// spec/0008 — revoke & renew handlers (admin+, behind auth + CSRF).
//
// Both actions act on a stored certificate identified by {id}. They resolve the
// CA connection + active provisioner (reusing resolveConn), call the certs
// domain (which performs the real CA round-trip), and re-render the detail view
// with a flash on success or a clear error on failure. Handlers stay thin: the
// guard rails (already-revoked, reason required), the CA call and the
// status-only-on-success atomicity all live in internal/certs.

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
	"github.com/nofuturekid/step-ui-ng/internal/certs"
	"github.com/nofuturekid/step-ui-ng/internal/config"
)

// postCertRevoke revokes the certificate at the CA by its serial with the
// supplied reason, after a typed confirmation (FR-3). On CA success the local
// status becomes 'revoked' and an audit event is recorded; on any CA failure the
// local row is left unchanged and the error is shown (FR-1 atomicity).
func (s *server) postCertRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := parseCertID(w, r)
	if !ok {
		return
	}
	actor := userFromContext(r.Context())

	// Require an explicit typed confirmation so a revoke is never accidental
	// (FR-3). The form's confirm field must equal the literal "REVOKE".
	if strings.TrimSpace(r.PostFormValue("confirm")) != "REVOKE" {
		s.renderDetailMsg(w, r, id, "", `Revocation not confirmed — type REVOKE to confirm.`)
		return
	}

	conn, msg := s.resolveConn(r)
	if msg != "" {
		s.renderDetailMsg(w, r, id, "", msg)
		return
	}

	err := s.certs.Revoke(r.Context(), certs.RevokeParams{
		Actor:           actor.Username,
		ID:              id,
		ProvisionerName: conn.provisioner,
		Password:        conn.password,
		CAURL:           conn.caURL,
		Fingerprint:     conn.fingerprint,
		Reason:          r.PostFormValue("reason"),
		ReasonCode:      parseReasonCode(r.PostFormValue("reason_code")),
	})
	if err != nil {
		s.renderDetailMsg(w, r, id, "", revokeErrorMessage(err))
		return
	}
	s.renderDetailMsg(w, r, id, "Certificate revoked at the CA.", "")
}

// postCertRenew re-issues a certificate for the same CN/SANs with the chosen
// validity (FR-2). The new cert is stored as a fresh inventory row with its
// sealed key and an audit event is recorded.
func (s *server) postCertRenew(w http.ResponseWriter, r *http.Request) {
	id, ok := parseCertID(w, r)
	if !ok {
		return
	}
	actor := userFromContext(r.Context())

	validity, err := parseValidity(r.PostFormValue("validity"))
	if err != nil {
		s.renderDetailMsg(w, r, id, "", "Validity must be a positive number of days.")
		return
	}

	conn, msg := s.resolveConn(r)
	if msg != "" {
		s.renderDetailMsg(w, r, id, "", msg)
		return
	}

	cert, err := s.certs.Renew(r.Context(), certs.RenewParams{
		Actor:           actor.Username,
		ID:              id,
		ProvisionerName: conn.provisioner,
		Password:        conn.password,
		CAURL:           conn.caURL,
		Fingerprint:     conn.fingerprint,
		ValidityDays:    validity,
	})
	if err != nil {
		s.renderDetailMsg(w, r, id, "", renewErrorMessage(err))
		return
	}
	// Redirect to the freshly-stored cert's detail view so the user sees the
	// renewed certificate (PoST/redirect/GET — avoids a resubmit on refresh).
	d := s.page(r, "Certificate — "+cert.CN)
	d.Flash = "Certificate renewed."
	s.renderCertDetail(w, r, cert.ID, d)
}

// parseCertID parses the {id} path value, writing a 400 and returning ok=false
// on failure.
func parseCertID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad certificate id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

// parseReasonCode parses an optional OCSP reason code; an empty/invalid value is
// 0 (unspecified).
func parseReasonCode(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// renderDetailMsg re-renders the certificate detail view with a flash or error
// message. It is used after a revoke/renew so the user stays on the same page
// and sees the outcome. A missing/not-found cert yields the usual 404.
func (s *server) renderDetailMsg(w http.ResponseWriter, r *http.Request, id int64, flash, errMsg string) {
	cert, err := s.certs.Get(r.Context(), id)
	if errors.Is(err, certs.ErrNotFound) {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	d := s.page(r, "Certificate — "+cert.CN)
	d.Flash = flash
	d.Error = errMsg
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusBadRequest
	}
	s.render(w, r, status, certDetailPage(d, certDetailView{Cert: cert, RenewDefaultDays: s.renewDefaultDays()}))
}

// renderCertDetail loads a cert and renders its detail view with the given page
// data (used by renew's success redirect-style render).
func (s *server) renderCertDetail(w http.ResponseWriter, r *http.Request, id int64, d pageData) {
	cert, err := s.certs.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, http.StatusOK, certDetailPage(d, certDetailView{Cert: cert, RenewDefaultDays: s.renewDefaultDays()}))
}

// renewDefaultDays returns the configured renew default, falling back to the
// package default if unset (e.g. a zero-value config in some tests).
func (s *server) renewDefaultDays() int {
	if s.cfg.RenewDefaultDays > 0 {
		return s.cfg.RenewDefaultDays
	}
	return config.DefaultRenewDays
}

// revokeErrorMessage maps a revoke failure to a clear, secret-free message.
func revokeErrorMessage(err error) string {
	switch {
	case errors.Is(err, certs.ErrAlreadyRevoked):
		return "This certificate is already revoked."
	case errors.Is(err, certs.ErrReasonRequired):
		return "A revocation reason is required."
	case errors.Is(err, certs.ErrNotFound):
		return "The certificate was not found."
	case errors.Is(err, ca.ErrRevokeFailed):
		return "The CA rejected the revoke request — the certificate was NOT revoked. Local status is unchanged."
	case errors.Is(err, ca.ErrRevokeInvalid):
		return "The revoke request was invalid (missing serial)."
	default:
		return caSignErrorMessage(err)
	}
}

// renewErrorMessage maps a renew failure to a clear message.
func renewErrorMessage(err error) string {
	if errors.Is(err, certs.ErrNotFound) {
		return "The certificate was not found."
	}
	return caSignErrorMessage(err)
}
