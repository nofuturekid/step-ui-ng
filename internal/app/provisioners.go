package app

import (
	"errors"
	"net/http"
	"strings"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
	"github.com/nofuturekid/step-ui-ng/internal/settings"
)

// provisionersView is the data the provisioners page renders: the CA-listed
// provisioners (with a flag marking the selected one), the selected name, and
// whether an admin credential is configured (gates the create/delete controls).
// listErr carries a non-fatal message when the CA could not be listed.
type provisionersView struct {
	Provisioners []provisionerRow
	Selected     string
	HasAdminCred bool
	CASettings   bool
	ListError    string
}

type provisionerRow struct {
	Name   string
	Type   string
	Active bool
}

// getProvisioners lists the CA's provisioners (FR-1) and renders the page
// (admin+). Listing needs no admin token; a CA/list failure is shown inline
// rather than failing the page.
func (s *server) getProvisioners(w http.ResponseWriter, r *http.Request) {
	view, ok, err := s.settings.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	d := s.page(r, "Provisioners")
	d.Flash = s.sessions.PopString(r.Context(), flashKey)
	d.Error = s.sessions.PopString(r.Context(), errorKey)

	pv := provisionersView{
		Selected:     view.SelectedProvisioner,
		HasAdminCred: view.HasAdminKey,
		CASettings:   ok,
	}
	if !ok {
		pv.ListError = "Configure the CA connection first (CA settings)."
		s.render(w, r, http.StatusOK, provisionersPage(d, pv))
		return
	}

	list, err := ca.ListProvisioners(r.Context(), view.CAURL, view.RootFingerprint)
	if err != nil {
		pv.ListError = provisionerListErrorMessage(err)
	}
	for _, p := range list {
		pv.Provisioners = append(pv.Provisioners, provisionerRow{
			Name:   p.Name,
			Type:   p.Type,
			Active: p.Name == view.SelectedProvisioner,
		})
	}
	s.render(w, r, http.StatusOK, provisionersPage(d, pv))
}

// postProvisionerSelect persists the active provisioner + sealed secret (FR-2).
// An audit event is recorded on success (spec/0009 FR-2).
func (s *server) postProvisionerSelect(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	name := r.PostFormValue("name")
	secret := r.PostFormValue("secret")
	if err := s.settings.SelectProvisioner(r.Context(), name, secret); err != nil {
		s.sessions.Put(r.Context(), errorKey, provisionerSelectErrorMessage(err))
	} else {
		s.sessions.Put(r.Context(), flashKey, "Active provisioner updated.")
		// Secret is write-only and never logged; only the name is recorded.
		_ = s.audit.Record(r.Context(), actor.Username, "provisioner.select", name, "")
	}
	http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
}

// postProvisioners creates a provisioner via the admin API (FR-3). It validates
// inputs in the ca package, signs an admin token from the stored credential, and
// surfaces a clear flash on success or failure (never leaking secrets).
func (s *server) postProvisioners(w http.ResponseWriter, r *http.Request) {
	view, ok, err := s.settings.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.sessions.Put(r.Context(), errorKey, "Configure the CA connection first.")
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}

	cred, credOK, err := s.adminCredential(r)
	if err != nil {
		s.sessions.Put(r.Context(), errorKey, "Could not load the admin credential.")
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}
	if !credOK {
		s.sessions.Put(r.Context(), errorKey, "No admin credential configured — add an admin certificate and key to manage provisioners.")
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}

	actor := userFromContext(r.Context())
	spec := ca.NewProvisionerSpec{
		Name:      r.PostFormValue("name"),
		Type:      r.PostFormValue("type"),
		JWKSecret: r.PostFormValue("secret"),
	}
	if _, err := ca.CreateProvisioner(r.Context(), view.CAURL, view.RootFingerprint, cred, spec); err != nil {
		s.sessions.Put(r.Context(), errorKey, provisionerCreateErrorMessage(err))
	} else {
		s.sessions.Put(r.Context(), flashKey, "Provisioner created.")
		// JWK secret is write-only and never logged.
		_ = s.audit.Record(r.Context(), actor.Username, "provisioner.create", spec.Name,
			"type="+spec.Type)
	}
	http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
}

// postProvisioner handles per-provisioner actions (currently delete) addressed
// by name (FR-4). Deleting the currently selected provisioner is refused with a
// clear error before any CA call.
func (s *server) postProvisioner(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if r.PostFormValue("action") != "delete" {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	view, ok, err := s.settings.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.sessions.Put(r.Context(), errorKey, "Configure the CA connection first.")
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}

	// FR-4 guard: refuse to delete the active provisioner.
	if name == view.SelectedProvisioner {
		s.sessions.Put(r.Context(), errorKey, "Cannot delete the active provisioner — select a different one first.")
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}

	cred, credOK, err := s.adminCredential(r)
	if err != nil {
		s.sessions.Put(r.Context(), errorKey, "Could not load the admin credential.")
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}
	if !credOK {
		s.sessions.Put(r.Context(), errorKey, "No admin credential configured — add an admin certificate and key to manage provisioners.")
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}

	actor := userFromContext(r.Context())
	if err := ca.DeleteProvisioner(r.Context(), view.CAURL, view.RootFingerprint, cred, name); err != nil {
		s.sessions.Put(r.Context(), errorKey, provisionerCreateErrorMessage(err))
	} else {
		s.sessions.Put(r.Context(), flashKey, "Provisioner deleted.")
		_ = s.audit.Record(r.Context(), actor.Username, "provisioner.delete", name, "")
	}
	http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
}

// adminCredential loads the stored admin credential and parses it into a
// ca.AdminCredential ready for signing. ok is false when none is configured. The
// plaintext key never leaves this function except inside the AdminCredential.
func (s *server) adminCredential(r *http.Request) (ca.AdminCredential, bool, error) {
	certPEM, keyPEM, ok, err := s.settings.AdminCredential(r.Context())
	if err != nil || !ok {
		return ca.AdminCredential{}, false, err
	}
	cred, err := ca.NewAdminCredential([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return ca.AdminCredential{}, false, err
	}
	return cred, true, nil
}

// provisionerListErrorMessage maps a list failure to a clear, secret-free
// message.
func provisionerListErrorMessage(err error) string {
	switch {
	case errors.Is(err, ca.ErrFingerprintMismatch):
		return "The CA's root certificate does not match the configured fingerprint."
	case errors.Is(err, ca.ErrUnreachable):
		return "Could not reach the CA at the configured URL."
	case errors.Is(err, ca.ErrBadTLS):
		return "TLS verification against the pinned root failed."
	case errors.Is(err, ca.ErrMalformedResponse):
		return "The CA returned an unexpected response."
	default:
		return "Could not list provisioners."
	}
}

// provisionerSelectErrorMessage maps a select failure to a clear message.
func provisionerSelectErrorMessage(err error) string {
	if errors.Is(err, settings.ErrNoSettings) {
		return "Configure the CA connection first."
	}
	return "Could not select the provisioner."
}

// provisionerCreateErrorMessage maps create/delete failures to clear messages.
func provisionerCreateErrorMessage(err error) string {
	switch {
	case errors.Is(err, ca.ErrInvalidProvisioner):
		return provisionerValidationMessage(err)
	case errors.Is(err, ca.ErrAdminUnauthorized):
		return "The CA rejected the admin credential (unauthorized). Check the admin certificate and key."
	case errors.Is(err, ca.ErrInvalidAdminCredential):
		return "The stored admin credential is invalid."
	case errors.Is(err, ca.ErrFingerprintMismatch):
		return "The CA's root certificate does not match the configured fingerprint."
	case errors.Is(err, ca.ErrUnreachable):
		return "Could not reach the CA at the configured URL."
	case errors.Is(err, ca.ErrBadTLS):
		return "TLS verification against the pinned root failed."
	case errors.Is(err, ca.ErrAdminRequestFailed):
		return "The CA could not complete the request."
	default:
		return "The provisioner operation failed."
	}
}

// provisionerValidationMessage turns a ca.ErrInvalidProvisioner into a
// field-specific hint (the ca error text already names name/type/secret).
func provisionerValidationMessage(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "name"):
		return "Invalid name — use letters, digits, dot, underscore or hyphen."
	case strings.Contains(msg, "type"):
		return "Invalid type — choose JWK, ACME or SSHPOP."
	case strings.Contains(msg, "secret"):
		return "The JWK secret must be at least 8 characters."
	default:
		return "Invalid provisioner details."
	}
}
