package app

import (
	"context"
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
	Provisioners      []provisionerRow
	Selected          string
	HasSelectedSecret bool // a secret is stored for the active provisioner
	HasAdminCred      bool
	CASettings        bool
	ListError         string
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
		Selected:          view.SelectedProvisioner,
		HasSelectedSecret: view.HasSelectedSecret,
		HasAdminCred:      viewHasAdminAuth(view),
		CASettings:        ok,
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

	auth, authOK, err := s.adminAuth(r.Context(), view)
	if err != nil {
		s.sessions.Put(r.Context(), errorKey, "Could not load the admin credential.")
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}
	if !authOK {
		s.sessions.Put(r.Context(), errorKey, adminAuthMissingMessage())
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}
	cred, err := auth.Credential(r.Context())
	if err != nil {
		s.sessions.Put(r.Context(), errorKey, provisionerCreateErrorMessage(err))
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

	auth, authOK, err := s.adminAuth(r.Context(), view)
	if err != nil {
		s.sessions.Put(r.Context(), errorKey, "Could not load the admin credential.")
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}
	if !authOK {
		s.sessions.Put(r.Context(), errorKey, adminAuthMissingMessage())
		http.Redirect(w, r, "/provisioners", http.StatusSeeOther)
		return
	}
	cred, err := auth.Credential(r.Context())
	if err != nil {
		s.sessions.Put(r.Context(), errorKey, provisionerCreateErrorMessage(err))
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

// adminAuth builds an ca.AdminAuth from the configured admin-auth method.
// ok is false when no admin auth is configured (method=none or not set).
// The plaintext key/password never escapes this function except inside the
// returned AdminAuth.
func (s *server) adminAuth(ctx context.Context, view settings.View) (ca.AdminAuth, bool, error) {
	switch view.AdminAuthMethod {
	case settings.AdminAuthX5C:
		certPEM, keyPEM, ok, err := s.settings.AdminCredential(ctx)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}
		cred, err := ca.NewAdminCredential([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, false, err
		}
		return ca.X5CStored(cred), true, nil

	case settings.AdminAuthJWK:
		password, ok, err := s.settings.AdminJWKPassword(ctx)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}
		return ca.JWKMinted(ca.JWKMintedParams{
			CAURL:           view.CAURL,
			Fingerprint:     view.RootFingerprint,
			ProvisionerName: view.AdminJWKProvisioner,
			Password:        password, // plaintext; never logged
			Subject:         view.AdminJWKSubject,
		}), true, nil

	default:
		return nil, false, nil
	}
}

// viewHasAdminAuth reports whether the View has a *usable* admin-auth method —
// the method is set AND its secret material is present. This drives the
// HasAdminCred gate in all pages. Gating on the method label alone would render
// the controls enabled for, e.g., method=jwk with no stored password, while
// every action then fails closed (a confusing footgun).
func viewHasAdminAuth(v settings.View) bool {
	switch v.AdminAuthMethod {
	case settings.AdminAuthX5C:
		return v.HasAdminKey
	case settings.AdminAuthJWK:
		return v.HasAdminJWK
	default:
		return false
	}
}

// adminAuthMissingMessage returns the honest FR-6 hint when no admin auth is
// configured, naming both options and the CLI alternative.
func adminAuthMissingMessage() string {
	return "No admin authentication configured — configure it on the CA settings page (x5c or JWK), or use the Step CLI directly."
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
	case errors.Is(err, ca.ErrProvisionerKey):
		return "Could not decrypt the JWK provisioner key — check the admin password."
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
