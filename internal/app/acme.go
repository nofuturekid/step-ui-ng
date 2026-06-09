package app

// ACME enablement handlers (spec/0010): manage ACME provisioners and their EAB
// keys, show directory URLs and client snippets. All routes are admin+, behind
// auth + CSRF. CA admin operations sign an x5c admin token from the stored admin
// credential (reused from spec/0005). The EAB HMAC is shown EXACTLY ONCE on
// creation: it is never persisted, never logged, never written to an audit row,
// and the one-time display response carries Cache-Control: no-store.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
	"github.com/nofuturekid/step-ui-ng/internal/settings"
)

// acmeHasAdminAuth reports whether ACME management controls should be enabled
// for the given settings View, using the unified admin-auth method.
func acmeHasAdminAuth(v settings.View) bool { return viewHasAdminAuth(v) }

// acmeChallengeChoices are the challenge types the UI offers (FR-1). Ordered for
// a stable form render.
//
// device-attest-01 is deliberately NOT offered here even though the CA layer's
// validator accepts it (ca.validACMEChallenge): it is only meaningful with
// attestation roots/formats configured on the provisioner, which this UI does not
// manage, so surfacing it as a bare checkbox would let an admin enable a challenge
// that cannot complete. It is omitted by intent, not silently dropped.
var acmeChallengeChoices = []string{"http-01", "dns-01", "tls-alpn-01"}

// acmeView is the data the /acme list page renders: the ACME provisioners with
// their directory URLs, plus whether an admin credential is configured (gates the
// create/edit/delete controls). ListError carries a non-fatal CA-list message.
type acmeView struct {
	Provisioners []acmeProvRow
	HasAdminCred bool
	CASettings   bool
	ListError    string
	Challenges   []string
}

type acmeProvRow struct {
	Name         string
	DirectoryURL string
	// Challenges + RequireEAB carry the provisioner's CURRENT ACME options so the
	// inline edit form is pre-filled from real state and an edit can merge rather
	// than clobber unspecified fields (spec/0010). Challenges holds the friendly
	// names (e.g. "dns-01"); empty means the CA's default set.
	Challenges []string
	RequireEAB bool
}

// getACME lists the CA's ACME provisioners with their directory URLs (FR-1/FR-3).
// Listing needs no admin token; a CA failure is shown inline.
func (s *server) getACME(w http.ResponseWriter, r *http.Request) {
	view, ok, err := s.settings.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	d := s.page(r, "ACME")
	d.Flash = s.sessions.PopString(r.Context(), flashKey)
	d.Error = s.sessions.PopString(r.Context(), errorKey)

	av := acmeView{
		HasAdminCred: acmeHasAdminAuth(view),
		CASettings:   ok,
		Challenges:   acmeChallengeChoices,
	}
	if !ok {
		av.ListError = "Configure the CA connection first (CA settings)."
		s.render(w, r, http.StatusOK, acmePage(d, av))
		return
	}

	list, err := ca.ListACMEProvisioners(r.Context(), view.CAURL, view.RootFingerprint)
	if err != nil {
		av.ListError = provisionerListErrorMessage(err)
	}
	for _, p := range list {
		av.Provisioners = append(av.Provisioners, acmeProvRow{
			Name:         p.Name,
			DirectoryURL: ca.DirectoryURL(view.CAURL, p.Name),
			Challenges:   p.Challenges,
			RequireEAB:   p.RequireEAB,
		})
	}
	s.render(w, r, http.StatusOK, acmePage(d, av))
}

// postACMEProvisioners creates an ACME provisioner with the chosen challenges and
// requireEAB flag via the admin API (FR-1). Audited on success (FR-5).
func (s *server) postACMEProvisioners(w http.ResponseWriter, r *http.Request) {
	view, cred, ok := s.acmeAdminContext(w, r)
	if !ok {
		return
	}

	actor := userFromContext(r.Context())
	name := r.PostFormValue("name")
	challenges := r.Form["challenge"]
	requireEAB := r.PostFormValue("require_eab") == "on"
	spec := ca.NewProvisionerSpec{
		Name:           name,
		Type:           "ACME",
		ACMEChallenges: challenges,
		ACMERequireEAB: requireEAB,
	}
	if _, err := ca.CreateProvisioner(r.Context(), view.CAURL, view.RootFingerprint, cred, spec); err != nil {
		s.sessions.Put(r.Context(), errorKey, provisionerCreateErrorMessage(err))
	} else {
		s.sessions.Put(r.Context(), flashKey, "ACME provisioner created.")
		_ = s.audit.Record(r.Context(), actor.Username, "acme.provisioner.create", name,
			acmeAuditDetails(challenges, requireEAB))
	}
	http.Redirect(w, r, "/acme", http.StatusSeeOther)
}

// postACMEProvisioner handles per-provisioner actions addressed by name: edit
// (update options) and delete-via-action (FR-1). The verb is tunnelled through an
// "action" form field to keep HTML forms + nosurf CSRF (spec/0005 reconciliation).
func (s *server) postACMEProvisioner(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	action := r.PostFormValue("action")
	if action != "delete" && action != "edit" {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	view, cred, ok := s.acmeAdminContext(w, r)
	if !ok {
		return
	}
	actor := userFromContext(r.Context())

	if action == "delete" {
		if err := ca.DeleteProvisioner(r.Context(), view.CAURL, view.RootFingerprint, cred, name); err != nil {
			s.sessions.Put(r.Context(), errorKey, provisionerCreateErrorMessage(err))
		} else {
			s.sessions.Put(r.Context(), flashKey, "ACME provisioner deleted.")
			_ = s.audit.Record(r.Context(), actor.Username, "acme.provisioner.delete", name, "")
		}
		http.Redirect(w, r, "/acme", http.StatusSeeOther)
		return
	}

	// Merge the edit onto the provisioner's CURRENT state so an admin changing one
	// option does not silently clear the others (spec/0010). A PUT replaces the
	// details wholesale, and HTML checkboxes submit nothing when unchecked — so an
	// unsubmitted field is ambiguous between "set false" and "not edited". We
	// resolve it by starting from the real current state and only overriding the
	// fields the form actually carried:
	//   - challenges: present iff the form sent any "challenge" value; else keep
	//     the current set.
	//   - requireEAB: present iff the form sent the "require_eab_present" marker
	//     (the rendered edit form always does); else keep the current value.
	current := s.currentACMEOptions(r, view, name)
	challenges := current.Challenges
	if _, edited := r.Form["challenge"]; edited {
		challenges = r.Form["challenge"]
	}
	requireEAB := current.RequireEAB
	if r.PostFormValue("require_eab_present") != "" {
		requireEAB = r.PostFormValue("require_eab") == "on"
	}
	spec := ca.NewProvisionerSpec{
		Name:           name,
		Type:           "ACME",
		ACMEChallenges: challenges,
		ACMERequireEAB: requireEAB,
	}
	if _, err := ca.UpdateProvisioner(r.Context(), view.CAURL, view.RootFingerprint, cred, spec); err != nil {
		s.sessions.Put(r.Context(), errorKey, provisionerCreateErrorMessage(err))
	} else {
		s.sessions.Put(r.Context(), flashKey, "ACME provisioner updated.")
		_ = s.audit.Record(r.Context(), actor.Username, "acme.provisioner.update", name,
			acmeAuditDetails(challenges, requireEAB))
	}
	http.Redirect(w, r, "/acme", http.StatusSeeOther)
}

// eabView is the data the per-provisioner EAB page renders: the provisioner name,
// its directory URL, the existing keys (NEVER with the HMAC), the client snippets,
// and — only immediately after a create — the one-time keyID + HMAC display.
type eabView struct {
	Provisioner  string
	DirectoryURL string
	Keys         []ca.EABKey
	HasAdminCred bool
	ListError    string
	Snippets     []clientSnippet
	RequireEAB   bool        // the provisioner's real requireEAB option; drives EAB params in snippets
	Created      *createdEAB // non-nil only on the one-time display
}

// createdEAB carries the one-time keyID + HMAC shown exactly once after creation.
// It is never persisted; it lives only for this single response.
type createdEAB struct {
	KeyID string
	HMAC  string
}

// getEAB lists the EAB keys for a provisioner and renders the management page with
// the directory URL and client snippets (FR-2/FR-3/FR-4). The list never carries
// the HMAC.
func (s *server) getEAB(w http.ResponseWriter, r *http.Request) {
	prov := r.PathValue("provisioner")
	view, ok, err := s.settings.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	d := s.page(r, "ACME EAB")
	d.Flash = s.sessions.PopString(r.Context(), flashKey)
	d.Error = s.sessions.PopString(r.Context(), errorKey)

	hasAuth := ok && viewHasAdminAuth(view)
	ev := eabView{Provisioner: prov, HasAdminCred: hasAuth}
	if !ok {
		ev.ListError = "Configure the CA connection first (CA settings)."
		s.render(w, r, http.StatusOK, eabPage(d, ev))
		return
	}
	ev.DirectoryURL = ca.DirectoryURL(view.CAURL, prov)

	// RequireEAB must reflect the provisioner's REAL requireEAB option, not whether
	// any keys happen to exist (spec/0010): a requireEAB directory with zero keys
	// still needs EAB params in its snippets, and a non-EAB directory with legacy
	// keys must not show them. The public list needs no admin token.
	ev.RequireEAB = s.currentACMEOptions(r, view, prov).RequireEAB

	if hasAuth {
		auth, authOK, cerr := s.adminAuth(r.Context(), view)
		if cerr != nil || !authOK {
			ev.ListError = adminAuthMissingMessage()
		} else if cred, credErr := auth.Credential(r.Context()); credErr != nil {
			ev.ListError = eabErrorMessage(credErr)
		} else if keys, lerr := ca.ListEABKeys(r.Context(), view.CAURL, view.RootFingerprint, cred, prov); lerr != nil {
			ev.ListError = eabErrorMessage(lerr)
		} else {
			ev.Keys = keys
		}
	}
	// Snippets are useful regardless of admin credential; show EAB params when the
	// provisioner requires EAB, with placeholders for the not-yet-created key.
	ev.Snippets = buildSnippets(ev.DirectoryURL, ev.RequireEAB, "", "")
	s.render(w, r, http.StatusOK, eabPage(d, ev))
}

// postEAB creates or revokes an EAB key (FR-2). Create renders the one-time
// keyID + HMAC display with Cache-Control: no-store; revoke is tunnelled through
// action=delete. Audited on success WITHOUT the HMAC/secret (FR-5).
func (s *server) postEAB(w http.ResponseWriter, r *http.Request) {
	prov := r.PathValue("provisioner")
	view, cred, ok := s.acmeAdminContext(w, r)
	if !ok {
		return
	}
	actor := userFromContext(r.Context())

	if r.PostFormValue("action") == "delete" {
		keyID := r.PostFormValue("key_id")
		if err := ca.DeleteEABKey(r.Context(), view.CAURL, view.RootFingerprint, cred, prov, keyID); err != nil {
			s.sessions.Put(r.Context(), errorKey, eabErrorMessage(err))
		} else {
			s.sessions.Put(r.Context(), flashKey, "EAB key revoked.")
			// keyID identifies the key; it is not a secret. The HMAC is never here.
			_ = s.audit.Record(r.Context(), actor.Username, "acme.eab.revoke", prov, "keyID="+keyID)
		}
		http.Redirect(w, r, "/acme/eab/"+prov, http.StatusSeeOther)
		return
	}

	// Create: returns the HMAC ONCE. Render it inline (no redirect) so the secret
	// is shown exactly once, with no-store, and is never stored on our side.
	reference := r.PostFormValue("reference")
	key, err := ca.CreateEABKey(r.Context(), view.CAURL, view.RootFingerprint, cred, prov, reference)
	if err != nil {
		s.sessions.Put(r.Context(), errorKey, eabErrorMessage(err))
		http.Redirect(w, r, "/acme/eab/"+prov, http.StatusSeeOther)
		return
	}
	// Audit WITHOUT the HMAC: only the keyID + reference, never the secret (FR-5).
	_ = s.audit.Record(r.Context(), actor.Username, "acme.eab.create", prov,
		"keyID="+key.KeyID+eabReferenceSuffix(reference))

	// Re-list (without HMAC) so the page below the one-time banner is complete.
	d := s.page(r, "ACME EAB")
	ev := eabView{
		Provisioner:  prov,
		HasAdminCred: true,
		DirectoryURL: ca.DirectoryURL(view.CAURL, prov),
		RequireEAB:   true,
		Created:      &createdEAB{KeyID: key.KeyID, HMAC: key.HMAC},
	}
	if keys, lerr := ca.ListEABKeys(r.Context(), view.CAURL, view.RootFingerprint, cred, prov); lerr == nil {
		ev.Keys = keys
	}
	ev.Snippets = buildSnippets(ev.DirectoryURL, true, key.KeyID, key.HMAC)

	// The one-time HMAC display must never be cached anywhere.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	s.render(w, r, http.StatusOK, eabPage(d, ev))
}

// currentACMEOptions fetches the named ACME provisioner's CURRENT options from
// the CA so an edit can merge onto them (spec/0010). It returns a zero value if
// the provisioner cannot be found or the list call fails: the caller then relies
// on the explicit form fields alone, never inventing a default that could weaken
// the directory (a missed requireEAB merges to whatever the form carried, which
// for the rendered form is the pre-filled real value).
func (s *server) currentACMEOptions(r *http.Request, view settings.View, name string) ca.ACMEProvisioner {
	list, err := ca.ListACMEProvisioners(r.Context(), view.CAURL, view.RootFingerprint)
	if err != nil {
		return ca.ACMEProvisioner{Name: name}
	}
	for _, p := range list {
		if p.Name == name {
			return p
		}
	}
	return ca.ACMEProvisioner{Name: name}
}

// acmeAdminContext loads CA settings + a usable admin credential, redirecting to
// /acme with a clear flash when either is missing. ok is false when the caller
// should stop (a redirect was already written).
func (s *server) acmeAdminContext(w http.ResponseWriter, r *http.Request) (view settings.View, cred ca.AdminCredential, ok bool) {
	v, exists, err := s.settings.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return view, cred, false
	}
	if !exists {
		s.sessions.Put(r.Context(), errorKey, "Configure the CA connection first.")
		http.Redirect(w, r, "/acme", http.StatusSeeOther)
		return view, cred, false
	}
	auth, authOK, authErr := s.adminAuth(r.Context(), v)
	if authErr != nil {
		s.sessions.Put(r.Context(), errorKey, "Could not load the admin credential.")
		http.Redirect(w, r, "/acme", http.StatusSeeOther)
		return view, cred, false
	}
	if !authOK {
		s.sessions.Put(r.Context(), errorKey, adminAuthMissingMessage())
		http.Redirect(w, r, "/acme", http.StatusSeeOther)
		return view, cred, false
	}
	c, credErr := auth.Credential(r.Context())
	if credErr != nil {
		s.sessions.Put(r.Context(), errorKey, eabErrorMessage(credErr))
		http.Redirect(w, r, "/acme", http.StatusSeeOther)
		return view, cred, false
	}
	return v, c, true
}

// eabReferenceSuffix returns a non-secret audit detail suffix for an optional
// reference (the reference is a human label, not a secret).
func eabReferenceSuffix(reference string) string {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return ""
	}
	return " reference=" + reference
}

// acmeAuditDetails summarises the ACME options for an audit row (no secrets).
func acmeAuditDetails(challenges []string, requireEAB bool) string {
	parts := []string{}
	if len(challenges) > 0 {
		parts = append(parts, "challenges="+strings.Join(challenges, ","))
	}
	if requireEAB {
		parts = append(parts, "requireEAB=true")
	}
	return strings.Join(parts, " ")
}

// eabErrorMessage maps EAB operation failures to clear, secret-free messages.
func eabErrorMessage(err error) string {
	switch {
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
	case errors.Is(err, ca.ErrMalformedResponse):
		return "The CA returned an unexpected response (EAB may not be enabled on this CA)."
	case errors.Is(err, ca.ErrAdminRequestFailed):
		return "The CA could not complete the EAB request (EAB may require Certificate Manager / remote management)."
	case errors.Is(err, ca.ErrInvalidProvisioner):
		return "Invalid EAB request."
	default:
		return "The EAB operation failed."
	}
}
