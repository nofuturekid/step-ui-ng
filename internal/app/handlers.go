package app

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/a-h/templ"
	"github.com/justinas/nosurf"

	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// render writes a templ component, defaulting to 200 unless status overrides it.
func (s *server) render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// page builds the common per-request page data (CSRF token + current user).
func (s *server) page(r *http.Request, title string) pageData {
	return pageData{
		Title:     title,
		CSRFToken: nosurf.Token(r),
		User:      userFromContext(r.Context()),
	}
}

// getSetup shows the first-run form, or redirects away once setup is done
// (acceptance: after setup complete, /setup is no longer available).
func (s *server) getSetup(w http.ResponseWriter, r *http.Request) {
	if s.setupDone(w, r) {
		return
	}
	s.render(w, r, http.StatusOK, setupPage(s.page(r, "Setup")))
}

// postSetup creates the first user as superadmin (only while none exist), logs
// them in, and renews the session token (FR-1, FR-3).
func (s *server) postSetup(w http.ResponseWriter, r *http.Request) {
	if s.setupDone(w, r) {
		return
	}

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	// CreateFirst is atomic: a concurrent setup that wins the race makes this one
	// return ErrSetupComplete, which we treat as "setup is done" and redirect to
	// login rather than creating a second superadmin (first-run TOCTOU guard).
	u, err := s.users.CreateFirst(r.Context(), username, password)
	if errors.Is(err, users.ErrSetupComplete) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err != nil {
		d := s.page(r, "Setup")
		d.Error = createErrorMessage(err)
		s.render(w, r, http.StatusBadRequest, setupPage(d))
		return
	}

	if err := s.login(r, u.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// setupDone reports whether at least one user exists; if so it redirects to
// /login and returns true so the caller stops.
func (s *server) setupDone(w http.ResponseWriter, r *http.Request) bool {
	n, err := s.users.Count(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	if n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return true
	}
	return false
}

// getLogin shows the login form (or sends an already-authenticated user home).
func (s *server) getLogin(w http.ResponseWriter, r *http.Request) {
	if userFromContext(r.Context()) != nil {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, loginPage(s.page(r, "Log in")))
}

// postLogin authenticates and, on success, renews the session token and stores
// the user id (FR-3, FR-7). An audit event is recorded with the authenticated
// user as actor (spec/0009 FR-2).
func (s *server) postLogin(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	u, err := s.users.Authenticate(r.Context(), username, password)
	if err != nil {
		d := s.page(r, "Log in")
		d.Error = loginErrorMessage(err)
		s.render(w, r, http.StatusUnauthorized, loginPage(d))
		return
	}

	if err := s.login(r, u.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Record after a successful login; the actor is the authenticated user.
	_ = s.audit.Record(r.Context(), u.Username, "login", u.Username, "")
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// login renews the session token (prevents fixation) and records the user id.
func (s *server) login(r *http.Request, id int64) error {
	if err := s.sessions.RenewToken(r.Context()); err != nil {
		return err
	}
	s.sessions.Put(r.Context(), sessionUserIDKey, id)
	return nil
}

// postLogout records an audit event attributed to the current session user,
// then destroys the session and returns to /login (spec/0009 FR-2).
func (s *server) postLogout(w http.ResponseWriter, r *http.Request) {
	// Capture the actor BEFORE destroying the session; after Destroy the context
	// user is gone.
	actor := userFromContext(r.Context())
	if actor != nil {
		_ = s.audit.Record(r.Context(), actor.Username, "logout", actor.Username, "")
	}
	if err := s.sessions.Destroy(r.Context()); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// getUsers lists users (admin+).
func (s *server) getUsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.users.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	d := s.page(r, "Users")
	d.Flash = s.sessions.PopString(r.Context(), flashKey)
	d.Error = s.sessions.PopString(r.Context(), errorKey)
	s.render(w, r, http.StatusOK, usersPage(d, list))
}

// postUsers creates a user (admin+). The role ceiling is enforced here, not in
// requireRole: an actor may not create a user with a role higher than their own
// (e.g. admin → superadmin), which would otherwise be a privilege escalation.
func (s *server) postUsers(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	role := users.Role(r.PostFormValue("role"))

	// Authorize before doing any work. Unknown roles fall through to Create's
	// validation (ErrInvalidRole) so the user sees a precise message; the ceiling
	// only gates assigning a *valid* role above the actor's own.
	if role.Valid() && !actor.Role.CanAssign(role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	u, err := s.users.Create(r.Context(), username, password, role)
	if err != nil {
		s.sessions.Put(r.Context(), errorKey, createErrorMessage(err))
	} else {
		s.sessions.Put(r.Context(), flashKey, "User created.")
		_ = s.audit.Record(r.Context(), actor.Username, "user.create", u.Username,
			fmt.Sprintf("role=%s", u.Role))
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// postUser applies an action (set_role / disable / enable / delete) to a user
// identified by the path id (admin+). Domain guards (e.g. last superadmin) are
// surfaced as flash errors.
func (s *server) postUser(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad user id", http.StatusBadRequest)
		return
	}

	// Authorize against the *target's current role*: managing a superadmin
	// (delete/disable/re-role) requires the actor to be superadmin, so an admin
	// cannot demote/disable/delete a superadmin (privilege-escalation guard).
	// The self-target path is covered too — an admin acting on their own account
	// is still bounded by the assign ceiling below.
	target, err := s.users.GetByID(r.Context(), id)
	if err != nil {
		s.sessions.Put(r.Context(), errorKey, actionErrorMessage(err))
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if !actor.Role.CanManage(target.Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	action := r.PostFormValue("action")
	var actErr error
	var auditAction, auditDetails string
	switch action {
	case "set_role":
		newRole := users.Role(r.PostFormValue("role"))
		// Ceiling: cannot grant a role above the actor's own (blocks an admin
		// promoting anyone — including themselves — to superadmin).
		if newRole.Valid() && !actor.Role.CanAssign(newRole) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		actErr = s.users.SetRole(r.Context(), id, newRole)
		auditAction = "user.update"
		auditDetails = fmt.Sprintf("action=set_role role=%s", newRole)
	case "disable":
		actErr = s.users.SetDisabled(r.Context(), id, true)
		auditAction = "user.update"
		auditDetails = "action=disable"
	case "enable":
		actErr = s.users.SetDisabled(r.Context(), id, false)
		auditAction = "user.update"
		auditDetails = "action=enable"
	case "delete":
		actErr = s.users.Delete(r.Context(), id)
		auditAction = "user.delete"
		auditDetails = ""
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	if actErr != nil {
		s.sessions.Put(r.Context(), errorKey, actionErrorMessage(actErr))
	} else {
		s.sessions.Put(r.Context(), flashKey, "Done.")
		_ = s.audit.Record(r.Context(), actor.Username, auditAction, target.Username, auditDetails)
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// Flash message session keys (one-shot, popped on the next /users render).
const (
	flashKey = "flash"
	errorKey = "flash_error"
)

// createErrorMessage maps Create's validation errors to user-facing text.
func createErrorMessage(err error) string {
	switch {
	case errors.Is(err, users.ErrUsernameTaken):
		return "That username is already taken."
	case errors.Is(err, users.ErrInvalidUsername):
		return "Username must be 3–64 characters."
	case errors.Is(err, users.ErrWeakPassword):
		return "Password must be at least 12 characters."
	case errors.Is(err, users.ErrInvalidRole):
		return "Invalid role."
	default:
		return "Could not create user."
	}
}

// actionErrorMessage maps user-management errors to user-facing text.
func actionErrorMessage(err error) string {
	switch {
	case errors.Is(err, users.ErrLastSuperadmin):
		return "At least one enabled superadmin must remain."
	case errors.Is(err, users.ErrInvalidRole):
		return "Invalid role."
	case errors.Is(err, users.ErrUserNotFound):
		return "User not found."
	default:
		return "Action failed."
	}
}
