package app

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// exemptExactFromFirstRun are the exact paths reachable while no users exist
// (FR-1). Exact match avoids accidentally exempting look-alikes such as
// "/setupX" or "/loginfoo".
var exemptExactFromFirstRun = []string{"/setup", "/login", "/healthz"}

// exemptPrefixFromFirstRun are the slash-terminated prefixes whose whole subtree
// is exempt (static assets).
var exemptPrefixFromFirstRun = []string{"/static/"}

// loadUser resolves the logged-in user id from the session into a *users.User in
// the request context. A stale/disabled/deleted session is silently cleared so
// downstream sees an anonymous request rather than a ghost user.
func (s *server) loadUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := s.sessions.GetInt64(r.Context(), sessionUserIDKey)
		if id == 0 {
			next.ServeHTTP(w, r)
			return
		}
		u, err := s.users.GetByID(r.Context(), id)
		if err != nil || u.Disabled {
			// Drop the dangling reference; treat as anonymous.
			s.sessions.Remove(r.Context(), sessionUserIDKey)
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, &u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// firstRun redirects every non-exempt route to /setup while no users exist
// (FR-1). The Count check runs per request; once the first user exists it is a
// cheap COUNT and the gate opens for everyone.
func (s *server) firstRun(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isExemptFromFirstRun(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		n, err := s.users.Count(r.Context())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if n == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isExemptFromFirstRun(path string) bool {
	for _, p := range exemptExactFromFirstRun {
		if path == p {
			return true
		}
	}
	for _, p := range exemptPrefixFromFirstRun {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// requireAuth redirects unauthenticated requests to /login (acceptance:
// unauthenticated → /login).
func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if userFromContext(r.Context()) == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireRole returns 403 if the logged-in user is below minRole (acceptance:
// viewer attempting a mutating action → 403). It assumes requireAuth ran first.
func (s *server) requireRole(minRole users.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFromContext(r.Context())
		if u == nil || !u.Role.AtLeast(minRole) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// loginErrorMessage maps domain errors to a single, non-enumerating message.
func loginErrorMessage(err error) string {
	switch {
	case errors.Is(err, users.ErrUserDisabled):
		return "This account is disabled."
	default:
		return "Invalid username or password."
	}
}
