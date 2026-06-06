// Package app wires the HTTP server together: the router, middleware (sessions,
// CSRF, RBAC, first-run gating) and the auth/user handlers (spec/0003).
//
// Handlers stay thin — all user/auth business logic lives in internal/users.
package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/justinas/nosurf"

	"github.com/nofuturekid/step-ui-ng/internal/config"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// Version is the application version (kept in sync with CHANGELOG.md).
const Version = "0.0.1"

// ctxKey is the unexported request-context key type for this package.
type ctxKey int

const userCtxKey ctxKey = iota

// Deps holds everything NewHandler needs to build the app.
type Deps struct {
	DB       *sql.DB
	Users    *users.Repo
	Sessions *scs.SessionManager
	Config   config.Config
}

// server bundles the dependencies for the handler methods.
type server struct {
	users    *users.Repo
	sessions *scs.SessionManager
	cfg      config.Config
}

// NewHandler builds the root HTTP handler from its dependencies. The returned
// handler is the full middleware stack: nosurf (CSRF) → session LoadAndSave →
// loadUser → first-run gating → router.
func NewHandler(deps Deps) http.Handler {
	s := &server{users: deps.Users, sessions: deps.Sessions, cfg: deps.Config}

	mux := http.NewServeMux()

	// Static assets and health are public and CSRF-exempt (GET).
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /healthz", health)

	// Auth flows.
	mux.HandleFunc("GET /setup", s.getSetup)
	mux.HandleFunc("POST /setup", s.postSetup)
	mux.HandleFunc("GET /login", s.getLogin)
	mux.HandleFunc("POST /login", s.postLogin)
	mux.HandleFunc("POST /logout", s.requireAuth(s.postLogout))

	// User management (admin+).
	mux.HandleFunc("GET /users", s.requireAuth(s.requireRole(users.RoleAdmin, s.getUsers)))
	mux.HandleFunc("POST /users", s.requireAuth(s.requireRole(users.RoleAdmin, s.postUsers)))
	mux.HandleFunc("POST /users/{id}", s.requireAuth(s.requireRole(users.RoleAdmin, s.postUser)))

	// Root → users (which itself enforces auth + first-run gating).
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
	})

	// Inner stack (after CSRF + session load): resolve the user, then gate
	// first-run so a fresh install funnels everyone to /setup.
	var handler http.Handler = mux
	handler = s.firstRun(handler)
	handler = s.loadUser(handler)
	handler = s.sessions.LoadAndSave(handler)
	handler = s.csrf(handler)
	return handler
}

// csrf wraps the stack with nosurf. GET/HEAD/OPTIONS are auto-exempt; static and
// healthz are GET-only so they are covered too. The base cookie's Secure flag
// follows config. A 403 is returned on token failure.
//
// nosurf's same-origin check derives the expected scheme from isTLS, which
// defaults to always-true. Left as-is, every POST over plain HTTP (the homelab
// default) would be rejected as a cross-origin request. We report TLS from the
// actual connection or the SecureCookies config (set when a TLS-terminating
// proxy fronts the app). We deliberately do NOT trust X-Forwarded-Proto: it is
// unauthenticated and attacker-settable, and SecureCookies already covers the
// trusted-proxy deployment.
func (s *server) csrf(next http.Handler) http.Handler {
	h := nosurf.New(next)
	h.SetBaseCookie(http.Cookie{
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	h.SetIsTLSFunc(func(r *http.Request) bool {
		return r.TLS != nil || s.cfg.SecureCookies
	})
	h.SetFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
	}))
	return h
}

// userFromContext returns the logged-in user, or nil.
func userFromContext(ctx context.Context) *users.User {
	u, _ := ctx.Value(userCtxKey).(*users.User)
	return u
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": Version,
	})
}
