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

	"github.com/nofuturekid/step-ui-ng/internal/audit"
	"github.com/nofuturekid/step-ui-ng/internal/certs"
	"github.com/nofuturekid/step-ui-ng/internal/config"
	"github.com/nofuturekid/step-ui-ng/internal/settings"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// Version is the application version. The literal here is the development
// fallback; releases stamp the git tag via ldflags
// (-X github.com/nofuturekid/step-ui-ng/internal/app.Version=<tag>). See
// BuildInfo (version.go) and ADR-0013.
var Version = "0.1.1"

// ctxKey is the unexported request-context key type for this package.
type ctxKey int

const userCtxKey ctxKey = iota

// Deps holds everything NewHandler needs to build the app.
type Deps struct {
	DB       *sql.DB
	Users    *users.Repo
	Settings *settings.Repo
	Certs    *certs.Service
	Audit    *audit.Recorder
	Sessions *scs.SessionManager
	Config   config.Config
}

// server bundles the dependencies for the handler methods.
type server struct {
	users    *users.Repo
	settings *settings.Repo
	certs    *certs.Service
	audit    *audit.Recorder
	sessions *scs.SessionManager
	cfg      config.Config
}

// NewHandler builds the root HTTP handler from its dependencies. The returned
// handler is the full middleware stack: nosurf (CSRF) → session LoadAndSave →
// loadUser → first-run gating → router.
func NewHandler(deps Deps) http.Handler {
	// Fail fast at construction if a required dependency is missing, so a wiring
	// omission (e.g. forgetting Audit, which made every auditable action panic)
	// surfaces at startup with a clear message instead of as a recovered 500 per
	// request.
	switch {
	case deps.DB == nil:
		panic("app.NewHandler: missing required dependency DB")
	case deps.Users == nil:
		panic("app.NewHandler: missing required dependency Users")
	case deps.Settings == nil:
		panic("app.NewHandler: missing required dependency Settings")
	case deps.Certs == nil:
		panic("app.NewHandler: missing required dependency Certs")
	case deps.Audit == nil:
		panic("app.NewHandler: missing required dependency Audit")
	case deps.Sessions == nil:
		panic("app.NewHandler: missing required dependency Sessions")
	}

	s := &server{users: deps.Users, settings: deps.Settings, certs: deps.Certs, audit: deps.Audit, sessions: deps.Sessions, cfg: deps.Config}

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

	// CA settings (admin+): view/save the connection, test connectivity (spec/0004).
	// Admin-auth method + material (spec/0012 FR-1/FR-3).
	mux.HandleFunc("GET /settings", s.requireAuth(s.requireRole(users.RoleAdmin, s.getSettings)))
	mux.HandleFunc("POST /settings", s.requireAuth(s.requireRole(users.RoleAdmin, s.postSettings)))
	mux.HandleFunc("POST /settings/test", s.requireAuth(s.requireRole(users.RoleAdmin, s.postSettingsTest)))
	mux.HandleFunc("POST /settings/admin-auth", s.requireAuth(s.requireRole(users.RoleAdmin, s.postAdminAuth)))

	// Provisioner management (admin+): list, select active, create, delete
	// (spec/0005). Create/delete sign an x5c admin token from the stored admin
	// credential; delete refuses the currently selected provisioner.
	mux.HandleFunc("GET /provisioners", s.requireAuth(s.requireRole(users.RoleAdmin, s.getProvisioners)))
	mux.HandleFunc("POST /provisioners", s.requireAuth(s.requireRole(users.RoleAdmin, s.postProvisioners)))
	mux.HandleFunc("POST /provisioners/select", s.requireAuth(s.requireRole(users.RoleAdmin, s.postProvisionerSelect)))
	mux.HandleFunc("POST /provisioners/{name}", s.requireAuth(s.requireRole(users.RoleAdmin, s.postProvisioner)))

	// Issuance (admin+): issue a server-generated certificate, or sign a client
	// CSR, via the active provisioner's OTT (spec/0006).
	mux.HandleFunc("GET /issue", s.requireAuth(s.requireRole(users.RoleAdmin, s.getIssue)))
	mux.HandleFunc("POST /issue", s.requireAuth(s.requireRole(users.RoleAdmin, s.postIssue)))
	mux.HandleFunc("GET /sign-csr", s.requireAuth(s.requireRole(users.RoleAdmin, s.getSignCSR)))
	mux.HandleFunc("POST /sign-csr", s.requireAuth(s.requireRole(users.RoleAdmin, s.postSignCSR)))

	// Inventory & download (spec/0007): list, detail, ZIP bundle.
	s.registerInventoryRoutes(mux)

	// ACME enablement (spec/0010, admin+): list ACME provisioners + directory
	// URLs, create/edit/delete (verb-tunnelled via action=), and per-provisioner
	// EAB management (create → one-time HMAC display, list, revoke-via-action) +
	// client snippets. All behind auth + CSRF; CA admin ops sign an x5c token. EAB
	// lives under /acme/eab/{provisioner} (mirroring the CA's admin path
	// /admin/acme/eab/{provisioner}) to avoid a router collision with the literal
	// /acme/provisioners segment — the spec's "/acme/{provisioner}/eab" wording is
	// reconciled to this unambiguous form.
	mux.HandleFunc("GET /acme", s.requireAuth(s.requireRole(users.RoleAdmin, s.getACME)))
	mux.HandleFunc("POST /acme/provisioners", s.requireAuth(s.requireRole(users.RoleAdmin, s.postACMEProvisioners)))
	mux.HandleFunc("POST /acme/provisioners/{name}", s.requireAuth(s.requireRole(users.RoleAdmin, s.postACMEProvisioner)))
	mux.HandleFunc("GET /acme/eab/{provisioner}", s.requireAuth(s.requireRole(users.RoleAdmin, s.getEAB)))
	mux.HandleFunc("POST /acme/eab/{provisioner}", s.requireAuth(s.requireRole(users.RoleAdmin, s.postEAB)))

	// Audit log (spec/0009): query/filter view (admin+).
	mux.HandleFunc("GET /audit", s.requireAuth(s.requireRole(users.RoleAdmin, s.getAudit)))

	// Root → inventory (which itself enforces auth + first-run gating).
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/inventory", http.StatusSeeOther)
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
