// Package app wires the HTTP server together.
//
// As features land (see spec/), this is where the router, middleware
// (sessions, RBAC, CSRF), and handlers are composed. For now it exposes a
// health endpoint so the scaffold builds, runs, and is testable.
package app

import (
	"encoding/json"
	"net/http"
)

// Version is the application version (kept in sync with CHANGELOG.md).
const Version = "0.0.1"

// NewHandler returns the root HTTP handler.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	return mux
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": Version,
	})
}
