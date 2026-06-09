package app

// spec/0007 — inventory & encrypted re-download handlers.
//
// Routes:
//   GET /inventory              — list + filters; any authenticated role (read-only).
//   GET /certificates/{id}      — detail view; any authenticated role.
//   POST /certificates/{id}/download — ZIP bundle; admin+ only (FR-4 RBAC).
//
// RBAC decision (download): the bundle may contain the private key, which is
// equivalent to exporting a secret. Admin+ mirrors the issuance gate (spec/0006)
// and ensures the download capability is limited to users already trusted to
// issue certificates. Viewers may browse and inspect metadata but cannot export
// key material. This choice is enforced by requireRole(RoleAdmin) on the route.

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nofuturekid/step-ui-ng/internal/certs"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// getInventory renders the certificate inventory list (FR-1).
// Filter parameters:
//
//	?status=active|expired|revoked  — derives status from not_after + DB status.
//	?q=<text>                       — substring search over CN/SAN.
//
// htmx: when the request carries HX-Request the response replaces only the
// table partial (hx-target="#inventory-table"), keeping the layout intact.
func (s *server) getInventory(w http.ResponseWriter, r *http.Request) {
	filter := certs.ListFilter{
		Status: r.URL.Query().Get("status"),
		Search: r.URL.Query().Get("q"),
	}
	list, err := s.certs.List(r.Context(), filter)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	d := s.page(r, "Certificates")
	d.Wide = true // data-heavy table: render at the wider content width
	d.ActiveSection = "/inventory"
	v := inventoryView{Filter: filter, Items: list}

	if r.Header.Get("HX-Request") == "true" {
		// htmx live-filter: replace only the table partial.
		s.render(w, r, http.StatusOK, inventoryTable(d, v))
		return
	}
	s.render(w, r, http.StatusOK, inventoryPage(d, v))
}

// getCertDetail renders the full-detail view for a single certificate (FR-1).
func (s *server) getCertDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad certificate id", http.StatusBadRequest)
		return
	}
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
	s.render(w, r, http.StatusOK, certDetailPage(d, certDetailView{Cert: cert, RenewDefaultDays: s.renewDefaultDays()}))
}

// postCertDownload assembles a ZIP bundle in memory and streams it to the
// client. The bundle always contains cert/chain/fullchain/README; it includes
// privkey.pem only when key_strategy=server (FR-6), and cert.p12 only when
// the pfx_password form field is non-empty (FR-3).
//
// Security: the PFX password is read from the POST body (r.PostFormValue), not
// from the URL query string, so it never appears in reverse-proxy/CDN access
// logs, browser history, or Referer headers. The endpoint is a POST rather than
// a GET to convey that it has a credential body, and it is protected by the
// global nosurf CSRF wrapper.
//
// RBAC: requires admin+ — the bundle may expose a private key.
// Cache-Control: no-store, no-cache, must-revalidate — the ZIP may contain
// the plaintext private key; it must not be cached by the browser or any
// intermediary (FR-4).
func (s *server) postCertDownload(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad certificate id", http.StatusBadRequest)
		return
	}

	// Read the PFX password from the POST body only — never from the URL.
	pfxPassword := r.PostFormValue("pfx_password")

	// Build the in-memory ZIP (key decrypted only in memory, never to disk — FR-4).
	bundle, err := s.certs.Bundle(r.Context(), id, pfxPassword)
	if errors.Is(err, certs.ErrNotFound) {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Derive a safe filename from the cert's CN (we need it for the header).
	cert, err := s.certs.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	filename := downloadName(cert.CN) + "-bundle.zip"

	// Security headers: no caching (may contain plaintext private key), forced
	// download (attachment disposition), correct MIME type (FR-4, spec).
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, strings.ReplaceAll(filename, `"`, `_`)))
	// Cache-Control: no-store prevents the bundle from being stored in any
	// cache (browser, proxy, CDN).  The key material must not outlive the
	// HTTP response in any cache layer.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Length", strconv.Itoa(len(bundle)))

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

// inventoryView carries the data for the inventory page.
type inventoryView struct {
	Filter certs.ListFilter
	Items  []certs.InventoryItem
}

// registerInventoryRoutes wires the inventory routes into mux. Separated so
// server.go stays focused on the overall topology.
func (s *server) registerInventoryRoutes(mux *http.ServeMux) {
	// Inventory list — any authenticated user may browse (read-only).
	mux.HandleFunc("GET /inventory",
		s.requireAuth(s.getInventory))

	// Certificate detail — any authenticated user.
	mux.HandleFunc("GET /certificates/{id}",
		s.requireAuth(s.getCertDetail))

	// Bundle download — POST with PFX password in body (never in URL), admin+ only.
	mux.HandleFunc("POST /certificates/{id}/download",
		s.requireAuth(s.requireRole(users.RoleAdmin, s.postCertDownload)))

	// Revoke & renew (spec/0008) — admin+ only, behind auth + CSRF. Revoke is real
	// (calls the CA); renew re-issues for the same CN/SANs.
	mux.HandleFunc("POST /certificates/{id}/revoke",
		s.requireAuth(s.requireRole(users.RoleAdmin, s.postCertRevoke)))
	mux.HandleFunc("POST /certificates/{id}/renew",
		s.requireAuth(s.requireRole(users.RoleAdmin, s.postCertRenew)))
}
