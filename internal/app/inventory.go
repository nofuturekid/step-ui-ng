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

// inventoryPageSize is the number of certificates shown per page.
// Matches auditPageSize for consistency across paginated views.
const inventoryPageSize = 50

// getInventory renders the certificate inventory list (FR-1).
// Filter parameters:
//
//	?status=active|expired|revoked  — derives status from not_after + DB status.
//	?q=<text>                       — substring search over CN/SAN.
//	?provisioner=<name>             — exact match on recorded provisioner name.
//	?page=<n>                       — 0-based page number (default 0).
//
// Pagination note: certs.Service.List returns the full filtered slice because
// the "expired" status is derived from not_after (not stored in the DB status
// column), so status filtering must happen in Go after the SQL query. SQL
// LIMIT/OFFSET is therefore not used — it would paginate before the Go-side
// status derivation and yield wrong counts and short pages. Pagination is
// applied here, after List returns the fully-filtered result set.
//
// htmx: when the request carries HX-Request the response replaces only the
// table partial (hx-target="#inventory-table"), keeping the layout intact.
// The pagination block lives inside inventoryTable so a filter change (which
// always resets to page 0) also updates the footer.
func (s *server) getInventory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 0 {
		page = 0
	}

	filter := certs.ListFilter{
		Status:      q.Get("status"),
		Search:      q.Get("q"),
		Provisioner: q.Get("provisioner"),
	}

	// List returns the full filtered slice (no SQL LIMIT — see note above).
	list, err := s.certs.List(r.Context(), filter)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	provisioners, err := s.certs.ListProvisioners(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Paginate the fully-filtered slice in-handler.
	total := len(list)
	offset := page * inventoryPageSize
	var pageItems []certs.InventoryItem
	var end int
	if offset < total {
		end = min(offset+inventoryPageSize, total)
		pageItems = list[offset:end]
	}
	hasMore := offset+inventoryPageSize < total

	// 1-based display range (Showing X–Y of N). When total==0, both are 0.
	rangeFrom := 0
	rangeTo := 0
	if total > 0 && len(pageItems) > 0 {
		rangeFrom = offset + 1
		rangeTo = end
	}

	d := s.page(r, "Certificates")
	d.Wide = true // data-heavy table: render at the wider content width
	d.ActiveSection = "/inventory"
	v := inventoryView{
		Filter:       filter,
		Items:        pageItems,
		Provisioners: provisioners,
		Total:        total,
		Page:         page,
		HasMore:      hasMore,
		NextPage:     page + 1,
		PrevPage:     page - 1,
		RangeFrom:    rangeFrom,
		RangeTo:      rangeTo,
	}

	if r.Header.Get("HX-Request") == "true" {
		// htmx live-filter: replace only the table partial (which includes the
		// pagination footer so the footer also refreshes on filter changes).
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
	// Parse the leaf PEM to derive enriched metadata (fingerprint, issuer, key type,
	// key usage, EKU). Failures are ignored — the page degrades gracefully by showing
	// only the stored fields and omitting the derived ones.
	parsed, _ := certs.ParseLeafPEM(cert.CertPEM)
	d := s.page(r, "Certificate — "+cert.CN)
	s.render(w, r, http.StatusOK, certDetailPage(d, certDetailView{
		Cert:             cert,
		Parsed:           parsed,
		RenewDefaultDays: s.renewDefaultDays(),
	}))
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
	Filter       certs.ListFilter
	Items        []certs.InventoryItem // current page slice (len ≤ inventoryPageSize)
	Provisioners []string              // distinct provisioner names for the filter dropdown
	// Pagination fields (mirroring auditView).
	Total     int  // total filtered item count (across all pages)
	Page      int  // 0-based current page
	HasMore   bool // true when there are further pages after this one
	NextPage  int
	PrevPage  int
	RangeFrom int // 1-based index of the first item on this page (0 when empty)
	RangeTo   int // 1-based index of the last item on this page (0 when empty)
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
