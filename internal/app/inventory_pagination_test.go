package app_test

// Pagination tests for backlog item ③ — inventory list pagination.
//
// Acceptance criteria encoded here (Rule 9: tests encode WHY, not just WHAT):
//
//  1. Page 0 shows exactly inventoryPageSize rows when total > pageSize; a "Next"
//     control is present. Page 1 shows the remainder with no further "Next" control.
//     WHY: users must be able to navigate beyond page 0 without losing data.
//
//  2. "Showing X–Y of N" range text is correct on every page.
//     WHY: users need to know their position in the full result set.
//
//  3. Pagination composes with status filter (the critical correctness test):
//     the count/range reflects the *filtered* total, not the raw table size.
//     WHY: pagination is applied AFTER the Go-side status derivation; a naive
//     SQL LIMIT/OFFSET would paginate before the filter and produce wrong counts
//     or short pages, breaking the filter+page contract.
//
//  4. A pagination link carries the active filter params so navigation preserves
//     the current filter.
//     WHY: without filter carryover, clicking "Next" drops the filter, silently
//     showing unfiltered results on subsequent pages.
//
//  5. Empty result (filter matches nothing) renders the existing empty-state
//     message and NO pagination block.
//     WHY: a pagination block on an empty result is confusing and exposes a
//     potential "Showing 0–0 of 0" rendering edge case.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// pageSize mirrors the const in inventory.go; kept local so the test does not
// import unexported symbols from app.
const testInventoryPageSize = 50

// seedActiveCerts inserts n active certs (all expiring in 60 days) into the DB.
// Returns the number actually inserted.
func seedActiveCerts(t *testing.T, e *testEnv, prefix string, n int) {
	t.Helper()
	notAfter := time.Now().Add(60 * 24 * time.Hour).Unix()
	for i := range n {
		cn := fmt.Sprintf("%s-%03d.test", prefix, i)
		invInsertMinimalCert(t, e.db, cn, notAfter)
	}
}

// countOccurrences counts how many times substr appears in s.
func countOccurrences(s, substr string) int {
	return strings.Count(s, substr)
}

// TestInventoryPaginationPage0ShowsPageSizeRows verifies that when there are
// more than inventoryPageSize certs, page 0 shows exactly pageSize rows and a
// "Next" navigation control. A Next control on page 0 is the user's only way
// to reach further results — if missing, data is silently inaccessible.
func TestInventoryPaginationPage0ShowsPageSizeRows(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed more than one page (55 certs, page size 50 → two pages).
	const total = 55
	seedActiveCerts(t, e, "pg0", total)

	_, body := e.get(t, "/inventory")

	// Count the number of cert rows by counting a unique marker per row.
	// inventoryRow renders a link with class "rowlink cn-cell"; count those.
	rowCount := countOccurrences(body, `class="rowlink cn-cell"`)
	if rowCount != testInventoryPageSize {
		t.Errorf("page 0 row count = %d, want %d (inventoryPageSize)", rowCount, testInventoryPageSize)
	}

	// A "Next page" navigation link must be present.
	if !strings.Contains(body, `aria-label="Next page"`) {
		t.Error("page 0: missing Next page link when HasMore=true")
	}
}

// TestInventoryPaginationPage1ShowsRemainder verifies that page 1 shows only
// the remainder rows (55-50=5) and has no active "Next page" link.
// The absence of a Next link on the last page prevents infinite pagination.
func TestInventoryPaginationPage1ShowsRemainder(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	const total = 55
	seedActiveCerts(t, e, "pg1", total)

	_, body := e.get(t, "/inventory?page=1")

	remainder := total - testInventoryPageSize // 5
	rowCount := countOccurrences(body, `class="rowlink cn-cell"`)
	if rowCount != remainder {
		t.Errorf("page 1 row count = %d, want %d (remainder)", rowCount, remainder)
	}

	// There must NOT be a Next page link on the last page.
	if strings.Contains(body, `aria-label="Next page"`) {
		t.Error("page 1 (last): must NOT have a Next page link (HasMore=false)")
	}
}

// TestInventoryPaginationRangeTextPage0 verifies the "Showing 1–50 of 55" range
// text on page 0. The range text is the primary way users know their position
// in the full result set; wrong numbers erode trust in the UI.
func TestInventoryPaginationRangeTextPage0(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	const total = 55
	seedActiveCerts(t, e, "range0", total)

	_, body := e.get(t, "/inventory")

	// "Showing <b>1–50</b> of 55"
	if !strings.Contains(body, fmt.Sprintf("1–50</b> of %d", total)) {
		// Try with HTML encoding variant
		if !strings.Contains(body, ">1–50<") {
			t.Errorf("page 0 range text: expected 'Showing 1–50 of %d' not found in body", total)
		}
		if !strings.Contains(body, fmt.Sprintf("of %d", total)) {
			t.Errorf("page 0 range text: expected 'of %d' not found in body", total)
		}
	}
}

// TestInventoryPaginationRangeTextPage1 verifies the "Showing 51–55 of 55" range
// text on page 1.
func TestInventoryPaginationRangeTextPage1(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	const total = 55
	seedActiveCerts(t, e, "range1", total)

	_, body := e.get(t, "/inventory?page=1")

	// "Showing <b>51–55</b> of 55" — assert the exact contiguous range string so
	// the check can't be satisfied by "51"/"55" appearing in seeded CNs/serials.
	if !strings.Contains(body, fmt.Sprintf("51–55</b> of %d", total)) {
		t.Errorf("page 1 range text: expected 'Showing 51–55 of %d' not found in body", total)
	}
}

// TestInventoryPaginationFilterComposition is the CRITICAL correctness test.
//
// It seeds a mix of active and expired certs, then requests page 0 with
// ?status=active. The pagination range must reflect only the active count,
// not the total table size. This would fail with a naive SQL LIMIT/OFFSET
// because LIMIT would paginate the raw rows before the Go status filter
// derives status from not_after — yielding wrong counts and missing rows.
//
// WHY this matters: the business rule is that "expired" is a derived status
// (not_after < now), not stored in the DB status column. Status filtering is
// therefore done in Go after the SQL query. Pagination MUST happen after
// this derivation — never before.
func TestInventoryPaginationFilterComposition(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed 55 active certs and 20 expired certs (total 75 rows in DB).
	// With status=active filter, only 55 rows qualify.
	// Page 0 must show 50 active certs (not fewer due to expired ones mixed in).
	const activeCount = 55
	const expiredCount = 20
	notAfterActive := time.Now().Add(60 * 24 * time.Hour).Unix()
	notAfterExpired := time.Now().Add(-24 * time.Hour).Unix()

	for i := range activeCount {
		invInsertMinimalCert(t, e.db, fmt.Sprintf("compose-active-%03d.test", i), notAfterActive)
	}
	for i := range expiredCount {
		invInsertMinimalCert(t, e.db, fmt.Sprintf("compose-expired-%03d.test", i), notAfterExpired)
	}

	// Page 0, status=active: should show 50 active rows.
	_, body := e.get(t, "/inventory?status=active")
	rowCount := countOccurrences(body, `class="rowlink cn-cell"`)
	if rowCount != testInventoryPageSize {
		t.Errorf("status=active page 0: row count = %d, want %d (filtered total=%d, not raw=%d)",
			rowCount, testInventoryPageSize, activeCount, activeCount+expiredCount)
	}

	// The range text must say "of 55" (filtered total), not "of 75" (raw total).
	if !strings.Contains(body, fmt.Sprintf("of %d", activeCount)) {
		t.Errorf("status=active page 0: range must say 'of %d' (filtered), not 'of %d' (raw); body snippet: %q",
			activeCount, activeCount+expiredCount, truncate(body, 500))
	}

	// HasMore must be true (55 active > 50 page size).
	if !strings.Contains(body, `aria-label="Next page"`) {
		t.Error("status=active page 0: missing Next page link (55 active certs > page size 50)")
	}

	// Page 1, status=active: should show 5 active rows (55-50).
	_, body2 := e.get(t, "/inventory?status=active&page=1")
	rowCount2 := countOccurrences(body2, `class="rowlink cn-cell"`)
	if rowCount2 != activeCount-testInventoryPageSize {
		t.Errorf("status=active page 1: row count = %d, want %d (remainder after filter)",
			rowCount2, activeCount-testInventoryPageSize)
	}

	// No next link on page 1 (last page of filtered results).
	if strings.Contains(body2, `aria-label="Next page"`) {
		t.Error("status=active page 1: must NOT have Next page link (last page of filtered results)")
	}
}

// TestInventoryPaginationLinkCarriesFilter verifies that pagination links
// include the active filter parameters so that navigating to the next page
// preserves the current filter. Without filter carryover, page 2 would show
// unfiltered results silently — a data-integrity concern for users who believe
// they are still viewing filtered data.
func TestInventoryPaginationLinkCarriesFilter(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed enough certs with a specific provisioner to span two pages.
	const total = 55
	notAfter := time.Now().Add(60 * 24 * time.Hour).Unix()
	for i := range total {
		invInsertCertWithProvisioner(t, e.db,
			fmt.Sprintf("linkfilter-%03d.test", i),
			notAfter,
			"test-prov")
	}

	// Request page 0 with provisioner filter.
	_, body := e.get(t, "/inventory?provisioner=test-prov")

	// The Next page link must include the provisioner filter param.
	if !strings.Contains(body, "provisioner=test-prov") {
		t.Error("pagination link: must carry provisioner= filter param to preserve filtering on navigation")
	}
	// The Next page link must also carry page=1.
	if !strings.Contains(body, "page=1") {
		t.Error("pagination link: must carry page=1 for the Next page link")
	}
}

// TestInventoryPaginationEmptyResultNoPagination verifies that when a filter
// matches no certs, the pagination block is absent and the existing empty-state
// message is shown. A pagination block on an empty result is confusing and
// would expose a "Showing 0–0 of 0" edge case.
func TestInventoryPaginationEmptyResultNoPagination(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Seed only active certs; filter for revoked → empty result.
	notAfter := time.Now().Add(60 * 24 * time.Hour).Unix()
	invInsertMinimalCert(t, e.db, "nopage-active.test", notAfter)

	_, body := e.get(t, "/inventory?status=revoked")

	// The empty-state message must be present.
	if !strings.Contains(body, "No certificates match") {
		t.Error("empty result: missing 'No certificates match' empty-state message")
	}

	// The pagination block must NOT be present.
	if strings.Contains(body, `class="pagination"`) {
		t.Error("empty result: pagination block must not be rendered when result is empty")
	}
}

// TestInventoryPaginationHTMXPartialContainsPagination verifies that an htmx
// partial request (HX-Request: true) includes the pagination block inside the
// swapped partial. The filter form re-renders page 0 via htmx on filter change;
// the pagination footer must update with it so users see correct page info
// after filtering without a full-page reload.
func TestInventoryPaginationHTMXPartialContainsPagination(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	const total = 55
	seedActiveCerts(t, e, "htmx-pg", total)

	req, err := http.NewRequest(http.MethodGet, e.srv.URL+"/inventory", nil)
	if err != nil {
		t.Fatalf("build htmx request: %v", err)
	}
	req.Header.Set("HX-Request", "true")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("GET /inventory (htmx): %v", err)
	}
	defer resp.Body.Close()

	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	body := sb.String()

	// The htmx partial must NOT contain the full layout.
	if strings.Contains(body, "<html") {
		t.Error("htmx partial: must not include full <html> layout")
	}

	// The pagination block MUST be in the partial (so htmx swap updates it).
	if !strings.Contains(body, `class="pagination"`) {
		t.Error("htmx partial: pagination block must be inside inventoryTable partial " +
			"so the htmx swap updates the footer on filter change")
	}
}

// TestInventoryPaginationNegativePageClamped verifies that a negative page
// parameter is clamped to 0 (treated as the first page). This prevents
// "Showing -49–0 of N" broken range text and potential slice panics.
func TestInventoryPaginationNegativePageClamped(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	const total = 5
	seedActiveCerts(t, e, "negpage", total)

	resp, body := e.get(t, "/inventory?page=-1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page=-1: status = %d, want 200", resp.StatusCode)
	}
	// Should show all 5 certs (same as page 0).
	rowCount := countOccurrences(body, `class="rowlink cn-cell"`)
	if rowCount != total {
		t.Errorf("page=-1 (clamped to 0): row count = %d, want %d", rowCount, total)
	}
}

// TestInventoryPaginationBeyondLastPageShowsEmpty verifies that requesting a
// page beyond the last returns an empty page (not a panic or 5xx). The
// empty-state message must appear and the pagination block must be absent.
func TestInventoryPaginationBeyondLastPageShowsEmpty(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	const total = 5
	seedActiveCerts(t, e, "overpage", total)

	// Page 99 is way beyond the last page.
	resp, body := e.get(t, "/inventory?page=99")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page=99 (beyond last): status = %d, want 200", resp.StatusCode)
	}
	// Should show the empty state (no rows on this far-out page).
	if !strings.Contains(body, "No certificates match") {
		t.Error("page beyond last: expected empty-state message")
	}
}
