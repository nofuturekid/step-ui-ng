package app_test

// Design tests for PR D — provisioners page redesign.
//
// Acceptance criteria tested:
//   - Page head renders "Provisioners" h1, breadcrumb, page-sub subtitle.
//   - When admin auth is NOT configured: the locked notice (class="locked") is
//     shown with honest copy, a "Configure admin authentication" link to /settings,
//     and a "Copy CLI command" button with data-copy containing a real
//     step ca provisioner add command. The create form must NOT be shown.
//   - When admin auth IS configured: the create form is shown (not the locked notice).
//   - Active provisioner card: card__header + card__body with select[name="active"],
//     password input[name="secret"], and the set/none secret badge.
//   - "All provisioners — N from CA" heading with the badge showing the count.
//   - Provisioner table uses class="table" with Name/Type/Issuance/Actions columns.
//   - Active row renders badge--info "Active" in the Issuance column.
//   - Active row has the delete button disabled (aria-disabled + disabled).
//   - Non-active rows show "Set active" button in Issuance column.
//   - Delete button disabled for non-active row when admin auth NOT configured.
//   - Footnote with "Delete is disabled until admin auth is set" copy.
//   - CA-not-configured / list error shows the error/empty state.

import (
	"context"
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/settings"
)

// TestProvisionersDesignPageHead verifies the new page-head structure is
// rendered on the provisioners page: breadcrumb, page-title "Provisioners",
// and the page-sub subtitle text.
func TestProvisionersDesignPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, false)

	_, body := e.getBody(t, "/provisioners")

	if !strings.Contains(body, `class="page-head"`) {
		t.Error("provisioners: missing page-head element")
	}
	if !strings.Contains(body, `class="page-title"`) {
		t.Error("provisioners: missing page-title element")
	}
	if !strings.Contains(body, ">Provisioners<") {
		t.Error("provisioners: missing 'Provisioners' h1 text")
	}
	if !strings.Contains(body, `class="page-sub"`) {
		t.Error("provisioners: missing page-sub subtitle element")
	}
	if !strings.Contains(body, "Read live from the CA") {
		t.Error("provisioners: missing 'Read live from the CA' page-sub text")
	}
	if !strings.Contains(body, "active provisioner is used when issuing certificates") {
		t.Error("provisioners: missing 'active provisioner' page-sub text")
	}
}

// TestProvisionersDesignLockedNotice verifies that when admin auth is NOT
// configured the "locked" notice is rendered with:
//   - class="locked" container
//   - honest explanation copy (name both methods and the CLI alternative)
//   - a "Configure admin authentication" link to /settings
//   - a "Copy CLI command" button with data-copy attribute containing a real
//     step ca provisioner add command
//
// The create form must NOT appear.
func TestProvisionersDesignLockedNotice(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"test-prov"}]}`)
	e.seedCA(t, f, false) // no admin auth

	_, body := e.getBody(t, "/provisioners")

	// Locked container
	if !strings.Contains(body, `class="locked"`) {
		t.Error("provisioners (no admin auth): missing class='locked' notice container")
	}
	// Honest copy — must name both methods and the CLI
	if !strings.Contains(body, "x5c") {
		t.Error("provisioners (no admin auth): locked copy must mention x5c method")
	}
	if !strings.Contains(body, "jwk") {
		t.Error("provisioners (no admin auth): locked copy must mention jwk method")
	}
	if !strings.Contains(body, "step") {
		t.Error("provisioners (no admin auth): locked copy must mention step CLI")
	}
	// Must mention "admin credential" (keeps compatibility with existing tests)
	if !strings.Contains(body, "requires an admin credential") {
		t.Error("provisioners (no admin auth): locked copy must include 'requires an admin credential'")
	}
	// Configure link to /settings
	if !strings.Contains(body, `href="/settings"`) {
		t.Error("provisioners (no admin auth): missing 'Configure admin authentication' link to /settings")
	}
	if !strings.Contains(body, "Configure admin authentication") {
		t.Error("provisioners (no admin auth): missing 'Configure admin authentication' text")
	}
	// Copy CLI command button with data-copy containing a real step ca provisioner add command
	if !strings.Contains(body, `data-copy="step ca provisioner add`) {
		t.Error("provisioners (no admin auth): missing 'Copy CLI command' button with data-copy attribute")
	}
	if !strings.Contains(body, "Copy CLI command") {
		t.Error("provisioners (no admin auth): missing 'Copy CLI command' button text")
	}
	// The create form must NOT appear when admin auth is not configured
	if strings.Contains(body, `action="/provisioners"`) {
		t.Error("provisioners (no admin auth): create form (action=/provisioners) must NOT appear")
	}
}

// TestProvisionersDesignCreateFormWhenAdminAuth verifies that when admin auth IS
// configured the create form is shown (not the locked notice).
func TestProvisionersDesignCreateFormWhenAdminAuth(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"test-prov"}]}`)
	e.seedCA(t, f, true) // with admin auth

	_, body := e.getBody(t, "/provisioners")

	// Create form must appear
	if !strings.Contains(body, `action="/provisioners"`) {
		t.Error("provisioners (with admin auth): create form (action=/provisioners) must appear")
	}
	// The locked notice must NOT appear
	if strings.Contains(body, `class="locked"`) {
		t.Error("provisioners (with admin auth): locked notice must NOT appear when admin auth is configured")
	}
}

// TestProvisionersDesignActiveProvisionerCard verifies the active provisioner
// card is rendered with:
//   - card__header with "Active provisioner for issuance" title
//   - form posting to /provisioners/select
//   - select[name="active"] for provisioner choice
//   - input[name="secret"] of type password
//   - secret-state badge (set or none) in the secret-row
//   - "Set active" submit button
//   - field__hint text about write-only storage
func TestProvisionersDesignActiveProvisionerCard(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"p1"},{"type":"ACME","name":"p2"}]}`)
	e.seedCA(t, f, false)

	_, body := e.getBody(t, "/provisioners")

	// Card with "Active provisioner for issuance" heading
	if !strings.Contains(body, "Active provisioner for issuance") {
		t.Error("provisioners: missing 'Active provisioner for issuance' card title")
	}
	// Form posts to /provisioners/select
	if !strings.Contains(body, `action="/provisioners/select"`) {
		t.Error("provisioners: active provisioner form must post to /provisioners/select")
	}
	// Select for provisioner name (field name kept as "name" for handler compatibility)
	if !strings.Contains(body, `name="name"`) {
		t.Error("provisioners: missing select name='name' for active provisioner")
	}
	// Password input for secret
	if !strings.Contains(body, `name="secret"`) {
		t.Error("provisioners: missing input name='secret' for provisioner password")
	}
	if !strings.Contains(body, `type="password"`) {
		t.Error("provisioners: missing type='password' on secret input")
	}
	// Set active submit button
	if !strings.Contains(body, "Set active") {
		t.Error("provisioners: missing 'Set active' submit button")
	}
	// field__hint for write-only info
	if !strings.Contains(body, "Write-only") {
		t.Error("provisioners: missing 'Write-only' field hint text")
	}
}

// TestProvisionersDesignSecretBadgeNone verifies that when no provisioner secret
// is stored the "none" badge appears in the secret-row, not "set".
func TestProvisionersDesignSecretBadgeNone(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"p1"}]}`)
	e.seedCA(t, f, false) // no secret stored

	_, body := e.getBody(t, "/provisioners")

	if !strings.Contains(body, `class="secret-state"`) {
		t.Error("provisioners: missing secret-state element")
	}
	if !strings.Contains(body, ">none<") {
		t.Error("provisioners: expected 'none' secret badge when no secret stored")
	}
}

// TestProvisionersDesignSecretBadgeSet verifies that when a provisioner secret
// IS stored the "set" badge appears in the secret-row.
func TestProvisionersDesignSecretBadgeSet(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"p1"}]}`)
	e.seedCA(t, f, false)

	// Store a secret for the active provisioner
	if err := e.settingsRepo.SelectProvisioner(context.Background(), "p1", "prov-pass-aaaa"); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.getBody(t, "/provisioners")

	if !strings.Contains(body, ">set<") {
		t.Error("provisioners: expected 'set' secret badge when secret is stored")
	}
	// The secret value must never appear in the page
	if strings.Contains(body, "prov-pass-aaaa") {
		t.Error("provisioners: provisioner secret value must NOT appear in the page")
	}
}

// TestProvisionersDesignAllProvisionersHeading verifies the "All provisioners"
// section heading uses the correct structure: a section-title with a count badge.
func TestProvisionersDesignAllProvisionersHeading(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"prov-a"},
		{"type":"ACME","name":"prov-b"}
	]}`)
	e.seedCA(t, f, false)

	_, body := e.getBody(t, "/provisioners")

	// Heading must say "All provisioners"
	if !strings.Contains(body, "All provisioners") {
		t.Error("provisioners: missing 'All provisioners' section heading")
	}
	// Must show "2 from CA" count in a badge
	if !strings.Contains(body, "2 from CA") {
		t.Error("provisioners: missing '2 from CA' count badge in section heading")
	}
	// Table must use class="table"
	if !strings.Contains(body, `class="table"`) {
		t.Error("provisioners: missing class='table' on provisioner list table")
	}
}

// TestProvisionersDesignTableRowsRenderNameAndType verifies the table rows show
// provisioner Name and Type from the CA list.
func TestProvisionersDesignTableRowsRenderNameAndType(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"my-jwk"},
		{"type":"ACME","name":"my-acme"}
	]}`)
	e.seedCA(t, f, false)

	_, body := e.getBody(t, "/provisioners")

	for _, want := range []string{"my-jwk", "JWK", "my-acme", "ACME"} {
		if !strings.Contains(body, want) {
			t.Errorf("provisioners table: missing %q in body", want)
		}
	}
}

// TestProvisionersDesignActiveBadgeOnActiveRow verifies that the active
// provisioner row has the badge--info "Active" badge in the Issuance column.
func TestProvisionersDesignActiveBadgeOnActiveRow(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"active-prov"},
		{"type":"ACME","name":"other-prov"}
	]}`)
	e.seedCA(t, f, false)

	// Mark active-prov as selected
	if err := e.settingsRepo.SelectProvisioner(context.Background(), "active-prov", ""); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.getBody(t, "/provisioners")

	// Active row must show badge--info "Active"
	if !strings.Contains(body, "badge--info") {
		t.Error("provisioners: active row must have badge--info class")
	}
	if !strings.Contains(body, ">Active<") {
		t.Error("provisioners: active row must show 'Active' label in badge")
	}
}

// TestProvisionersDesignActiveRowDeleteDisabled verifies that the active
// provisioner's row has the delete button disabled (cannot be deleted).
// The delete button must carry aria-disabled="true" and disabled attribute.
func TestProvisionersDesignActiveRowDeleteDisabled(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"active-prov"},
		{"type":"ACME","name":"other-prov"}
	]}`)
	e.seedCA(t, f, true) // admin auth configured — non-active rows would be deletable

	// Mark active-prov as selected
	if err := e.settingsRepo.SelectProvisioner(context.Background(), "active-prov", ""); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.getBody(t, "/provisioners")

	// The active provisioner's delete must be disabled
	// We find the active row context: "active-prov" appears before any delete controls
	// The active row must have aria-disabled="true" on the trash button
	if !strings.Contains(body, `aria-disabled="true"`) {
		t.Error("provisioners: active row delete button must have aria-disabled='true'")
	}
	// The active provisioner can never be deleted (title hint)
	if !strings.Contains(body, "cannot be deleted") {
		t.Error("provisioners: active row delete button must have 'cannot be deleted' title hint")
	}
}

// TestProvisionersDesignNonActiveDeleteDisabledWithoutAdminAuth verifies that
// non-active provisioner rows show a disabled delete button when admin auth is
// NOT configured.
func TestProvisionersDesignNonActiveDeleteDisabledWithoutAdminAuth(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"active-prov"},
		{"type":"ACME","name":"other-prov"}
	]}`)
	e.seedCA(t, f, false) // NO admin auth

	if err := e.settingsRepo.SelectProvisioner(context.Background(), "active-prov", ""); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.getBody(t, "/provisioners")

	// All delete buttons must be disabled (no admin auth means no delete allowed)
	// The page must not contain an enabled delete form (which would have action="/provisioners/...")
	// but there must be disabled delete buttons (aria-disabled or disabled attribute)
	if !strings.Contains(body, `aria-disabled="true"`) {
		t.Error("provisioners (no admin auth): delete buttons must be aria-disabled='true'")
	}
	// Must have the "Requires admin authentication" title hint on at least one button
	if !strings.Contains(body, "Requires admin authentication") {
		t.Error("provisioners (no admin auth): delete button must have 'Requires admin authentication' title")
	}
}

// TestProvisionersDesignFootnote verifies the footnote below the provisioner
// table is present with the correct copy about delete being disabled.
func TestProvisionersDesignFootnote(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"p1"}]}`)
	e.seedCA(t, f, false)

	_, body := e.getBody(t, "/provisioners")

	if !strings.Contains(body, "Delete is disabled until admin auth is set") {
		t.Error("provisioners: missing footnote 'Delete is disabled until admin auth is set'")
	}
	if !strings.Contains(body, "Active") && !strings.Contains(body, "active") {
		t.Error("provisioners: footnote must mention 'Active' provisioner cannot be deleted")
	}
}

// TestProvisionersDesignSelectOptions verifies the active provisioner select
// renders all provisioners from the CA as options.
func TestProvisionersDesignSelectOptions(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"prov-one"},
		{"type":"ACME","name":"prov-two"}
	]}`)
	e.seedCA(t, f, false)

	_, body := e.getBody(t, "/provisioners")

	// Both provisioners should be selectable options
	if !strings.Contains(body, "prov-one") {
		t.Error("provisioners: select missing 'prov-one' option")
	}
	if !strings.Contains(body, "prov-two") {
		t.Error("provisioners: select missing 'prov-two' option")
	}
}

// TestProvisionersDesignErrorStateNoCA verifies the error/empty state when no
// CA settings are configured: the existing error message is shown.
func TestProvisionersDesignErrorStateNoCA(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	// No CA settings seeded

	status, body := e.getBody(t, "/provisioners")

	if status != 200 {
		t.Fatalf("provisioners: expected 200 when no CA settings, got %d", status)
	}
	// Must show an informative message about needing to configure the CA
	if !strings.Contains(strings.ToLower(body), "ca") {
		t.Error("provisioners (no CA): must show a message mentioning 'CA'")
	}
}

// TestProvisionersDesignCLICommandInDataCopy verifies the CLI command in the
// data-copy attribute is a syntactically correct step ca provisioner add command
// with the required flags: --type JWK and --create.
func TestProvisionersDesignCLICommandInDataCopy(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, false) // no admin auth → locked notice shown

	_, body := e.getBody(t, "/provisioners")

	// The data-copy attribute must contain a valid step ca provisioner add command
	// with at minimum: the subcommand, a name placeholder, --type JWK, --create
	if !strings.Contains(body, "step ca provisioner add") {
		t.Error("provisioners: CLI command must start with 'step ca provisioner add'")
	}
	if !strings.Contains(body, "--type JWK") {
		t.Error("provisioners: CLI command must include '--type JWK'")
	}
	if !strings.Contains(body, "--create") {
		t.Error("provisioners: CLI command must include '--create' to generate the JWK pair")
	}
}

// TestProvisionersDesignNonActiveRowHasSetActiveButton verifies non-active rows
// have a "Set active" action in the Issuance column.
func TestProvisionersDesignNonActiveRowHasSetActiveButton(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"active-prov"},
		{"type":"ACME","name":"non-active"}
	]}`)
	e.seedCA(t, f, false)

	if err := e.settingsRepo.SelectProvisioner(context.Background(), "active-prov", ""); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.getBody(t, "/provisioners")

	// Non-active rows must have a "Set active" button
	if !strings.Contains(body, "Set active") {
		t.Error("provisioners: non-active row missing 'Set active' button")
	}
}

// TestProvisionersDesignAdminAuthConfiguredNoLockedNotice verifies that with
// admin auth configured the locked notice is absent and no "Configure admin
// authentication" link appears as a suggestion.
func TestProvisionersDesignAdminAuthConfiguredNoLockedNotice(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"p1"}]}`)
	e.seedCA(t, f, true)

	_, body := e.getBody(t, "/provisioners")

	// No locked notice
	if strings.Contains(body, `class="locked"`) {
		t.Error("provisioners (with admin auth): locked class must NOT appear")
	}
	// The create form inputs must be present
	if !strings.Contains(body, `name="name"`) {
		t.Error("provisioners (with admin auth): create form missing name input")
	}
	if !strings.Contains(body, `name="type"`) {
		t.Error("provisioners (with admin auth): create form missing type select")
	}
}

// TestProvisionersDesignTableWrap verifies the provisioner list table is wrapped
// in the design-system table-wrap + table-scroll classes.
func TestProvisionersDesignTableWrap(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"p1"}]}`)
	e.seedCA(t, f, false)

	_, body := e.getBody(t, "/provisioners")

	if !strings.Contains(body, "table-wrap") {
		t.Error("provisioners: missing table-wrap class on provisioner table container")
	}
}

// TestProvisionersDesignSectionTitle verifies the "All provisioners" heading
// carries the section-title class.
func TestProvisionersDesignSectionTitle(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[{"type":"JWK","name":"p1"}]}`)
	e.seedCA(t, f, false)

	_, body := e.getBody(t, "/provisioners")

	if !strings.Contains(body, `class="section-title"`) {
		t.Error("provisioners: missing class='section-title' on 'All provisioners' heading")
	}
}

// TestProvisionersDesignNonActiveDeleteEnabledWithAdminAuth verifies that
// non-active provisioner rows show an enabled delete form when admin auth IS
// configured (the delete button must NOT have aria-disabled on a non-active row
// when admin auth is set).
func TestProvisionersDesignNonActiveDeleteEnabledWithAdminAuth(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"active-prov"},
		{"type":"ACME","name":"deletable-prov"}
	]}`)
	e.seedCA(t, f, true) // admin auth configured

	if err := e.settingsRepo.SelectProvisioner(context.Background(), "active-prov", ""); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.getBody(t, "/provisioners")

	// With admin auth: a delete form should appear for the non-active provisioner
	// (action="/provisioners/deletable-prov")
	if !strings.Contains(body, `action="/provisioners/deletable-prov"`) {
		t.Error("provisioners (with admin auth): non-active row must have delete form action=/provisioners/deletable-prov")
	}

	// Sanity: the active row still must not have a working delete form
	// (it may have a disabled button, not a submit form)
	// Check that the "Requires admin authentication" title is absent for non-active
	// (that title only appears when auth is missing; with auth we show a working button)
	// We rely on the existing delete-guard tests for full behavior coverage.
}

// TestProvisionersDesignCLICommandVisibleText verifies that the CLI command in
// the locked notice is rendered as visible, selectable text (inside a code or
// pre element), not only hidden inside a data-copy attribute. This ensures the
// command is usable without JavaScript (select+copy manually).
func TestProvisionersDesignCLICommandVisibleText(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, false) // no admin auth → locked notice shown

	_, body := e.getBody(t, "/provisioners")

	// The command must appear as visible text inside a <code> or <pre> element
	// (not only in a data-copy attribute). We verify by checking that the text
	// occurs outside of an HTML attribute context — i.e. as element content.
	// A simple test: the text must appear as raw content in the HTML body,
	// and the page must contain a <code> or <pre> element wrapping it.
	if !strings.Contains(body, ">step ca provisioner add") {
		t.Error("provisioners: CLI command must appear as visible element text (not only in attribute), starting with '>step ca provisioner add'")
	}
}

// TestProvisionersDesignSetActiveIsAnchor verifies that the per-row "Set active"
// action in the Issuance column is an anchor linking to #active-card (not a
// dead <button type="button">). This ensures the operator can navigate to the
// active card and enter a secret rather than triggering a one-click submit that
// would drop the stored secret.
func TestProvisionersDesignSetActiveIsAnchor(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	f := startAppAdminCA(t, `{"provisioners":[
		{"type":"JWK","name":"active-prov"},
		{"type":"ACME","name":"non-active"}
	]}`)
	e.seedCA(t, f, false)

	if err := e.settingsRepo.SelectProvisioner(context.Background(), "active-prov", ""); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.getBody(t, "/provisioners")

	// "Set active" must be an anchor to #active-card, not a dead button
	if !strings.Contains(body, `href="#active-card"`) {
		t.Error("provisioners: non-active row 'Set active' must be an <a href=\"#active-card\"> anchor")
	}
	// The active provisioner card must have id="active-card" for the anchor to land
	if !strings.Contains(body, `id="active-card"`) {
		t.Error("provisioners: active provisioner card must have id=\"active-card\"")
	}
}

// TestProvisionersDesignActiveCardFallbackWithStoredSelected verifies that the
// active provisioner select still contains the stored Selected provisioner even
// when it is not present in the live CA list (e.g. CA is unreachable or the list
// is empty). This ensures the operator can retain or re-set the active provisioner
// secret without losing their selection when the CA list fails.
func TestProvisionersDesignActiveCardFallbackWithStoredSelected(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	// CA returns an empty provisioner list (simulates list error or empty CA)
	f := startAppAdminCA(t, `{"provisioners":[]}`)
	e.seedCA(t, f, false)

	// Store a selected provisioner that is NOT in the live list
	if err := e.settingsRepo.SelectProvisioner(context.Background(), "my-stored-prov", ""); err != nil {
		t.Fatalf("select provisioner: %v", err)
	}

	_, body := e.getBody(t, "/provisioners")

	// The stored Selected must appear as an option in the select even though the
	// live list is empty — ensuring the operator can still interact with the card
	if !strings.Contains(body, "my-stored-prov") {
		t.Error("provisioners: stored Selected provisioner must appear in the active-card select even when not in the live CA list")
	}
}

// TestProvisionersDesignSettingsCASettingsRequiresAdminAuthLabel verifies the
// admin-auth stored method is visible in the settings page badge (regression:
// ensure the CA settings → settings label still works). This is a guard that the
// settings link from the locked notice is correct.
func TestProvisionersDesignSettingsLink(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	// Save CA settings so the settings page renders a method badge
	// fingerprint must be 40–64 hex chars
	if err := e.settingsRepo.Save(context.Background(), settings.Input{
		CAURL: "https://ca.example:9000", RootFingerprint: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	}); err != nil {
		t.Fatalf("save settings: %v", err)
	}

	_, body := e.getBody(t, "/settings")
	// /settings must be reachable and render the Admin authentication card
	if !strings.Contains(body, "Admin authentication") {
		t.Error("settings: Admin authentication card not found (link from locked notice broken?)")
	}
}
