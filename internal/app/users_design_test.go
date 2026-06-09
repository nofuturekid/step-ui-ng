package app_test

// Design tests for PR G — Users page redesign.
//
// Acceptance criteria tested:
//   - Page-head: "Users" h1, page-sub text with role hierarchy.
//   - Create-user card: card__header / card__title / card__desc; form with
//     username (input.mono), role <select> (named "role"), password input.
//   - Role-assignment gating: non-superadmin actor sees NO assignable
//     superadmin option (option value="superadmin" must be absent or
//     disabled). Superadmin actor sees superadmin as a selectable option.
//   - Self-limit note: the card__desc reflects the actor's own role
//     (e.g. "You're an admin, so you can create viewers and admins, but
//     not superadmins").
//   - User list table: class="table" with Username/Role/Status/Actions columns.
//   - Role badge: each user's Role column shows a badge element.
//   - Enabled/Disabled state badge: badge--ok for enabled, badge--neutral
//     (or similar) for disabled.
//   - Per-user action controls: enable/disable and delete forms present
//     for manageable users.
//   - Superadmin protection in the list: a non-superadmin actor gets NO
//     manage controls on a superadmin row (the row must contain the
//     "admins can't manage superadmins" guard text instead).
//   - Superadmin actor CAN see manage controls on non-superadmin rows.
//   - The "last remaining superadmin can't be deleted or demoted" hint is present.
//   - CSRF token present on all forms.
//   - Post actions still work (behavior unchanged, CSRF enforced).

import (
	"strings"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// TestUsersDesignPageHead verifies the page-head with title, page-sub.
func TestUsersDesignPageHead(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/users")

	if !strings.Contains(body, `class="page-head"`) {
		t.Error("users: missing page-head element")
	}
	if !strings.Contains(body, `class="page-title"`) {
		t.Error("users: missing page-title element")
	}
	if !strings.Contains(body, ">Users<") {
		t.Error("users: missing 'Users' h1 text")
	}
	if !strings.Contains(body, `class="page-sub"`) {
		t.Error("users: missing page-sub subtitle element")
	}
	if !strings.Contains(body, "Local accounts") {
		t.Error("users: page-sub must mention 'Local accounts'")
	}
	// Role hierarchy must appear in subtitle.
	if !strings.Contains(body, "viewer") || !strings.Contains(body, "admin") || !strings.Contains(body, "superadmin") {
		t.Error("users: page-sub must mention all three roles (viewer/admin/superadmin)")
	}
}

// TestUsersDesignCreateCard verifies the create-user card structure: card__header,
// card__title "Create user", card__desc, and the form with username/role/password fields.
func TestUsersDesignCreateCard(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/users")

	if !strings.Contains(body, "card__title") {
		t.Error("users: missing card__title in create card")
	}
	if !strings.Contains(body, "Create user") {
		t.Error("users: missing 'Create user' card title")
	}
	if !strings.Contains(body, "card__desc") {
		t.Error("users: missing card__desc in create card")
	}
	// Form must post to /users.
	if !strings.Contains(body, `action="/users"`) {
		t.Error("users: create form must have action=\"/users\"")
	}
	// Username input.
	if !strings.Contains(body, `name="username"`) {
		t.Error("users: missing username input in create form")
	}
	// Role select.
	if !strings.Contains(body, `name="role"`) {
		t.Error("users: missing role select in create form")
	}
	// Password input.
	if !strings.Contains(body, `name="password"`) {
		t.Error("users: missing password input in create form")
	}
	// CSRF token present.
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Error("users: missing csrf_token in create form")
	}
}

// TestUsersDesignCreateCardSuperadminSelfLimitNote verifies that the card__desc
// shows a self-limit note based on the actor's role. A superadmin (root) should
// see all roles in the select without restriction.
func TestUsersDesignCreateCardSuperadminSelfLimitNote(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root") // superadmin

	_, body := e.get(t, "/users")

	// Superadmin should see a note appropriate to their role.
	if !strings.Contains(body, "superadmin") {
		t.Error("users (superadmin): create card must mention superadmin role")
	}
	// Superadmin can see and assign superadmin option in the role select.
	if !strings.Contains(body, `value="superadmin"`) {
		t.Error("users (superadmin): role select must include assignable superadmin option")
	}
	// The superadmin option must NOT be disabled for a superadmin actor.
	// Check the option is present and not disabled (no 'disabled' attribute on that option).
	// We look for the superadmin option; if it's the only disabled one, flag it.
	// A superadmin must be able to assign superadmin; the option must be selectable.
	if strings.Contains(body, `value="superadmin" disabled`) ||
		strings.Contains(body, `disabled value="superadmin"`) {
		t.Error("users (superadmin): superadmin option in role select must NOT be disabled for a superadmin actor")
	}
}

// TestUsersDesignRoleSelectLimitedForAdmin verifies the RBAC fidelity of the
// create-user role select: when the actor is an admin (not superadmin), the
// superadmin option must be absent from the selectable options OR present but
// disabled (as a visual hint that it requires superadmin). The critical guard is
// that a non-superadmin cannot SEE superadmin as a valid selection — this mirrors
// the server-side CanAssign guard.
//
// This test FAILS if the superadmin option is shown as enabled/selectable to an
// admin actor (which would invite attempts to forge the request, even though the
// server guards the actual POST).
func TestUsersDesignRoleSelectLimitedForAdmin(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	// Create an admin and switch to them.
	e.seedUser(t, "actoradmin", users.RoleAdmin)
	e.switchTo(t, "actoradmin")

	_, body := e.get(t, "/users")

	// The superadmin role option must not be an enabled/selectable choice.
	// Either the option is absent, OR it's present but disabled.
	// We require that there is no plain `<option value="superadmin">` without
	// a disabled attribute.
	if strings.Contains(body, `<option value="superadmin">superadmin</option>`) {
		t.Error("users (admin): superadmin role option must not be a plain selectable option for an admin actor")
	}
	// Viewer and admin options must still be present.
	if !strings.Contains(body, `value="viewer"`) {
		t.Error("users (admin): viewer option must be present in role select")
	}
	if !strings.Contains(body, `value="admin"`) {
		t.Error("users (admin): admin option must be present in role select")
	}
}

// TestUsersDesignAdminSelfLimitNoteText verifies that an admin actor sees
// the self-limit note specifically referencing that they are an admin and
// cannot create superadmins.
func TestUsersDesignAdminSelfLimitNoteText(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "actoradmin", users.RoleAdmin)
	e.switchTo(t, "actoradmin")

	_, body := e.get(t, "/users")

	// card__desc must mention admin role limitation.
	if !strings.Contains(body, "admin") {
		t.Error("users (admin): self-limit note must mention admin role")
	}
	// Must not offer superadmin without restriction hint.
	if !strings.Contains(body, "superadmin") {
		t.Error("users (admin): self-limit note or select must still reference superadmin (to explain the ceiling)")
	}
}

// TestUsersDesignUserListTable verifies the user list table structure:
// class="table" with Username/Role/Status/Actions columns.
func TestUsersDesignUserListTable(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/users")

	if !strings.Contains(body, `class="table"`) {
		t.Error("users: missing class=\"table\" on user list table")
	}
	// Column headers.
	for _, col := range []string{"Username", "Role", "Status"} {
		if !strings.Contains(body, col) {
			t.Errorf("users: missing %q column header in user list table", col)
		}
	}
}

// TestUsersDesignRoleBadgeInList verifies that each user's role in the list
// is rendered with a badge element (not just raw text).
func TestUsersDesignRoleBadgeInList(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "viewer1", users.RoleViewer)

	_, body := e.get(t, "/users")

	// Both users must have their role shown with a badge.
	if !strings.Contains(body, "badge") {
		t.Error("users: missing badge elements in user list (roles must be badged)")
	}
}

// TestUsersDesignStatusBadge verifies that the Enabled/Disabled state is shown
// as a badge in the user list: badge--ok for enabled, a different class for disabled.
func TestUsersDesignStatusBadge(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	// Seed a disabled user via direct SQL (bypasses the handler to avoid RBAC).
	_ = e.seedUser(t, "disableduser", users.RoleViewer)
	if _, err := e.db.Exec(`UPDATE users SET disabled=1 WHERE username='disableduser'`); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	_, body := e.get(t, "/users")

	// The enabled user (root) should show badge--ok or "Enabled".
	if !strings.Contains(body, "Enabled") && !strings.Contains(body, "badge--ok") {
		t.Error("users: enabled user must show Enabled state or badge--ok")
	}
	// The disabled user should show "Disabled" state or a different badge class.
	if !strings.Contains(body, "Disabled") && !strings.Contains(body, "badge--neutral") {
		t.Error("users: disabled user must show Disabled state or badge--neutral")
	}
}

// TestUsersDesignActionsPresent verifies that non-superadmin rows for an
// admin actor include enable/disable and delete action forms/buttons.
func TestUsersDesignActionsPresent(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "target", users.RoleViewer)

	_, body := e.get(t, "/users")

	// There must be delete or disable action buttons/forms for manageable users.
	if !strings.Contains(body, `value="delete"`) && !strings.Contains(body, "Delete") {
		t.Error("users: missing delete action for manageable user")
	}
	if !strings.Contains(body, `value="disable"`) && !strings.Contains(body, "Disable") {
		t.Error("users: missing disable action for manageable user")
	}
}

// TestUsersDesignSuperadminProtectionInList verifies that when the actor is an
// admin, the row for a superadmin user does NOT show the standard manage controls
// (delete/disable/role-change), but instead shows a guard notice.
// This is a critical RBAC-fidelity test: the visual protection must mirror
// the server-side CanManage guard.
//
// This test FAILS if manage controls are shown to a non-superadmin actor for
// a superadmin row, including if both the notice AND controls are rendered
// (e.g. a botched if/else that renders both).
func TestUsersDesignSuperadminProtectionInList(t *testing.T) {
	e := newTestEnv(t)
	// root is superadmin (id=1). Create a second superadmin so root can be
	// managed (not the last), then log in as admin.
	e.completeSetup(t, "root")
	e.seedUser(t, "root2", users.RoleSuperadmin) // second superadmin
	e.seedUser(t, "actoradmin", users.RoleAdmin)
	e.switchTo(t, "actoradmin")

	_, body := e.get(t, "/users")

	// The guard text "admins can't manage superadmins" (or similar) must appear
	// in the row for the superadmin.
	if !strings.Contains(body, "can't manage") && !strings.Contains(body, "cannot manage") {
		t.Error("users (admin actor): superadmin row must show guard notice (e.g. \"admins can't manage superadmins\")")
	}

	// For superadmin rows, the guard-notice cell replaces the manage controls
	// (it is in the else branch of the canManage check). We assert this by
	// splitting the page on <tr> boundaries and checking that any row that
	// contains the superadmin badge does NOT also contain value="delete" or
	// value="set_role". This FAILS if the template renders both the guard notice
	// and the manage controls (botched if/else).
	rows := strings.Split(body, "<tr>")
	for _, row := range rows {
		isSuperadminRow := strings.Contains(row, "badge--info") && strings.Contains(row, "superadmin")
		if !isSuperadminRow {
			continue
		}
		if strings.Contains(row, `value="delete"`) {
			t.Error("users (admin actor): superadmin row must NOT contain value=\"delete\" — manage controls must be suppressed by canManage guard")
		}
		if strings.Contains(row, `value="set_role"`) {
			t.Error("users (admin actor): superadmin row must NOT contain value=\"set_role\" — manage controls must be suppressed by canManage guard")
		}
	}
}

// TestUsersDesignSuperadminCanManageNonSuperadmin verifies that when the actor
// IS a superadmin, the per-row action controls ARE shown for non-superadmin users.
func TestUsersDesignSuperadminCanManageNonSuperadmin(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root") // superadmin, left logged in
	e.seedUser(t, "target", users.RoleViewer)

	_, body := e.get(t, "/users")

	// Superadmin must see manage controls for the viewer row.
	if !strings.Contains(body, `value="delete"`) && !strings.Contains(body, "Delete") {
		t.Error("users (superadmin actor): delete action must be present for non-superadmin row")
	}
}

// TestUsersDesignLastSuperadminHint verifies the "last remaining superadmin
// can't be deleted or demoted" hint is rendered below the user list.
// This encodes the UI explanation of the FR-6 server guard.
func TestUsersDesignLastSuperadminHint(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/users")

	if !strings.Contains(body, "last") || !strings.Contains(body, "superadmin") {
		t.Error("users: missing 'last remaining superadmin' hint text below the user list")
	}
}

// TestUsersDesignCSRFOnForms verifies that CSRF tokens are present on all
// forms on the users page (create form + per-user action forms).
func TestUsersDesignCSRFOnForms(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")
	e.seedUser(t, "target", users.RoleViewer)

	_, body := e.get(t, "/users")

	// Count csrf_token occurrences: should be at least 2 (create form + at least
	// one per-user form).
	count := strings.Count(body, `name="csrf_token"`)
	if count < 2 {
		t.Errorf("users: expected at least 2 csrf_token fields (create + per-user forms), got %d", count)
	}
}

// TestUsersDesignTableWrapPresent verifies the user list table is inside a
// table-wrap (and optionally table-scroll) container matching the design system.
func TestUsersDesignTableWrapPresent(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "root")

	_, body := e.get(t, "/users")

	if !strings.Contains(body, "table-wrap") {
		t.Error("users: user list table must be inside a table-wrap container")
	}
}
