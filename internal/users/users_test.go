package users_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/store"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// newRepo returns a Repo backed by a freshly migrated, isolated database.
func newRepo(t *testing.T) *users.Repo {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return users.NewRepo(st.DB())
}

const goodPassword = "correct-horse-battery-staple"

// --- Role -------------------------------------------------------------------

// Roles gate behaviour, so an unknown role must never be treated as valid and
// privilege helpers must reflect the documented hierarchy (FR-4).
func TestRoleValid(t *testing.T) {
	for _, r := range []users.Role{users.RoleSuperadmin, users.RoleAdmin, users.RoleViewer} {
		if !r.Valid() {
			t.Errorf("%q should be valid", r)
		}
	}
	for _, r := range []users.Role{"", "root", "Admin", "SUPERADMIN"} {
		if users.Role(r).Valid() {
			t.Errorf("%q should be invalid", r)
		}
	}
}

// CanManageUsers must admit admin and superadmin but never viewer; a viewer
// reaching a mutating handler is the bug this guards (acceptance: viewer → 403).
func TestRoleCanManageUsers(t *testing.T) {
	cases := map[users.Role]bool{
		users.RoleSuperadmin: true,
		users.RoleAdmin:      true,
		users.RoleViewer:     false,
	}
	for role, want := range cases {
		if got := role.CanManageUsers(); got != want {
			t.Errorf("%q.CanManageUsers() = %v, want %v", role, got, want)
		}
	}
}

// CanAssign enforces the role ceiling: an actor may never grant a role above
// their own (admin cannot mint/promote to superadmin), which is the core of the
// privilege-escalation fix (FR-4).
func TestRoleCanAssign(t *testing.T) {
	cases := []struct {
		actor, target users.Role
		want          bool
	}{
		{users.RoleSuperadmin, users.RoleSuperadmin, true},
		{users.RoleSuperadmin, users.RoleAdmin, true},
		{users.RoleSuperadmin, users.RoleViewer, true},
		{users.RoleAdmin, users.RoleSuperadmin, false}, // ceiling
		{users.RoleAdmin, users.RoleAdmin, true},
		{users.RoleAdmin, users.RoleViewer, true},
		{users.RoleViewer, users.RoleViewer, true},
		{users.RoleViewer, users.RoleAdmin, false},
	}
	for _, c := range cases {
		if got := c.actor.CanAssign(c.target); got != c.want {
			t.Errorf("%q.CanAssign(%q) = %v, want %v", c.actor, c.target, got, c.want)
		}
	}
}

// CanManage protects superadmin accounts: only a superadmin may delete/disable/
// re-role an existing superadmin; an admin is limited to admin/viewer targets.
func TestRoleCanManage(t *testing.T) {
	cases := []struct {
		actor, target users.Role
		want          bool
	}{
		{users.RoleSuperadmin, users.RoleSuperadmin, true},
		{users.RoleSuperadmin, users.RoleAdmin, true},
		{users.RoleSuperadmin, users.RoleViewer, true},
		{users.RoleAdmin, users.RoleSuperadmin, false}, // protected
		{users.RoleAdmin, users.RoleAdmin, true},
		{users.RoleAdmin, users.RoleViewer, true},
		{users.RoleViewer, users.RoleViewer, false}, // viewers cannot manage
		{users.RoleViewer, users.RoleAdmin, false},
	}
	for _, c := range cases {
		if got := c.actor.CanManage(c.target); got != c.want {
			t.Errorf("%q.CanManage(%q) = %v, want %v", c.actor, c.target, got, c.want)
		}
	}
}

// --- Count / gating ---------------------------------------------------------

// First-run gating (FR-1) keys off Count==0, so it must start at zero and track
// creates exactly.
func TestCountGating(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	if n, err := repo.Count(ctx); err != nil || n != 0 {
		t.Fatalf("Count on empty = (%d, %v), want (0, nil)", n, err)
	}
	if _, err := repo.Create(ctx, "alice", goodPassword, users.RoleSuperadmin); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n, err := repo.Count(ctx); err != nil || n != 1 {
		t.Fatalf("Count after one create = (%d, %v), want (1, nil)", n, err)
	}
}

// --- Create -----------------------------------------------------------------

// Create must persist a usable user and never expose or store the plaintext;
// the returned User carries no password field at all (FR-2/FR-7).
func TestCreateReturnsUserWithoutPassword(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	u, err := repo.Create(ctx, "  alice  ", goodPassword, users.RoleAdmin)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("Username = %q, want trimmed %q", u.Username, "alice")
	}
	if u.Role != users.RoleAdmin {
		t.Errorf("Role = %q, want %q", u.Role, users.RoleAdmin)
	}
	if u.ID == 0 {
		t.Error("ID should be assigned")
	}
	if u.CreatedAt == 0 || u.UpdatedAt == 0 {
		t.Error("CreatedAt/UpdatedAt should be set (unix seconds)")
	}
	if u.Disabled {
		t.Error("new user should not be disabled")
	}
}

// The stored hash must be argon2id, never the plaintext — the core of FR-2.
func TestCreateStoresArgon2idHashNotPlaintext(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	u, err := repo.Create(ctx, "alice", goodPassword, users.RoleViewer)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	hash := readPasswordHash(t, repo, u.ID)
	if hash == goodPassword {
		t.Fatal("password stored in plaintext")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash %q is not argon2id", hash)
	}
}

func TestCreateValidation(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	cases := []struct {
		name     string
		username string
		password string
		role     users.Role
		wantErr  error
	}{
		{"empty username", "", goodPassword, users.RoleViewer, users.ErrInvalidUsername},
		{"blank username", "   ", goodPassword, users.RoleViewer, users.ErrInvalidUsername},
		{"short username", "ab", goodPassword, users.RoleViewer, users.ErrInvalidUsername},
		{"weak password", "alice", "short", users.RoleViewer, users.ErrWeakPassword},
		{"invalid role", "alice", goodPassword, users.Role("root"), users.ErrInvalidRole},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := repo.Create(ctx, tc.username, tc.password, tc.role); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Create err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// Usernames are unique (FR data model); duplicate creation must be rejected
// distinctly so the handler can surface a friendly message.
func TestCreateUniqueUsername(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	if _, err := repo.Create(ctx, "alice", goodPassword, users.RoleAdmin); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := repo.Create(ctx, "alice", goodPassword, users.RoleViewer); !errors.Is(err, users.ErrUsernameTaken) {
		t.Fatalf("duplicate Create err = %v, want ErrUsernameTaken", err)
	}
}

// --- CreateFirst (first-run setup, FR-1) ------------------------------------

// CreateFirst creates the initial superadmin only when the table is empty, and
// always as superadmin regardless of input.
func TestCreateFirstCreatesSuperadmin(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	u, err := repo.CreateFirst(ctx, "root", goodPassword)
	if err != nil {
		t.Fatalf("CreateFirst: %v", err)
	}
	if u.Role != users.RoleSuperadmin {
		t.Fatalf("role = %q, want superadmin", u.Role)
	}
	// A second CreateFirst is refused.
	if _, err := repo.CreateFirst(ctx, "root2", goodPassword); !errors.Is(err, users.ErrSetupComplete) {
		t.Fatalf("second CreateFirst err = %v, want ErrSetupComplete", err)
	}
}

// First-run setup must be atomic: many concurrent CreateFirst calls (as two
// racing POST /setup requests would be) must yield exactly one user. Without the
// transactional COUNT+INSERT this can create several superadmins. Must pass
// under `go test -race`.
func TestCreateFirstIsAtomicUnderConcurrency(t *testing.T) {
	for iter := 0; iter < 30; iter++ {
		repo := newRepo(t)
		ctx := context.Background()

		const n = 8
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(i int) {
				defer wg.Done()
				_, _ = repo.CreateFirst(ctx, "root"+strconv.Itoa(i), goodPassword)
			}(i)
		}
		wg.Wait()

		if got, err := repo.Count(ctx); err != nil || got != 1 {
			t.Fatalf("iteration %d: Count = (%d, %v), want exactly 1 user", iter, got, err)
		}
	}
}

// --- Authenticate -----------------------------------------------------------

// The whole login flow hinges on this: right password authenticates, wrong
// password and unknown user both yield ErrInvalidCredentials (no enumeration),
// disabled user yields ErrUserDisabled (FR-7).
func TestAuthenticate(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	if _, err := repo.Create(ctx, "alice", goodPassword, users.RoleAdmin); err != nil {
		t.Fatalf("Create: %v", err)
	}

	t.Run("correct password", func(t *testing.T) {
		u, err := repo.Authenticate(ctx, "alice", goodPassword)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if u.Username != "alice" || u.Role != users.RoleAdmin {
			t.Fatalf("authenticated user = %+v", u)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		if _, err := repo.Authenticate(ctx, "alice", "wrong-password-zzzz"); !errors.Is(err, users.ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		if _, err := repo.Authenticate(ctx, "nobody", goodPassword); !errors.Is(err, users.ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("disabled user", func(t *testing.T) {
		u, err := repo.Create(ctx, "bob", goodPassword, users.RoleViewer)
		if err != nil {
			t.Fatalf("Create bob: %v", err)
		}
		if err := repo.SetDisabled(ctx, u.ID, true); err != nil {
			t.Fatalf("SetDisabled: %v", err)
		}
		if _, err := repo.Authenticate(ctx, "bob", goodPassword); !errors.Is(err, users.ErrUserDisabled) {
			t.Fatalf("err = %v, want ErrUserDisabled", err)
		}
	})
}

// --- List / Get -------------------------------------------------------------

func TestListAndGetByID(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	a, _ := repo.Create(ctx, "alice", goodPassword, users.RoleSuperadmin)
	b, _ := repo.Create(ctx, "bob", goodPassword, users.RoleViewer)

	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}

	got, err := repo.GetByID(ctx, b.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Username != "bob" || got.Role != users.RoleViewer {
		t.Fatalf("GetByID = %+v", got)
	}

	if _, err := repo.GetByID(ctx, a.ID+9999); !errors.Is(err, users.ErrUserNotFound) {
		t.Fatalf("GetByID missing err = %v, want ErrUserNotFound", err)
	}
}

// --- Last-superadmin invariant (FR-6) ---------------------------------------

// A superadmin must never be able to lock everyone out: deleting, disabling, or
// demoting the last enabled superadmin must fail; the same operations succeed
// once a second enabled superadmin exists.
func TestLastSuperadminGuard(t *testing.T) {
	t.Run("delete last superadmin blocked", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()
		su, _ := repo.Create(ctx, "root", goodPassword, users.RoleSuperadmin)
		if err := repo.Delete(ctx, su.ID); !errors.Is(err, users.ErrLastSuperadmin) {
			t.Fatalf("Delete err = %v, want ErrLastSuperadmin", err)
		}
	})

	t.Run("disable last superadmin blocked", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()
		su, _ := repo.Create(ctx, "root", goodPassword, users.RoleSuperadmin)
		if err := repo.SetDisabled(ctx, su.ID, true); !errors.Is(err, users.ErrLastSuperadmin) {
			t.Fatalf("SetDisabled err = %v, want ErrLastSuperadmin", err)
		}
	})

	t.Run("demote last superadmin blocked", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()
		su, _ := repo.Create(ctx, "root", goodPassword, users.RoleSuperadmin)
		if err := repo.SetRole(ctx, su.ID, users.RoleAdmin); !errors.Is(err, users.ErrLastSuperadmin) {
			t.Fatalf("SetRole err = %v, want ErrLastSuperadmin", err)
		}
	})

	t.Run("a disabled second superadmin does not satisfy the invariant", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()
		su1, _ := repo.Create(ctx, "root", goodPassword, users.RoleSuperadmin)
		su2, _ := repo.Create(ctx, "root2", goodPassword, users.RoleSuperadmin)
		if err := repo.SetDisabled(ctx, su2.ID, true); err != nil {
			t.Fatalf("disable su2: %v", err)
		}
		if err := repo.Delete(ctx, su1.ID); !errors.Is(err, users.ErrLastSuperadmin) {
			t.Fatalf("Delete su1 err = %v, want ErrLastSuperadmin (su2 is disabled)", err)
		}
	})

	t.Run("operations succeed with a second enabled superadmin", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()
		su1, _ := repo.Create(ctx, "root", goodPassword, users.RoleSuperadmin)
		if _, err := repo.Create(ctx, "root2", goodPassword, users.RoleSuperadmin); err != nil {
			t.Fatalf("create su2: %v", err)
		}
		if err := repo.SetRole(ctx, su1.ID, users.RoleAdmin); err != nil {
			t.Fatalf("demote su1 should succeed: %v", err)
		}
	})
}

// The last-superadmin guard must be atomic, not check-then-act. With two enabled
// superadmins, concurrent removal/demotion/disable of *both* must never succeed
// for both: the guard+mutation share a transaction, so one loses and at least
// one enabled superadmin always remains. This fails under a TOCTOU
// (SELECT COUNT then separate UPDATE/DELETE) implementation and must pass under
// `go test -race`.
func TestLastSuperadminGuardIsAtomicUnderConcurrency(t *testing.T) {
	ops := []struct {
		name string
		do   func(ctx context.Context, repo *users.Repo, id int64) error
	}{
		{"delete", func(ctx context.Context, repo *users.Repo, id int64) error {
			return repo.Delete(ctx, id)
		}},
		{"demote", func(ctx context.Context, repo *users.Repo, id int64) error {
			return repo.SetRole(ctx, id, users.RoleAdmin)
		}},
		{"disable", func(ctx context.Context, repo *users.Repo, id int64) error {
			return repo.SetDisabled(ctx, id, true)
		}},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			// Repeat to make the race more likely to manifest if reintroduced.
			for i := 0; i < 50; i++ {
				repo := newRepo(t)
				ctx := context.Background()
				su1, err := repo.Create(ctx, "root", goodPassword, users.RoleSuperadmin)
				if err != nil {
					t.Fatalf("create su1: %v", err)
				}
				su2, err := repo.Create(ctx, "root2", goodPassword, users.RoleSuperadmin)
				if err != nil {
					t.Fatalf("create su2: %v", err)
				}

				var wg sync.WaitGroup
				wg.Add(2)
				for _, id := range []int64{su1.ID, su2.ID} {
					go func(id int64) {
						defer wg.Done()
						_ = op.do(ctx, repo, id)
					}(id)
				}
				wg.Wait()

				// Invariant: at least one enabled superadmin survives.
				list, err := repo.List(ctx)
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				enabled := 0
				for _, u := range list {
					if u.Role == users.RoleSuperadmin && !u.Disabled {
						enabled++
					}
				}
				if enabled < 1 {
					t.Fatalf("iteration %d: %s left zero enabled superadmins (TOCTOU)", i, op.name)
				}
			}
		})
	}
}

// SetRole must reject invalid roles outright.
func TestSetRoleInvalid(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	u, _ := repo.Create(ctx, "alice", goodPassword, users.RoleAdmin)
	if err := repo.SetRole(ctx, u.ID, users.Role("root")); !errors.Is(err, users.ErrInvalidRole) {
		t.Fatalf("SetRole err = %v, want ErrInvalidRole", err)
	}
}

// readPasswordHash reaches into the repo's DB to assert on the at-rest hash.
func readPasswordHash(t *testing.T, repo *users.Repo, id int64) string {
	t.Helper()
	var hash string
	if err := repo.DB().QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE id = ?", id).Scan(&hash); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	return hash
}
