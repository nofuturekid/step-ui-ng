// Package users owns the user/auth domain (spec/0003, ADR-0005): roles, the
// User model, password hashing with argon2id, and a SQLite-backed repository.
//
// All business rules live here — handlers stay thin (see internal/app). The
// plaintext password and the stored hash never leave this package: User carries
// no password field, and nothing here logs credentials (FR-2, FR-7).
package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Sentinel errors let handlers branch without inspecting driver/SQL details.
var (
	ErrInvalidCredentials = errors.New("users: invalid credentials")
	ErrUserDisabled       = errors.New("users: user is disabled")
	ErrWeakPassword       = errors.New("users: password too weak")
	ErrInvalidRole        = errors.New("users: invalid role")
	ErrInvalidUsername    = errors.New("users: invalid username")
	ErrUsernameTaken      = errors.New("users: username already taken")
	ErrLastSuperadmin     = errors.New("users: cannot remove the last superadmin")
	ErrUserNotFound       = errors.New("users: user not found")
)

// Validation bounds. minPasswordLen encodes the "strong password" requirement
// (FR-1); usernames are bounded to keep the UI and storage sane.
const (
	minPasswordLen = 12
	minUsernameLen = 3
	maxUsernameLen = 64
)

// Role is a user's authorization level (FR-4).
type Role string

// The three roles, from most to least privileged.
const (
	RoleSuperadmin Role = "superadmin"
	RoleAdmin      Role = "admin"
	RoleViewer     Role = "viewer"
)

// Valid reports whether r is one of the known roles.
func (r Role) Valid() bool {
	switch r {
	case RoleSuperadmin, RoleAdmin, RoleViewer:
		return true
	default:
		return false
	}
}

// rank orders roles for privilege comparisons (higher = more privileged).
func (r Role) rank() int {
	switch r {
	case RoleSuperadmin:
		return 3
	case RoleAdmin:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r is at least as privileged as other.
func (r Role) AtLeast(other Role) bool { return r.rank() >= other.rank() }

// CanManageUsers reports whether r may create/modify/delete users (admin+).
// Viewers are read-only.
func (r Role) CanManageUsers() bool { return r.AtLeast(RoleAdmin) }

// CanAssign reports whether an actor with role r may create a user with, or
// assign, the target role. Enforces the role ceiling: nobody may grant a role
// higher than their own, so an admin can never mint or promote to superadmin
// (FR-4, privilege-escalation guard). Equal-or-lower is permitted.
func (r Role) CanAssign(target Role) bool { return r.AtLeast(target) }

// CanManage reports whether an actor with role r may act on (delete/disable/
// change the role of) an existing user whose current role is target. An admin
// may only manage admin/viewer accounts; touching a superadmin requires the
// actor to be superadmin. This protects superadmins from being demoted, disabled
// or deleted by a mere admin.
func (r Role) CanManage(target Role) bool {
	if target == RoleSuperadmin {
		return r == RoleSuperadmin
	}
	return r.CanManageUsers()
}

// User is the public view of a row in the users table. It deliberately omits
// the password hash so it can never be logged or rendered by accident.
type User struct {
	ID        int64
	Username  string
	Role      Role
	Disabled  bool
	CreatedAt int64 // unix seconds
	UpdatedAt int64 // unix seconds
}

// Repo is the SQLite-backed user repository.
type Repo struct {
	db *sql.DB
}

// NewRepo returns a Repo over an already-migrated database handle.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

// DB exposes the underlying handle (used by tests and the session store).
func (r *Repo) DB() *sql.DB { return r.db }

// now is overridable in tests; defaults to wall-clock unix seconds.
var now = func() int64 { return time.Now().Unix() }

// Count returns the number of users; first-run setup is gated on Count==0
// (FR-1).
func (r *Repo) Count(ctx context.Context) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		return 0, fmt.Errorf("users: count: %w", err)
	}
	return n, nil
}

// ErrSetupComplete is returned by CreateFirst when at least one user already
// exists, so the first-run setup can no longer create the initial superadmin.
var ErrSetupComplete = errors.New("users: setup already complete")

// Create validates input, hashes the password with argon2id, and inserts a new
// user. The plaintext is never stored or logged (FR-2).
func (r *Repo) Create(ctx context.Context, username, password string, role Role) (User, error) {
	username, hash, role, err := r.prepareCreate(username, password, role)
	if err != nil {
		return User{}, err
	}

	ts := now()
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role, disabled, created_at, updated_at)
		 VALUES (?, ?, ?, 0, ?, ?)`,
		username, hash, string(role), ts, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrUsernameTaken
		}
		return User{}, fmt.Errorf("users: insert: %w", err)
	}
	return r.builtUser(res, username, role, ts)
}

// CreateFirst creates the initial superadmin during first-run setup, but only
// while no users exist. The COUNT check and the INSERT run in one BEGIN
// IMMEDIATE transaction, so two concurrent POST /setup requests cannot both
// create a superadmin: the loser sees ErrSetupComplete (FR-1). The role is fixed
// to superadmin regardless of input.
func (r *Repo) CreateFirst(ctx context.Context, username, password string) (u User, err error) {
	username, hash, _, err := r.prepareCreate(username, password, RoleSuperadmin)
	if err != nil {
		return User{}, err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("users: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var n int
	if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n); e != nil {
		return User{}, fmt.Errorf("users: count: %w", e)
	}
	if n > 0 {
		return User{}, ErrSetupComplete
	}

	ts := now()
	res, e := tx.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role, disabled, created_at, updated_at)
		 VALUES (?, ?, ?, 0, ?, ?)`,
		username, hash, string(RoleSuperadmin), ts, ts)
	if e != nil {
		if isUniqueViolation(e) {
			return User{}, ErrUsernameTaken
		}
		return User{}, fmt.Errorf("users: insert: %w", e)
	}
	if u, err = r.builtUser(res, username, RoleSuperadmin, ts); err != nil {
		return User{}, err
	}
	if err = tx.Commit(); err != nil {
		return User{}, fmt.Errorf("users: commit: %w", err)
	}
	return u, nil
}

// prepareCreate validates input and hashes the password, returning the
// normalized username, the argon2id hash, and the validated role.
func (r *Repo) prepareCreate(username, password string, role Role) (string, string, Role, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return "", "", "", err
	}
	if !role.Valid() {
		return "", "", "", ErrInvalidRole
	}
	if len(password) < minPasswordLen {
		return "", "", "", ErrWeakPassword
	}
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return "", "", "", fmt.Errorf("users: hash password: %w", err)
	}
	return username, hash, role, nil
}

// builtUser assembles the returned User from an insert result.
func (r *Repo) builtUser(res sql.Result, username string, role Role, ts int64) (User, error) {
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("users: last insert id: %w", err)
	}
	return User{
		ID:        id,
		Username:  username,
		Role:      role,
		Disabled:  false,
		CreatedAt: ts,
		UpdatedAt: ts,
	}, nil
}

// Authenticate verifies username+password in (near) constant time. Unknown user
// and wrong password both return ErrInvalidCredentials so login does not leak
// which usernames exist (FR-7); a disabled account returns ErrUserDisabled. A
// dummy comparison runs for unknown users to keep timing comparable.
//
// note: FR-7's "rate-limit / constant-time compare" is satisfied here by the
// constant-time argon2id compare (the "/" is a disjunction). Brute-force request
// throttling is deliberately deferred to a later spec; do not add it here.
func (r *Repo) Authenticate(ctx context.Context, username, password string) (User, error) {
	username = strings.TrimSpace(username)

	var (
		u    User
		hash string
		role string
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, disabled, created_at, updated_at
		 FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &hash, &role, &u.Disabled, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Run a comparison anyway to avoid a fast path that reveals non-existence.
		_, _ = argon2id.ComparePasswordAndHash(password, dummyHash)
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, fmt.Errorf("users: lookup: %w", err)
	}

	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return User{}, fmt.Errorf("users: compare: %w", err)
	}
	if !match {
		return User{}, ErrInvalidCredentials
	}
	if u.Disabled {
		return User{}, ErrUserDisabled
	}

	u.Role = Role(role)
	return u, nil
}

// List returns all users ordered by id.
func (r *Repo) List(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, role, disabled, created_at, updated_at
		 FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("users: list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []User
	for rows.Next() {
		var (
			u    User
			role string
		)
		if err := rows.Scan(&u.ID, &u.Username, &role, &u.Disabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("users: scan: %w", err)
		}
		u.Role = Role(role)
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("users: rows: %w", err)
	}
	return out, nil
}

// GetByID returns one user or ErrUserNotFound.
func (r *Repo) GetByID(ctx context.Context, id int64) (User, error) {
	var (
		u    User
		role string
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT id, username, role, disabled, created_at, updated_at
		 FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &role, &u.Disabled, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("users: get: %w", err)
	}
	u.Role = Role(role)
	return u, nil
}

// SetRole changes a user's role. Demoting the last enabled superadmin away from
// superadmin is refused (FR-6). The guard and the write run in one transaction
// (BEGIN IMMEDIATE via the store DSN) so two concurrent demotions of different
// superadmins cannot both pass the guard.
func (r *Repo) SetRole(ctx context.Context, id int64, role Role) error {
	if !role.Valid() {
		return ErrInvalidRole
	}
	return r.guardedMutate(ctx, id, func(tx *sql.Tx, current Role) error {
		if current == RoleSuperadmin && role != RoleSuperadmin {
			if err := guardLastSuperadminTx(ctx, tx, id); err != nil {
				return err
			}
		}
		return updateTx(ctx, tx, id, "role = ?", string(role))
	})
}

// SetDisabled enables/disables a user. Disabling the last enabled superadmin is
// refused (FR-6); see SetRole for the atomicity guarantee.
func (r *Repo) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	return r.guardedMutate(ctx, id, func(tx *sql.Tx, current Role) error {
		if disabled && current == RoleSuperadmin {
			if err := guardLastSuperadminTx(ctx, tx, id); err != nil {
				return err
			}
		}
		return updateTx(ctx, tx, id, "disabled = ?", disabled)
	})
}

// Delete removes a user. Deleting the last enabled superadmin is refused
// (FR-6); see SetRole for the atomicity guarantee.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	return r.guardedMutate(ctx, id, func(tx *sql.Tx, current Role) error {
		if current == RoleSuperadmin {
			if err := guardLastSuperadminTx(ctx, tx, id); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
		if err != nil {
			return fmt.Errorf("users: delete: %w", err)
		}
		return rowsAffected(res, ErrUserNotFound)
	})
}

// guardedMutate opens a write transaction, loads the target user's current role
// (returning ErrUserNotFound if it is gone), runs fn under the same transaction,
// and commits. Because the store opens connections with _txlock=immediate, the
// transaction takes a write lock at BEGIN, so the SELECT-then-write the
// last-superadmin guards perform is atomic against concurrent writers (closes
// the TOCTOU window).
func (r *Repo) guardedMutate(ctx context.Context, id int64, fn func(tx *sql.Tx, current Role) error) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("users: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var role string
	switch e := tx.QueryRowContext(ctx,
		"SELECT role FROM users WHERE id = ?", id).Scan(&role); {
	case errors.Is(e, sql.ErrNoRows):
		return ErrUserNotFound
	case e != nil:
		return fmt.Errorf("users: load role: %w", e)
	}

	if err = fn(tx, Role(role)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("users: commit: %w", err)
	}
	return nil
}

// guardLastSuperadminTx returns ErrLastSuperadmin if removing the privilege of
// user id would leave no enabled superadmin. The candidate row (id) is excluded
// from the count of "other" enabled superadmins. It runs inside the caller's
// transaction so the count and the subsequent write are atomic.
func guardLastSuperadminTx(ctx context.Context, tx *sql.Tx, id int64) error {
	var others int
	err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users
		 WHERE role = ? AND disabled = 0 AND id != ?`,
		string(RoleSuperadmin), id).Scan(&others)
	if err != nil {
		return fmt.Errorf("users: count superadmins: %w", err)
	}
	if others == 0 {
		return ErrLastSuperadmin
	}
	return nil
}

// updateTx sets one column plus updated_at on a user within tx, returning
// ErrUserNotFound if the row vanished.
func updateTx(ctx context.Context, tx *sql.Tx, id int64, setClause string, arg any) error {
	res, err := tx.ExecContext(ctx,
		fmt.Sprintf("UPDATE users SET %s, updated_at = ? WHERE id = ?", setClause),
		arg, now(), id)
	if err != nil {
		return fmt.Errorf("users: update: %w", err)
	}
	return rowsAffected(res, ErrUserNotFound)
}

func rowsAffected(res sql.Result, notFound error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("users: rows affected: %w", err)
	}
	if n == 0 {
		return notFound
	}
	return nil
}

// normalizeUsername trims and length-checks a username.
func normalizeUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if l := len(username); l < minUsernameLen || l > maxUsernameLen {
		return "", ErrInvalidUsername
	}
	return username, nil
}

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint failure.
func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		code := se.Code()
		return code == sqlite3.SQLITE_CONSTRAINT_UNIQUE || code == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	}
	return false
}

// dummyHash is a real argon2id hash of a throwaway password, generated once at
// init with the same DefaultParams the real Create path uses. Comparing against
// it for unknown users keeps Authenticate's timing comparable to the real path
// on any host, without revealing that the user does not exist (FR-7). Generating
// it (rather than hardcoding fixed params) avoids a timing skew on machines
// whose default differs from a baked-in p=16.
var dummyHash = mustDummyHash()

func mustDummyHash() string {
	h, err := argon2id.CreateHash("unused-constant-time-dummy", argon2id.DefaultParams)
	if err != nil {
		panic("users: cannot create dummy argon2id hash: " + err.Error())
	}
	return h
}
