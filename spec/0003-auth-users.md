# 0003 — Authentication, users & first-run setup

## Context
The UI controls a CA and must require authentication from the start (ADR-0005).

## User stories
- As a new operator, on first launch I create the super-admin account.
- As an admin, I can manage users and roles.
- As any user, I must log in; viewers cannot perform mutating actions.

## Functional requirements
- FR-1: If no users exist, all routes redirect to a **first-run setup** that
  creates the first user as `superadmin` (username + strong password).
- FR-2: Passwords hashed with argon2id; never stored/logged in clear text.
- FR-3: Session login/logout via secure, http-only cookies (`scs`, SQLite store).
- FR-4: Roles: `superadmin`, `admin`, `viewer`. RBAC middleware guards routes.
- FR-5: CSRF protection on all state-changing requests (htmx-friendly).
- FR-6: User management (list/create/disable/delete, role assignment); a superadmin
  cannot be locked out (at least one superadmin must remain).
- FR-7: Rate-limit / constant-time compare on login to resist brute force.

## Data model
- `users(id, username unique, password_hash, role, disabled, created_at, updated_at)`
- session store table (managed by scs).

## Routes / UI
- `GET/POST /setup` (only until first user exists)
- `GET/POST /login`, `POST /logout`
- `GET /users`, `POST /users`, `POST /users/{id}` (admin+)

## Acceptance criteria
- Given no users, When I open any page, Then I'm redirected to `/setup`.
- Given I submit valid setup, Then a superadmin is created and I'm logged in.
- Given setup is complete, When I open `/setup`, Then it is no longer available.
- Given I'm a viewer, When I attempt a mutating action, Then I get 403.
- Given I'm not authenticated, When I open a protected page, Then I'm redirected to
  `/login`.
- Given a form POST without a valid CSRF token, Then it is rejected.

## Tests
- setup gating; argon2id verify; role enforcement (table-driven); CSRF rejection;
  "last superadmin" protection.

## Out of scope
- OIDC/SSO and forward-auth (future ADR/spec).
