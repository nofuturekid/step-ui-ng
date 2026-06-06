# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions are bumped only when a release is cut; in-progress work lives under
[Unreleased] (see ADR-0011).

## [Unreleased]

### Added

- Step-CA connection configured in the UI (spec/0004, ADR-0004, ADR-0006). New
  migration `0003_ca_settings.sql` adds a single-row `ca_settings` table
  (STRICT, `CHECK (id = 1)`). New `internal/ca` package talks to Step-CA over its
  HTTPS API only — no `step` CLI — with `TestConnection` fetching `GET /roots`
  and verifying the pinned root fingerprint (SHA-256 of the root's DER), plus
  typed errors (unreachable, fingerprint mismatch, bad TLS, malformed response).
  TLS is pinned to the fingerprint in two phases: a bootstrap fetch whose
  `VerifyConnection` callback enforces the pin (never trusts arbitrary certs),
  then steady-state verification against a `RootCAs` pool built from the verified
  root with `InsecureSkipVerify:false`. New `internal/settings` repo loads/saves
  the row, sealing the admin secret via `internal/crypto` (AES-256-GCM) on write
  and never decrypting it toward the client (write-only field; an empty value
  preserves the stored secret), with `ca_url` http(s) and 40–64-hex-fingerprint
  validation. New admin-only routes `GET/POST /settings` and `POST /settings/test`
  (htmx result partial), rendered with a Templ settings page that shows the admin
  secret only as set/empty.
- Foundation persistence (`internal/store`): pure-Go SQLite opened under
  `DATA_DIR`, with embedded, idempotent goose migrations applied on startup
  (spec/0001). Wired into server boot; logs the applied schema version.
- Secrets encryption at rest (`internal/crypto`): AES-256-GCM secret box with a
  32-byte master key auto-generated at `DATA_DIR/secret.key` (mode 0600) on first
  start and loaded thereafter; `Seal`/`Open` use a fresh random nonce per message
  and base64 output (spec/0002, ADR-0006). Key creation is wired into startup.
- Built-in authentication, users and first-run setup (spec/0003, ADR-0005). New
  `internal/users` domain: roles (`superadmin`/`admin`/`viewer`) with RBAC
  helpers, a SQLite-backed `Repo` (count/create/authenticate/list/get/set-role/
  set-disabled/delete), argon2id password hashing with a constant-time
  unknown-user compare, and the last-superadmin invariant (cannot delete/disable/
  demote the final enabled superadmin). New `internal/app` web layer: scs
  sessions over SQLite (HttpOnly, SameSite=Lax, Secure from config), nosurf CSRF
  on all mutating forms (htmx-friendly via `X-CSRF-Token`), first-run gating, and
  `requireAuth`/`requireRole` middleware. Routes `GET/POST /setup`,
  `GET/POST /login`, `POST /logout`, and admin-only `GET/POST /users` +
  `POST /users/{id}`, rendered with embedded Templ templates and embedded
  htmx/CSS assets (ADR-0002, ADR-0007).

### Changed

- `internal/config`: add `SecureCookies` (env `COOKIE_SECURE`, default false) to
  set the `Secure` attribute on session/CSRF cookies behind TLS.
- `app.NewHandler` now takes its dependencies (`app.Deps`: DB, users repo,
  settings repo, session manager, config) instead of being argument-less.
- The startup `crypto.Box` is now retained and wired into the web layer (via the
  settings repo) to seal CA admin secrets, rather than being created and
  discarded.
- Align repo conventions and CI to the `main` branch (docs + workflow triggers).
- CI derives the Go version from `go.mod` (now `1.25`, required by the SQLite/goose
  dependencies) and enables module caching.
- Migrate the golangci-lint config to the v2 format.
- Adopt release-only versioning: bump the `Version` constant and add a dated
  changelog heading only when cutting a release (ADR-0011, supersedes the per-spec
  bump cadence of ADR-0008).

### Fixed

- Harden spec/0003 auth against the security review: enforce a role ceiling and
  protect superadmin accounts in the user-management handlers (an admin can no
  longer create/assign `superadmin`, nor delete/disable/demote a superadmin);
  make the last-superadmin invariant and first-run setup atomic via BEGIN
  IMMEDIATE transactions (closing two TOCTOU windows), with `busy_timeout` and a
  single SQLite connection as defence-in-depth; use exact-match first-run
  exemptions; stop trusting the unauthenticated `X-Forwarded-Proto` header in the
  CSRF same-origin check; and derive the constant-time dummy hash from
  `DefaultParams`. Added regression tests (privilege escalation, concurrency
  under `-race`, session fixation, logout destruction, cross-origin CSRF). Note:
  brute-force login throttling is deferred to a later spec (FR-7 is met by the
  constant-time argon2id compare).
- Pin templ as a go.mod `tool` dependency and run `go tool templ generate`
  everywhere (CI + Makefile), silencing the "templ not found in go.mod" version
  warning and making generation reproducible.
- Bump `golangci-lint-action` v8 → v9 (runs on Node.js 24), silencing the GitHub
  Actions Node.js 20 deprecation warning ahead of the 2026-06-16 cutover.

## [0.0.1] - 2026-06-06

### Added

- Initial scaffold: project layout, build/CI tooling, ADRs (MADR) and feature
  specs (SDD), minimal compiling HTTP skeleton with a health endpoint and tests.
