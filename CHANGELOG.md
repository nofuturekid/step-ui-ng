# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions are bumped only when a release is cut; in-progress work lives under
[Unreleased] (see ADR-0011).

## [Unreleased]

## [0.1.0] - 2026-06-07

### Added

- ACME enablement (spec/0010, ADR-0010, ADR-0004, ADR-0006). Full ACME
  management via the CA's admin API (no `step` CLI): create/edit/delete ACME
  provisioners with allowed challenges (`http-01`, `dns-01`, `tls-alpn-01`) and
  `requireEAB`; per-provisioner External Account Binding (EAB) key
  create/list/revoke; the ACME directory URL with a copy button; and copy-paste
  client snippets (certbot, acme.sh, Caddy, Traefik) parameterized with the
  directory URL and, when EAB is required, the EAB keyID/HMAC. `internal/ca`
  gains, over the existing two-phase pinned-trust client + x5c admin token
  (spec/0005, no blanket skip-verify): `UpdateProvisioner`
  (`PUT /admin/provisioners/{name}`); ACME options on `NewProvisionerSpec`
  (`ACMEChallenges`, `ACMERequireEAB`) serialized into the linkedca
  `details.ACME` protojson shape (`requireEab`, `challenges` as the protojson
  enum names `HTTP_01`/`DNS_01`/`TLS_ALPN_01`); EAB ops `CreateEABKey`
  (`POST /admin/acme/eab/{provisioner}` `{"reference":…}` → a single protojson
  `linkedca.EABKey` `{id, hmacKey(base64), provisioner, reference, account,
createdAt, boundAt}`), `ListEABKeys` (`GET …`, follows `nextCursor`) and
  `DeleteEABKey` (`DELETE …/{keyID}`); and `DirectoryURL` returning
  `{ca}/acme/{provisioner}/directory`. The **EAB HMAC is a secret shown EXACTLY
  ONCE on creation**: `ListEABKeys` strips it from every row, the create result
  is rendered inline with `Cache-Control: no-store`, and it is never persisted on
  our side, never logged, and never written to an audit row. New admin-only
  routes (auth + CSRF, `requireRole(RoleAdmin)`): `GET /acme`,
  `POST /acme/provisioners` (create), `POST /acme/provisioners/{name}` (edit via
  `action=edit`, delete via `action=delete`), `GET /acme/eab/{provisioner}` (list
  - create form + snippets), `POST /acme/eab/{provisioner}` (create → one-time
    display; revoke via `action=delete`). As reconciled for spec/0005, edit/delete
    verbs are tunnelled through a POST `action` field (HTML forms + nosurf); the EAB
    routes are mounted under `/acme/eab/{provisioner}` (mirroring the CA admin path)
    to avoid a ServeMux collision with the literal `/acme/provisioners` segment.
    Audit events for every change (`acme.provisioner.create/update/delete`,
    `acme.eab.create/revoke`), attributed to the session user, never carrying the
    HMAC/secret. The admin-API calls are proven by an `httptest` mock that
    re-implements step-ca's `AuthorizeAdminToken` (x5c chain to root, leaf
    digital-signature usage, JWS signature by the leaf key, audience/issuer/subject
    claims) for both provisioner and EAB endpoints, with a non-vacuousness probe;
    it is **not** validated against a live Step-CA (the OSS step-ca stubs the EAB
    endpoints — EAB management is a Certificate Manager / remote-management feature
    — so EAB behaviour against a real CA is not observable here). Acceptance tests
    cover: create an ACME provisioner with `dns-01` + `requireEAB` (CA receives the
    correct options; directory URL shown); EAB create shows keyID + HMAC once with
    `no-store`, then is listed WITHOUT the HMAC (asserts the HMAC string is absent
    from the list); revoke removes the key (CA receives the delete by keyID); client
    snippets contain the directory URL and, after a create, the real EAB keyID/HMAC
    (and `--eab-kid` params); audit events per change with `who`=session user and no
    HMAC in the row; ACME provisioner edit/delete; and RBAC (viewer → 403).
- Audit log query/filter UI and full event emission (spec/0009). All
  security-relevant actions now emit an audit event attributed to the
  authenticated session user (never "system" or empty): `login`, `logout`,
  `user.create`, `user.update`, `user.delete`, `settings.update`,
  `provisioner.create`, `provisioner.select`, `provisioner.delete`, `issue`,
  `sign`, `revoke`, `renew`. `internal/audit` gains `List(ctx, Filter)`:
  parameterized SQL only, filters on action/who/from/to (Unix timestamps),
  newest-first, paginated with limit+offset. New admin-only route
  `GET /audit` (behind auth + CSRF, `requireRole(RoleAdmin)`): a filter form
  (action dropdown, user text, from/to date) and a paginated table (who,
  action, target, details, timestamp, newest first). A clear ACME extension
  point is left in the action dropdown for spec/0010. No secrets or passwords
  are ever written to any audit row. Acceptance tests cover: actor = session
  user (not "system") per action (table-driven, 8 actions); filter by
  action/who/time range; the `/audit` page renders events and is admin-only
  (viewer → 403); all existing cert/revoke/renew audit tests remain green.

- Revoke & renew certificates (spec/0008, ADR-0004). Revocation is now **real**:
  it is performed against the CA (no longer a local-only mark). New
  `POST /certificates/{id}/revoke` and `POST /certificates/{id}/renew` (both
  admin+, behind auth + CSRF), with Revoke (reason + OCSP reason code + a typed
  `REVOKE` confirmation) and Renew (validity, defaulted from config) controls on
  the certificate detail view. `internal/ca` gains `RevokeCert`: it signs a JWK
  provisioner **OTT** whose subject is the certificate **serial** and whose
  audience is `{ca}/1.0/revoke` (step-ca's revoke contract — `authorizeRevoke`
  rejects a token whose subject ≠ serial), then `POST {ca}/1.0/revoke`
  `{serial, ott, reasonCode, reason, passive:true}` (step-ca only implements
  passive revocation). It reuses the two-phase pinned-trust client (no blanket
  skip-verify); typed errors `ErrRevokeInvalid`, `ErrRevokeFailed`. The token
  format follows smallstep/cli's revoke token flow and smallstep/certificates'
  `api/revoke.go`. `internal/certs` gains `Revoke` and `Renew`: `Revoke` calls
  the CA FIRST and sets local `status=revoked` + records an audit event **only on
  CA success** (a CA failure leaves the local row UNCHANGED — the atomicity the
  predecessor lacked), refuses an already-revoked cert (`ErrAlreadyRevoked`) and
  requires a reason (`ErrReasonRequired`). `Renew` re-issues for the SAME CN/SANs
  via the existing issue path (new server keypair → CSR → CA sign → sealed key →
  new inventory row) with the chosen validity, bounded by the provisioner's max
  at the CA, and records a `renew` audit event. The default renew validity is
  **configurable**, not hard-coded: new `RENEW_DEFAULT_DAYS` env (default 90) in
  `internal/config` (`Config.RenewDefaultDays`/`DefaultRenewDays`); the renew form
  shows it pre-filled and the user can override. Acceptance tests (mock CA via
  httptest) cover: revoke success (CA receives the call by serial + OTT subject ==
  serial + passive:true, local status → revoked); CA rejects → local status
  unchanged + error shown (atomicity, fails on regression); already-revoked guard
  (no CA call); reason required; renew with 30 days → new cert, same CN/SANs,
  not_after ≈ now+30d; renew over provisioner max → rejected; configurable default
  (env-driven, not hard-coded); RBAC (viewer → 403); audit events for revoke and
  renew with the session actor. Limitation: as with issue/sign, behaviour is
  proven against an httptest mock CA, not a live Step-CA.

- Certificate inventory & encrypted re-download (spec/0007). New
  `GET /inventory` (list with htmx live-filter by status and CN/SAN text
  search), `GET /certificates/{id}` (detail view), and
  `GET /certificates/{id}/download` (ZIP bundle; admin+ only — may contain
  the private key). Status derivation (active/expired/revoked + days-until-
  expiry) is computed in Go from `not_after` vs now and the persisted `status`
  column (revoked is authoritative; expired is derived from date). The ZIP is
  assembled in memory: `cert.pem`, `chain.pem`, `fullchain.pem`, `README.txt`
  always; `privkey.pem` only when `key_strategy=server` (FR-6); `cert.p12`
  only when `?pfx_password` is supplied (FR-3). The sealed private key is
  decrypted in-memory only via `internal/crypto Box.Open` — never written to
  disk or logged (FR-4). Download is admin+ (RBAC comment in handler), carries
  `Cache-Control: no-store, no-cache, must-revalidate` and
  `Content-Disposition: attachment`. The inventory link is added to the nav
  (all authenticated roles). Acceptance tests cover: bundle contents per key
  strategy; sealed-at-rest assertion; status derivation (active/expired/
  revoked + days); filter logic (8 table-driven cases); RBAC (viewer→403);
  response headers (no-store, attachment, application/zip); PFX inclusion.

- Issue certificate & sign CSR (spec/0006, ADR-0004; audit foundation from
  spec/0009). New migration `0005_certificates_audit.sql` adds two STRICT tables:
  `certificates` (the issued/signed inventory: cn, sans_json, serial,
  not_before/after, status, key_strategy ∈ {server, csr}, cert/chain/fullchain
  PEM, nullable sealed `privkey_sealed`, created_by, timestamps) and the
  append-only `audit_events` (id, who, action, target, details, created_at) — the
  exact spec/0009 data model, introduced early so FR-4 is satisfiable. New
  `internal/audit` package: a minimal append-only `Recorder.Record(ctx, who,
action, target, details)` that rejects an empty actor (the actor is always the
  authenticated session user, never "system"); spec/0009 will add the
  query/filter UI on top. `internal/ca` gains provisioner **OTT (one-time token)**
  signing over the existing two-phase pinned-trust client (no blanket
  skip-verify): `SignCSR` fetches the active JWK provisioner from
  `GET /provisioners`, decrypts its `encryptedKey` (a JWE) with the selected
  provisioner password (`jose.Decrypt`), builds a short-lived OTT JWT
  (`sub`=CN, `sans`=SAN list, `aud={ca}/1.0/sign`, `iss`=provisioner name,
  `iat/nbf/exp`, `jti`, header `kid`=JWK key id) signed with the provisioner JWK
  via `go.step.sm/crypto/jose`, then `POST {ca}/1.0/sign` `{csr, ott, notAfter}`
  and parses the returned `crt`/`certChain`. The OTT format follows
  smallstep/cli's token package (`sans` claim) and smallstep/certificates' JWK
  provisioner `authorizeToken` (`iss`==provisioner name, non-empty `sub`, JWS
  verified against the public JWK); typed errors `ErrProvisionerNotFound`,
  `ErrProvisionerKey`, `ErrInvalidCSR`, `ErrSignRejected`, `ErrSignFailed`. New
  `internal/certs` domain + persistence: `Issue` (FR-1) generates an EC keypair
  server-side, builds a CSR (CN added as a SAN; SANs classified into DNS/IP/email/
  URI), obtains the cert, seals the private key (`key_strategy=server`), and can
  bundle PEM or PKCS#12/PFX (`software.sslmate.com/src/go-pkcs12`, Modern/AES);
  `Sign` (FR-2) parses the PEM CSR with `crypto/x509`, **verifies the CSR
  signature** (rejecting on failure) and takes CN+SANs from it
  (`key_strategy=csr`, no private key). Both persist metadata (serial,
  not_before/after parsed from the issued leaf, status=valid) and emit an audit
  event attributed to the session user (FR-4). New admin-only routes
  `GET/POST /issue` and `GET/POST /sign-csr` (auth + admin via `requireRole`,
  behind CSRF), with Templ pages for the issue form (CN, SANs, validity, format)
  and the sign-csr form (CSR textarea), each rendering the result (metadata + PEM
  display; the server-generated private key/PFX is shown once as a download, never
  persisted in clear). Clear validation errors (FR-5) for a bad/garbled CSR,
  validity over the provisioner max (surfaced from the CA's 4xx), and a missing/
  unselected provisioner. The OTT signing is proven by an `httptest` mock that
  publishes a JWK provisioner whose `encryptedKey` the test controls and whose
  `/1.0/sign` verifies the OTT signature + claims against the published public JWK
  before issuing (plus a white-box non-vacuousness probe); it is **not** validated
  against a live Step-CA (real provisioner validity policy, templates and
  DB-backed token reuse are only observable against a real CA). Re-download UX and
  the full inventory view are spec/0007; revoke/renew spec/0008; the audit
  query/filter UI and remaining emit points spec/0009.
- Provisioner management (spec/0005, ADR-0004, ADR-0012). New migration
  `0004_provisioners.sql` extends `ca_settings` with the selected provisioner
  (`selected_provisioner` + sealed `selected_provisioner_secret_sealed`) and the
  admin credential for x5c admin-token signing (`admin_cert_pem`, the public
  chain, plus sealed `admin_key_sealed`). `internal/ca` gains provisioner
  operations over the existing two-phase pinned-trust client (no blanket
  skip-verify): `ListProvisioners` (`GET /provisioners`, no admin auth, follows
  the CA's `nextCursor` pagination), `CreateProvisioner`
  (`POST /admin/provisioners`) and `DeleteProvisioner`
  (`DELETE /admin/provisioners/{name}`). Create/delete authenticate with an
  SDK-signed x5c admin JWT built via `go.step.sm/crypto/jose`
  (`iss=step-admin-client/1.0`, `sub=<admin leaf CN>`, `aud=<endpoint URL>`,
  `jti`, short validity; admin chain in the `x5c` header; token placed verbatim
  in the `Authorization` header) — the exact format Step-CA's
  `AuthorizeAdminToken` validates. JWK provisioners are created by generating a
  keypair and shipping the public JWK plus the JWE-encrypted private key (the
  plaintext password never leaves the process). `internal/settings` gains
  `SelectProvisioner` (seals the secret), `SaveAdminCredential`/`AdminCredential`
  (seals the private key, write-only toward the client) and `SelectedSecret`. New
  admin-only routes `GET /provisioners`, `POST /provisioners` (create),
  `POST /provisioners/select`, `POST /provisioners/{name}` (delete via
  `action=delete`), with a Templ page listing provisioners + types, marking the
  active one, and create/select/delete controls. Deleting the currently selected
  provisioner is refused with a clear error (FR-4). Validation: name
  `^[a-zA-Z0-9._-]+$`, type ∈ {JWK, ACME, SSHPOP}, JWK secret ≥ 8 chars. The
  admin-token signing is proven by an `httptest` mock that re-implements Step-CA's
  verification (x5c chain to root, leaf digital-signature usage, JWS signature by
  the leaf key, claim checks); it is **not** validated against a live CA. Audit
  events for provisioner actions (FR-5) are **deferred to spec/0009**;
  ACME-specific options / EAB to spec/0010.
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
