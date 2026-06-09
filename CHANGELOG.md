# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions are bumped only when a release is cut; in-progress work lives under
[Unreleased] (see ADR-0011).

## [Unreleased]

### Added

- **CA settings page redesign** (PR C): ports `GET /settings` to the approved
  design mock (`docs/design/ca-settings.html`).
  - **Page shell**: `content--narrow` wrapper, `page-head` with breadcrumb
    (`Settings / CA settings`), `page-title`, and `page-sub` subtitle.
  - **Card 1 — CA connection**: `card__header` / `card__body` layout; two
    `.field .input.mono` controls for CA URL and root fingerprint (with
    `field__hint` helper text); `btn--primary` "Save connection" + plain `btn`
    "Test connection" in `.form-actions`; the Test button carries the existing
    `hx-post="/settings/test"` / `hx-target="#test-result"` wiring (behaviour
    unchanged); `#test-result` div preserved for the htmx swap.
  - **Card 2 — Admin authentication**: `card__header` with `card__actions`
    holding an `"Active: <method>"` badge (`badge--info` for x5c/jwk,
    `badge--neutral` for none); method selector replaced from `<select
onchange=…>` to a `.seg` radio group (three `<input type="radio"
name="admin_auth_method">`) — **no inline JS**; the checked state is driven
    by the stored method from the server.
  - **Method-group reveal via CSS `:has()`**: three `.method-group` divs
    (`.mg-none` / `.mg-x5c` / `.mg-jwk`) are always in the DOM; the active
    group is shown by `.method-fieldset:has(#m-<method>:checked) .mg-<method>
{ display: block }`. An `@supports not (selector(:has(*)))` fallback shows
    all groups when `:has()` is unsupported, keeping the form usable in older
    browsers without requiring any server-side class.
  - **x5c group**: `admin_x5c_cert` + `admin_x5c_key` `.textarea.mono` fields;
    `badge--set` / `badge--none` key-status indicator; copyable `step ca
certificate …` codeblock with the CA URL interpolated.
  - **jwk group**: `admin_jwk_subject` + `admin_jwk_provisioner` `.input.mono`
    inputs; `secret-row` wrapper with `admin_jwk_password type="password"` +
    `badge--set` / `badge--none` inline status badge; `field__hint` text varies
    with stored vs. not-stored state. Secrets never echoed.
  - **New CSS** in `internal/app/static/app.css`: `.content--narrow`,
    `.req`/`.opt` markers, `.field__hint`, `.col-span-2`, `.textarea`,
    `.flash--warn` / `.flash--ok` / `.flash--error`, `.seg` / `.seg__name` /
    `.seg__desc`, `.method-fieldset` / `.method-group` / `:has()` reveal rules
    - `@supports not (selector(:has(*)))` fallback, `.method-group__title`,
      `.badge--set` / `.badge--none`, `.secret-row` / `.secret-state`,
      `.codeblock--cmd`.
  - Dead `adminAuthOption` templ helper removed (no callers after rewrite to `.seg` radio group).
  - New pure-Go helpers: `activeBadgeClass`, `activeMethodLabel`,
    `settingsSecretBadgeClass`, `settingsSecretBadgeLabel`.

### Fixed

- **Revoke form confirm input** (PR B review): the redesigned revoke form was
  missing `<input type="hidden" name="confirm" value="REVOKE"/>`, causing every
  real browser submission to fail with "Revocation not confirmed". Added the
  required hidden field (spec/0008 FR-3).
- **Revoke reason defaulting** (PR B review): when the optional reason note is
  left blank the handler now defaults to the selected reason-code's label
  (e.g. "unspecified", "keyCompromise") so the domain's `ErrReasonRequired`
  guard is satisfied without forcing extra typing.
- **Renew form placement** (PR B review): the editable validity Renew form
  (spec/0008 FR-2) now appears for **non-revoked** certs (active/expiring) as
  a card section below the metadata. Revoked certs no longer show a Renew form.
  The quick header "Renew" button (with hidden default validity) is replaced by
  a link scrolling to the editable form card.
- **Badge CSS conflict** (PR B review): a stale `.badge` rule at the bottom of
  `app.css` set `background: var(--surface-2)` and `border-radius: 999px`,
  overriding the design-system `.badge--ok/warn/danger/neutral` modifier
  backgrounds (making all badges grey) and forcing a pill shape. The base
  `.badge` rule now carries only `font-size`, `padding`, and
  `border-radius: var(--r-sm, 4px)` (rounded-rect); semantic backgrounds and
  colors remain in the modifier rules.
- **Serial Copy button** (PR B review): the `.copyline` for the serial number
  lacked an `input` or `textarea`, making `copyText()` a no-op. A hidden
  `<input type="hidden" value={serial}/>` is now included so the browser copy
  path works correctly.

### Added

- **Inventory + certificate detail redesign** (PR B): ports the inventory list
  and certificate detail screens to the approved Claude-Design mock.
  - **Inventory page** (`inventoryPage`, `inventoryTable`): new `page-head` with
    title, subtitle, and admin-only action buttons (Issue certificate / Sign CSR);
    `flash--info` "recorded view" banner with honest copy (no fake timestamp);
    `.filterbar` / `.searchbox` / `.select` filter bar; `.table-wrap` /
    `table.table` design-system table with columns: Common name, Status, Expires,
    Serial, Actions; chevron-right icon link per row.
  - **Status badges** (`statusBadge`): `badge--ok` "Valid" (green with dot) for
    active certs; `badge--warn` "Expiring" (amber with clock icon + day countdown)
    for active certs with ≤ 30 days remaining; `badge--neutral` "Expired" (grey)
    for expired; `badge--danger` "Revoked" (red with ban icon) for revoked.
  - **"Expiring" filter**: `status=expiring` in the filter bar / htmx partial now
    selects active certs with DaysLeft ≤ `ExpiringThresholdDays` (30). Added
    `ExpiringThresholdDays` constant to `internal/certs/inventory.go`; filter
    logic extended in `List()`.
  - **Certificate detail page** (`certDetailPage`): `page-head` with breadcrumb
    (Certificates / CN), monospace `page-title`, status badge + admin action
    buttons (Download bundle, Renew, Revoke) in `page-head__actions`; two-column
    `grid-2` metadata (Overview / Identifiers cards) with `dl` definition list;
    `.codeblock.pem` PEM viewers with `.codeblock__bar` toolbar and copy button;
    admin-only Revoke card with reason dropdown; viewer sees metadata + PEM only.
  - **Design-system CSS** ported into `internal/app/static/app.css`: page-head,
    stack, card sub-elements (card**header / card**body / card\_\_footer), btn
    variants (btn--primary / btn--danger / btn--ghost), badge modifiers
    (badge--ok / badge--warn / badge--danger / badge--neutral), tag, flash--info,
    table-wrap / table.table, filterbar / searchbox, input / select, field,
    form-actions, codeblock, copyline, dl, grid-2.
  - New pure-Go helpers: `fmtDate`, `fmtDaysAgo`, `fmtDaysHint`, `certFilename`.

- **Design foundation + new app shell** (PR A): ports the approved Claude-Design
  token system and app shell into the Templ/htmx app.
  - `internal/app/static/tokens.css` — IBM Plex design token system (pure
    `prefers-color-scheme` dark mode; no `[data-theme]` toggle); includes
    compatibility alias tokens mapping the old vocabulary (`--fg`, `--card`,
    `--radius`, `--shadow`, `--content-width`, etc.) to new tokens so existing
    page bodies keep rendering without changes.
  - `internal/app/static/fonts.css` — self-hosted IBM Plex Sans + IBM Plex Mono
    `@font-face` declarations (paths relative to `/static/`).
  - `internal/app/static/icons.svg` — Lucide-style SVG `<symbol>` sprite.
  - **Rebuilt app shell** (`layout` templ): dark-navy topbar with brand logo,
    `.nav__primary` (Certificates / Issue / Sign CSR with icons), JS-free
    checkbox-hamburger (`#nav-toggle` + `.nav__burger`), and a
    `<details class="menu mainmenu">` user-chip menu holding admin config links (Users,
    CA settings, Provisioners, ACME, Audit log, Log out). Viewers see only the
    Certificates primary link; no admin menu is rendered.
  - Link order in `<head>`: `fonts.css` → `tokens.css` → `app.css`.
  - `pageData.ActiveSection` field for `aria-current="page"` on primary nav.

- **Dual admin authentication** (spec/0012): the CA-settings page gains an
  **Admin authentication** card. Operators choose between three methods:
  - `none` — disables admin operations (create/delete provisioners, ACME management).
  - `x5c` — the **upload form** is now wired end-to-end. The operator pastes the
    admin certificate chain (PEM, leaf first) and the private key into the
    Admin authentication card; the handler validates keypair match,
    `digitalSignature` key usage, non-empty leaf CN (via `ca.NewAdminCredential`),
    **and** the `clientAuth` extended key usage required by Step-CA's
    `AuthorizeAdminToken`. The key is AES-256-GCM–sealed at rest and is
    write-only: never echoed in the response or any audit log detail
    (only `method=x5c subject=<leaf CN>` is recorded). A `set`/`none` status badge
    reflects whether a key is stored. A pre-filled `step ca certificate` command
    (with the stored CA URL) is shown as a guided hint for operators who need to
    issue the admin cert.
  - `jwk` — stores a JWK provisioner name, subject, and password. On demand the app
    mints an ephemeral P-256 key, obtains a short-lived admin cert via `POST /1.0/sign`
    (signed with a JWK OTT), then uses that cert to sign admin tokens — the ephemeral
    key and cert live only in memory (ADR-0018). The password is AES-256-GCM–sealed
    at rest and never logged, echoed, or included in audit details (FR-7).
    Switching methods clears the other method's sealed material (FR-5). The provisioner
    and ACME pages show an honest FR-6 hint naming both options when no auth is
    configured.

- Unraid Community-Applications template for **Step-CA** itself
  (`deploy/unraid/step-ca.xml`), alongside the existing step-ui-ng template, so the
  repository serves both halves of the stack. Documented how to register the repo as an
  Unraid template source (CA scans `.xml`; each template's `<TemplateURL>` enables
  update tracking).
- The Step-CA Unraid template now sets `--user 99:100` so the appdata bind mount is
  writable; without it the first-run init failed with `Permission denied` writing the
  generated password (the image runs as uid 1000, Unraid appdata is owned 99:100).
- Container `HEALTHCHECK` in both runtime images (`Dockerfile`, `Dockerfile.release`):
  probes the auth-exempt `/healthz` endpoint via busybox `wget`, honouring `${PORT}`. So
  `docker`/compose/Unraid now report container health (previously the UI image reported
  none).

### Fixed

- The CA-settings **Admin secret** and the **Provisioner secret** are write-only (never
  echoed), but it was unclear whether one was stored. Both now show a **set/none**
  status badge and a clear hint. The provisioner secret is also **preserved when you
  re-select the same provisioner with a blank field** (it used to be cleared on every
  save) — matching the admin secret's "leave blank to keep"; switching to a _different_
  provisioner with a blank secret still clears it.

### Removed

- **Vestigial CA-settings admin fields** (`admin_provisioner`, `admin_subject`,
  `admin_secret_sealed`) removed from `ca_settings`. Nothing in the codebase read
  these columns: certificate issuance uses the selected provisioner (spec/0005) and
  admin-API authentication uses the admin-authentication methods (spec/0012). Migration
  `0007_drop_unused_admin_fields.sql` drops the three columns; the CA-connection form
  no longer shows the admin-secret inputs. The CA-URL input is now styled consistently
  with other text fields (`input[type="url"]` added to the shared input rule in
  `app.css`).

### Changed

- Corrected spec 0012 (dual admin auth) and recorded **ADR-0018** after verifying against
  a live Step-CA: the Admin API accepts **only x5c** tokens (there is no "JWK admin
  token"), so the JWK/password method mints a short-lived x5c admin cert via the
  provisioner rather than signing a JWK token, reusing the existing x5c signer. Docs only;
  implementation pending.
- CI: `main.yml` also runs on `release: published`, so `:main` is rebuilt at the tagged
  commit after a release and reports the release version (a new tag changes
  `git describe` without a file change, so the push trigger alone left `:main` on the
  pre-tag describe).

## [0.3.1] - 2026-06-07

### Fixed

- **CA "Test connection" rejected every real Step-CA** with "The CA's root
  certificate does not match the configured fingerprint", even with the correct root
  fingerprint. The Phase-1 bootstrap required the configured fingerprint to appear in
  the **presented TLS chain**, but a real Step-CA presents only its leaf +
  intermediate (never the root). The root fingerprint is now matched against the
  `/roots` body (as intended); Phase-2 verification against the pinned root remains
  the authoritative MITM/anchor gate. The same Phase-1 client backs all CA operations
  (provisioners, ACME, sign/revoke), so those were affected too. Added a regression
  test that models a real root→intermediate→leaf topology (root only in `/roots`).

### Added

- The build version (`BuildInfo()`) is shown in a subtle fixed badge in the
  bottom-right corner of every page (`.appver`), so the running version is visible in
  the UI.

### Changed

- CI: `ci.yml` (Go lint/vet/test) now **skips docs-only changes** (`paths-ignore`:
  `**.md`, `docs/**`, `spec/**`, `deploy/**`, `LICENSE`) — safe because `main` has no
  required status checks. `main.yml` additionally ignores `.github/**`, so `:main`
  rebuilds only when the binary/image could change (not on docs or workflow edits).
- CI: `main.yml` now runs **automatically on every push to `main`** (docs-only changes
  excluded via `paths-ignore`; `concurrency` cancels superseded runs) in addition to
  `workflow_dispatch`, so the `:main` image + binary artifacts always reflect `main`.
  It pushes **only the moving `:main` tag** now (the immutable `:main-<shortsha>` pin
  was dropped so dev tags don't accumulate; the commit is still in the binary's version).

## [0.3.0] - 2026-06-07

### Added

- **CI: `:main` on-demand dev builds** (`main.yml`, `workflow_dispatch`) — build the
  current `main` (or any ref) without cutting a tag/release: binaries are published as
  workflow **artifacts** and the image is pushed as the moving **`:main`** tag (plus
  immutable `:main-<shortsha>`), versioned via `git describe`. Lets you test between
  betas with zero beta/tag inflation (ADR-0015).
- **Dark mode** — the UI follows the OS `prefers-color-scheme`. Colors are tokenized
  in `:root`, so a single dark token set flips the whole UI (no per-component rules).
- **Responsive topbar** — on narrow screens the nav collapses behind a JS-free
  hamburger (`<details>`-based) that drops a panel. In the panel the actions are
  organised under two section headings — **Certificates** (List / Issue / Sign CSR)
  and **Settings** (Users / CA settings / Provisioners / ACME) — with their items
  always listed and indented consistently; **Audit log** sits between them. On desktop
  the nav is a flat row and Settings stays a click-to-open dropdown. Desktop layout is
  unchanged.

### Changed

- **CI: image channel `:edge` renamed to `:beta`** (consistent with `:latest` / `:main`).
  `:beta` is the release edge: moved by every prerelease **and** every stable, so it is
  **never older than `:latest`** (`:beta` ⊇ `:latest`). Freshness `:latest` ⊆ `:beta` ⊆
  `:main` (ADR-0015).
- The inventory nav item is renamed **List** (the page heading stays "Certificates").
- UI foundation (ADR-0016): design tokens for shape/elevation/surfaces
  (`--radius`, `--radius-sm`, `--shadow`, `--input-bg`, `--surface-2`, flash tints),
  a shared `.popover` chrome class (Settings dropdown + mobile nav panel), and a
  per-page content width — data-heavy pages (inventory, audit) now render wider
  (`--content-width-wide`) while forms stay at the default width.

## [0.2.1] - 2026-06-07

### Added

- Topbar logo badge and favicon: `internal/app/static/logo.svg` (SVG shield/checkmark
  design) embedded and served at `/static/logo.svg`; rasterized `icon-256.png`,
  `icon-512.png`, and `favicon-32.png` committed alongside. The topbar brand link now
  shows the logo image (`<img class="brand-logo">`) before the "step-ui-ng" text;
  the layout `<head>` includes `<link rel="icon">` (favicon-32) and
  `<link rel="apple-touch-icon">` (icon-256). Minimal `.brand` / `.brand-logo` CSS
  added to `app.css` for alignment.
- Unraid Community-Applications template (`deploy/unraid/step-ui-ng.xml`): pulls
  `ghcr.io/nofuturekid/step-ui-ng:latest`, maps `/data` to appdata, exposes port
  8080, and configures `COOKIE_SECURE` and `RENEW_DEFAULT_DAYS` env vars.

- Password confirmation on the setup and create-user forms: both `/setup` and
  `POST /users` now require a matching `password_confirm` field, rejecting
  mismatched submissions with a clear error before any user is created.
- A **Users** link in the admin topbar (`internal/app`). The user-management page
  (`GET /users`, admin+) already existed and worked but was unreachable from the
  navigation — only the logo pointed at `/users`.
- Command-line flags that override the environment (`internal/config`
  `LoadWithFlags`): `-addr`, `-data-dir`, `-cookie-secure`, `-renew-default-days`,
  and `-version`. Precedence is flag > env > built-in default; env-only operation
  (`Load()`) is unchanged. `-version` prints the build version and exits before
  opening the store.

### Changed

- Topbar navigation restructured (`internal/app`): admin configuration links
  (Users, CA settings, Provisioners, ACME) are grouped under a JS-free **Settings**
  `<details>` menu, in that logical setup order; Certificates, Issue, Sign CSR and
  Audit log stay top-level. Topbar content is now width-limited and centered (shared
  `--content-width`, `.topbar-inner` wrapper) so it aligns with the page on ultrawide
  displays while the bar background stays full-bleed. The menu is admin-only and
  works without JavaScript.
- CI: image tag channels — a stable release publishes `:latest` + `:edge` + `:<tag>`;
  a prerelease publishes the moving `:edge` channel + `:<tag>` and never moves
  `:latest`. So `:latest` = newest stable (the default `docker pull`), `:edge` =
  newest build including betas. A stable release also advances `:edge` (a stable is
  the newest build), keeping `:edge` ⊇ `:latest` so `:edge` never goes stale behind a
  newer stable (ADR-0015).

- CI: bump the release workflow's GitHub Actions to their current Node 24 majors
  (`actions/upload-artifact` v4→v7, `actions/download-artifact` v4→v8,
  `docker/setup-qemu-action` v3→v4), clearing the Node.js 20 deprecation warnings.
  `ci.yml` was already on Node 24 majors.

- CI: release binaries now build in parallel via a 6-entry job matrix (one
  runner per target: `linux/amd64`, `linux/arm64`, `linux/arm`, `darwin/amd64`,
  `darwin/arm64`, `windows/amd64`). Each job emits a dedicated
  `<archive>.sha256` file (e.g. `stepui_v1.0.0_linux_amd64.tar.gz.sha256`)
  uploadable with `sha256sum -c`; the combined `SHA256SUMS.txt` is removed.

- The application version is stamped from the git tag at build time via
  `-ldflags "-X …/internal/app.Version=<tag>"` instead of a hand-edited constant
  (ADR-0013, supersedes the constant-bump mechanics of ADR-0011). `Version` is now
  a `var` whose literal is only the development fallback; new `app.BuildInfo()`
  returns the stamped tag verbatim, or enriches the fallback with the VCS revision
  (`<commit>`, plus `-dirty`) for development builds. The startup log and
  `-version` use `BuildInfo()`; `/healthz` still returns the bare `Version`.
- The published container image now reuses the prebuilt, ldflags-stamped binary
  from the `binaries` CI job instead of recompiling inside the Docker build
  (ADR-0014). A new `Dockerfile.release` accepts the binary via
  `COPY dist/stepui_linux_${TARGETARCH}` (no Go toolchain required). The
  `release.yml` job graph is `binaries` → `image`: `binaries` produces the
  version-stamped archives and uploads the raw linux amd64/arm64 binaries as an
  Actions artifact; `image` downloads them and builds the multi-arch image. The
  base image is minimal Alpine (`alpine:3`, pinned by digest) with
  `ca-certificates`, a nonroot user (uid/gid 65532), and a writable `/data`
  volume. The local `Dockerfile` is reworked to the same Alpine runtime (2-stage:
  Go toolchain builds, Alpine runs) so `make docker` and `make docker-release`
  produce compatible images; `make build` now also stamps the version via ldflags.

### Fixed

- Unraid: the container no longer fails to start on a fresh appdata bind mount.
  The image runs as `nonroot` (uid 65532), which cannot write Unraid's appdata
  (owned `nobody:users` = 99:100), so SQLite/`secret.key` creation failed unless
  the directory was `chmod 777`. The Unraid template now sets `--user 99:100`
  (Extra Parameters) to match appdata ownership. Documented bind-mount permission
  guidance for plain `docker run` too.

- Viewer no longer hits a "forbidden" page immediately after login. The three
  landing redirects (`postLogin`, `getLogin` already-authenticated guard, and the
  root `GET /` route) now send users to `/inventory` instead of `/users`.
  `/inventory` is accessible by all authenticated roles (`requireAuth`); `/users`
  is admin-only (`requireRole(RoleAdmin)`), so viewers previously got a 403
  straight after a successful login. The top-left logo link in the shared layout
  (`internal/app/templates.templ`) is also corrected from `/users` to `/inventory`,
  so viewers are never pointed at an admin-only route by the navigation.

- Auditable actions no longer crash with a recovered HTTP 500. `cmd/stepui`
  built `app.Deps` without `Audit`, leaving the server's audit recorder nil so
  every audit `Record`/`List` panicked. The recorder is now wired into the
  handler; `internal/audit` `Record`/`List` degrade to a no-op on a nil recorder
  (defence in depth); and `app.NewHandler` now fails fast at startup with a clear
  message if any required dependency (`DB`, `Users`, `Settings`, `Certs`,
  `Audit`, `Sessions`) is missing, so a future wiring omission cannot regress to
  a per-request panic.

## [0.1.1] - 2026-06-07

### Added

- Prebuilt, CGO-free binaries attached to every GitHub release (with a
  `SHA256SUMS.txt`): `linux/amd64`, `linux/arm64`, `linux/arm`, `darwin/amd64`,
  `darwin/arm64`, `windows/amd64` — packaged as `.tar.gz` (`.zip` for Windows).
  The `release.yml` workflow now builds and uploads them alongside the container
  image.

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
