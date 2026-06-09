# step-ui-ng

A modern, self-contained web UI to operate a **Smallstep Step-CA** — greenfield
rewrite of `step-ui`.

> **Status: all feature specs (0001–0010) implemented.** Built-in auth & users,
> CA settings, provisioners, issue/sign, inventory & encrypted download, real
> revoke/renew, audit log, and ACME (provisioners, EAB, client onboarding) — each
> built **Spec-Driven (SDD)** + **Test-Driven (TDD)**, reviewed, and merged. The
> version stays `v0.0.1` until the first release is cut (ADR-0011).

## What this is

A single Go binary that serves both the API and a server-rendered UI
(**Templ + htmx**, no Node/React) and talks to a Step-CA over its HTTP/admin API.
SQLite for state, secrets encrypted at rest, built-in authentication with a
first-run super-admin setup. Almost everything (CA URL, provisioners, ACME) is
configured **in the UI**, not via environment variables.

## Highlights / design

- **Go**, server-rendered **Templ + htmx**, assets via `go:embed` → one static binary.
- **Pure-Go SQLite** (`modernc.org/sqlite`), `CGO_ENABLED=0` → trivial multi-arch.
- **Step-CA via SDK/HTTP API** (`go.step.sm/crypto`), **no `step` CLI** in the image.
- **Built-in auth**: local users, roles (superadmin/admin/viewer), first-run setup.
- **Secrets & private keys encrypted at rest** (AES-256-GCM); master key stored
  next to the database in the data volume.
- **ACME enablement** in the UI (provisioners, EAB keys, directory + client hints).
- Distroless, multi-arch image; structured logging (`slog`); real migrations.

See the decision records in [`docs/adr/`](docs/adr/) (MADR format) and the feature
specs in [`spec/`](spec/).

## Quick start (development)

```bash
make tools      # install templ, golangci-lint, goose (see Makefile)
make generate   # templ generate
make test       # go test ./...
make run        # start on http://localhost:8080
```

On first launch the app guides you through creating the **super-admin**, then the
**Step-CA connection** — no env vars required. Data (SQLite + `secret.key`) lives
in `./data` (mount this volume in production).

## For the implementing agent

Read [`AGENTS.md`](AGENTS.md) first. Work the specs in order, test-first, one
focused PR per spec, Conventional Commits, changelog under `[Unreleased]` (versions
are bumped only at releases — ADR-0011).

## Deployment

### Unraid

Two Unraid Community-Applications templates are provided — the full stack:

- [`deploy/unraid/step-ui-ng.xml`](deploy/unraid/step-ui-ng.xml) — this web UI.
- [`deploy/unraid/step-ca.xml`](deploy/unraid/step-ca.xml) — the Smallstep **Step-CA**
  itself, so you can run the CA and its UI from one source.

To install a single template, copy the `.xml` into
`/boot/config/plugins/dockerMan/templates-user/` on your Unraid box, then
**Docker → Add Container** and pick it from the template list.

To use this repository as a **template source** (so both templates appear and stay
update-tracked), add it as a private template repository — in Community Applications:
_Settings → Manage repositories_ (or drop the repo URL into
`/boot/config/plugins/dockerMan/template-repos`). CA scans the repo for `.xml`
templates; each template's `<TemplateURL>` points back at its raw GitHub path, so edits
pushed to `main` show up as updates.

#### step-ui-ng — key settings

- **Data path** — map `/data` to an appdata location (e.g. `/mnt/user/appdata/step-ui-ng`).
  This directory holds the SQLite database **and** the master encryption key (`secret.key`).
  Back it up and restrict access.
- **Runs as `99:100`** — the image's default user is `nonroot` (uid 65532), which cannot
  write Unraid's appdata (owned `nobody:users` = 99:100). The template sets
  `--user 99:100` (Extra Parameters) so the bind mount is writable **without** `chmod 777`.
  For a plain `docker run`, either use a named volume (works out of the box) or, for a
  bind mount, make the host dir writable by the container user (own it as the uid you run
  as, or pass `--user <uid>:<gid>` matching the dir's owner).
- **COOKIE_SECURE** — set to `true` when the UI is behind a TLS reverse proxy (Nginx, Caddy, etc.).
- **RENEW_DEFAULT_DAYS** — default validity (days) pre-filled in the renewal form (default: 90).

Image tags: `:latest` (newest stable) · `:beta` (release edge — newest pre-release,
moved by stables too, so **never older than `:latest`**) · `:main` (newest `main`
build — built on every push to `main` and on demand via the `main.yml` workflow; a
moving tag, no per-commit pins). Freshness `:latest` ⊆ `:beta` ⊆ `:main`. Use
`:latest` for production, `:beta` to track the release edge, `:main` to test unreleased
changes between betas. See ADR-0015.

App icon URL (resolves once merged to main):
`https://raw.githubusercontent.com/nofuturekid/step-ui-ng/main/internal/app/static/icon-256.png`

#### step-ca — key settings

- **First-run init** — the `Init: …` variables apply **only** on the first start (empty
  appdata); they are ignored once the CA is initialized. After the first start, read the
  admin username/password from `docker logs step-ca` (save them — shown once) and the
  root fingerprint via `docker exec step-ca step certificate fingerprint certs/root_ca.crt`.
- **DNS Names** — add your Unraid host IP/hostname to `Init: DNS Names`; these become the
  CA's TLS SANs, and clients (including step-ui-ng) can only verify names listed there.
  Keep `localhost,127.0.0.1` so the image's built-in healthcheck stays green.
- **Remote Management** — left `true` so the Admin API is enabled (a JWK super-admin with
  a password); required to manage provisioners at runtime.
- **Appdata** — map `/home/step` to an appdata location (e.g. `/mnt/user/appdata/step-ca`).
  It holds the root/intermediate keys and config; back it up. Deleting it forces a reinit
  with a **new root**, invalidating all previously issued certificates.
- **Runs as `99:100`** — the image's default user is `step` (uid 1000), which cannot write
  a `99:100`-owned appdata dir; without it the first-run init fails with
  `Permission denied`. The template sets `--user 99:100` (Extra Parameters). Make the
  appdata dir match: `chown -R 99:100 /mnt/user/appdata/step-ca` once (a freshly created
  bind-mount dir is `root:root`).

Point step-ui-ng at the CA with its URL (`https://HOST:9000`) and the root fingerprint.

## License

MIT — see [LICENSE](LICENSE).
