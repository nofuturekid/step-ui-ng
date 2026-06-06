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

## License

MIT — see [LICENSE](LICENSE).
