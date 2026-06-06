# step-ui-ng

A modern, self-contained web UI to operate a **Smallstep Step-CA** — greenfield
rewrite of `step-ui`.

> **Status: `v0.0.1` — scaffold.** This repository is a _seed_ for an AI agent to
> implement feature-by-feature using **Spec-Driven Development (SDD)** and
> **Test-Driven Development (TDD)**. Start at [`spec/0001-foundation.md`](spec/0001-foundation.md).

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
