# Repository Guidelines (for Claude Code & other agents)

Authoritative workflow lives in [`AGENTS.md`](AGENTS.md). Summary:

## Project

Self-contained Go web UI for Smallstep **Step-CA**. Server-rendered **Templ + htmx**
(no Node/React), **pure-Go SQLite**, secrets encrypted at rest, built-in auth.
Talks to Step-CA via **SDK/HTTP API** (no `step` CLI).

## Verify before committing

- `make check` (runs `gofmt`, `go vet`, `golangci-lint`, `templ generate` check, `go test ./...`)

## Working conventions (IMPORTANT)

- **Conventional Commits** (minimalistic), single subject line unless a body adds value.
- **One branch + PR per logical change**, based on `main`; **no merge without approval**.
- **SemVer (pre-1.0)**: bump the version only at releases (ADR-0011); per spec, add
  a `CHANGELOG.md` entry under `[Unreleased]`.
- **SDD/TDD**: spec → failing test → implement → refactor. See `spec/` and `docs/adr/`.

> Commits in this environment may carry a required session-link trailer; it is a
> footer and is compatible with Conventional Commits.
