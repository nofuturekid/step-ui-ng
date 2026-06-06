# Agent guide — how to build step-ui-ng

This repo is a **seed**. Implement it feature-by-feature with **SDD + TDD**.

## Golden rules

1. **Spec first.** Each feature has a spec in `spec/NNNN-*.md` with acceptance
   criteria (Given/When/Then). Implement specs in numeric order. If a spec is
   ambiguous, refine the spec (and, if it is an architectural choice, add an ADR)
   **before** writing code.
2. **Test first (TDD).** Turn each acceptance criterion into a test, watch it fail
   (red), implement until green, then refactor. Don't write code without a failing
   test that justifies it.
3. **Small, focused PRs.** One spec (or one coherent slice) per branch + PR.
4. **Decisions are recorded.** Any non-trivial architectural choice → a new ADR in
   `docs/adr/` using the MADR template (`docs/adr/0000-template.md`).

## Workflow per spec

```
spec → write failing test(s) → implement → refactor → make check → commit → bump version → PR
```

## Conventions

- **Conventional Commits** (minimalistic): `type(scope): imperative summary`
  (lowercase, ≤ ~72 chars, no trailing period). Types: feat, fix, docs, refactor,
  perf, test, build, ci, chore.
- **Branches:** `type/short-kebab`, branched from `main`. One logical change each.
- **Pull Requests** to `main`, Conventional title; **do not merge without the
  maintainer's approval**.
- **Versioning (SemVer, pre-1.0):** start at `v0.0.1`. Each completed spec → patch
  bump, with a `CHANGELOG.md` entry (Keep a Changelog). A release tag triggers the
  image build (`.github/workflows/release.yml`).

## Quality gate (`make check` must pass)

- `gofmt`/`go vet` clean, `golangci-lint run` clean.
- `templ generate` is up to date (CI runs `templ generate` and checks for diffs).
- `go test ./...` green, with meaningful coverage of acceptance criteria.

## Architecture guardrails (see ADRs)

- The **CA is the source of truth**; keep local state minimal. Don't duplicate what
  the CA owns (provisioners, revocation state) — read/act through the CA.
- Talk to Step-CA via **SDK/HTTP API**, never by shelling out to the `step` CLI.
- **No secrets or private keys in clear text** — always through `internal/crypto`.
- **No business logic in templates**; handlers stay thin; domain logic in `internal/*`.
- Keep the binary **self-contained** (`go:embed` for templates/static), `CGO_ENABLED=0`.

## Definition of Done (per spec)

- [ ] Acceptance criteria covered by passing tests
- [ ] `make check` green
- [ ] Docs/specs updated; ADR added if a decision was made
- [ ] `CHANGELOG.md` + version bumped
- [ ] PR opened, description links the spec
