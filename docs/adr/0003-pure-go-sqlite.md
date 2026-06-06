# 0003. Pure-Go SQLite (modernc.org/sqlite)

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement
We want SQLite persistence but also a static, CGO-free binary that cross-compiles
to amd64/arm64 without a C toolchain.

## Decision Drivers
- `CGO_ENABLED=0` for static binary + distroless + easy multi-arch.
- Avoid cgo build complexity (the predecessor used mattn/go-sqlite3 + cgo).

## Considered Options
- modernc.org/sqlite (pure Go)
- mattn/go-sqlite3 (cgo)
- Embedded server DB (e.g. Postgres) — overkill

## Decision Outcome
Chosen option: "modernc.org/sqlite", because it removes cgo while keeping SQLite's
single-file simplicity.

### Consequences
- Good, because static binary, simple multi-arch, no C toolchain.
- Bad, because slightly slower than the C driver (irrelevant at this scale).

## More Information
Use a query layer of choice (database/sql + a thin repo, or sqlc). Migrations: ADR-0009.
