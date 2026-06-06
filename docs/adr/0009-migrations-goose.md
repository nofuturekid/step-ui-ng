# 0009. Schema migrations with goose (embedded)

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement
The predecessor relied on GORM AutoMigrate, which obscures schema evolution. We want
explicit, versioned, reviewable migrations.

## Decision Drivers
- Deterministic, reviewable schema changes.
- Run automatically at startup; embedded in the binary.

## Considered Options
- goose (embedded SQL via go:embed)
- golang-migrate
- Hand-rolled migration runner

## Decision Outcome
Chosen option: "goose with embedded SQL migrations", applied on startup.

### Consequences
- Good, because explicit, ordered, embeddable, widely used.
- Bad, because a small dependency and migration discipline required.

## More Information
Migrations live in `internal/store/migrations/*.sql`, embedded via `go:embed`.
