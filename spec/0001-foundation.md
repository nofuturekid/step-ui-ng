# 0001 — Foundation

## Context
Establish the skeleton everything else builds on: configuration, persistence,
logging, embedded assets, and a health endpoint.

## User stories
- As an operator, I can run a single binary/container and reach a health endpoint.
- As a developer, I have a DB with versioned migrations and structured logs.

## Functional requirements
- FR-1: Config loads `PORT` (default 8080) and `DATA_DIR` (default `./data`); no
  other required env vars.
- FR-2: On startup, ensure `DATA_DIR` exists; open SQLite at `DATA_DIR/stepui.db`
  (modernc.org/sqlite, CGO-free).
- FR-3: Run embedded goose migrations on startup; record schema version.
- FR-4: Structured logging via `slog` (JSON).
- FR-5: `GET /healthz` returns 200 with `{"status":"ok","version":"<v>"}`.
- FR-6: Templates/static assets are embedded via `go:embed`; graceful shutdown.

## Data model / Routes
- Migrations table managed by goose. Route: `GET /healthz`.

## Acceptance criteria
- Given the server is running, When I GET `/healthz`, Then I receive 200 and a JSON
  body with `status=ok` and the current version.
- Given no `DATA_DIR` exists, When the app starts, Then it is created and the DB +
  migrations are initialized without error.
- Given `PORT=9000`, When the app starts, Then it listens on `:9000`.

## Tests
- `internal/app`: healthz returns 200 + version (provided in scaffold).
- `internal/config`: defaults and env overrides (provided in scaffold).
- `internal/store`: migrations apply to a temp DB; re-running is idempotent.

## Out of scope
- Auth, CA, UI pages (later specs).
