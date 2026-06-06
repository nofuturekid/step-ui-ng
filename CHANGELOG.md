# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions are bumped only when a release is cut; in-progress work lives under
[Unreleased] (see ADR-0011).

## [Unreleased]

### Added

- Foundation persistence (`internal/store`): pure-Go SQLite opened under
  `DATA_DIR`, with embedded, idempotent goose migrations applied on startup
  (spec/0001). Wired into server boot; logs the applied schema version.

### Changed

- Align repo conventions and CI to the `main` branch (docs + workflow triggers).
- CI derives the Go version from `go.mod` (now `1.25`, required by the SQLite/goose
  dependencies) and enables module caching.
- Migrate the golangci-lint config to the v2 format.
- Adopt release-only versioning: bump the `Version` constant and add a dated
  changelog heading only when cutting a release (ADR-0011, supersedes the per-spec
  bump cadence of ADR-0008).

### Fixed

- Pin templ as a go.mod `tool` dependency and run `go tool templ generate`
  everywhere (CI + Makefile), silencing the "templ not found in go.mod" version
  warning and making generation reproducible.
- Bump `golangci-lint-action` v8 → v9 (runs on Node.js 24), silencing the GitHub
  Actions Node.js 20 deprecation warning ahead of the 2026-06-16 cutover.

## [0.0.1] - 2026-06-06

### Added

- Initial scaffold: project layout, build/CI tooling, ADRs (MADR) and feature
  specs (SDD), minimal compiling HTTP skeleton with a health endpoint and tests.
