# 0015. Beta / prerelease lane for small or risky changes

- Status: accepted
- Date: 2026-06-07
- Deciders: maintainer

## Context and Problem Statement

Small fixes shouldn't always force a stable release, and risky changes benefit
from being tried before they become the default pull. We want a lightweight way to
publish a candidate build that does not affect users tracking the stable line.

## Decision Drivers

- Try small/risky changes in the wild without moving the stable pointer.
- Reuse the existing tag-driven release machinery (ADR-0011/0013) — no new tooling.
- Keep `latest` meaning "newest stable".

## Considered Options

- SemVer prerelease tags marked as GitHub "prerelease"
- A separate `next`/`edge` branch with its own image tag
- No prereleases (every change → stable patch)

## Decision Outcome

Chosen option: "SemVer prerelease tags". Cut prereleases as `vX.Y.Z-beta.N`
(`-rc.N` for release candidates), published as a GitHub **prerelease**
(`gh release create --prerelease`).

Rules:

- A prerelease attaches the prebuilt binaries (+ per-file `.sha256`) and pushes a
  container image tagged `:vX.Y.Z-beta.N` plus the moving **`:beta`** channel. It does
  **not** move `:latest` (enforced in `release.yml` via
  `github.event.release.prerelease`). A stable release pushes `:vX.Y.Z` + `:latest`.
- **Container tag channels** (named to mirror each other):
  - `:latest` — newest **stable** (the default `docker pull`).
  - `:beta` — newest **prerelease** (beta/RC). Tracks the beta lane only, so after a
    stable ships it may point at an older commit than `:latest` — that is intentional;
    for newer-than-stable testing use `:main`.
  - `:main` — newest **`main` build**, produced on demand by `main.yml`
    (`workflow_dispatch`). Also pushes an immutable `:main-<shortsha>`. Creates **no
    git tag and no GitHub release**, so testing between betas adds zero inflation. Its
    binaries are published as **workflow artifacts** on the run (downloadable for
    ~30 days), not as a release.
  - Rough freshness order: `:latest` ⊆ `:beta`/`:main` over time, but the channels are
    independent pointers, not enforced supersets.
- The version is stamped via ldflags (ADR-0013): a tagged build reports its tag
  (`vX.Y.Z` / `vX.Y.Z-beta.N`); a `main` build reports `git describe` output, e.g.
  `vX.Y.Z-beta.N-<commits>-g<sha>`.
- `CHANGELOG.md` stays under `[Unreleased]` for a prerelease; it is promoted to the
  dated `[vX.Y.Z]` heading only when the **stable** release is cut.
- When validated, cut the stable `vX.Y.Z` (which moves `:latest` and promotes the
  changelog); if problems surface, iterate `-beta.N+1`.

### Consequences

- Good, because users on `:latest`/stable are unaffected by betas; testers opt in
  explicitly by tag.
- Good, because it reuses the tag → release.yml flow unchanged except the
  `:latest` guard.
- Neutral, requires choosing beta vs stable per release.
- Bad, because more tags/releases to track.

## More Information

Builds on ADR-0011 (release-only versioning) and ADR-0013 (version from the git
tag). See `release.yml` for the prerelease `:latest` guard and `main.yml` for the
on-demand `:main` dev build (artifacts + `:main`/`:main-<sha>`).
