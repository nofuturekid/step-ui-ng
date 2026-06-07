# 0013. Stamp the version from the git tag via ldflags, with a build-info fallback

- Status: accepted
- Date: 2026-06-07
- Deciders: maintainer

## Context and Problem Statement

ADR-0011 made the release the source of the version, but still hand-edited the
`Version` constant at release time. A hand-edited constant can drift from the tag
that actually triggers the release build, and it adds a manual step that is easy
to forget. We want the published binary to carry exactly the tag it was built
from, with no manual edit.

## Decision Drivers

- The version a binary reports should equal the git tag that produced it — no
  manual sync, no drift.
- Releasing should be "tag and push", not "edit a constant, then tag".
- Development builds should still be identifiable (which commit, clean or dirty).
- No new dependencies; keep the version in `internal/app` (no extra package).

## Considered Options

- Hand-edit the `Version` constant at release (ADR-0011 mechanics).
- Stamp the version from the git tag at build time via `-ldflags -X` and keep the
  in-source literal only as a development fallback.

## Decision Outcome

Chosen option: "stamp from the git tag via ldflags". `internal/app.Version`
becomes a `var` whose literal is only the development fallback. Release builds
pass `-ldflags "-X github.com/nofuturekid/step-ui-ng/internal/app.Version=<tag>"`
so the binary reports the tag verbatim. A new `app.BuildInfo()` returns `Version`
when it was stamped, and otherwise enriches the fallback with the VCS revision
(short commit + `-dirty`) read from `runtime/debug.ReadBuildInfo()`. `BuildInfo()`
is used for the startup log and the `-version` flag; `/healthz` keeps returning
the bare `Version`. The build/CI/Docker ldflags wiring is a separate change.

This supersedes the "bump the `Version` constant at release" mechanics of
ADR-0011. ADR-0011's broader decision — accumulate changes under CHANGELOG
`[Unreleased]` and only promote them to a dated `vX.Y.Z` heading at release —
still stands; only the constant-bump step is replaced by the tag stamp.

### Consequences

- Good, because the binary's reported version always equals its release tag.
- Good, because releasing is just tagging; no source edit can drift from the tag.
- Good, because development builds self-identify via commit + dirty flag.
- Neutral, the `Version` literal remains in source as the dev fallback and must
  stay in sync with `defaultVersion` (one place, in `version.go`).
- Bad, because a plain `go build` (no ldflags) reports the fallback, not a tag —
  acceptable, as untagged builds are by definition not releases.

## Pros and Cons of the Options

### Hand-edit the `Version` constant at release

- Good, because the value is visible in source with no build flags.
- Bad, because it can drift from the actual tag and is a manual, forgettable step.

### Stamp from the git tag via ldflags

- Good, because the tag is the single source of truth; no manual sync.
- Bad, because the in-source literal is only a fallback (mitigated by BuildInfo).

## More Information

Supersedes the version-bump mechanics of ADR-0011 (which retains the
`[Unreleased]` → dated-heading changelog policy). See `internal/app/version.go`
(`BuildInfo`) and the release build's `-ldflags` for the wiring.
