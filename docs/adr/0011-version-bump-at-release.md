# 0011. Bump the version only at releases; accumulate changes under [Unreleased]

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement

ADR-0008 prescribed a SemVer patch bump per completed spec. In practice this
produces version numbers (e.g. `0.0.2`) that were never released or tagged,
decoupling the version from any actual artifact. We want the version to denote a
real release, not a development milestone.

## Decision Drivers

- A version number should map to a published release (tag → image build via
  `release.yml`), not to an in-progress branch.
- "Keep a Changelog" already models in-progress work via an `[Unreleased]` section.
- Less churn: no per-spec edits to the version constant and changelog headings.

## Considered Options

- Bump the patch version per completed spec (ADR-0008, status quo).
- Bump the version only when cutting a release; accumulate changes under
  `[Unreleased]` until then.

## Decision Outcome

Chosen option: "bump only at releases". Per spec/PR, add entries under the
CHANGELOG `[Unreleased]` section and leave the `Version` constant untouched. When
the maintainer cuts a release, rename `[Unreleased]` to the new `vX.Y.Z` with a
date, bump the `Version` constant to match, and publish a GitHub release (which
tags the commit and triggers the image build).

### Consequences

- Good, because the version always corresponds to a released, tagged artifact.
- Good, because per-spec PRs touch only `[Unreleased]`, reducing merge churn.
- Neutral, the release step now bundles the version bump + changelog promotion.
- Bad, because `main` between releases reports the last released version, not the
  set of merged-but-unreleased changes (the changelog `[Unreleased]` covers this).

## More Information

Supersedes the versioning cadence of ADR-0008 (SDD/TDD, Conventional Commits and
SemVer itself are unchanged). See `AGENTS.md` for the revised per-spec loop.

> Note: ADR-0013 supersedes the _mechanics_ of the version bump described here —
> the version is now stamped from the git tag via ldflags rather than by editing
> the `Version` constant. The `[Unreleased]` → dated-heading changelog policy
> above is unchanged.
