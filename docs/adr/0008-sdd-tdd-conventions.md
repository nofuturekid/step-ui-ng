# 0008. SDD/TDD workflow, Conventional Commits, SemVer v0.0.x

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement

This repo seeds an AI agent. We need a predictable, reviewable process.

## Decision Drivers

- Traceability from spec → test → code.
- Small, reviewable changes; clear history and versioning.

## Considered Options

- SDD + TDD with Conventional Commits and SemVer
- Ad-hoc development

## Decision Outcome

Chosen option: "SDD + TDD + Conventional Commits + SemVer (start v0.0.1)". Specs in
`spec/`, decisions in `docs/adr/`, one branch+PR per spec, patch bump per spec.

### Consequences

- Good, because predictable, reviewable, well-documented.
- Bad, because more upfront writing (specs/ADRs) before coding.

## More Information

See AGENTS.md for the per-spec loop and Definition of Done.

> Note: the "patch bump per spec" cadence above is revised by **ADR-0011** —
> versions are bumped only at releases; per-spec changes go under CHANGELOG
> `[Unreleased]`. The SDD/TDD, Conventional Commits and SemVer decisions stand.
