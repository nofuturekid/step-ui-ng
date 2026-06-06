# 0001. Backend in Go

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement
We need a backend for a self-contained Step-CA web UI that ships as a single,
low-footprint container for homelab use and integrates tightly with Step-CA.

## Decision Drivers
- Native Step-CA ecosystem (libraries are Go).
- Single static binary, small image, easy multi-arch.
- Low idle footprint for an always-on container.

## Considered Options
- Go
- Python (FastAPI)
- Node/TypeScript

## Decision Outcome
Chosen option: "Go", because the Step-CA SDK is Go-native (avoids brittle CLI
shelling) and Go's single-binary/cross-compile story fits the deployment target.

### Consequences
- Good, because native SDK, static binary, trivial multi-arch, low memory.
- Bad, because more verbose than Python for some glue code.
- Neutral, predecessor `step-ui` was already Go.

## More Information
Supersedes the predecessor's Go+Gin backend with a cleaner architecture (see other ADRs).
