# 0004. Talk to Step-CA via SDK/HTTP API, not the step CLI

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement
The predecessor shelled out to the `step` CLI for everything (issue, sign, revoke,
provisioner mgmt), parsing CLI output and writing password temp files (some at
0644). This is fragile and a security smell.

## Decision Drivers
- Robustness (no output parsing, no temp-file secrets).
- Testability (mock an HTTP CA in tests).
- Smaller image (no CLI binary).

## Considered Options
- Go SDK + HTTP/admin API (`go.step.sm/crypto`, smallstep client)
- Keep shelling out to `step`
- Hybrid (SDK for most, CLI for admin)

## Decision Outcome
Chosen option: "Go SDK + HTTP/admin API", including admin-token signing via
`go.step.sm/crypto` for provisioner/ACME admin operations.

### Consequences
- Good, because typed, robust, testable; no CLI in the image.
- Bad, because admin-token (JWK/x5c) signing must be implemented carefully.
- Neutral, requires the CA's remote management to be enabled for admin ops.

## More Information
Admin endpoints: `/admin/provisioners`, `/admin/acme/eab/...`. See spec 0005/0010.
