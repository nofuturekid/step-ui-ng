# 0007. Embed assets with go:embed; distroless multi-arch image

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement
The predecessor copied the built frontend into the image and served it from disk
(STATIC_DIR), so the binary was not self-contained.

## Decision Drivers
- One artifact to ship; no path/mount coupling.
- Small, secure runtime image; multi-arch for homelabs (arm64).

## Considered Options
- go:embed templates/static into the binary; distroless runtime
- Copy assets dir into the image (status quo)

## Decision Outcome
Chosen option: "go:embed + distroless (nonroot) multi-arch", building with
`CGO_ENABLED=0`.

### Consequences
- Good, because a single binary, tiny attack surface, simple deploy.
- Bad, because asset changes require a rebuild (acceptable).

## More Information
Image: `gcr.io/distroless/static-debian12:nonroot`. Platforms: amd64, arm64.
