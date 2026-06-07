# 0014. Publish the container image from the prebuilt, version-stamped binary on Alpine

- Status: accepted
- Date: 2026-06-07
- Deciders: maintainer

## Context and Problem Statement

The previous `release.yml` had two parallel jobs: `binaries` cross-compiled the
six release binaries and attached them to the GitHub release, while `build` ran
`docker/build-push-action` with the 2-stage `Dockerfile` — which downloaded the
Go toolchain, ran `go tool templ generate`, and recompiled everything inside the
Docker build. The binary in the published image was therefore a distinct artifact
from the one in the release archives: different build environment, no ldflags
version stamp, and redundant compile work. Requiring a Go toolchain in every
release image build also prevents using a lighter base image.

## Decision Drivers

- The container image and the release binary archives must be the same artifact:
  the exact bytes that were version-stamped by the `binaries` job must go into the
  image, with no recompile.
- The published image should not carry a Go toolchain — it only needs a shell,
  TLS CA certificates, a nonroot user, and a writable `/data` volume.
- A plain `make docker` for local development should still produce the same Alpine
  runtime via a 2-stage Dockerfile (toolchain compiles locally, runtime is Alpine).
- No new external dependencies; pinned base image by digest for reproducibility.

## Considered Options

- Keep the 2-stage `Dockerfile` for both CI and local builds (status quo).
- Introduce `Dockerfile.release` that consumes the prebuilt binary, used by CI;
  keep the 2-stage `Dockerfile` for local `make docker`.

## Decision Outcome

Chosen option: "Dockerfile.release for CI, 2-stage Dockerfile for local dev".

A new `Dockerfile.release` accepts the prebuilt, ldflags-stamped linux binary via
`COPY dist/stepui_linux_${TARGETARCH}`. The `release.yml` job graph is now
`binaries` → `image`: the `binaries` job builds and archives all six targets (with
the version ldflags), keeps stable raw copies of `dist/stepui_linux_amd64` and
`dist/stepui_linux_arm64`, and uploads them as a GitHub Actions artifact. The
`image` job downloads that artifact, restores the executable bit (upload-artifact
drops it), and runs `docker/build-push-action` with `Dockerfile.release`.

The local `Dockerfile` is reworked to the same Alpine runtime (replacing distroless),
so `make docker` produces an identical runtime layer. A new `make docker-release`
target simulates the CI path locally (cross-builds the linux binary into `dist/`,
then builds `Dockerfile.release`).

The base image is `alpine:3` pinned by digest (`sha256:5b10f432…`). The Alpine
runtime setup (apk ca-certificates, nonroot uid/gid 65532, `/data` owned by
nonroot) is identical between `Dockerfile.release` and the runtime stage of the
2-stage `Dockerfile`.

### Consequences

- Good, because the released binary and the image are provably the same artifact.
- Good, because the published image carries no Go toolchain (smaller attack surface).
- Good, because the CI image build is fast — no compile, no templ generate.
- Good, because the base image digest is pinned for reproducibility.
- Neutral, two Dockerfiles exist; their Alpine runtime stanzas are intentionally
  duplicated (small, stable, easy to keep in sync).
- Bad, because `Dockerfile.release` cannot build without a pre-populated `dist/`
  directory — `make docker` (2-stage) is the correct path for local builds.

## Pros and Cons of the Options

### Keep the 2-stage Dockerfile for CI

- Good, because a single file serves both purposes.
- Bad, because the image binary is a distinct artifact from the release archive.
- Bad, because no version ldflags in the image (the CI `build` job did not pass them).
- Bad, because the Go toolchain is pulled on every release image build.

### Dockerfile.release for CI, 2-stage Dockerfile for local dev

- Good, because CI image = release binary = single stamped artifact.
- Good, because no toolchain in the published image.
- Bad, because there are two Dockerfiles to maintain.

## More Information

- See `Dockerfile.release` (CI runtime), `Dockerfile` (local 2-stage), and
  `.github/workflows/release.yml` (`binaries` → `image` job graph).
- The ldflags wiring is described in ADR-0013.
- `.dockerignore` must not exclude `dist/` so that `Dockerfile.release` can
  access the prebuilt binary in the build context.
