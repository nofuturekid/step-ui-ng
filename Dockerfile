# syntax=docker/dockerfile:1
# 2-stage local build: Go toolchain compiles, Alpine runs.
# Use `make docker` for local dev builds; CI uses Dockerfile.release instead
# (which reuses the prebuilt, version-stamped binary — no toolchain in the image).

# ---- build (pure Go, static, no cgo) ----
FROM golang:1.25-bookworm AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
# templ is a go.mod tool; generate the *_templ.go before building.
RUN go tool templ generate
RUN CGO_ENABLED=0 GOFLAGS=-trimpath \
    go build \
    -ldflags="-s -w -X github.com/nofuturekid/step-ui-ng/internal/app.Version=${VERSION}" \
    -o /out/stepui ./cmd/stepui

# ---- runtime (minimal Alpine, same as Dockerfile.release) ----
# Pin alpine:3 by digest (alpine:3.22 / edge of 3.x as of 2026-06-07).
# To update: docker pull alpine:3 && docker inspect alpine:3 --format '{{index .RepoDigests 0}}'
FROM alpine@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 65532 nonroot && adduser -S -u 65532 -G nonroot nonroot \
 && mkdir -p /data && chown nonroot:nonroot /data
WORKDIR /app
COPY --from=build /out/stepui /app/stepui
USER nonroot:nonroot
# Data dir (SQLite + secret.key) — mount a volume here.
VOLUME ["/data"]
ENV DATA_DIR=/data PORT=8080
EXPOSE 8080
ENTRYPOINT ["/app/stepui"]
