# syntax=docker/dockerfile:1

# ---- build (pure Go, static, no cgo) ----
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
# templ is a go.mod tool; generate the *_templ.go (gitignored) before building.
RUN go tool templ generate
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/stepui ./cmd/stepui
# Empty data dir so the runtime VOLUME is owned by nonroot (distroless has no shell).
RUN mkdir -p /out/data

# ---- runtime (distroless, nonroot) ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/stepui /app/stepui
COPY --from=build --chown=nonroot:nonroot /out/data /data
# Data dir (SQLite + secret.key) — mount a volume here.
VOLUME ["/data"]
ENV DATA_DIR=/data PORT=8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/stepui"]
