# syntax=docker/dockerfile:1

# ---- build (pure Go, static, no cgo) ----
FROM golang:1.23-bookworm AS build
WORKDIR /src
# templ for code generation
RUN go install github.com/a-h/templ/cmd/templ@latest
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN templ generate
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/stepui ./cmd/stepui

# ---- runtime (distroless, nonroot) ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/stepui /app/stepui
# Data dir (SQLite + secret.key) — mount a volume here.
VOLUME ["/data"]
ENV DATA_DIR=/data PORT=8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/stepui"]
