BINARY := stepui
PKG := ./...
VERSION ?= $(shell git describe --tags --always --dirty)

.PHONY: all tools generate build run test check lint fmt vet docker docker-release

all: check build

tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/pressly/goose/v3/cmd/goose@latest

generate:
	go tool templ generate

build: generate
	CGO_ENABLED=0 go build \
		-ldflags "-X github.com/nofuturekid/step-ui-ng/internal/app.Version=$(VERSION)" \
		-o bin/$(BINARY) ./cmd/stepui

run: generate
	go run ./cmd/stepui

test:
	go test $(PKG)

fmt:
	gofmt -w .

vet:
	go vet $(PKG)

lint:
	golangci-lint run

# Quality gate used in CI and locally before committing.
check: vet test
	@gofmt -l . | (! grep .) || (echo "gofmt needed"; exit 1)
	@go tool templ generate; git diff --exit-code -- '*_templ.go' || (echo "run 'go tool templ generate'"; exit 1)
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed, skipping"

# Local dev: 2-stage build (Go toolchain → Alpine runtime). Same Alpine base as
# Dockerfile.release, compiled locally with ldflags.
docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		-t ghcr.io/nofuturekid/step-ui-ng:dev .

# Simulate the CI release path locally: cross-build the linux binary for the
# host arch into dist/, then build the runtime image from that prebuilt binary.
docker-release:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=$(shell go env GOARCH) \
		go build -trimpath \
		-ldflags "-s -w -X github.com/nofuturekid/step-ui-ng/internal/app.Version=$(VERSION)" \
		-o dist/stepui_linux_$(shell go env GOARCH) ./cmd/stepui
	docker build -f Dockerfile.release \
		-t ghcr.io/nofuturekid/step-ui-ng:dev-release .
