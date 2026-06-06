BINARY := stepui
PKG := ./...

.PHONY: all tools generate build run test check lint fmt vet docker

all: check build

tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/pressly/goose/v3/cmd/goose@latest

generate:
	go tool templ generate

build: generate
	CGO_ENABLED=0 go build -o bin/$(BINARY) ./cmd/stepui

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

docker:
	docker build -t ghcr.io/nofuturekid/step-ui-ng:dev .
