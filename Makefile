BINARY  := gs-secrets
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X github.com/guionardo/gs-secrets/internal/app.version=$(VERSION)"

.PHONY: build test vet lint fmt clean vulncheck snapshot release

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/gs-secrets

test:
	go test -race -cover ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .
	goimports -w . 2>/dev/null || true

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Local release dry-run: builds all platform archives into dist/ with a
# fake version, without publishing anything.
snapshot:
	goreleaser release --snapshot --clean

# Publish a release. Prefer pushing a v* tag and letting CI run
# .github/workflows/release.yml; this target is for local full runs.
release:
	goreleaser release --clean

clean:
	rm -rf bin dist