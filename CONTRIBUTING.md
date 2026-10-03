# Contributing to gs-secrets

Thanks for considering a contribution. This guide gets you from clone to
merge in under ten minutes.

## Prerequisites

- Go 1.27 or newer (see `go.mod`)
- [golangci-lint](https://golangci-lint.run/) v2.14 or newer
  (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`)

## Development workflow

```bash
git clone https://github.com/guionardo/gs-secrets.git
cd gs-secrets

make test    # go test -race -cover ./... (includes CLI integration tests)
make lint    # golangci-lint run ./...
make vet     # go vet ./...
make build   # builds bin/gs-secrets with the current git version
```

All checks must pass before a PR is merged. The CI pipeline
(`.github/workflows/ci.yml`) runs test, lint, and a `govulncheck`
vulnerability scan on every push and pull request — tests run on the
**ubuntu, macOS, and Windows** runners, so platform-specific permission
code (Unix modes, Windows DACL) is exercised on every change.

## Project layout

```
cmd/gs-secrets/       Thin entry point: parses args, delegates to internal/app
internal/app/         CLI logic: flag parsing, command dispatch (Run)
pkg/store/            Public library: encrypted vault, key-file management
```

- Business logic lives in `internal/`; `cmd/gs-secrets` stays thin.
- The `pkg/store` package is a **public library** (importable from other
  repositories) — its API must stay documented, tested, and backward
  compatible. Breaking changes require a major version bump.
- The `app` package must remain testable: `Run(args, stdout, stderr)` never
  calls `os.Exit` or writes to global state.

## Code style

- `gofmt -s` and `goimports` (module-local imports grouped last).
- Lint clean with the project `.golangci.yml` — do not add bare `//nolint`;
  if you must suppress a finding, justify it on the same line.
- Doc comments on every exported identifier; comments explain *why*, not
  what the code already shows.
- Tests use `testing` + `testify`, co-located with the code, `t.TempDir()`
  for fixtures, and the race detector must pass.

## Security-sensitive changes

Crypto code lives in `pkg/store/store.go`. Changes to key handling,
encryption, or file permissions must update [SECURITY.md](./SECURITY.md) and
add tests for the failure modes (tampered vault, wrong key, missing key
file).

## Pull request process

1. Create a branch with a descriptive name (`fix/`, `feat/`, `docs/`).
2. Make your change; keep commits focused and messages imperative.
3. Run `make test lint vet` locally and fix everything.
4. Open the PR against `main`; CI must be green.
5. Reference the issue the PR fixes, if any.

## Releasing

Releases are built with [GoReleaser](https://goreleaser.com) (`.goreleaser.yml`).
Maintainers create a release by pushing a semantic version tag; the
`release.yml` workflow runs the test suite, then GoReleaser cross-compiles,
archives (tar.gz / zip), verifies, and attaches binaries and `checksums.txt`
for linux, darwin and windows on amd64 and arm64:

```bash
git tag v1.2.3
git push origin v1.2.3
```

Stable tags additionally publish the Windows installer entry point:
`install.ps1` in the repository root stays current with `main`.

Prerelease tags containing a `-` (e.g. `v1.2.3-rc.1`) are published as
prereleases. To test a release locally without publishing:

```bash
make snapshot   # goreleaser release --snapshot --clean → dist/
```