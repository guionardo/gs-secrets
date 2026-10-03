# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Replace the machine-ID-derived master key with a random 32-byte key
  file.** The previous key was derived from the machine serial number /
  machine-id, which is not secret; anyone who could read the machine ID
  could decrypt the vault. The vault now uses a fresh random key in
  `.gs-secrets.key` (mode `0600`) next to the vault, and refuses to open
  when the vault exists but the key file is missing.

### Changed

- **Encryption upgraded from AES-CTR to AES-256-GCM.** The ciphertext is
  now authenticated: any tampering is detected and rejected instead of
  silently returning corrupted secrets.
- **Refactored the CLI into a testable `app.Run`** with the entry point
  moved to `cmd/gs-secrets/main.go`; `main` no longer mutates global state
  or calls `os.Exit` in library code.
- **`--get` now prints the secret value** by default (previously it printed
  nothing unless `--verbose` was set).
- **Verbose and diagnostic messages go to stderr**, keeping stdout (or
  `--output FILE`) free for the secret value.
- TTL expiry now has millisecond precision.
- The `github.com/guionardo/go` dependency was removed; the project has no
  runtime dependencies beyond the Go standard library.

### Added

- `--list` command: sorted list of stored keys (never values).
- `--delete key` command: explicit deletion replaces the hidden
  `--set key=` convention.
- `--version` flag backed by build-time version injection.
- `--keyfile PATH` flag to override the master key file location.
- Makefile targets (`build`, `test`, `vet`, `lint`, `fmt`, `vulncheck`,
  `snapshot`, `release`, `clean`), golangci-lint configuration, and GitHub
  Actions workflows for CI (`ci.yml`) and automated versioned releases
  (`release.yml`).
- **Release pipeline moved to [GoReleaser](https://goreleaser.com)**:
  pushing a `v*` tag now cross-compiles archives for linux, darwin (macOS)
  and windows on amd64 and arm64 (tar.gz, zip for windows), generates
  `checksums.txt` and release notes, and publishes the GitHub release —
  configured in `.goreleaser.yml`, locally testable via `make snapshot`.
- **Homebrew tap**: stable releases publish a cask to
  `guionardo/homebrew-tap` (`brew install guionardo/tap/gs-secrets`), with a
  post-install hook that clears the macOS quarantine attribute. Requires the
  `HOMEBREW_TAP_TOKEN` secret.
- **Windows installer script** (`install.ps1`): downloads the release
  archive for the machine architecture, verifies the SHA-256 checksum,
  extracts `gs-secrets.exe` into `%LOCALAPPDATA%\gs-secrets\bin` and adds it
  to the user PATH:
  `irm https://raw.githubusercontent.com/guionardo/gs-secrets/main/install.ps1 | iex`
- Documentation: README, CONTRIBUTING, SECURITY policy, and this changelog.

## [0.1.0] - 2026-10-03

### Added

- Initial release: `--set key=value [--ttl]` and `--get key` over an
  encrypted file vault, with machine-ID-derived key and AES-CTR encryption.