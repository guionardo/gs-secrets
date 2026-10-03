# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-03

### Added

- **Secret input without process-argument exposure**: `--set key` reads the
  value from stdin, `--set key --prompt` reads it from a masked terminal
  prompt (`golang.org/x/term`). Error messages no longer echo `--set`
  arguments (they could contain values).
- **Inter-process serialization**: every store operation takes an advisory
  exclusive lock on `<vault file>.lock` (flock on Unix, LockFileEx on
  Windows), so concurrent processes cannot corrupt the vault or lose
  updates.
- **Integration contract documentation** (`docs/API.md`): public API
  versioning policy, vault format compatibility, stdout/stderr contract for
  automation, safe stdin capture (with Node.js example), concurrency and
  key-lifecycle behavior, and per-platform permission enforcement.
- **Integration tests**: a Go process writes through `pkg/store` and the CLI
  binary reads (and vice versa, including stdin-fed values), asserting
  stdout purity and that secret values never reach stderr.
- **Platform test matrix in CI**: tests now run on ubuntu, macOS, and
  Windows runners, exercising the Unix mode enforcement and the Windows DACL
  code paths.

### Changed

- `app.Run` now takes the input stream explicitly (`Run(args, stdin, stdout,
  stderr)`).

## [0.2.0] - 2026-10-03

### Security

- **Replace the machine-ID-derived master key with a random 32-byte key
  file.** The previous key was derived from the machine serial number /
  machine-id, which is not secret; anyone who could read the machine ID
  could decrypt the vault. The vault now uses a fresh random key in
  `.gs-secrets.key` next to the vault, and refuses to open when the vault
  exists but the key file is missing.
- **Permissions are now enforced, not requested.** On Unix, vault and key
  files are chmod'ed to `0600` (directories `0700`) and verified on every
  open, failing loudly when that is not possible. On Windows, where POSIX
  modes are ignored by the OS, a user-restricted DACL (current user, SYSTEM,
  Administrators, protected from inheritance) is enforced and verified via
  `golang.org/x/sys/windows`.
- **Atomic writes**: vault and key files are written via temp file + fsync +
  rename, so a crash never leaves a truncated or corrupted file.
- **Key memory hygiene**: key bytes are zeroed when they become unreachable
  in process memory (`runtime.AddCleanup`).
- **Vault format header** (`GSSEC` magic + version + cipher id): foreign or
  corrupted blobs fail loudly; v0.1.0 files without the header are still
  readable and upgraded on the next write.

### Added

- `--rekey` command: rotates the master key in place, re-encrypting the
  vault. The previous key is kept as `.gs-secrets.key.bak` until the
  rotation completes, and decryption failures hint at restoring it after an
  interrupted rekey.
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
- **Windows installer script** (`install.ps1`): downloads the release
  archive for the machine architecture, verifies the SHA-256 checksum,
  extracts `gs-secrets.exe` into `%LOCALAPPDATA%\gs-secrets\bin` and adds it
  to the user PATH:
  `irm https://raw.githubusercontent.com/guionardo/gs-secrets/main/install.ps1 | iex`
- **`pkg/store` is now a public library**: moved out of `internal/` so other
  projects and repositories can import it (`github.com/guionardo/gs-secrets/pkg/store`).
  The `Store`, `Secret`, `New`, `WithKeyFile`, `Get`, `Set`, `Delete`,
  `List`, and `Rekey` APIs are exported, documented, and covered by a
  runnable example.
- Documentation: README, CONTRIBUTING, SECURITY policy, and this changelog.

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
- The `github.com/guionardo/go` dependency was removed; the only external
  dependency is `golang.org/x/sys` (Windows DACL enforcement, Windows only).

## [0.1.0] - 2026-10-03

### Added

- Initial release: `--set key=value [--ttl]` and `--get key` over an
  encrypted file vault, with machine-ID-derived key and AES-CTR encryption.

[0.3.0]: https://github.com/guionardo/gs-secrets/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/guionardo/gs-secrets/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/guionardo/gs-secrets/releases/tag/v0.1.0