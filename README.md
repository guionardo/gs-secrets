# gs-secrets

[![Go Version](https://img.shields.io/github/go-mod/go-version/guionardo/gs-secrets)](https://go.dev/)
[![License](https://img.shields.io/github/license/guionardo/gs-secrets)](./LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/guionardo/gs-secrets/ci.yml?branch=main)](https://github.com/guionardo/gs-secrets/actions)

Poor-man's secret vault: a single-file CLI to store and retrieve API keys,
passwords, and other secrets in an AES-256-GCM encrypted local vault.

No cloud, no daemon, no dependencies beyond the Go standard library. Secrets
expire on demand with a TTL.

## Demo

```console
$ gs-secrets --set github_token=ghp_xxxxxxxx --ttl 24h
$ gs-secrets --get github_token
ghp_xxxxxxxx
$ gs-secrets --list
github_token
$ gs-secrets --delete github_token
```

## Getting Started

### Install from source

```bash
go install github.com/guionardo/gs-secrets/cmd/gs-secrets@latest
```

### Install from a release

**Windows (PowerShell)** — downloads the right binary for your architecture,
verifies its SHA-256 checksum, and adds it to your user PATH:

```powershell
irm https://raw.githubusercontent.com/guionardo/gs-secrets/main/install.ps1 | iex
```

Open a new terminal afterwards, then `gs-secrets --version`.

**Linux / macOS / manual** — download the binary for your platform from the
[releases page](https://github.com/guionardo/gs-secrets/releases) and verify
its checksum against `checksums.txt` attached to the release.

### Build from source

```bash
git clone https://github.com/guionardo/gs-secrets.git
cd gs-secrets
make build          # produces bin/gs-secrets with the current git version
make test           # run the test suite with the race detector
```

## Usage

```
gs-secrets --set key=value [--ttl DURATION] [--store PATH] [--keyfile PATH]
gs-secrets --set key [--prompt] [--ttl DURATION] [--store PATH] [--keyfile PATH]
gs-secrets --get key [--output FILE] [--store PATH] [--keyfile PATH]
gs-secrets --delete key [--store PATH] [--keyfile PATH]
gs-secrets --list [--store PATH] [--keyfile PATH]
gs-secrets --rekey [--store PATH] [--keyfile PATH]
gs-secrets --version
```

**Never pass secrets as command-line arguments.** Use `--set key` to feed
the value via stdin, or `--set key --prompt` for a masked terminal prompt.
The inline `--set key=value` form exists only for non-sensitive data — the
value would be visible in the process argument list.

| Flag | Description |
| --- | --- |
| `--set key=value` | Store a secret inline (non-sensitive values only — visible in process args). With `--ttl`, it expires after the given duration. |
| `--set key` | Store a secret reading the value from stdin; the secret never appears in process arguments. |
| `--set key --prompt` | Store a secret from a masked terminal prompt (no echo, no process args). |
| `--get key` | Print the secret value to stdout (or `--output FILE`). |
| `--delete key` | Remove a secret. Deleting a missing key is not an error. |
| `--list` | List stored keys, sorted, never values. |
| `--rekey` | Rotate the master key and re-encrypt the vault (backup of the old key kept as `.bak` until completion). |
| `--ttl DURATION` | Time to live for `--set`, e.g. `1h`, `30m`, `90s`. `0` (default) means never expires. |
| `--store PATH` | Vault file. Default: `<user config dir>/gs-secrets/.store`. |
| `--keyfile PATH` | Master key file. Default: `<vault dir>/.gs-secrets.key`. |
| `--output FILE` | Write command output to FILE instead of stdout. |
| `--verbose` | Print progress messages to stderr (never secret values). |
| `--version` | Print the version and exit. |

Exit code is `0` on success and `1` on any error, including a missing secret.

### Examples

```bash
# Store a secret that expires in one hour, without exposing it in process args
printf '%s' "$TOKEN" | gs-secrets --set api_key --ttl 1h

# Masked interactive prompt
gs-secrets --set db_password --prompt

# Use a project-local vault instead of the user-global one
gs-secrets --set db_password=secret --store ./vault/.store

# Pipe a secret into another command without echoing it
gs-secrets --get api_key | curl -H "Authorization: Bearer $(cat)" ...

# Write a secret straight to a file
gs-secrets --get api_key --output /tmp/key
```

For automation contracts (stdout purity, exit codes, safe stdin capture,
Node.js example) see [docs/API.md](docs/API.md).

## Using as a library

The vault is also a public Go library (`pkg/store`), importable from other
projects and repositories:

```go
import "github.com/guionardo/gs-secrets/pkg/store"

s, err := store.New("/path/to/vault/.store") // generates the master key on first use
if err != nil {
    log.Fatal(err)
}
if err := s.Set("api_key", "secret", 24*time.Hour); err != nil {
    log.Fatal(err)
}
value, ok := s.Get("api_key") // ok=false if missing or expired
if err := s.Rekey(); err != nil { // rotate the master key
    log.Fatal(err)
}
```

All operations reload the vault file, so multiple processes share it safely.
The full threat model in [SECURITY.md](./SECURITY.md) applies to library use
too.

## How it works

The vault is a JSON map of secrets encrypted with **AES-256-GCM** and stored
in a single file with a small format header (magic + version + cipher id).
Each secret carries an optional expiration timestamp (millisecond precision).

The master key is a random 32-byte value kept in its own key file
(`.gs-secrets.key`) next to the vault. Permissions are **enforced** on every
open: `0600` on Unix, a user-restricted DACL on Windows (where POSIX modes
are ignored). Writes are atomic (temp file + fsync + rename). `--rekey`
rotates the key in place with a recoverable backup. See
[SECURITY.md](./SECURITY.md) for the full threat model — in short: **the
vault is only as safe as your file permissions**. The key file is generated
on first use and never leaves the machine.

## Features

- Set, get, delete, and list secrets with a tiny flag-based CLI
- AES-256-GCM authenticated encryption (tampering is detected and rejected)
- Per-secret TTL with millisecond precision
- Random master key file generated on first use
- Default paths follow the OS user config directory
- Zero runtime dependencies beyond the Go standard library
- Thread-safe store, race-detector clean

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the development workflow, lint
and test commands, and the PR process.

## License

[MIT](./LICENSE)