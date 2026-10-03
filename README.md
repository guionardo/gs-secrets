# gs-secrets

[![Go Version](https://img.shields.io/github/go-mod/go-version/guionardo/gs-secrets)](https://go.dev/)
[![License](https://img.shields.io/github/license/guionardo/gs-secrets)](./LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/guionardo/gs-secrets/ci.yml?branch=main)](https://github.com/guionardo/gs-secrets/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/guionardo/gs-secrets)](https://goreportcard.com/report/github.com/guionardo/gs-secrets)

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
gs-secrets --get key [--output FILE] [--store PATH] [--keyfile PATH]
gs-secrets --delete key [--store PATH] [--keyfile PATH]
gs-secrets --list [--store PATH] [--keyfile PATH]
gs-secrets --version
```

| Flag | Description |
| --- | --- |
| `--set key=value` | Store a secret. With `--ttl`, it expires after the given duration. |
| `--get key` | Print the secret value to stdout (or `--output FILE`). |
| `--delete key` | Remove a secret. Deleting a missing key is not an error. |
| `--list` | List stored keys, sorted, never values. |
| `--ttl DURATION` | Time to live for `--set`, e.g. `1h`, `30m`, `90s`. `0` (default) means never expires. |
| `--store PATH` | Vault file. Default: `<user config dir>/gs-secrets/.store`. |
| `--keyfile PATH` | Master key file. Default: `<vault dir>/.gs-secrets.key`. |
| `--output FILE` | Write command output to FILE instead of stdout. |
| `--verbose` | Print progress messages to stderr. |
| `--version` | Print the version and exit. |

Exit code is `0` on success and `1` on any error, including a missing secret.

### Examples

```bash
# Store a secret that expires in one hour
gs-secrets --set api_key=abcd1234 --ttl 1h

# Use a project-local vault instead of the user-global one
gs-secrets --set db_password=secret --store ./vault/.store

# Pipe a secret into another command without echoing it
gs-secrets --get api_key | curl -H "Authorization: Bearer $(cat)" ...

# Write a secret straight to a file
gs-secrets --get api_key --output /tmp/key
```

## How it works

The vault is a JSON map of secrets encrypted with **AES-256-GCM** and stored
in a single file. Each secret carries an optional expiration timestamp
(millisecond precision).

The master key is a random 32-byte value kept in its own key file
(`.gs-secrets.key`, mode `0600`) next to the vault. Both files live in a
directory created with mode `0700`. See [SECURITY.md](./SECURITY.md) for the
full threat model — in short: **the vault is only as safe as your file
permissions**. The key file is generated on first use and never leaves the
machine.

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