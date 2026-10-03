# @guionardo/gs-secrets

> Poor-man's secret vault: encrypted, file-based storage for API keys and
> passwords.

This package installs the [gs-secrets](https://github.com/guionardo/gs-secrets)
CLI binary for your platform (linux, macOS, Windows; amd64 and arm64). The
binary is downloaded from the matching GitHub release on first use,
checksum-verified, and cached — no `postinstall` script, so it works with
`--ignore-scripts`, pnpm, and yarn.

## Install

```bash
npm install -g @guionardo/gs-secrets
# or
npx @guionardo/gs-secrets --version
```

## Usage

```bash
printf '%s' "$TOKEN" | gs-secrets --set api_key --ttl 24h   # value via stdin
gs-secrets --get api_key                                     # stdout carries only the value
gs-secrets --list
gs-secrets --delete api_key
gs-secrets --rekey
```

Never pass secrets as command-line arguments; use stdin (`--set key`) or the
masked prompt (`--set key --prompt`). See the
[README](https://github.com/guionardo/gs-secrets#readme) and
[docs/API.md](https://github.com/guionardo/gs-secrets/blob/main/docs/API.md)
for the full integration contract.

## Cache

The binary is cached in the platform cache directory
(`~/.cache/gs-secrets/bin`, `~/Library/Caches/gs-secrets/bin`, or
`%LOCALAPPDATA%\gs-secrets\bin` on Windows). Override with
`GS_SECRETS_CACHE_DIR`, or pin a different version with
`GS_SECRETS_VERSION` (useful for testing).