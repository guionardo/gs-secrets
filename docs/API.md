# Integration contract

This document is the reference for teams integrating `gs-secrets` into their
own software — as a Go library, or by driving the CLI from another language
(e.g. Node.js, Python, shell).

## Public Go API (`pkg/store`)

Stable, documented surface for opening, reading, writing, deleting, and
listing secrets. Importable from any Go module; nothing under `internal/` is
required.

```go
import "github.com/guionardo/gs-secrets/pkg/store"

s, err := store.New("/path/to/vault/.store") // creates the master key on first use
if err != nil { /* vault unreadable or permissions cannot be enforced */ }

err = s.Set(key, value, ttl) // ttl=0 means never expires
value, ok := s.Get(key)      // ok=false if missing or expired
err = s.Delete(key)
keys := s.List()             // sorted; expired keys excluded
err = s.Rekey()              // rotate the master key in place
```

| API | Behavior |
| --- | --- |
| `New(storeFile, ...Option)` | Opens (or creates) the vault, loads/generates the master key, hardens permissions, verifies vault/key decryption state. Fails with `ErrMasterKeyMissing` if the vault exists but the key file does not. |
| `WithKeyFile(path)` | Overrides the key file location (default `<vault dir>/.gs-secrets.key`). |
| `Get(key)` | Returns the value and whether it exists. Never errors on missing keys. |
| `Set(key, value, ttl)` | Upserts a secret with optional expiry (millisecond precision). |
| `Delete(key)` | Removes a key; deleting a missing key is not an error. |
| `List()` | Sorted key names, never values. |
| `Rekey()` | Rotates the master key and re-encrypts the vault. |

### Versioning policy

- The module follows [Semantic Versioning](https://semver.org). Breaking
  changes to the public API bump the major (or minor, while at v0) version.
- The **vault format** is independently versioned (see below) and is *not*
  tied to the API version: a newer library reads older vaults, and format
  changes are always backward compatible with automatic on-write upgrade.

## Vault format compatibility

| Format | Marker | Status |
| --- | --- | --- |
| v1 (current) | `GSSEC` + version byte + cipher-suite byte, then `nonce \|\| AES-256-GCM ciphertext` | Written by all releases ≥ v0.2.0 |
| legacy | no header, `nonce \|\| ciphertext` | Written by v0.1.0; still readable, upgraded to v1 on the next write |

Unrecognized magic, unsupported version, or cipher-suite id cause a hard
error; corrupt or tampered data fails GCM authentication.

## CLI contract for automation

The CLI is designed to be driven from other processes:

- **stdout carries only data**: the secret value for `--get`, key names for
  `--list`, the version string for `--version`. Nothing else is ever written
  there. With `--output FILE`, the data goes to the file and stdout stays
  empty.
- **stderr carries only diagnostics**: errors and `--verbose` messages.
  Secret values never appear on stderr.
- **Exit codes**: `0` success, `1` any failure (including missing secret).
- **Secret values never appear in process arguments.** Use `--set key` to
  read the value from stdin, or `--set key --prompt` for a masked terminal
  prompt:

  ```bash
  # value piped via stdin — safe for scripts
  printf '%s' "$TOKEN" | gs-secrets --set github_token

  # masked prompt — safe for interactive use
  gs-secrets --set github_token --prompt
  ```

  The inline form `--set key=value` still exists for non-sensitive data but
  exposes the value in the process argument list (visible via `ps`, process
  managers, and shell history) and must not be used for secrets.
- **Error messages never include secret values**; malformed `--set`
  arguments are reported without echoing the value.

### Capturing a secret in memory

Consumers should capture stdout directly, without going through a shell
pipeline or a file that could log or persist the value:

```js
// Node.js
const { execFile } = require('node:child_process');

function getSecret(key) {
  return new Promise((resolve, reject) => {
    execFile('gs-secrets', ['--get', key, '--store', vaultPath], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr.trim() || err.message));
      resolve(stdout.replace(/\n$/, '')); // value only, in memory
    });
  });
}
```

Do not use `shell: true` or shell interpolation with the key or value, and
do not log the returned string.

## Concurrency and lifecycle

- **Atomic writes**: vault and key files are replaced via temp file + fsync +
  rename; a crash or interruption never leaves a truncated file.
- **Inter-process serialization**: every operation takes an advisory
  exclusive lock on `<vault file>.lock` for its read-modify-write cycle.
  Concurrent processes see a consistent vault with no lost updates. The
  lock file is private (0600 / user-restricted DACL). On platforms without
  file locking (e.g. plan9) locking is a no-op.
- **Key rotation**: `Rekey()` (or `gs-secrets --rekey`) replaces the master
  key and re-encrypts the vault. The previous key is kept as
  `<key file>.bak` until the rotation completes; if a rotation is
  interrupted, restore the backup:

  ```sh
  mv <vault dir>/.gs-secrets.key.bak <vault dir>/.gs-secrets.key
  ```

  Decryption errors mention this step when a backup is present.
- **Key loss is permanent data loss.** The vault cannot be decrypted
  without the key file. Back up `<vault dir>/.gs-secrets.key` together with
  the vault file, on media with equivalent access protection.

## Permissions by platform

| Platform | Enforcement | Failure mode |
| --- | --- | --- |
| Unix | `chmod` 0600 files / 0700 directories, verified on every open; temp files 0600 | Operations fail if the mode cannot be guaranteed |
| Windows | User-restricted DACL (current user, SYSTEM, Administrators) marked protected against inheritance; set and verified on every open | Operations fail if the DACL cannot be set or verified |
| Other | Best-effort chmod; documented no-op | — |

## Reference use case

1. A Go program captures a token with a masked prompt (`--prompt` or
   `golang.org/x/term`) and stores it through `pkg/store`.
2. A Node.js consumer invokes the binary with `--get`, captures stdout in
   memory, and uses the value without ever writing it to disk.
3. The token never appears in process arguments, logs, or error output.