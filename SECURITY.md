# Security Policy

## Threat model

`gs-secrets` is a poor-man's secret vault: **confidentiality rests on the
operating system's file permissions**, not on a password or a remote
key-management service.

What the vault protects against:

- A reader who can see the vault file but **not** the key file (e.g. an
  accidental `cat ~/.config/gs-secrets/.store`, a backup that captured only
  the vault, a shared-directory listing). The vault is AES-256-GCM encrypted;
  without the 32-byte key it cannot be decrypted.
- **Tampering**: GCM authenticates the ciphertext. Any modification of the
  vault file is detected and the read fails instead of returning corrupted
  secrets.
- **Accidental world-readable files**: permissions are enforced, not just
  requested. On Unix, existing vault/key files are chmod'ed to `0600` (and
  the directory to `0700`); if that cannot be guaranteed, the tool refuses
  to run. On Windows, where POSIX modes are ignored by the OS, a
  user-restricted DACL is enforced instead (see below).

What it does **not** protect against:

- Anyone who can read the key file (`.gs-secrets.key`) — or the whole config
  directory. The key file is random and stored in plaintext by design;
  copying both files decrypts everything.
- Malware running as your user, which can read both files while you can.
- Physical theft of the machine while unlocked.
- Key-file loss: without `.gs-secrets.key`, the vault is **unrecoverable**.
  Back up the key file together with the vault, or re-create secrets.

## Files and permissions

| Path (default) | Protection | Content |
| --- | --- | --- |
| `<user config dir>/gs-secrets/` | Unix `0700`; Windows DACL | Vault directory |
| `<user config dir>/gs-secrets/.store` | Unix `0600`; Windows DACL | Encrypted vault |
| `<user config dir>/gs-secrets/.gs-secrets.key` | Unix `0600`; Windows DACL | 32-byte AES-256 master key |

### Windows note

Go's `os` package ignores POSIX permission bits on Windows, so modes like
`0600` alone would not restrict access. `gs-secrets` therefore replaces the
DACL of the vault, key, and directory files with one that grants access only
to the current user, SYSTEM, and Administrators, and marks it protected so
it no longer inherits from the parent directory. Files are verified against
this policy on every open.

The vault refuses to open with a newly generated key when the vault exists
but the key file is missing, so a key-file loss surfaces as an error instead
of silently encrypting data under a fresh, useless key.

## Encryption details

- Algorithm: AES-256-GCM (AEAD) from `crypto/aes` + `crypto/cipher`.
- Nonce: fresh random 96-bit nonce per encryption, `crypto/rand`.
- Layout on disk: `GSSEC` magic, format version, cipher-suite id, then
  `nonce || ciphertext`. Files written by v0.1.0 (no header) are still
  readable and are upgraded to the header format on the next write.
- Key: 32 random bytes from `crypto/rand`, generated on first use.
- Key bytes are zeroed when they become unreachable in process memory.

## Crash safety and key rotation

- Vault and key files are written atomically (temp file + fsync + rename),
  so an interrupted write never leaves a truncated file.
- Operations are serialized across processes with an advisory exclusive
  lock on `<vault file>.lock` (private, like the vault), so concurrent
  readers/writers never corrupt the vault or lose updates.
- `gs-secrets --rekey` rotates the master key: the vault is re-encrypted
  with a fresh key and the key file is replaced. The previous key is kept
  as `.gs-secrets.key.bak` until the rotation completes. If a rekey is
  interrupted (e.g. power loss between the key-file swap and the vault
  rewrite), restore the backup manually:

  ```sh
  mv <vault dir>/.gs-secrets.key.bak <vault dir>/.gs-secrets.key
  ```

  Decryption errors hint at this recovery step when a backup is present.

## Secret handling in the CLI

- Secret values are **never** passed as process arguments when written via
  `--set key` (stdin) or `--set key --prompt` (masked prompt). The inline
  `--set key=value` form exists only for non-sensitive data.
- Secret values never appear on stderr, in `--verbose` output, or in error
  messages.
- stdout carries only data (the value, key list, version); consumers can
  capture it directly. See [docs/API.md](docs/API.md) for the full
  automation contract.

## Backup procedure

Back up the key file **together with** the vault file, on media with
equivalent access protection:

| Path (default) | Required? |
| --- | --- |
| `<user config dir>/gs-secrets/.gs-secrets.key` | Required — without it the vault is unrecoverable |
| `<user config dir>/gs-secrets/.store` | Required — holds the secrets |
| `<user config dir>/gs-secrets/.store.lock` | No — recreated on demand |

Losing only the key file means losing the vault. Rotating keys with
`--rekey` does not invalidate an existing backup that contains the old key
file version.

## Reporting a vulnerability

This is a personal tool; report issues via the
[GitHub issue tracker](https://github.com/guionardo/gs-secrets/issues). Do
not include secret material or live keys in reports.