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

What it does **not** protect against:

- Anyone who can read the key file (`.gs-secrets.key`, mode `0600`) — or the
  whole config directory (mode `0700`). The key file is random and stored in
  plaintext by design; copying both files decrypts everything.
- Malware running as your user, which can read both files while you can.
- Physical theft of the machine while unlocked.
- Key-file loss: without `.gs-secrets.key`, the vault is **unrecoverable**.
  Back up the key file together with the vault, or re-create secrets.

## Files and permissions

| Path (default) | Mode | Content |
| --- | --- | --- |
| `<user config dir>/gs-secrets/` | `0700` | Vault directory |
| `<user config dir>/gs-secrets/.store` | `0600` | Encrypted vault |
| `<user config dir>/gs-secrets/.gs-secrets.key` | `0600` | 32-byte AES-256 master key |

The vault refuses to open with a newly generated key when the vault exists
but the key file is missing, so a key-file loss surfaces as an error instead
of silently encrypting data under a fresh, useless key.

## Encryption details

- Algorithm: AES-256-GCM (AEAD) from `crypto/aes` + `crypto/cipher`.
- Nonce: fresh random 96-bit nonce per encryption, `crypto/rand`.
- Layout on disk: `nonce || ciphertext`.
- Key: 32 random bytes from `crypto/rand`, generated on first use.

## Reporting a vulnerability

This is a personal tool; report issues via the
[GitHub issue tracker](https://github.com/guionardo/gs-secrets/issues). Do
not include secret material or live keys in reports.