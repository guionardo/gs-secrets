// Package store implements an encrypted, file-backed secret vault.
//
// The vault is a JSON map of secrets encrypted with AES-256-GCM, prefixed
// with a small format header (see format.go). The encryption key is a
// random 32-byte master key stored in a separate key file beside the vault.
// Security relies on OS file permissions: anyone who can read the key file
// can decrypt the vault. On Unix the key and vault files are forced to mode
// 0600; on Windows a restrictive DACL is enforced instead (see perms_*.go).
//
// This is a public library: other projects can import it and manage their
// own vaults. A vault is created with New, which generates the master key
// on first use, and each operation reloads the vault file, so concurrent
// processes see each other's writes.
//
// Example:
//
//	s, err := store.New("/path/to/vault/.store")
//	if err != nil {
//		log.Fatal(err)
//	}
//	if err := s.Set("api_key", "secret", 24*time.Hour); err != nil {
//		log.Fatal(err)
//	}
//	value, ok := s.Get("api_key")
//	if !ok {
//		log.Fatal("secret not found or expired")
//	}
//	fmt.Println(value)
//
// The vault file format is versioned ("GSSEC" header) and the master key can
// be rotated with Rekey; see SECURITY.md in the repository root for the
// threat model.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by Store methods.
var (
	// ErrEmptyKey is returned by Set when the key is empty or only whitespace.
	ErrEmptyKey = errors.New("key cannot be empty")
	// ErrCiphertextTooShort is returned when a vault blob is smaller than the
	// GCM nonce size and cannot be a valid encryption result.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	// ErrMasterKeyMissing is returned when the vault exists but its master
	// key file does not. The vault is unrecoverable without the key.
	ErrMasterKeyMissing = errors.New("vault exists but master key file is missing")
	// ErrNoVault is returned by Rekey when the vault file does not exist yet.
	ErrNoVault = errors.New("no vault found; nothing to rekey")
)

// Secret is a single stored value with an optional expiration time.
type Secret struct {
	Value      string `json:"v"`
	ValidUntil int64  `json:"u"` // Unix millisecond timestamp; 0 means never expires
}

// Store is a thread-safe, encrypted secret vault backed by a single file.
type Store struct {
	mu        sync.RWMutex
	storeFile string
	keyFile   string
	key       []byte
	secrets   map[string]Secret
}

// Option configures a Store. Use WithKeyFile to override the default
// key file location.
type Option func(*Store)

// WithKeyFile sets the path of the master key file. The default is
// <vault dir>/.gs-secrets.key.
func WithKeyFile(keyFile string) Option {
	return func(s *Store) {
		s.keyFile = keyFile
	}
}

// New creates a Store backed by storeFile and loads (or, on first use,
// generates) the master key. The key file defaults to
// <vault dir>/.gs-secrets.key unless overridden with WithKeyFile.
//
// New fails with ErrMasterKeyMissing when the vault exists but no key file
// does, to avoid silently re-keying (and losing access to) existing data.
// Existing vault, key, and directory permissions are hardened on open.
func New(storeFile string, opts ...Option) (*Store, error) {
	s := &Store{
		storeFile: storeFile,
		keyFile:   filepath.Join(filepath.Dir(storeFile), ".gs-secrets.key"),
		secrets:   make(map[string]Secret),
	}
	for _, opt := range opts {
		opt(s)
	}
	if err := ensureDir(filepath.Dir(s.storeFile)); err != nil {
		return nil, fmt.Errorf("vault directory: %w", err)
	}
	if _, err := os.Stat(s.storeFile); err == nil {
		if _, err := os.Stat(s.keyFile); errors.Is(err, fs.ErrNotExist) {
			return nil, ErrMasterKeyMissing
		}
		if err := hardenFile(s.storeFile); err != nil {
			return nil, err
		}
	}
	key, err := loadKey(s.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load master key: %w", err)
	}
	s.key = key
	return s, nil
}

// VaultFile returns the absolute path of the vault file.
func (s *Store) VaultFile() string {
	return s.storeFile
}

// KeyFile returns the absolute path of the master key file.
func (s *Store) KeyFile() string {
	return s.keyFile
}

// Get returns the value for key and whether it exists. Expired secrets are
// treated as missing and removed from the in-memory copy; the cleanup is
// persisted on the next Set or Delete.
func (s *Store) Get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return "", false
	}
	secret, ok := s.secrets[key]
	if !ok {
		return "", false
	}
	if secret.expired(time.Now()) {
		delete(s.secrets, key)
		return "", false
	}
	return secret.Value, true
}

// Set stores value under key, replacing any existing entry. A positive ttl
// makes the secret expire after ttl; zero or negative ttl means never.
func (s *Store) Set(key, value string, ttl time.Duration) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return ErrEmptyKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	validUntil := int64(0)
	if ttl > 0 {
		validUntil = time.Now().Add(ttl).UnixMilli()
	}
	s.secrets[key] = Secret{Value: value, ValidUntil: validUntil}
	return s.save()
}

// Delete removes key from the vault. Deleting a missing key is not an error.
func (s *Store) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	delete(s.secrets, key)
	return s.save()
}

// List returns all stored keys in sorted order. Expired keys are excluded.
func (s *Store) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil
	}
	keys := make([]string, 0, len(s.secrets))
	now := time.Now()
	for k, secret := range s.secrets {
		if secret.expired(now) {
			delete(s.secrets, k)
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Rekey rotates the master key: a fresh random key is generated, the vault
// is re-encrypted with it, and the key file is replaced. The previous key is
// kept in <key file>.bak until the rotation completes, so an interrupted
// rekey can be recovered by restoring the backup next to the key file.
//
// On failure before the vault is re-encrypted, the old key file is restored
// automatically.
func (s *Store) Rekey() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(s.storeFile); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNoVault
		}
		return fmt.Errorf("stat vault: %w", err)
	}
	if err := s.load(); err != nil {
		return fmt.Errorf("read vault before rekey: %w", err)
	}
	oldKey := s.key
	newKey, err := newRandomKey()
	if err != nil {
		return fmt.Errorf("generate new master key: %w", err)
	}

	// Stage 1: persist the backup of the old key, then replace the key file.
	if err := writeFileAtomic(s.keyFile+".bak", oldKey); err != nil {
		return fmt.Errorf("backup old master key: %w", err)
	}
	if err := hardenFile(s.keyFile + ".bak"); err != nil {
		return fmt.Errorf("harden key backup: %w", err)
	}
	if err := writeFileAtomic(s.keyFile, newKey); err != nil {
		return fmt.Errorf("write new master key: %w", err)
	}
	// Stage 2: re-encrypt the vault with the new key. On failure, restore
	// the old key so the old vault stays readable.
	s.key = newKey
	if err := s.save(); err != nil {
		s.key = oldKey
		_ = writeFileAtomic(s.keyFile, oldKey)
		return fmt.Errorf("re-encrypt vault: %w", err)
	}
	// Stage 3: rotation is complete; drop the backup.
	_ = os.Remove(s.keyFile + ".bak")
	return nil
}

// load reads and decrypts the vault file into memory. A missing vault file
// is treated as an empty vault; a missing master key is not, because the
// vault would be unrecoverable. Blobs without the format header are treated
// as the legacy pre-header layout and upgraded on the next save.
func (s *Store) load() error {
	content, err := os.ReadFile(s.storeFile) // #nosec G304 -- path comes from --store flag or the default config dir
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.secrets = make(map[string]Secret)
			return nil
		}
		return fmt.Errorf("read vault: %w", err)
	}
	plain, err := decodeVault(s.key, content)
	if errors.Is(err, errLegacyVault) {
		// The file predates the format header; the next save rewrites it
		// with the versioned header.
		plain, err = decrypt(s.key, content)
	}
	if err != nil {
		return s.recoveryHint(fmt.Errorf("decrypt vault: %w", err))
	}
	var secrets map[string]Secret
	if err := json.Unmarshal(plain, &secrets); err != nil {
		return fmt.Errorf("decode vault: %w", err)
	}
	if secrets == nil {
		secrets = make(map[string]Secret)
	}
	s.secrets = secrets
	return nil
}

// recoveryHint augments a decryption failure with a recovery pointer when a
// rekey backup exists, since an interrupted Rekey is the usual cause.
func (s *Store) recoveryHint(err error) error {
	if _, statErr := os.Stat(s.keyFile + ".bak"); statErr == nil {
		return fmt.Errorf("%w: an interrupted rekey may have replaced the key; restore the backup with: mv %s %s",
			err, s.keyFile+".bak", s.keyFile)
	}
	return err
}

// save encrypts and writes the in-memory secrets to the vault file, creating
// the vault directory with private permissions if needed.
func (s *Store) save() error {
	plain, err := json.Marshal(s.secrets)
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}
	blob, err := encodeVault(s.key, plain)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}
	if err := ensureDir(filepath.Dir(s.storeFile)); err != nil {
		return err
	}
	if err := writeFileAtomic(s.storeFile, blob); err != nil {
		return fmt.Errorf("write vault: %w", err)
	}
	return hardenFile(s.storeFile)
}

// expired reports whether the secret has passed its ValidUntil time.
func (s Secret) expired(now time.Time) bool {
	return s.ValidUntil != 0 && s.ValidUntil <= now.UnixMilli()
}

// encrypt seals plaintext with AES-256-GCM under key. The result is
// nonce || ciphertext, with a fresh random 96-bit nonce per call.
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt opens a nonce || ciphertext blob with AES-256-GCM. It fails on
// any tampering, truncation, or wrong key, because GCM authenticates the
// ciphertext.
func decrypt(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, ErrCiphertextTooShort
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
