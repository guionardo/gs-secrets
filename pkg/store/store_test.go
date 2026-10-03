//nolint:gosec // tests only read and write files inside t.TempDir()
package store_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guionardo/gs-secrets/pkg/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), ".store"))
	require.NoError(t, err)
	return s
}

func TestSetGetUpdateDelete(t *testing.T) {
	s := newTestStore(t)

	value, ok := s.Get("missing")
	assert.False(t, ok)
	assert.Empty(t, value)

	require.NoError(t, s.Set("key1", "value1", 0))
	value, ok = s.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", value)

	require.NoError(t, s.Set("key1", "value2", 0))
	value, ok = s.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value2", value)

	require.NoError(t, s.Delete("key1"))
	value, ok = s.Get("key1")
	assert.False(t, ok)
	assert.Empty(t, value)
}

func TestSetEmptyKey(t *testing.T) {
	s := newTestStore(t)
	err := s.Set("  ", "value", 0)
	assert.ErrorIs(t, err, store.ErrEmptyKey)
}

func TestTTLExpiry(t *testing.T) {
	s := newTestStore(t)
	// Long TTL: the secret is present right after being stored, with a wide
	// margin for slow CI runners.
	require.NoError(t, s.Set("ephemeral", "value", 10*time.Second))
	value, ok := s.Get("ephemeral")
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	// Short TTL: the secret is gone once the expiry passes. The sleep gives
	// slow CI runners (e.g. Windows with antivirus scanning) ample margin.
	require.NoError(t, s.Set("ephemeral", "value", 10*time.Millisecond))
	time.Sleep(100 * time.Millisecond)
	value, ok = s.Get("ephemeral")
	assert.False(t, ok)
	assert.Empty(t, value)
}

func TestGetEExistingKey(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Set("key1", "value1", 0))

	value, exists, err := s.GetE("key1")
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, "value1", value)
}

func TestGetEMissingKey(t *testing.T) {
	s := newTestStore(t)

	value, exists, err := s.GetE("missing")
	assert.NoError(t, err)
	assert.False(t, exists)
	assert.Empty(t, value)
}

func TestGetEExpiredKey(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Set("ephemeral", "value", 10*time.Millisecond))
	time.Sleep(100 * time.Millisecond)

	value, exists, err := s.GetE("ephemeral")
	assert.NoError(t, err)
	assert.False(t, exists)
	assert.Empty(t, value)
}

func TestGetETamperedVault(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("key1", "value1", 0))

	content, err := os.ReadFile(vaultFile) // #nosec G304 G703 -- test reads/writes its own temp vault
	require.NoError(t, err)
	content[len(content)-1] ^= 0xFF
	require.NoError(t, os.WriteFile(vaultFile, content, 0o600))

	value, exists, err := s.GetE("key1")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Empty(t, value)
}

func TestGetEVaultWithoutKeyFile(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("key1", "value1", 0))

	require.NoError(t, os.Remove(filepath.Join(dir, ".gs-secrets.key")))

	value, exists, err := s.GetE("key1")
	assert.ErrorIs(t, err, store.ErrMasterKeyMissing)
	assert.False(t, exists)
	assert.Empty(t, value)
}

func TestGetELockFailure(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Set("key1", "value1", 0))
	// A directory where the lock file should be: opening it must fail.
	require.NoError(t, os.Remove(s.LockFile()))
	require.NoError(t, os.Mkdir(s.LockFile(), 0o700))

	value, exists, err := s.GetE("key1")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Empty(t, value)
}

func TestGetEReadPermissionFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows a user-restricted DACL is enforced instead of mode bits")
	}
	s := newTestStore(t)
	require.NoError(t, s.Set("key1", "value1", 0))
	require.NoError(t, os.Chmod(s.VaultFile(), 0o000))
	defer func() { _ = os.Chmod(s.VaultFile(), 0o600) }()

	value, exists, err := s.GetE("key1")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Empty(t, value)
}

func TestGetEErrorsDoNotLeakValues(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("key1", "super-secret-value-42", 0))

	content, err := os.ReadFile(vaultFile) // #nosec G304 G703 -- test reads/writes its own temp vault
	require.NoError(t, err)
	content[len(content)-1] ^= 0xFF
	require.NoError(t, os.WriteFile(vaultFile, content, 0o600))

	_, _, err = s.GetE("key1")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-value-42")
}

func TestGetEDecodeErrorDoesNotLeak(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("key1", "value1", 0))

	// Craft a header-versioned vault that decrypts fine but holds non-JSON:
	// decoding must fail without echoing the embedded plaintext in the error.
	key, err := os.ReadFile(filepath.Join(dir, ".gs-secrets.key")) // #nosec G304 G703 -- test temp vault
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	sealed := gcm.Seal(nonce, nonce, []byte("not json super-secret-value-42"), nil)
	blob := append(append([]byte("GSSEC"), 0x01, 0x01), sealed...)
	require.NoError(t, os.WriteFile(vaultFile, blob, 0o600))

	value, exists, err := s.GetE("key1")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Empty(t, value)
	assert.NotContains(t, err.Error(), "super-secret-value-42")
}

func TestListSortedAndExcludesExpired(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Set("zeta", "1", 0))
	require.NoError(t, s.Set("alpha", "2", 0))
	require.NoError(t, s.Set("gone", "3", time.Nanosecond))

	time.Sleep(time.Millisecond)
	assert.Equal(t, []string{"alpha", "zeta"}, s.List())
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "sub", ".store")

	s1, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s1.Set("key1", "value1", 0))

	s2, err := store.New(vaultFile)
	require.NoError(t, err)
	value, ok := s2.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", value)
}

func TestTamperedVaultIsRejected(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("key1", "value1", 0))

	content, err := os.ReadFile(vaultFile) // #nosec G304 G703 -- test reads/writes its own temp vault
	require.NoError(t, err)
	content[len(content)-1] ^= 0xFF
	require.NoError(t, os.WriteFile(vaultFile, content, 0o600)) // #nosec G703 -- test temp vault

	value, ok := s.Get("key1")
	assert.False(t, ok)
	assert.Empty(t, value)
}

func TestVaultWithoutKeyFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("key1", "value1", 0))

	require.NoError(t, os.Remove(filepath.Join(dir, ".gs-secrets.key")))
	_, err = store.New(vaultFile)
	assert.ErrorIs(t, err, store.ErrMasterKeyMissing)
}

func TestWrongKeyCannotRead(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("key1", "value1", 0))

	otherDir := t.TempDir()
	// Generate a key for the other store first, then try to open the vault
	// with it: decryption must fail.
	_, err = store.New(filepath.Join(otherDir, ".store"))
	require.NoError(t, err)
	s2, err := store.New(vaultFile, store.WithKeyFile(filepath.Join(otherDir, ".gs-secrets.key")))
	require.NoError(t, err)
	value, ok := s2.Get("key1")
	assert.False(t, ok)
	assert.Empty(t, value)
}

func TestKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows a user-restricted DACL is enforced instead of mode bits")
	}
	dir := t.TempDir()
	_, err := store.New(filepath.Join(dir, ".store"))
	require.NoError(t, err)
	info, err := os.Stat(filepath.Join(dir, ".gs-secrets.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestNewHardensInsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows a user-restricted DACL is enforced instead of mode bits")
	}
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("k", "v", 0))

	// Simulate a file that lost its private mode (e.g. copied with a loose
	// umask): reopening must harden it back to 0600 and still read it.
	require.NoError(t, os.Chmod(vaultFile, 0o644))
	s2, err := store.New(vaultFile)
	require.NoError(t, err)
	info, err := os.Stat(vaultFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	value, ok := s2.Get("k")
	assert.True(t, ok)
	assert.Equal(t, "v", value)
}

func TestLockFileCreatedAndPrivate(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Set("k", "v", 0))
	info, err := os.Stat(s.LockFile())
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestConcurrentProcessAccess(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s1, err := store.New(vaultFile)
	require.NoError(t, err)
	s2, err := store.New(vaultFile)
	require.NoError(t, err)

	// Two Store instances (two open file descriptions) racing on the same
	// vault: the inter-process lock serializes the read-modify-write cycles,
	// so no update is lost and the vault stays valid.
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if err := s1.Set(fmt.Sprintf("k%d", i), "v", 0); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			if err := s2.Set(fmt.Sprintf("kb%d", i), "v", 0); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	require.Empty(t, errs)

	keys := s1.List()
	require.Len(t, keys, 10)
}

func TestConcurrentAccess(t *testing.T) {
	s := newTestStore(t)
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_ = s.Set("k", "v", 0)
			_, _ = s.Get("k")
			_ = s.List()
			_ = s.Delete("k")
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestCorruptVaultFile(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Set("key1", "value1", 0))
	require.NoError(t, os.WriteFile(s.VaultFile(), []byte("not a vault"), 0o600))

	value, ok := s.Get("key1")
	assert.False(t, ok)
	assert.Empty(t, value)

	err := s.Set("key2", "value2", 0)
	require.Error(t, err)
}

func TestVaultHasFormatHeader(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Set("key1", "value1", 0))
	content, err := os.ReadFile(s.VaultFile())
	require.NoError(t, err)
	assert.Equal(t, "GSSEC", string(content[:5]))
}

func TestLegacyVaultFormatIsReadAndUpgraded(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	s, err := store.New(vaultFile)
	require.NoError(t, err)

	// Craft a pre-header vault: AES-256-GCM over JSON, no magic bytes.
	key, err := os.ReadFile(filepath.Join(dir, ".gs-secrets.key"))
	require.NoError(t, err)
	plain, err := json.Marshal(map[string]store.Secret{"legacy": {Value: "old"}})
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	legacyBlob := gcm.Seal(nonce, nonce, plain, nil)
	require.NoError(t, os.WriteFile(vaultFile, legacyBlob, 0o600))

	value, ok := s.Get("legacy")
	assert.True(t, ok)
	assert.Equal(t, "old", value)

	// The next save rewrites the vault with the versioned header.
	require.NoError(t, s.Set("legacy", "new", 0))
	content, err := os.ReadFile(vaultFile)
	require.NoError(t, err)
	assert.Equal(t, "GSSEC", string(content[:5]))
	value, ok = s.Get("legacy")
	assert.True(t, ok)
	assert.Equal(t, "new", value)
}

func TestRekeyRotatesKeyAndKeepsSecrets(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	keyFile := filepath.Join(dir, ".gs-secrets.key")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("k", "v", 0))

	oldKey, err := os.ReadFile(keyFile)
	require.NoError(t, err)

	require.NoError(t, s.Rekey())

	newKey, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	assert.NotEqual(t, oldKey, newKey)
	_, err = os.Stat(keyFile + ".bak")
	assert.True(t, os.IsNotExist(err), "rekey backup should be removed on success")

	value, ok := s.Get("k")
	assert.True(t, ok)
	assert.Equal(t, "v", value)

	// The old key must no longer decrypt the vault.
	oldKeyFile := filepath.Join(dir, "old.key")
	require.NoError(t, os.WriteFile(oldKeyFile, oldKey, 0o600))
	sOld, err := store.New(vaultFile, store.WithKeyFile(oldKeyFile))
	require.NoError(t, err)
	_, ok = sOld.Get("k")
	assert.False(t, ok)
}

func TestRekeyWithoutVault(t *testing.T) {
	s := newTestStore(t)
	err := s.Rekey()
	assert.ErrorIs(t, err, store.ErrNoVault)
}

func TestRekeyFailureKeepsOldKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory read-only enforcement differs on Windows; DACL tests run there")
	}
	dir := t.TempDir()
	keyDir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	keyFile := filepath.Join(keyDir, "key")
	s, err := store.New(vaultFile, store.WithKeyFile(keyFile))
	require.NoError(t, err)
	require.NoError(t, s.Set("k", "v", 0))
	oldKey, err := os.ReadFile(keyFile)
	require.NoError(t, err)

	// Make the key directory read-only so the first rekey write fails.
	require.NoError(t, os.Chmod(keyDir, 0o500))
	defer func() { _ = os.Chmod(keyDir, 0o700) }()

	err = s.Rekey()
	require.Error(t, err)

	restored, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	assert.Equal(t, oldKey, restored)
}

func TestInterruptedRekeyHintsRecovery(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, ".store")
	keyFile := filepath.Join(dir, ".gs-secrets.key")
	s, err := store.New(vaultFile)
	require.NoError(t, err)
	require.NoError(t, s.Set("k", "v", 0))
	oldKey, err := os.ReadFile(keyFile)
	require.NoError(t, err)

	// Simulate an interrupted rekey: the key file was replaced by a wrong
	// key while the vault still holds the old one, and the backup remains.
	require.NoError(t, os.WriteFile(keyFile+".bak", oldKey, 0o600))
	require.NoError(t, os.WriteFile(keyFile, make([]byte, 32), 0o600))

	s2, err := store.New(vaultFile)
	require.NoError(t, err)
	err = s2.Set("k", "v2", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restore the backup")
}
