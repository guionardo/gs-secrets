package store_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guionardo/gs-secrets/internal/store"
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
	require.NoError(t, s.Set("ephemeral", "value", 10*time.Millisecond))

	value, ok := s.Get("ephemeral")
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	time.Sleep(20 * time.Millisecond)
	value, ok = s.Get("ephemeral")
	assert.False(t, ok)
	assert.Empty(t, value)
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
	dir := t.TempDir()
	_, err := store.New(filepath.Join(dir, ".store"))
	require.NoError(t, err)
	info, err := os.Stat(filepath.Join(dir, ".gs-secrets.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
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
