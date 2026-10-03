package store

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// keySize is the AES-256 master key length in bytes.
const keySize = 32

// loadKey reads the 32-byte master key from keyFile, hardening the file
// permissions. If the file does not exist, a new random key is generated and
// persisted with private permissions, so a vault created afterwards is only
// as protected as the filesystem permits.
func loadKey(keyFile string) ([]byte, error) {
	content, err := os.ReadFile(keyFile) // #nosec G304 -- path comes from --keyfile flag or the default config dir
	if err == nil {
		if len(content) != keySize {
			return nil, fmt.Errorf("key file %s: expected %d bytes, got %d", keyFile, keySize, len(content))
		}
		if err := hardenFile(keyFile); err != nil {
			return nil, err
		}
		return content, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	key, err := newRandomKey()
	if err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	if err := ensureDir(filepath.Dir(keyFile)); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(keyFile, key); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}
	if err := hardenFile(keyFile); err != nil {
		return nil, err
	}
	return key, nil
}

// newRandomKey generates a fresh 32-byte master key from crypto/rand.
//
// Key bytes are zeroed when they are replaced (see Rekey) rather than when
// they become unreachable: runtime.AddCleanup cannot reference the
// allocation being cleaned up — "if ptr is reachable from cleanup or arg,
// ptr will never be collected" — so a garbage-collection-based wipe is
// impossible, and wiping dead memory via a raw address could corrupt a
// different allocation that reused the block.
func newRandomKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
