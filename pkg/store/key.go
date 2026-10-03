package store

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"
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
		return registerKeyCleanup(content), nil
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

// newRandomKey generates a fresh 32-byte master key from crypto/rand and
// registers a cleanup that wipes the bytes once they become unreachable.
func newRandomKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return registerKeyCleanup(key), nil
}

// registerKeyCleanup arranges for the key's backing array to be zeroed when
// it becomes unreachable, shortening the key's lifetime in process memory.
// keySize is a constant, so the cleanup closure does not capture the slice
// (capturing it would keep the array alive and the cleanup would never run).
func registerKeyCleanup(key []byte) []byte {
	runtime.AddCleanup(&key[0], func(first *byte) { // #nosec G103 -- wipes the key allocation
		clear(unsafe.Slice(first, keySize))
	}, nil)
	return key
}
