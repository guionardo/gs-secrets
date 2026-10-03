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

// loadKey reads the 32-byte master key from keyFile. If the file does not
// exist, a new random key is generated and persisted with mode 0600, so a
// vault created afterwards is only as protected as the filesystem permits.
func loadKey(keyFile string) ([]byte, error) {
	content, err := os.ReadFile(keyFile) // #nosec G304 -- path comes from --keyfile flag or the default config dir
	if err == nil {
		if len(content) != keySize {
			return nil, fmt.Errorf("key file %s: expected %d bytes, got %d", keyFile, keySize, len(content))
		}
		return content, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}
	return key, nil
}
