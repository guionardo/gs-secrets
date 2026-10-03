package store

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultStoreFile returns the default vault path:
//
//	<os.UserConfigDir()>/gs-secrets/.store
//
// On machines without a config directory it falls back to the home
// directory, and finally to a relative ".store" in the current directory.
func DefaultStoreFile() (string, error) {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "gs-secrets", ".store"), nil
	}
	if dir, err := os.UserHomeDir(); err == nil && dir != "" {
		return filepath.Join(dir, "gs-secrets", ".store"), nil
	}
	return ".store", fmt.Errorf("could not determine config directory: %w", os.ErrNotExist)
}
