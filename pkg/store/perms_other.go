//go:build !unix && !windows

package store

import (
	"fmt"
	"os"
)

// restrictFilePermissions makes a best-effort attempt to restrict path to
// its owner. On platforms without POSIX modes (e.g. plan9) this may be a
// no-op; verifyFilePermissions then falls back to a mode check.
func restrictFilePermissions(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// verifyFilePermissions reports an error unless path's mode bits are owner-only.
func verifyFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has permissions %04o; expected 0600", path, info.Mode().Perm())
	}
	return nil
}

// syncDir is a no-op on platforms without directory fsync support.
func syncDir(dir string) {}

// lockFile and unlockFile are no-ops on platforms without file locking
// support (e.g. plan9); concurrent access is then not serialized.
func lockFile(f *os.File) error { return nil }

func unlockFile(f *os.File) error { return nil }
