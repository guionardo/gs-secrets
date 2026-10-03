//go:build unix

package store

import (
	"fmt"
	"os"
)

// restrictFilePermissions makes path readable and writable only by its
// owner (mode 0600 for files, 0700 for directories).
func restrictFilePermissions(path string) error {
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}

// verifyFilePermissions reports an error unless path is private to its
// owner. On Unix the mode bits are authoritative after restrictFilePermissions.
func verifyFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	expected := os.FileMode(0o600)
	if info.IsDir() {
		expected = 0o700
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has permissions %04o; expected %04o", path, info.Mode().Perm(), expected)
	}
	return nil
}

// syncDir flushes the directory entry of a renamed file to disk, making an
// atomic rename durable across a crash.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- dir is the parent of a store path chosen by the user
		_ = d.Sync()
		_ = d.Close()
	}
}
