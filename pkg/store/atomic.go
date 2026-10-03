package store

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic writes data to path via a temp file in the same directory,
// fsyncs it, and renames it over the target. A crash at any point leaves
// either the old file or the complete new file, never a truncated one. The
// temp file is created with mode 0600.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gs-secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temp file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	tmpName = ""
	syncDir(dir)
	return nil
}

// ensureDir creates dir with mode 0700 when missing and then hardens its
// permissions so files created inside start from a private base.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	if err := restrictFilePermissions(dir); err != nil {
		return fmt.Errorf("harden directory %s: %w", dir, err)
	}
	return nil
}

// hardenFile ensures path is private to its owner, refusing to proceed when
// that cannot be guaranteed.
func hardenFile(path string) error {
	if err := restrictFilePermissions(path); err != nil {
		return fmt.Errorf("harden %s: %w", path, err)
	}
	if err := verifyFilePermissions(path); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}
