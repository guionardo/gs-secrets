package store

import (
	"fmt"
	"os"
)

// Store operations are serialized across processes with an advisory file
// lock on <vault file>.lock. Each public method takes the lock for the
// duration of its read-modify-write cycle, so concurrent processes see a
// consistent vault: atomic writes guarantee no corruption, and the lock
// guarantees no lost updates.

// withFileLock acquires an exclusive lock on the vault's lock file, runs fn,
// and releases the lock. The lock file is created on demand with private
// permissions and hardened like the vault itself.
func (s *Store) withFileLock(fn func() error) error {
	f, err := os.OpenFile(s.lockFile, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- lock file derived from the user-chosen vault path
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := lockFile(f); err != nil {
		return fmt.Errorf("lock vault: %w", err)
	}
	defer func() { _ = unlockFile(f) }()
	if err := hardenFile(s.lockFile); err != nil {
		return err
	}
	return fn()
}
