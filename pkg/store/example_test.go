package store_test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/guionardo/gs-secrets/pkg/store"
)

// Example demonstrates the public API of the store package: create a vault,
// set a secret with a TTL, read it back, and rotate the master key.
func Example() {
	dir, err := os.MkdirTemp("", "gs-secrets-example")
	if err != nil {
		fmt.Println("tempdir:", err)
		return
	}
	s, err := store.New(filepath.Join(dir, ".store"))
	if err != nil {
		fmt.Println("new:", err)
		return
	}
	if err := s.Set("api_key", "secret-value", 24*time.Hour); err != nil {
		fmt.Println("set:", err)
		return
	}
	value, ok := s.Get("api_key")
	fmt.Printf("get: %q ok=%v\n", value, ok)
	if err := s.Rekey(); err != nil {
		fmt.Println("rekey:", err)
		return
	}
	value, ok = s.Get("api_key")
	fmt.Printf("after rekey: %q ok=%v\n", value, ok)

	// Output:
	// get: "secret-value" ok=true
	// after rekey: "secret-value" ok=true
}
