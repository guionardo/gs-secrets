//nolint:gosec // integration tests only touch t.TempDir() paths
package main_test

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guionardo/gs-secrets/pkg/store"
)

// buildBinary compiles the gs-secrets CLI into a temp directory.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gs-secrets")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	require.NoError(t, err, "go build failed: %s", out)
	return bin
}

func runBinary(t *testing.T, bin string, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

func TestGoWritesBinaryReads(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	args := []string{"--store", filepath.Join(dir, ".store"), "--keyfile", filepath.Join(dir, "key")}

	// A Go program writes a secret through the public API...
	s, err := store.New(filepath.Join(dir, ".store"), store.WithKeyFile(filepath.Join(dir, "key")))
	require.NoError(t, err)
	require.NoError(t, s.Set("api_key", "secret-value", 24*time.Hour))

	// ...and the CLI process reads it. stdout carries exactly the value.
	stdout, stderr, err := runBinary(t, bin, "", append(args, "--get", "api_key")...)
	require.NoError(t, err)
	assert.Equal(t, "secret-value\n", stdout)
	assert.Empty(t, stderr)
}

func TestBinaryWritesStdinGoReads(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	args := []string{"--store", filepath.Join(dir, ".store"), "--keyfile", filepath.Join(dir, "key")}

	// The secret is piped through stdin, never passed as a process argument.
	stdout, stderr, err := runBinary(t, bin, "piped-secret\n", append(args, "--set", "token")...)
	require.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)

	s, err := store.New(filepath.Join(dir, ".store"), store.WithKeyFile(filepath.Join(dir, "key")))
	require.NoError(t, err)
	value, ok := s.Get("token")
	assert.True(t, ok)
	assert.Equal(t, "piped-secret", value)
}

func TestBinaryGetStdoutPurity(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	args := []string{"--store", filepath.Join(dir, ".store"), "--keyfile", filepath.Join(dir, "key")}
	require.NoError(t, runBinaryErr(t, bin, append(args, "--set", "k=v")))

	// Even with --verbose, stdout carries only the value; diagnostics and the
	// key name go to stderr, and the value never appears on stderr.
	stdout, stderr, err := runBinary(t, bin, "", append(args, "--get", "k", "--verbose")...)
	require.NoError(t, err)
	assert.Equal(t, "v\n", stdout)
	assert.Contains(t, stderr, "secret retrieved: k")
	assert.NotContains(t, stderr, "v\n")
}

func TestBinarySetInlineGoReads(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	args := []string{"--store", filepath.Join(dir, ".store"), "--keyfile", filepath.Join(dir, "key")}

	require.NoError(t, runBinaryErr(t, bin, append(args, "--set", "k=inline-value")))

	s, err := store.New(filepath.Join(dir, ".store"), store.WithKeyFile(filepath.Join(dir, "key")))
	require.NoError(t, err)
	value, ok := s.Get("k")
	assert.True(t, ok)
	assert.Equal(t, "inline-value", value)
}

func runBinaryErr(t *testing.T, bin string, args []string) error {
	t.Helper()
	_, _, err := runBinary(t, bin, "", args...)
	return err
}
