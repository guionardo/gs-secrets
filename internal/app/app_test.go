//nolint:gosec // tests only read and write files inside t.TempDir()
package app_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guionardo/gs-secrets/internal/app"
)

func runApp(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err = app.Run(args, &out, &errOut)
	return out.String(), errOut.String(), err
}

func runErr(t *testing.T, args []string) error {
	t.Helper()
	_, _, err := runApp(t, args...)
	return err
}

// newArgs builds the common store/keyfile flags pointing into dir, so every
// invocation within one test shares the same vault.
func newArgs(dir string, extra ...string) []string {
	args := []string{"--store", filepath.Join(dir, ".store"), "--keyfile", filepath.Join(dir, "key")}
	return append(args, extra...)
}

func TestSetGet(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := runApp(t, append(newArgs(dir), "--set", "api_key=secret123")...)
	require.NoError(t, err)
	assert.Empty(t, stdout)

	stdout, _, err = runApp(t, append(newArgs(dir), "--get", "api_key")...)
	require.NoError(t, err)
	assert.Equal(t, "secret123\n", stdout)
}

func TestGetMissingSecret(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runApp(t, append(newArgs(dir), "--get", "nope")...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found for key: nope")
}

func TestSetWithTTLExpires(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, runErr(t, append(newArgs(dir), "--set", "temp=1", "--ttl", "1ns")))

	_, _, err := runApp(t, append(newArgs(dir), "--get", "temp")...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found")
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, runErr(t, append(newArgs(dir), "--set", "k=v")))
	require.NoError(t, runErr(t, append(newArgs(dir), "--delete", "k")))

	_, _, err := runApp(t, append(newArgs(dir), "--get", "k")...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found")
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, runErr(t, append(newArgs(dir), "--set", "b=1")))
	require.NoError(t, runErr(t, append(newArgs(dir), "--set", "a=2")))

	stdout, _, err := runApp(t, append(newArgs(dir), "--list")...)
	require.NoError(t, err)
	assert.Equal(t, "a\nb\n", stdout)
}

func TestOutputFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, runErr(t, append(newArgs(dir), "--set", "k=v")))

	outFile := filepath.Join(t.TempDir(), "secret.txt")
	stdout, _, err := runApp(t, append(newArgs(dir), "--get", "k", "--output", outFile)...)
	require.NoError(t, err)
	assert.Empty(t, stdout)

	content, err := os.ReadFile(outFile) // #nosec G304 -- test reads its own temp output file
	require.NoError(t, err)
	assert.Equal(t, "v\n", string(content))
}

func TestVersion(t *testing.T) {
	stdout, _, err := runApp(t, "--version")
	require.NoError(t, err)
	assert.Contains(t, stdout, "gs-secrets")
}

func TestNoCommand(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runApp(t, "--store", filepath.Join(dir, ".store"))
	require.Error(t, err)
	assert.ErrorIs(t, err, app.ErrNoCommand)
}

func TestMultipleCommands(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runApp(t, append(newArgs(dir), "--set", "k=v", "--get", "k")...)
	require.Error(t, err)
	assert.ErrorIs(t, err, app.ErrMultipleCommands)
}

func TestInvalidSetFormat(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runApp(t, append(newArgs(dir), "--set", "novalue")...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected key=value")
}

func TestVerboseGoesToStderr(t *testing.T) {
	dir := t.TempDir()
	_, stderr, err := runApp(t, append(newArgs(dir), "--set", "k=v", "--verbose")...)
	require.NoError(t, err)
	assert.Contains(t, stderr, "secret set: k")
}

func TestRekeyCommand(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, runErr(t, append(newArgs(dir), "--set", "k=v")))
	oldKey, err := os.ReadFile(filepath.Join(dir, "key"))
	require.NoError(t, err)

	require.NoError(t, runErr(t, append(newArgs(dir), "--rekey")))

	newKey, err := os.ReadFile(filepath.Join(dir, "key"))
	require.NoError(t, err)
	assert.NotEqual(t, oldKey, newKey)
	_, err = os.Stat(filepath.Join(dir, "key.bak"))
	assert.True(t, os.IsNotExist(err), "rekey backup should be removed")

	stdout, _, err := runApp(t, append(newArgs(dir), "--get", "k")...)
	require.NoError(t, err)
	assert.Equal(t, "v\n", stdout)
}

func TestRekeyWithoutVault(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runApp(t, append(newArgs(dir), "--rekey")...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no vault found")
}

func TestParseErrors(t *testing.T) {
	_, stderr, err := runApp(t, "--bogus-flag")
	require.Error(t, err)
	assert.NotEmpty(t, stderr)
}

func TestUsageShownOnNoCommand(t *testing.T) {
	dir := t.TempDir()
	_, stderr, err := runApp(t, "--store", filepath.Join(dir, ".store"))
	require.Error(t, err)
	assert.Contains(t, stderr, "Usage:")
}
