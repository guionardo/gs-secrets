// Package app implements the gs-secrets command-line interface.
//
// Run is the single entry point: it parses flags, dispatches to the store,
// and returns an error for every failure path. The main package only
// forwards the process arguments and maps errors to the exit code.
package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/guionardo/gs-secrets/pkg/store"
)

// version is the release version, injected at build time with
//
//	-ldflags "-X github.com/guionardo/gs-secrets/internal/app.version=v1.2.3"
//
// It defaults to "dev" for locally built binaries.
var version = "dev"

// ErrNoCommand is returned when no command flag was given.
var ErrNoCommand = errors.New("no command specified: use --set, --get, --delete, --list or --rekey")

// ErrMultipleCommands is returned when more than one command flag was given.
var ErrMultipleCommands = errors.New("specify exactly one command: --set, --get, --delete, --list or --rekey")

// options holds the parsed flags of a single invocation.
type options struct {
	command        string // set | get | delete | list | rekey
	key            string
	value          string
	valueFromStdin bool
	prompt         bool
	ttl            time.Duration
	storeFile      string
	keyFile        string
	outputFile     string
	verbose        bool
	version        bool
	rekey          bool
}

// Run executes the gs-secrets CLI with the given arguments. stdin provides
// secret values for `--set key` (or the masked prompt); stdout receives
// command output (secret values, key lists, version) and nothing else;
// stderr receives diagnostics and verbose messages. Secret values never
// appear on stderr or in returned errors.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	if opts.version {
		fmt.Fprintf(stdout, "gs-secrets %s\n", version)
		return nil
	}
	if opts.storeFile == "" {
		opts.storeFile, err = store.DefaultStoreFile()
		if err != nil {
			return fmt.Errorf("resolve default vault path: %w", err)
		}
	}

	out := io.Writer(stdout)
	if opts.outputFile != "" {
		f, err := os.Create(opts.outputFile) // #nosec G304 -- user-provided --output path
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	var storeOpts []store.Option
	if opts.keyFile != "" {
		storeOpts = append(storeOpts, store.WithKeyFile(opts.keyFile))
	}
	s, err := store.New(opts.storeFile, storeOpts...)
	if err != nil {
		return err
	}
	return execute(opts, s, stdin, out, stderr)
}

// execute runs the selected command against the store.
func execute(opts *options, s *store.Store, stdin io.Reader, out, stderr io.Writer) error {
	switch opts.command {
	case "set":
		return executeSet(opts, s, stdin, stderr)
	case "get":
		value, ok := s.Get(opts.key)
		if !ok {
			return fmt.Errorf("secret not found for key: %s", opts.key)
		}
		fmt.Fprintln(out, value)
		if opts.verbose {
			fmt.Fprintf(stderr, "secret retrieved: %s\n", opts.key)
		}
	case "delete":
		if err := s.Delete(opts.key); err != nil {
			return err
		}
		if opts.verbose {
			fmt.Fprintf(stderr, "secret deleted: %s\n", opts.key)
		}
	case "list":
		for _, k := range s.List() {
			fmt.Fprintln(out, k)
		}
	case "rekey":
		if err := s.Rekey(); err != nil {
			return err
		}
		if opts.verbose {
			fmt.Fprintf(stderr, "master key rotated\n")
		}
	}
	return nil
}

// parseFlags defines the flag set, parses args, and validates command
// selection. Flag errors are printed to stderr by the flag package itself.
func parseFlags(args []string, stderr io.Writer) (*options, error) {
	opts := &options{}
	var setArg, getArg, deleteArg string
	var list bool

	fs := flag.NewFlagSet("gs-secrets", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, `gs-secrets - poor-man's secret vault

Usage:
  gs-secrets --set key=value [--ttl DURATION] [--store PATH] [--keyfile PATH]
  gs-secrets --get key [--output FILE] [--store PATH] [--keyfile PATH]
  gs-secrets --delete key [--store PATH] [--keyfile PATH]
  gs-secrets --list [--store PATH] [--keyfile PATH]
  gs-secrets --rekey [--store PATH] [--keyfile PATH]
  gs-secrets --version

Flags:
`)
		fs.PrintDefaults()
	}
	fs.StringVar(&setArg, "set", "", "store a secret, in key=value form")
	fs.StringVar(&getArg, "get", "", "retrieve the secret for a key")
	fs.StringVar(&deleteArg, "delete", "", "delete the secret for a key")
	fs.BoolVar(&list, "list", false, "list stored keys")
	fs.BoolVar(&opts.rekey, "rekey", false, "rotate the master key and re-encrypt the vault")
	fs.BoolVar(&opts.prompt, "prompt", false, "read the secret value for --set from a masked terminal prompt instead of stdin")
	fs.BoolVar(&opts.version, "version", false, "print version and exit")
	fs.DurationVar(&opts.ttl, "ttl", 0, "time to live for a secret set with --set (e.g. 1h, 30m); 0 means never expire")
	fs.StringVar(&opts.storeFile, "store", "", "path to the secrets vault (default: <user config dir>/gs-secrets/.store)")
	fs.StringVar(&opts.keyFile, "keyfile", "", "path to the master key file (default: <vault dir>/.gs-secrets.key)")
	fs.StringVar(&opts.outputFile, "output", "", "write command output to FILE instead of stdout")
	fs.BoolVar(&opts.verbose, "verbose", false, "print progress messages to stderr")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if opts.version {
		return opts, nil
	}

	var err error
	opts.key, opts.value, opts.valueFromStdin, err = parseSet(setArg)
	if err != nil {
		return nil, err
	}
	if opts.prompt && !opts.valueFromStdin {
		return nil, errors.New("--prompt can only be used with --set key (no inline value)")
	}
	if err := validateCommands(setArg != "", getArg != "", deleteArg != "", list, opts.rekey); err != nil {
		if errors.Is(err, ErrNoCommand) {
			fs.Usage()
		}
		return nil, err
	}
	switch {
	case setArg != "":
		opts.command = "set"
	case getArg != "":
		opts.command = "get"
		opts.key = getArg
	case deleteArg != "":
		opts.command = "delete"
		opts.key = deleteArg
	case list:
		opts.command = "list"
	case opts.rekey:
		opts.command = "rekey"
	}
	return opts, nil
}

// parseSet splits a --set argument into key and value. An empty --set
// argument is not an error; the caller validates command selection.
//
// Two forms are supported:
//
//	--set key=value   inline value (convenient for non-sensitive data)
//	--set key         value read from stdin (or a --prompt); keeps the
//	                  secret out of the process argument list
//
// Error messages never include the argument, because it may contain a
// secret value.
func parseSet(setArg string) (key, value string, fromStdin bool, err error) {
	if setArg == "" {
		return "", "", false, nil
	}
	k, v, hasValue := strings.Cut(setArg, "=")
	key = strings.TrimSpace(k)
	if key == "" {
		return "", "", false, errors.New("invalid --set: key cannot be empty")
	}
	if !hasValue {
		return key, "", true, nil
	}
	return key, strings.TrimSpace(v), false, nil
}

// executeSet stores a secret, resolving the value from the inline flag,
// stdin, or the masked prompt as selected during parsing.
func executeSet(opts *options, s *store.Store, stdin io.Reader, stderr io.Writer) error {
	value := opts.value
	if opts.valueFromStdin {
		v, err := readSecret(stdin, opts.prompt, stderr)
		if err != nil {
			return err
		}
		value = v
	}
	if err := s.Set(opts.key, value, opts.ttl); err != nil {
		return err
	}
	if opts.verbose {
		fmt.Fprintf(stderr, "secret set: %s\n", opts.key)
	}
	return nil
}

// readSecret obtains the value for --set key: either from the masked
// terminal prompt (--prompt) or by consuming stdin to EOF. With --prompt the
// input must be a terminal; otherwise the caller would not see the echo
// suppression and might assume the input was read.
func readSecret(stdin io.Reader, prompt bool, stderr io.Writer) (string, error) {
	if prompt {
		f, ok := stdin.(*os.File)
		if !ok || !term.IsTerminal(int(f.Fd())) {
			return "", errors.New("--prompt requires an interactive terminal")
		}
		b, err := term.ReadPassword(int(f.Fd()))
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		fmt.Fprintln(stderr)
		return string(b), nil
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return "", fmt.Errorf("read secret from stdin: %w", err)
	}
	value := string(data)
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	return value, nil
}

// validateCommands enforces that exactly one command flag was provided.
func validateCommands(hasSet, hasGet, hasDelete, hasList, hasRekey bool) error {
	count := 0
	for _, present := range []bool{hasSet, hasGet, hasDelete, hasList, hasRekey} {
		if present {
			count++
		}
	}
	switch count {
	case 0:
		return ErrNoCommand
	case 1:
		return nil
	default:
		return ErrMultipleCommands
	}
}
