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

	"github.com/guionardo/gs-secrets/internal/store"
)

// version is the release version, injected at build time with
//
//	-ldflags "-X github.com/guionardo/gs-secrets/internal/app.version=v1.2.3"
//
// It defaults to "dev" for locally built binaries.
var version = "dev"

// ErrNoCommand is returned when no command flag was given.
var ErrNoCommand = errors.New("no command specified: use --set, --get, --delete or --list")

// ErrMultipleCommands is returned when more than one command flag was given.
var ErrMultipleCommands = errors.New("specify exactly one command: --set, --get, --delete or --list")

// options holds the parsed flags of a single invocation.
type options struct {
	command    string // set | get | delete | list
	key        string
	value      string
	ttl        time.Duration
	storeFile  string
	keyFile    string
	outputFile string
	verbose    bool
	version    bool
}

// Run executes the gs-secrets CLI with the given arguments. stdout receives
// command output (secret values, key lists, version); stderr receives
// diagnostics and verbose messages.
func Run(args []string, stdout, stderr io.Writer) error {
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
	return execute(opts, s, out, stderr)
}

// execute runs the selected command against the store.
func execute(opts *options, s *store.Store, out, stderr io.Writer) error {
	switch opts.command {
	case "set":
		if err := s.Set(opts.key, opts.value, opts.ttl); err != nil {
			return err
		}
		if opts.verbose {
			fmt.Fprintf(stderr, "secret set: %s\n", opts.key)
		}
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
  gs-secrets --version

Flags:
`)
		fs.PrintDefaults()
	}
	fs.StringVar(&setArg, "set", "", "store a secret, in key=value form")
	fs.StringVar(&getArg, "get", "", "retrieve the secret for a key")
	fs.StringVar(&deleteArg, "delete", "", "delete the secret for a key")
	fs.BoolVar(&list, "list", false, "list stored keys")
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
	opts.key, opts.value, err = parseSet(setArg)
	if err != nil {
		return nil, err
	}
	if err := validateCommands(setArg != "", getArg != "", deleteArg != "", list); err != nil {
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
	}
	return opts, nil
}

// parseSet splits a --set argument into key and value. An empty --set
// argument is not an error; the caller validates command selection.
func parseSet(setArg string) (key, value string, err error) {
	if setArg == "" {
		return "", "", nil
	}
	k, v, ok := strings.Cut(setArg, "=")
	if !ok {
		return "", "", fmt.Errorf("invalid --set %q: expected key=value", setArg)
	}
	key = strings.TrimSpace(k)
	if key == "" {
		return "", "", fmt.Errorf("invalid --set %q: key cannot be empty", setArg)
	}
	return key, strings.TrimSpace(v), nil
}

// validateCommands enforces that exactly one command flag was provided.
func validateCommands(hasSet, hasGet, hasDelete, hasList bool) error {
	count := 0
	for _, present := range []bool{hasSet, hasGet, hasDelete, hasList} {
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
