// Command gs-secrets is a poor-man's secret vault: a CLI to store and
// retrieve encrypted secrets in a single local file.
package main

import (
	"fmt"
	"os"

	"github.com/guionardo/gs-secrets/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gs-secrets: %v\n", err)
		os.Exit(1)
	}
}
