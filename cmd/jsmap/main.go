package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Shell-I-Byte/jsmap/internal/jsmap"
)

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("jsmap", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // never reflect untrusted flags into logs
	root := fs.String("root", "", "Local root directory containing JavaScript files")
	version := fs.Bool("version", false, "Print version")
	parseErr := fs.Parse(args)
	if errors.Is(parseErr, flag.ErrHelp) {
		fmt.Fprintln(out, "Usage: jsmap --root DIRECTORY [--version]")
		return 0
	}
	if parseErr != nil || fs.NArg() != 0 {
		fmt.Fprintln(errOut, "jsmap: invalid arguments")
		return 2
	}
	if *version {
		fmt.Fprintln(out, jsmap.Version)
		return 0
	}
	if *root == "" {
		fmt.Fprintln(errOut, "jsmap: --root is required")
		return 2
	}
	report, err := jsmap.Scan(*root)
	if err != nil {
		fmt.Fprintln(errOut, "jsmap: scan failed (invalid, changed, unreadable, or oversized input)")
		return 3
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(true)
	if enc.Encode(report) != nil {
		fmt.Fprintln(errOut, "jsmap: output failed")
		return 3
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
