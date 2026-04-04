// Command filterlist-check validates filter list directories offline.
//
// Usage:
//
//	filterlist-check validate --list DIR [--list DIR ...] [--matcher-mode hybrid|dfa]
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/TomTonic/filterlist/pkg/blockloader"
	"github.com/TomTonic/filterlist/pkg/matcher"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// multiFlag supports repeatable --list flags.
type multiFlag []string

// String returns a comma-separated view of all provided --list values.
func (m *multiFlag) String() string {
	if m == nil {
		return ""
	}
	return strings.Join(*m, ",")
}

// Set appends one --list directory argument.
func (m *multiFlag) Set(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("--list requires a non-empty directory path")
	}
	*m = append(*m, trimmed)
	return nil
}

// run dispatches a CLI subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 1
	}

	switch args[0] {
	case "validate":
		return cmdValidate(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stderr)
		return 0
	default:
		writef(stderr, "unknown command: %s\n\n", args[0])
		usage(stderr)
		return 1
	}
}

// usage prints the top-level command help text.
func usage(stderr io.Writer) {
	writeln(stderr, `filterlist-check - offline filter list validator

Commands:
  validate   Load list directories, parse rules, compile matcher, print summary

Validate flags:
  --list DIR         List directory to validate (repeatable, at least one)
	--matcher-mode M   Matcher mode: hybrid or dfa (default: hybrid)
  --max-states N     Maximum DFA states (0 disables the cap, default: 200000)`)
}

// cliLogger adapts blockloader warnings to the CLI stderr stream.
type cliLogger struct {
	stderr io.Writer
}

// Warnf writes parser and loader warnings to stderr for CLI execution paths.
func (l cliLogger) Warnf(format string, args ...interface{}) {
	writef(l.stderr, "WARN: "+format+"\n", args...)
}

// Infof writes informational load progress to stderr for CLI execution paths.
func (l cliLogger) Infof(format string, args ...interface{}) {
	writef(l.stderr, "INFO: "+format+"\n", args...)
}

// cmdValidate loads configured list directories and reports compile results.
//
// The command is format-agnostic: each --list directory is parsed and compiled
// as-is without allow/deny semantics.
func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var lists multiFlag
	fs.Var(&lists, "list", "list directory to validate (repeatable)")
	matcherMode := fs.String("matcher-mode", string(matcher.ModeHybrid), "matcher mode: hybrid or dfa")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states (0 disables limit)")
	if err := fs.Parse(args); err != nil {
		writef(stderr, "validate parse error: %v\n", err)
		return 1
	}
	if len(lists) == 0 {
		writeln(stderr, "error: at least one --list DIR is required")
		return 1
	}
	if *maxStates < 0 {
		writeln(stderr, "error: --max-states must be >= 0")
		return 1
	}
	mode, err := matcher.ParseMode(*matcherMode)
	if err != nil {
		writef(stderr, "error: %v\n", err)
		return 1
	}

	logger := cliLogger{stderr: stderr}
	exitCode := 0

	for idx, dir := range lists {
		writef(stdout, "[list:%d] loading %s...\n", idx+1, dir)
		rules, err := blockloader.LoadDirectory(dir, &logger)
		if err != nil {
			writef(stderr, "[list:%d] ERROR: %v\n", idx+1, err)
			exitCode = 1
			continue
		}

		writef(stdout, "[list:%d] parsed %d rules\n", idx+1, len(rules))
		if len(rules) == 0 {
			continue
		}

		writef(stdout, "[list:%d] compiling...\n", idx+1)
		m, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: *maxStates, Mode: mode, Logger: &logger})
		if err != nil {
			writef(stderr, "[list:%d] COMPILE ERROR: %v\n", idx+1, err)
			exitCode = 1
			continue
		}

		writef(stdout, "[list:%d] compiled: mode=%s %d literals, %d DFA states\n", idx+1, mode, m.LiteralCount(), m.StateCount())
	}

	return exitCode
}

// writef ignores best-effort CLI write errors after formatting output.
func writef(w io.Writer, format string, args ...interface{}) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// writeln ignores best-effort CLI line write errors.
func writeln(w io.Writer, text string) {
	_, _ = fmt.Fprintln(w, text)
}
