// Command regfilter-check is a CLI tool for offline validation and debugging
// of filter lists and compiled DFAs.
//
// Usage:
//
//	regfilter-check validate --whitelist DIR --blacklist DIR
//	regfilter-check match --whitelist DIR --blacklist DIR --name example.com
//	regfilter-check dump-dot --whitelist DIR --blacklist DIR --out whitelist.dot,blacklist.dot
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/TomTonic/coredns-regfilter/pkg/automaton"
	"github.com/TomTonic/coredns-regfilter/pkg/blockloader"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
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
	case "match":
		return cmdMatch(args[1:], stdout, stderr)
	case "dump-dot":
		return cmdDumpDot(args[1:], stdout, stderr)
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
	writeln(stderr, `regfilter-check — offline filter list validator and debugger

Commands:
  validate   Load directories, compile DFAs, print summary
  match      Check if a name is whitelisted, blacklisted, or allowed
  dump-dot   Write DFAs as Graphviz DOT files

Flags (all commands):
  --whitelist DIR    Whitelist filter directory
  --blacklist DIR    Blacklist filter directory

Match-specific:
  --name DOMAIN      Domain name to check

Dump-dot-specific:
	--out WL.dot,BL.dot   Output file paths (default: whitelist.dot,blacklist.dot)`)
}

// cliLogger adapts blockloader warnings to the CLI stderr stream.
type cliLogger struct {
	stderr          io.Writer
	suppressSummary bool
}

// Warnf writes parser and loader warnings to stderr for CLI execution paths.
func (l cliLogger) Warnf(format string, args ...interface{}) {
	if l.suppressSummary && strings.HasPrefix(format, "blockloader: loaded ") {
		return
	}
	writef(l.stderr, "WARN: "+format+"\n", args...)
}

// cmdValidate loads configured directories and reports compile success or failure.
func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wlDir := fs.String("whitelist", "", "whitelist directory")
	blDir := fs.String("blacklist", "", "blacklist directory")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states")
	if err := fs.Parse(args); err != nil {
		writef(stderr, "validate parse error: %v\n", err)
		return 1
	}

	logger := cliLogger{stderr: stderr}
	exitCode := 0

	for _, item := range []struct {
		label string
		dir   string
	}{
		{"whitelist", *wlDir},
		{"blacklist", *blDir},
	} {
		if item.dir == "" {
			writef(stdout, "[%s] no directory specified, skipping\n", item.label)
			continue
		}

		writef(stdout, "[%s] loading %s...\n", item.label, item.dir)
		rules, err := blockloader.LoadDirectory(item.dir, &logger)
		if err != nil {
			writef(stderr, "[%s] ERROR: %v\n", item.label, err)
			exitCode = 1
			continue
		}

		writef(stdout, "[%s] parsed %d rules\n", item.label, len(rules))
		if len(rules) == 0 {
			continue
		}

		writef(stdout, "[%s] compiling DFA...\n", item.label)
		dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{MaxStates: *maxStates})
		if err != nil {
			writef(stderr, "[%s] COMPILE ERROR: %v\n", item.label, err)
			exitCode = 1
			continue
		}
		writef(stdout, "[%s] DFA compiled: %d states\n", item.label, dfa.StateCount())
	}

	return exitCode
}

// cmdMatch evaluates a single domain name against the loaded allow and deny sets.
func cmdMatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("match", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wlDir := fs.String("whitelist", "", "whitelist directory")
	blDir := fs.String("blacklist", "", "blacklist directory")
	name := fs.String("name", "", "domain name to check")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states")
	if err := fs.Parse(args); err != nil {
		writef(stderr, "match parse error: %v\n", err)
		return 1
	}

	if *name == "" {
		writeln(stderr, "error: --name is required")
		return 1
	}

	logger := cliLogger{stderr: stderr, suppressSummary: true}
	normalized := normalizeDomain(*name)

	var wlDFA, blDFA *automaton.DFA

	if *wlDir != "" {
		rules, err := blockloader.LoadDirectory(*wlDir, &logger)
		if err != nil {
			writef(stderr, "whitelist load error: %v\n", err)
		} else if len(rules) > 0 {
			dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{MaxStates: *maxStates})
			if err != nil {
				writef(stderr, "whitelist compile error: %v\n", err)
			} else {
				wlDFA = dfa
			}
		}
	}

	if *blDir != "" {
		rules, err := blockloader.LoadDirectory(*blDir, &logger)
		if err != nil {
			writef(stderr, "blacklist load error: %v\n", err)
		} else if len(rules) > 0 {
			dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{MaxStates: *maxStates})
			if err != nil {
				writef(stderr, "blacklist compile error: %v\n", err)
			} else {
				blDFA = dfa
			}
		}
	}

	writef(stdout, "checking: %s\n", normalized)

	if wlDFA != nil {
		matched, ruleIDs := wlDFA.Match(normalized)
		if matched {
			writef(stdout, "result: WHITELISTED (rules: %v)\n", ruleIDs)
			return 0
		}
	}

	if blDFA != nil {
		matched, ruleIDs := blDFA.Match(normalized)
		if matched {
			writef(stdout, "result: BLACKLISTED (rules: %v)\n", ruleIDs)
			return 1
		}
	}

	writeln(stdout, "result: ALLOWED (no match)")
	return 0
}

// cmdDumpDot exports compiled DFAs into Graphviz DOT files for inspection.
func cmdDumpDot(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dump-dot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wlDir := fs.String("whitelist", "", "whitelist directory")
	blDir := fs.String("blacklist", "", "blacklist directory")
	out := fs.String("out", "whitelist.dot,blacklist.dot", "output files (comma-separated)")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states")
	if err := fs.Parse(args); err != nil {
		writef(stderr, "dump-dot parse error: %v\n", err)
		return 1
	}

	outFiles := strings.SplitN(*out, ",", 2)
	wlOut := "whitelist.dot"
	blOut := "blacklist.dot"
	if len(outFiles) >= 1 {
		wlOut = strings.TrimSpace(outFiles[0])
	}
	if len(outFiles) >= 2 {
		blOut = strings.TrimSpace(outFiles[1])
	}

	logger := cliLogger{stderr: stderr, suppressSummary: true}

	for _, item := range []struct {
		label  string
		dir    string
		output string
	}{
		{"whitelist", *wlDir, wlOut},
		{"blacklist", *blDir, blOut},
	} {
		if item.dir == "" {
			continue
		}

		rules, err := blockloader.LoadDirectory(item.dir, &logger)
		if err != nil {
			writef(stderr, "[%s] load error: %v\n", item.label, err)
			continue
		}
		if len(rules) == 0 {
			writef(stdout, "[%s] no rules, skipping DOT output\n", item.label)
			continue
		}

		dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{MaxStates: *maxStates})
		if err != nil {
			writef(stderr, "[%s] compile error: %v\n", item.label, err)
			continue
		}

		f, err := os.Create(item.output)
		if err != nil {
			writef(stderr, "[%s] create %s: %v\n", item.label, item.output, err)
			continue
		}
		if err := dfa.DumpDot(f); err != nil {
			writef(stderr, "[%s] dump error: %v\n", item.label, err)
		}
		if err := f.Close(); err != nil {
			writef(stderr, "[%s] close %s: %v\n", item.label, item.output, err)
			continue
		}
		writef(stdout, "[%s] DOT written to %s\n", item.label, item.output)
	}

	return 0
}

// writef ignores best-effort CLI write errors after formatting output.
func writef(w io.Writer, format string, args ...interface{}) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// writeln ignores best-effort CLI line write errors.
func writeln(w io.Writer, text string) {
	_, _ = fmt.Fprintln(w, text)
}

// normalizeDomain lowercases a domain name and removes a trailing dot.
func normalizeDomain(name string) string {
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	return name
}
