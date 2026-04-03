// Command filterlist-check is a CLI tool for offline validation and debugging
// of filter lists and compiled DFAs.
//
// Usage:
//
//	filterlist-check validate --allowlist DIR --denylist DIR
//	filterlist-check match --allowlist DIR --denylist DIR --name example.com
//	filterlist-check dump-dot --allowlist DIR --denylist DIR --out allowlist.dot,denylist.dot
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TomTonic/filterlist/pkg/blockloader"
	"github.com/TomTonic/filterlist/pkg/listparser"
	"github.com/TomTonic/filterlist/pkg/matcher"
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
	writeln(stderr, `filterlist-check — offline filter list validator and debugger

Commands:
  validate   Load directories, compile DFAs, print summary
	match      Check if a name is allowlisted, denylisted, or allowed
  dump-dot   Write DFAs as Graphviz DOT files

Flags (all commands):
	--allowlist DIR    Allowlist filter directory
	--denylist DIR     Denylist filter directory

Match-specific:
	--invert-allowlist   Use ||domain^ (not @@) for allowlist entries

Dump-dot-specific:
  --out WL.dot,BL.dot   Output file paths (default: whitelist.dot,blacklist.dot)`)
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

// cmdValidate loads configured directories and reports compile success or failure.
func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wlDir := fs.String("allowlist", "", "allowlist directory")
	blDir := fs.String("denylist", "", "denylist directory")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states")
	invertAL := fs.Bool("invert-allowlist", false, "use ||domain^ (not @@) for allowlist entries")
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
		{"allowlist", *wlDir},
		{"denylist", *blDir},
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

		rules = filterRulesForList(rules, item.label, *invertAL)

		writef(stdout, "[%s] parsed %d rules\n", item.label, len(rules))
		if len(rules) == 0 {
			continue
		}

		writef(stdout, "[%s] compiling..\n", item.label)
		m, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: *maxStates, Logger: &logger})
		if err != nil {
			writef(stderr, "[%s] COMPILE ERROR: %v\n", item.label, err)
			exitCode = 1
			continue
		}
		writef(stdout, "[%s] compiled: %d literals, %d DFA states\n", item.label, m.LiteralCount(), m.StateCount())
	}

	return exitCode
}

// cmdMatch evaluates a single domain name against the loaded allow and deny sets.
func cmdMatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("match", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wlDir := fs.String("allowlist", "", "allowlist directory")
	blDir := fs.String("denylist", "", "denylist directory")
	name := fs.String("name", "", "domain name to check")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states")
	invertAL := fs.Bool("invert-allowlist", false, "use ||domain^ (not @@) for allowlist entries")
	if err := fs.Parse(args); err != nil {
		writef(stderr, "match parse error: %v\n", err)
		return 1
	}

	if *name == "" {
		writeln(stderr, "error: --name is required")
		return 1
	}

	logger := cliLogger{stderr: stderr}
	normalized := normalizeDomain(*name)

	type listInfo struct {
		m        *matcher.Matcher
		sources  []string
		patterns []string
	}

	loadList := func(dir, label string) listInfo {
		if dir == "" {
			return listInfo{}
		}
		rules, err := blockloader.LoadDirectory(dir, &logger)
		if err != nil {
			writef(stderr, "load error: %v\n", err)
			return listInfo{}
		}
		rules = filterRulesForList(rules, label, *invertAL)
		if len(rules) == 0 {
			return listInfo{}
		}
		m, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: *maxStates})
		if err != nil {
			writef(stderr, "compile error: %v\n", err)
			return listInfo{}
		}
		sources := make([]string, len(rules))
		patterns := make([]string, len(rules))
		for i, r := range rules {
			sources[i] = r.Source
			patterns[i] = r.Pattern
		}
		return listInfo{m: m, sources: sources, patterns: patterns}
	}

	wl := loadList(*wlDir, "allowlist")
	bl := loadList(*blDir, "denylist")

	writef(stdout, "checking: %s\n", normalized)

	if wl.m != nil {
		matched, ruleIDs := wl.m.Match(normalized)
		if matched {
			writef(stdout, "result: ALLOWLISTED")
			writeRuleDetail(stdout, ruleIDs, wl.sources, wl.patterns)
			writeln(stdout, "")
			return 0
		}
	}

	if bl.m != nil {
		matched, ruleIDs := bl.m.Match(normalized)
		if matched {
			writef(stdout, "result: DENYLISTED")
			writeRuleDetail(stdout, ruleIDs, bl.sources, bl.patterns)
			writeln(stdout, "")
			return 1
		}
	}

	writeln(stdout, "result: ALLOWED (no match)")
	return 0
}

// writeRuleDetail appends rule source and pattern info for the first matching
// rule to the output line. It shows the basename:line and the original pattern
// so operators can trace which filter file line caused the decision.
func writeRuleDetail(w io.Writer, ruleIDs []uint32, sources, patterns []string) {
	if len(ruleIDs) == 0 || len(sources) == 0 {
		return
	}
	id := int(ruleIDs[0])
	if id >= len(sources) {
		return
	}
	src := shortSource(sources[id])
	if id < len(patterns) && patterns[id] != "" {
		writef(w, " rule=%s (%s)", src, patterns[id])
	} else {
		writef(w, " rule=%s", src)
	}
}

// cmdDumpDot exports compiled DFAs into Graphviz DOT files for inspection.
func cmdDumpDot(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dump-dot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wlDir := fs.String("allowlist", "", "allowlist directory")
	blDir := fs.String("denylist", "", "denylist directory")
	out := fs.String("out", "allowlist.dot,denylist.dot", "output files (comma-separated)")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states")
	if err := fs.Parse(args); err != nil {
		writef(stderr, "dump-dot parse error: %v\n", err)
		return 1
	}

	outFiles := strings.SplitN(*out, ",", 2)
	wlOut := "allowlist.dot"
	blOut := "denylist.dot"
	if len(outFiles) >= 1 {
		wlOut = strings.TrimSpace(outFiles[0])
	}
	if len(outFiles) >= 2 {
		blOut = strings.TrimSpace(outFiles[1])
	}

	logger := cliLogger{stderr: stderr}

	for _, item := range []struct {
		label  string
		dir    string
		output string
	}{
		{"allowlist", *wlDir, wlOut},
		{"denylist", *blDir, blOut},
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

		m, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: *maxStates})
		if err != nil {
			writef(stderr, "[%s] compile error: %v\n", item.label, err)
			continue
		}

		f, err := os.Create(filepath.Clean(item.output))
		if err != nil {
			writef(stderr, "[%s] create %s: %v\n", item.label, item.output, err)
			continue
		}
		if err := m.DumpDot(f); err != nil {
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

// shortSource converts a "path/to/dir/list.txt:42" source string to "list.txt:42".
func shortSource(source string) string {
	if source == "" {
		return "unknown"
	}
	if idx := strings.LastIndex(source, ":"); idx > 0 {
		return filepath.Base(source[:idx]) + source[idx:]
	}
	return filepath.Base(source)
}

// filterRulesForList selects the subset of rules appropriate for the given list
// label. Blacklist directories exclude @@ (exception) rules; whitelist
// directories keep only @@ rules by default or non-@@ rules when inverted.
func filterRulesForList(rules []listparser.Rule, label string, invertAllowlist bool) []listparser.Rule {
	switch label {
	case "denylist":
		return keepRules(rules, false)
	case "allowlist":
		if invertAllowlist {
			return keepRules(rules, false)
		}
		return keepRules(rules, true)
	default:
		return rules
	}
}

// keepRules returns the subset of rules whose IsAllow field equals wantAllow.
func keepRules(rules []listparser.Rule, wantAllow bool) []listparser.Rule {
	filtered := make([]listparser.Rule, 0, len(rules))
	for _, r := range rules {
		if r.IsAllow == wantAllow {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
