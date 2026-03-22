// Command regfilter-check is a CLI tool for offline validation and debugging
// of filter lists and compiled DFAs.
//
// Usage:
//
//	regfilter-check validate --whitelist DIR --blacklist DIR
//	regfilter-check match --whitelist DIR --blacklist DIR --name example.com
//	regfilter-check dump-dot --whitelist DIR --blacklist DIR --out whitelist.dot blacklist.dot
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tomtonic/coredns-regfilter/internal/util"
	"github.com/tomtonic/coredns-regfilter/pkg/automaton"
	"github.com/tomtonic/coredns-regfilter/pkg/blockloader"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "validate":
		cmdValidate(os.Args[2:])
	case "match":
		cmdMatch(os.Args[2:])
	case "dump-dot":
		cmdDumpDot(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `regfilter-check — offline filter list validator and debugger

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
  --out WL.dot BL.dot   Output file paths (default: whitelist.dot blacklist.dot)`)
}

type cliLogger struct{}

func (cliLogger) Warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARN: "+format+"\n", args...)
}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	wlDir := fs.String("whitelist", "", "whitelist directory")
	blDir := fs.String("blacklist", "", "blacklist directory")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "validate parse error: %v\n", err)
		os.Exit(1)
	}

	logger := cliLogger{}
	exitCode := 0

	for _, item := range []struct {
		label string
		dir   string
	}{
		{"whitelist", *wlDir},
		{"blacklist", *blDir},
	} {
		if item.dir == "" {
			fmt.Printf("[%s] no directory specified, skipping\n", item.label)
			continue
		}

		fmt.Printf("[%s] loading %s...\n", item.label, item.dir)
		rules, err := blockloader.LoadDirectory(item.dir, &logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] ERROR: %v\n", item.label, err)
			exitCode = 1
			continue
		}

		fmt.Printf("[%s] parsed %d rules\n", item.label, len(rules))
		if len(rules) == 0 {
			continue
		}

		fmt.Printf("[%s] compiling DFA...\n", item.label)
		dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{MaxStates: *maxStates})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] COMPILE ERROR: %v\n", item.label, err)
			exitCode = 1
			continue
		}
		fmt.Printf("[%s] DFA compiled: %d states\n", item.label, dfa.StateCount())
	}

	os.Exit(exitCode)
}

func cmdMatch(args []string) {
	fs := flag.NewFlagSet("match", flag.ExitOnError)
	wlDir := fs.String("whitelist", "", "whitelist directory")
	blDir := fs.String("blacklist", "", "blacklist directory")
	name := fs.String("name", "", "domain name to check")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "match parse error: %v\n", err)
		os.Exit(1)
	}

	if *name == "" {
		fmt.Fprintln(os.Stderr, "error: --name is required")
		os.Exit(1)
	}

	logger := cliLogger{}
	normalized := util.NormalizeDomain(*name)

	var wlDFA, blDFA *automaton.DFA

	if *wlDir != "" {
		rules, err := blockloader.LoadDirectory(*wlDir, &logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "whitelist load error: %v\n", err)
		} else if len(rules) > 0 {
			dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{MaxStates: *maxStates})
			if err != nil {
				fmt.Fprintf(os.Stderr, "whitelist compile error: %v\n", err)
			} else {
				wlDFA = dfa
			}
		}
	}

	if *blDir != "" {
		rules, err := blockloader.LoadDirectory(*blDir, &logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "blacklist load error: %v\n", err)
		} else if len(rules) > 0 {
			dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{MaxStates: *maxStates})
			if err != nil {
				fmt.Fprintf(os.Stderr, "blacklist compile error: %v\n", err)
			} else {
				blDFA = dfa
			}
		}
	}

	fmt.Printf("checking: %s\n", normalized)

	if wlDFA != nil {
		matched, ruleIDs := wlDFA.Match(normalized)
		if matched {
			fmt.Printf("result: WHITELISTED (rules: %v)\n", ruleIDs)
			return
		}
	}

	if blDFA != nil {
		matched, ruleIDs := blDFA.Match(normalized)
		if matched {
			fmt.Printf("result: BLACKLISTED (rules: %v)\n", ruleIDs)
			os.Exit(1)
		}
	}

	fmt.Println("result: ALLOWED (no match)")
}

func cmdDumpDot(args []string) {
	fs := flag.NewFlagSet("dump-dot", flag.ExitOnError)
	wlDir := fs.String("whitelist", "", "whitelist directory")
	blDir := fs.String("blacklist", "", "blacklist directory")
	out := fs.String("out", "whitelist.dot,blacklist.dot", "output files (comma-separated)")
	maxStates := fs.Int("max-states", 200000, "maximum DFA states")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "dump-dot parse error: %v\n", err)
		os.Exit(1)
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

	logger := cliLogger{}

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
			fmt.Fprintf(os.Stderr, "[%s] load error: %v\n", item.label, err)
			continue
		}
		if len(rules) == 0 {
			fmt.Printf("[%s] no rules, skipping DOT output\n", item.label)
			continue
		}

		dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{MaxStates: *maxStates})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] compile error: %v\n", item.label, err)
			continue
		}

		f, err := os.Create(item.output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] create %s: %v\n", item.label, item.output, err)
			continue
		}
		if err := dfa.DumpDot(f); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] dump error: %v\n", item.label, err)
		}
		f.Close()
		fmt.Printf("[%s] DOT written to %s\n", item.label, item.output)
	}
}
