package automaton

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/TomTonic/filterlist/pkg/listparser"
)

// TestProfileCompilePhases profiles a realistic subset of rules to identify
// where compilation time is spent. Run with:
//
//	go test -run TestProfileCompilePhases -v -timeout=600s ./pkg/automaton/
func TestProfileCompilePhases(t *testing.T) {
	patterns := loadProfilePatterns(t)
	subsets := []int{1000, 5000, 10000}

	for _, n := range subsets {
		if n > len(patterns) {
			n = len(patterns)
		}
		subset := patterns[:n]
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			profileCompile(t, subset)
		})
	}

	// Write CPU profile for the 5000-pattern case for pprof analysis
	n := 5000
	if n > len(patterns) {
		n = len(patterns)
	}
	profPath := filepath.Join(t.TempDir(), "cpu_automaton.prof")
	f, err := os.Create(profPath) //nolint:gosec // test-only profiling output
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Errorf("close profile: %v", cerr)
		}
	}()
	if err := pprof.StartCPUProfile(f); err != nil {
		t.Fatal(err)
	}
	_, compileErr := Compile(patterns[:n], CompileOptions{MaxStates: 0})
	pprof.StopCPUProfile()
	if compileErr != nil {
		t.Fatalf("compile error: %v", compileErr)
	}
	t.Logf("CPU profile written to %s", profPath)
}

func profileCompile(t *testing.T, patterns []Pattern) {
	t.Helper()

	// Phase 1: Build per-pattern NFAs
	start := time.Now()
	var nfas []*nfa
	for i, p := range patterns {
		n, err := buildPatternNFA(p.Expr, p.RuleID)
		if err != nil {
			t.Fatalf("pattern %d: %v", i, err)
		}
		nfas = append(nfas, n)
	}
	nfaBuild := time.Since(start)

	// Phase 2: Combine NFAs
	combineStart := time.Now()
	combined, err := combineNFAs(nfas)
	if err != nil {
		t.Fatalf("combine NFAs: %v", err)
	}
	combineTime := time.Since(combineStart)

	// Phase 3: Subset construction
	subsetStart := time.Now()
	md, err := subsetConstruction(combined, 0, time.Time{})
	if err != nil {
		t.Fatalf("subset construction: %v", err)
	}
	subsetTime := time.Since(subsetStart)

	// Phase 4: Hopcroft minimization
	hopcroftStart := time.Now()
	minMD := hopcroftMinimize(md)
	hopcroftTime := time.Since(hopcroftStart)

	// Phase 5: Convert to array DFA
	convertStart := time.Now()
	dfa := minMD.toDFA()
	convertTime := time.Since(convertStart)

	total := time.Since(start)
	t.Logf("Rules: %d, NFA states: %d, DFA states (before min): %d, DFA states (after min): %d",
		len(patterns), len(combined.states), md.stateCount(), dfa.StateCount())
	t.Logf("Phase timings:")
	t.Logf("  NFA build:      %12v (%5.1f%%)", nfaBuild, 100*float64(nfaBuild)/float64(total))
	t.Logf("  NFA combine:    %12v (%5.1f%%)", combineTime, 100*float64(combineTime)/float64(total))
	t.Logf("  Subset constr:  %12v (%5.1f%%)", subsetTime, 100*float64(subsetTime)/float64(total))
	t.Logf("  Hopcroft min:   %12v (%5.1f%%)", hopcroftTime, 100*float64(hopcroftTime)/float64(total))
	t.Logf("  Array convert:  %12v (%5.1f%%)", convertTime, 100*float64(convertTime)/float64(total))
	t.Logf("  Total:          %12v", total)
}

func loadProfilePatterns(t *testing.T) []Pattern {
	t.Helper()

	paths := []string{
		"../../testdata/filterlists/Adguard_filter_example.txt",
		"../../testdata/filterlists/easylistgermany_example.txt",
	}

	var patterns []Pattern
	for _, p := range paths {
		parsed, err := listparser.ParseFile(p, nil)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", p, err)
		}
		for _, r := range parsed {
			if !r.IsAllow && strings.Contains(r.Pattern, "*") {
				if len(patterns) > int(^uint32(0)) {
					t.Fatal("too many wildcard patterns for uint32 rule IDs")
				}
				patterns = append(patterns, Pattern{Expr: r.Pattern, RuleID: uint32(len(patterns))}) //nolint:gosec // guarded by the bound check above
			}
		}
	}
	t.Logf("Loaded %d wildcard patterns", len(patterns))
	return patterns
}
