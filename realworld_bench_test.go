package regfilter_test

import (
	"path/filepath"
	"testing"

	"github.com/TomTonic/coredns-regfilter/pkg/automaton"
	"github.com/TomTonic/coredns-regfilter/pkg/filterlist"
	"github.com/TomTonic/coredns-regfilter/pkg/matcher"
)

var benchmarkMatcher *matcher.Matcher
var benchmarkAutomaton *automaton.DFA

const realisticBenchmarkMaxStates = 0

// loadRealisticDenylistRules combines the two sample filter lists from
// testdata/filterlists into one denylist-style rule set.
func loadRealisticDenylistRules(tb testing.TB) []filterlist.Rule {
	tb.Helper()

	logger := &testLogger{}
	paths := []string{
		filepath.Join(testdataDir(), "Adguard_filter_example.txt"),
		filepath.Join(testdataDir(), "easylistgermany_example.txt"),
	}

	var rules []filterlist.Rule
	for _, path := range paths {
		parsed, err := filterlist.ParseFile(path, logger)
		if err != nil {
			tb.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		rules = append(rules, parsed...)
	}

	filtered := make([]filterlist.Rule, 0, len(rules))
	for _, rule := range rules {
		if !rule.IsAllow {
			filtered = append(filtered, rule)
		}
	}

	return filtered
}

// loadRealisticDenylistPatterns converts the two sample filter lists into one
// pure-automaton pattern set so benchmarks can measure DFA construction without
// the hybrid suffix-map split used by the matcher package.
func loadRealisticDenylistPatterns(tb testing.TB) []automaton.Pattern {
	tb.Helper()

	rules := loadRealisticDenylistRules(tb)
	patterns := make([]automaton.Pattern, 0, len(rules))
	for i, rule := range rules {
		patterns = append(patterns, automaton.Pattern{
			Expr:   rule.Pattern,
			RuleID: uint32(i),
		})
	}

	return patterns
}

// BenchmarkCompileRealisticDenylist measures DFA compilation for the two large
// example lists after parsing and denylist-style rule selection have already
// completed.
func BenchmarkCompileRealisticDenylist(b *testing.B) {
	rules := loadRealisticDenylistRules(b)
	baseline, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}

	b.ReportAllocs()
	b.ReportMetric(float64(len(rules)), "rules")
	b.ReportMetric(float64(baseline.StateCount()), "states")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dfa, compileErr := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
		if compileErr != nil {
			b.Fatalf("CompileRules error: %v", compileErr)
		}
		benchmarkMatcher = dfa
	}
}

// BenchmarkCompileRealisticDenylistPureAutomaton measures compilation of the
// same denylist sample lists when all denylist patterns are forced through
// the automaton package instead of the hybrid matcher split.
func BenchmarkCompileRealisticDenylistPureAutomaton(b *testing.B) {
	patterns := loadRealisticDenylistPatterns(b)
	baseline, err := automaton.Compile(patterns, automaton.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
	if err != nil {
		b.Fatalf("Compile error: %v", err)
	}

	b.ReportAllocs()
	b.ReportMetric(float64(len(patterns)), "patterns")
	b.ReportMetric(float64(baseline.StateCount()), "states")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dfa, compileErr := automaton.Compile(patterns, automaton.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
		if compileErr != nil {
			b.Fatalf("Compile error: %v", compileErr)
		}
		benchmarkAutomaton = dfa
	}
}

// BenchmarkParseAndCompileRealisticDenylist measures the end-to-end cost of
// parsing both sample lists, selecting denylist rules, and compiling the DFA.
func BenchmarkParseAndCompileRealisticDenylist(b *testing.B) {
	rules := loadRealisticDenylistRules(b)
	baseline, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}

	b.ReportAllocs()
	b.ReportMetric(float64(len(rules)), "rules")
	b.ReportMetric(float64(baseline.StateCount()), "states")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rules := loadRealisticDenylistRules(b)
		dfa, compileErr := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
		if compileErr != nil {
			b.Fatalf("CompileRules error: %v", compileErr)
		}
		benchmarkMatcher = dfa
	}
}
