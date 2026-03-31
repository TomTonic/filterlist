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

// loadRealisticBlacklistRules combines the two sample filter lists from
// testdata/filterlists into one blacklist-style rule set.
func loadRealisticBlacklistRules(tb testing.TB) []filterlist.Rule {
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

// loadRealisticBlacklistPatterns converts the two sample filter lists into one
// pure-automaton pattern set so benchmarks can measure DFA construction without
// the hybrid suffix-map split used by the matcher package.
func loadRealisticBlacklistPatterns(tb testing.TB) []automaton.Pattern {
	tb.Helper()

	rules := loadRealisticBlacklistRules(tb)
	patterns := make([]automaton.Pattern, 0, len(rules))
	for i, rule := range rules {
		patterns = append(patterns, automaton.Pattern{
			Expr:   rule.Pattern,
			RuleID: uint32(i),
		})
	}

	return patterns
}

// BenchmarkCompileRealisticBlacklist measures DFA compilation for the two large
// example lists after parsing and blacklist-style rule selection have already
// completed.
func BenchmarkCompileRealisticBlacklist(b *testing.B) {
	rules := loadRealisticBlacklistRules(b)
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

// BenchmarkCompileRealisticBlacklistPureAutomaton measures compilation of the
// same blacklist sample lists when all blacklist patterns are forced through
// the automaton package instead of the hybrid matcher split.
func BenchmarkCompileRealisticBlacklistPureAutomaton(b *testing.B) {
	patterns := loadRealisticBlacklistPatterns(b)
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

// BenchmarkParseAndCompileRealisticBlacklist measures the end-to-end cost of
// parsing both sample lists, selecting blacklist rules, and compiling the DFA.
func BenchmarkParseAndCompileRealisticBlacklist(b *testing.B) {
	rules := loadRealisticBlacklistRules(b)
	baseline, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}

	b.ReportAllocs()
	b.ReportMetric(float64(len(rules)), "rules")
	b.ReportMetric(float64(baseline.StateCount()), "states")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rules := loadRealisticBlacklistRules(b)
		dfa, compileErr := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
		if compileErr != nil {
			b.Fatalf("CompileRules error: %v", compileErr)
		}
		benchmarkMatcher = dfa
	}
}
