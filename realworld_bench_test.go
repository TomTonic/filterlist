package filterlist_test

import (
	"testing"

	"github.com/TomTonic/filterlist/internal/benchfixture"
	"github.com/TomTonic/filterlist/pkg/listparser"
	"github.com/TomTonic/filterlist/pkg/matcher"
)

var benchmarkMatcher *matcher.Matcher

const realisticBenchmarkMaxStates = 0

// loadRealisticDenylistRules combines the two sample filter lists from
// testdata/filterlists into one denylist-style rule set; see
// benchfixture.DenylistRules, which the runtime comparisons share.
func loadRealisticDenylistRules(tb testing.TB) []listparser.Rule {
	tb.Helper()
	rules, err := benchfixture.DenylistRules()
	if err != nil {
		tb.Fatalf("load realistic denylist rules: %v", err)
	}
	return rules
}

// BenchmarkCompileRealisticDenylist measures DFA compilation for the two large
// example lists after parsing and denylist-style rule selection have already
// completed.
func BenchmarkCompileRealisticDenylist(b *testing.B) {
	rules := loadRealisticDenylistRules(b)
	baseline, err := matcher.CompileRules(rules, matcher.CompileOptions{
		MaxStates: realisticBenchmarkMaxStates,
		Mode:      matcher.ModeHybrid,
	})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}

	b.ReportAllocs()
	b.ReportMetric(float64(len(rules)), "rules")
	b.ReportMetric(float64(baseline.StateCount()), "states")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dfa, compileErr := matcher.CompileRules(rules, matcher.CompileOptions{
			MaxStates: realisticBenchmarkMaxStates,
			Mode:      matcher.ModeHybrid,
		})
		if compileErr != nil {
			b.Fatalf("CompileRules error: %v", compileErr)
		}
		benchmarkMatcher = dfa
	}
}

// BenchmarkCompileRealisticDenylistModeDFA measures compilation of the same
// denylist sample lists when matcher mode forces all rules through the DFA
// path instead of the hybrid suffix-map split.
func BenchmarkCompileRealisticDenylistModeDFA(b *testing.B) {
	rules := loadRealisticDenylistRules(b)
	baseline, err := matcher.CompileRules(rules, matcher.CompileOptions{
		MaxStates: realisticBenchmarkMaxStates,
		Mode:      matcher.ModeDFA,
	})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}

	b.ReportAllocs()
	b.ReportMetric(float64(len(rules)), "rules")
	b.ReportMetric(float64(baseline.StateCount()), "states")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dfa, compileErr := matcher.CompileRules(rules, matcher.CompileOptions{
			MaxStates: realisticBenchmarkMaxStates,
			Mode:      matcher.ModeDFA,
		})
		if compileErr != nil {
			b.Fatalf("CompileRules error: %v", compileErr)
		}
		benchmarkMatcher = dfa
	}
}

// BenchmarkParseAndCompileRealisticDenylist measures the end-to-end cost of
// parsing both sample lists, selecting denylist rules, and compiling the DFA.
func BenchmarkParseAndCompileRealisticDenylist(b *testing.B) {
	rules := loadRealisticDenylistRules(b)
	baseline, err := matcher.CompileRules(rules, matcher.CompileOptions{
		MaxStates: realisticBenchmarkMaxStates,
		Mode:      matcher.ModeHybrid,
	})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}

	b.ReportAllocs()
	b.ReportMetric(float64(len(rules)), "rules")
	b.ReportMetric(float64(baseline.StateCount()), "states")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rules := loadRealisticDenylistRules(b)
		dfa, compileErr := matcher.CompileRules(rules, matcher.CompileOptions{
			MaxStates: realisticBenchmarkMaxStates,
			Mode:      matcher.ModeHybrid,
		})
		if compileErr != nil {
			b.Fatalf("CompileRules error: %v", compileErr)
		}
		benchmarkMatcher = dfa
	}
}
