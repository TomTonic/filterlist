package matcher

import (
	"fmt"
	"testing"

	"github.com/TomTonic/filterlist/pkg/listparser"
)

// TestCompileRulesEmpty verifies that users can safely compile an empty rule set
// through the matcher package by asserting that the result never matches.
func TestCompileRulesEmpty(t *testing.T) {
	m, err := CompileRules(nil, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if matched, _ := m.Match("anything"); matched {
		t.Error("empty matcher should not match")
	}
	if m.StateCount() != 0 {
		t.Errorf("empty matcher state count = %d, want 0", m.StateCount())
	}
	if m.LiteralCount() != 0 {
		t.Errorf("empty matcher literal count = %d, want 0", m.LiteralCount())
	}
}

// TestCompileRulesNilMatcher verifies that a nil Matcher is safe to use
// by asserting that Match, StateCount, and LiteralCount return zero values.
func TestCompileRulesNilMatcher(t *testing.T) {
	var m *Matcher
	if matched, _ := m.Match("anything"); matched {
		t.Error("nil matcher should not match")
	}
	if m.StateCount() != 0 {
		t.Error("nil matcher state count should be 0")
	}
	if m.LiteralCount() != 0 {
		t.Error("nil matcher literal count should be 0")
	}
}

// TestLiteralOnlyMatch verifies that users get exact domain blocking for
// literal-only rule sets through the matcher package by asserting that
// literal domains and their subdomains match while unrelated names do not.
func TestLiteralOnlyMatch(t *testing.T) {
	rules := []listparser.Rule{
		{Pattern: "ads.example.com"},
		{Pattern: "tracker.example.com"},
	}
	m, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if m.LiteralCount() != 2 {
		t.Errorf("literal count = %d, want 2", m.LiteralCount())
	}
	if m.StateCount() != 0 {
		t.Errorf("state count = %d, want 0 (no wildcards)", m.StateCount())
	}

	tests := []struct {
		input string
		match bool
	}{
		{"ads.example.com", true},
		{"tracker.example.com", true},
		{"sub.ads.example.com", true}, // subdomain match
		{"deep.sub.ads.example.com", true},
		{"example.com", false},
		{"other.example.com", false},
		{"notads.example.com", false},
	}
	for _, tt := range tests {
		matched, _ := m.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, matched, tt.match)
		}
	}
}

// TestWildcardOnlyMatch verifies that users get pattern-based blocking for
// wildcard-only rule sets through the matcher package by asserting that
// wildcard patterns match expected inputs.
func TestWildcardOnlyMatch(t *testing.T) {
	rules := []listparser.Rule{
		{Pattern: "*.ad.example.com"},
	}
	m, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if m.LiteralCount() != 0 {
		t.Errorf("literal count = %d, want 0", m.LiteralCount())
	}
	if m.StateCount() < 2 {
		t.Errorf("state count = %d, want >= 2", m.StateCount())
	}

	tests := []struct {
		input string
		match bool
	}{
		{"foo.ad.example.com", true},
		{"bar.ad.example.com", true},
		{"ad.example.com", false}, // '*' must match at least empty
		{"example.com", false},
	}
	for _, tt := range tests {
		matched, _ := m.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, matched, tt.match)
		}
	}
}

// TestMixedRules verifies that users get correct results when combining
// literal and wildcard rules through the matcher package by asserting
// that both kinds of patterns match independently.
func TestMixedRules(t *testing.T) {
	rules := []listparser.Rule{
		{Pattern: "ads.example.com"},       // literal → suffix map
		{Pattern: "*.tracker.example.com"}, // wildcard → DFA
	}
	m, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if m.LiteralCount() != 1 {
		t.Errorf("literal count = %d, want 1", m.LiteralCount())
	}
	if m.StateCount() < 2 {
		t.Errorf("state count = %d, want >= 2", m.StateCount())
	}

	tests := []struct {
		input string
		match bool
	}{
		{"ads.example.com", true},
		{"sub.ads.example.com", true},     // subdomain of literal
		{"foo.tracker.example.com", true}, // wildcard match
		{"tracker.example.com", false},    // wildcard needs prefix
		{"example.com", false},
		{"safe.example.com", false},
	}
	for _, tt := range tests {
		matched, _ := m.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, matched, tt.match)
		}
	}
}

// TestRuleAttribution verifies that users can trace matches back to their
// original rule indices through the matcher package by asserting that
// returned rule IDs correspond to input positions.
func TestRuleAttribution(t *testing.T) {
	rules := []listparser.Rule{
		{Pattern: "a.com"},   // index 0 → literal
		{Pattern: "b.com"},   // index 1 → literal
		{Pattern: "*.c.com"}, // index 2 → wildcard
	}
	m, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	matched, ids := m.Match("a.com")
	if !matched || len(ids) != 1 || ids[0] != 0 {
		t.Errorf("Match(a.com) = %v, %v; want true, [0]", matched, ids)
	}

	matched, ids = m.Match("b.com")
	if !matched || len(ids) != 1 || ids[0] != 1 {
		t.Errorf("Match(b.com) = %v, %v; want true, [1]", matched, ids)
	}

	matched, ids = m.Match("x.c.com")
	if !matched || len(ids) != 1 || ids[0] != 2 {
		t.Errorf("Match(x.c.com) = %v, %v; want true, [2]", matched, ids)
	}
}

// TestCaseInsensitive verifies that the matcher normalizes input to lowercase
// by asserting that mixed-case queries match lowercase patterns.
func TestCaseInsensitive(t *testing.T) {
	rules := []listparser.Rule{
		{Pattern: "Ads.Example.COM"},
	}
	m, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{"ads.example.com", "ADS.EXAMPLE.COM", "Ads.Example.Com"} {
		matched, _ := m.Match(input)
		if !matched {
			t.Errorf("Match(%q) should match", input)
		}
	}
}

// TestLargeScale verifies correctness at scale by combining many literal
// and wildcard patterns.
func TestLargeScale(t *testing.T) {
	var rules []listparser.Rule
	nLiteral := 500
	nWildcard := 50
	for i := range nLiteral {
		rules = append(rules, listparser.Rule{
			Pattern: fmt.Sprintf("host%d.example.com", i),
		})
	}
	for i := range nWildcard {
		rules = append(rules, listparser.Rule{
			Pattern: fmt.Sprintf("*.ad%d.example.com", i),
		})
	}

	m, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("literals=%d wildcardStates=%d", m.LiteralCount(), m.StateCount())

	// Verify literal matches (exact + subdomain)
	for i := range nLiteral {
		name := fmt.Sprintf("host%d.example.com", i)
		if matched, _ := m.Match(name); !matched {
			t.Fatalf("expected literal match for %q", name)
		}
		sub := fmt.Sprintf("sub.host%d.example.com", i)
		if matched, _ := m.Match(sub); !matched {
			t.Fatalf("expected subdomain match for %q", sub)
		}
	}

	// Verify wildcard matches
	for i := range nWildcard {
		name := fmt.Sprintf("foo.ad%d.example.com", i)
		if matched, _ := m.Match(name); !matched {
			t.Fatalf("expected wildcard match for %q", name)
		}
	}

	// Verify non-matches
	for _, name := range []string{"safe.example.com", "example.com", "nothere.test"} {
		if matched, _ := m.Match(name); matched {
			t.Errorf("unexpected match for %q", name)
		}
	}
}

// TestCompileRulesPureDFAPreservesLiteralSuffixSemantics verifies that users
// can switch to the pure-DFA matcher mode without losing ||domain^ semantics.
//
// This test covers the matcher package's full-DFA compilation path.
//
// It asserts that a literal domain rule still matches both the exact domain
// and deeper subdomains when CompileRules runs in ModeDFA.
func TestCompileRulesPureDFAPreservesLiteralSuffixSemantics(t *testing.T) {
	rules := []listparser.Rule{{Pattern: "ads.example.com"}}

	m, err := CompileRules(rules, CompileOptions{Mode: ModeDFA})
	if err != nil {
		t.Fatal(err)
	}

	if m.LiteralCount() != 1 {
		t.Fatalf("LiteralCount() = %d, want 1", m.LiteralCount())
	}
	if m.StateCount() == 0 {
		t.Fatal("expected DFA states in pure DFA mode")
	}

	for _, input := range []string{"ads.example.com", "sub.ads.example.com", "a.b.ads.example.com"} {
		matched, _ := m.Match(input)
		if !matched {
			t.Fatalf("expected Match(%q) to succeed in pure DFA mode", input)
		}
	}

	matched, _ := m.Match("safe.example.com")
	if matched {
		t.Fatal("expected safe.example.com not to match in pure DFA mode")
	}
}

// TestCompileRulesPureDFAMatchesHybrid verifies that users get the same match
// decisions from the hybrid and pure-DFA modes for a mixed rule set.
//
// This test covers semantic equivalence between the two matcher runtime modes.
//
// It asserts that exact literals, subdomains of literals, wildcard hits, and
// non-matches produce the same boolean results in both modes.
func TestCompileRulesPureDFAMatchesHybrid(t *testing.T) {
	rules := []listparser.Rule{
		{Pattern: "ads.example.com"},
		{Pattern: "*.tracker.example.com"},
		{Pattern: "malware.example.org"},
	}

	hybrid, err := CompileRules(rules, CompileOptions{Mode: ModeHybrid})
	if err != nil {
		t.Fatal(err)
	}
	pure, err := CompileRules(rules, CompileOptions{Mode: ModeDFA})
	if err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{
		"ads.example.com",
		"sub.ads.example.com",
		"foo.tracker.example.com",
		"malware.example.org",
		"safe.example.com",
		"tracker.example.com",
	} {
		hybridMatched, _ := hybrid.Match(input)
		pureMatched, _ := pure.Match(input)
		if hybridMatched != pureMatched {
			t.Fatalf("hybrid/pure mismatch for %q: hybrid=%v pure=%v", input, hybridMatched, pureMatched)
		}
	}
}

// TestCompileRulesWildcardSuffixSemantics verifies that wildcard host rules
// keep the repository's suffix semantics in the default hybrid matcher mode.
//
// This test covers DFA-backed wildcard matching in the matcher package.
//
// It asserts that a parsed rule equivalent to ||www.ad*.example.com^ matches
// both the exact hostname branch and deeper subdomains such as
// 123.www.adxxx.example.com.
func TestCompileRulesWildcardSuffixSemantics(t *testing.T) {
	rules := []listparser.Rule{{Pattern: "www.ad*.example.com"}}

	m, err := CompileRules(rules, CompileOptions{Mode: ModeHybrid})
	if err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{"www.adxxx.example.com", "123.www.adxxx.example.com"} {
		matched, _ := m.Match(input)
		if !matched {
			t.Fatalf("expected Match(%q) to succeed in hybrid mode", input)
		}
	}

	for _, input := range []string{"adxxx.example.com", "www.safe.example.com"} {
		matched, _ := m.Match(input)
		if matched {
			t.Fatalf("expected Match(%q) to fail in hybrid mode", input)
		}
	}
}

// TestCompileRulesPureDFAWildcardSuffixSemantics verifies that wildcard host
// rules keep the same suffix semantics in pure DFA mode.
//
// This test covers the full-DFA matcher compilation path for anchored wildcard
// host rules.
//
// It asserts that the pure DFA matcher agrees with the hybrid matcher for a
// rule equivalent to ||www.ad*.example.com^, including deeper subdomains.
func TestCompileRulesPureDFAWildcardSuffixSemantics(t *testing.T) {
	rules := []listparser.Rule{{Pattern: "www.ad*.example.com"}}

	m, err := CompileRules(rules, CompileOptions{Mode: ModeDFA})
	if err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{"www.adxxx.example.com", "123.www.adxxx.example.com"} {
		matched, _ := m.Match(input)
		if !matched {
			t.Fatalf("expected Match(%q) to succeed in pure DFA mode", input)
		}
	}

	for _, input := range []string{"adxxx.example.com", "www.safe.example.com"} {
		matched, _ := m.Match(input)
		if matched {
			t.Fatalf("expected Match(%q) to fail in pure DFA mode", input)
		}
	}
}
