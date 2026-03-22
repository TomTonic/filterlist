package automaton

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tomtonic/coredns-regfilter/pkg/filterlist"
)

func TestMatchLiteral(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "ads.example.com"},
		{Pattern: "tracker.example.com"},
	}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		match bool
	}{
		{"ads.example.com", true},
		{"tracker.example.com", true},
		{"example.com", false},
		{"other.example.com", false},
		{"ads.example.co", false},
		{"", false},
	}
	for _, tt := range tests {
		matched, _ := dfa.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, matched, tt.match)
		}
	}
}

func TestMatchWildcard(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "*.ads.example.com"},
	}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		match bool
	}{
		{"foo.ads.example.com", true},
		{"bar.ads.example.com", true},
		{"a.b.ads.example.com", true},
		{".ads.example.com", true}, // * matches empty
		{"ads.example.com", false}, // * matches empty but pattern has literal '.'
		{"example.com", false},
		{"other.example.com", false},
	}
	for _, tt := range tests {
		matched, _ := dfa.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v (pattern: *.ads.example.com)", tt.input, matched, tt.match)
		}
	}
}

func TestMatchWildcardMiddle(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "ads*.example.com"},
	}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		match bool
	}{
		{"ads.example.com", true},
		{"ads1.example.com", true},
		{"ads123.example.com", true},
		{"ads-new.example.com", true},
		{"example.com", false},
		{"notads.example.com", false},
	}
	for _, tt := range tests {
		matched, _ := dfa.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v (pattern: ads*.example.com)", tt.input, matched, tt.match)
		}
	}
}

func TestMatchMultipleRules(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "ads.example.com"},
		{Pattern: "*.tracker.example.com"},
		{Pattern: "malware.example.com"},
	}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		match bool
	}{
		{"ads.example.com", true},
		{"foo.tracker.example.com", true},
		{"malware.example.com", true},
		{"safe.example.com", false},
	}
	for _, tt := range tests {
		matched, _ := dfa.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, matched, tt.match)
		}
	}
}

func TestMatchRuleIDs(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "ads.example.com"},
		{Pattern: "ads.example.com"}, // duplicate
	}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	matched, ruleIDs := dfa.Match("ads.example.com")
	if !matched {
		t.Fatal("expected match")
	}
	if len(ruleIDs) != 2 {
		t.Errorf("expected 2 ruleIDs, got %d: %v", len(ruleIDs), ruleIDs)
	}
}

func TestMatchEmpty(t *testing.T) {
	dfa, err := CompileRules(nil, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	matched, _ := dfa.Match("anything")
	if matched {
		t.Error("empty DFA should not match")
	}
}

func TestMatchNilDFA(t *testing.T) {
	var dfa *DFA
	matched, ruleIDs := dfa.Match("anything")
	if matched {
		t.Error("nil DFA should not match")
	}
	if ruleIDs != nil {
		t.Error("nil DFA should return nil ruleIDs")
	}
}

func TestCompileMaxStates(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "*.*.*.example.com"},
	}
	_, err := CompileRules(rules, CompileOptions{MaxStates: 2})
	if err == nil {
		t.Error("expected MaxStates error")
	}
	if !strings.Contains(err.Error(), "MaxStates") {
		t.Errorf("expected MaxStates in error, got: %v", err)
	}
}

func TestCompileTimeout(t *testing.T) {
	// Many complex patterns to trigger timeout with very short duration
	var rules []filterlist.Rule
	for i := 0; i < 10000; i++ {
		rules = append(rules, filterlist.Rule{Pattern: "*.*.*.example.com"})
	}
	_, err := CompileRules(rules, CompileOptions{CompileTimeout: 1}) // 1 nanosecond
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestMinimization(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "a.com"},
		{Pattern: "b.com"},
	}
	noMin := boolPtr(false)
	dfaNoMin, err := CompileRules(rules, CompileOptions{Minimize: noMin})
	if err != nil {
		t.Fatal(err)
	}

	dfaMin, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Minimized DFA should have fewer or equal states
	if dfaMin.StateCount() > dfaNoMin.StateCount() {
		t.Errorf("minimized DFA has more states (%d) than unminimized (%d)",
			dfaMin.StateCount(), dfaNoMin.StateCount())
	}

	// Both should produce same match results
	for _, name := range []string{"a.com", "b.com", "c.com", "a.co"} {
		m1, _ := dfaNoMin.Match(name)
		m2, _ := dfaMin.Match(name)
		if m1 != m2 {
			t.Errorf("Match(%q) differs: nomin=%v, min=%v", name, m1, m2)
		}
	}
}

func TestDumpDot(t *testing.T) {
	rules := []filterlist.Rule{{Pattern: "a.b"}}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err = dfa.DumpDot(&buf)
	if err != nil {
		t.Fatal(err)
	}

	dot := buf.String()
	if !strings.Contains(dot, "digraph DFA") {
		t.Error("DOT output missing header")
	}
	if !strings.Contains(dot, "doublecircle") {
		t.Error("DOT output missing accept state")
	}
}

func TestDumpDotNil(t *testing.T) {
	var dfa *DFA
	err := dfa.DumpDot(&bytes.Buffer{})
	if err == nil {
		t.Error("expected error for nil DFA")
	}
}

func TestStateCount(t *testing.T) {
	var dfa *DFA
	if dfa.StateCount() != 0 {
		t.Error("nil DFA state count should be 0")
	}

	dfa = &DFA{States: make([]DFAState, 5)}
	if dfa.StateCount() != 5 {
		t.Errorf("state count = %d, want 5", dfa.StateCount())
	}
}

func TestCompileInvalidPattern(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "invalid_domain!"},
	}
	_, err := CompileRules(rules, CompileOptions{})
	if err == nil {
		t.Error("expected error for invalid character in pattern")
	}
}

func boolPtr(b bool) *bool { return &b }

// Benchmarks

func BenchmarkMatch(b *testing.B) {
	rules := []filterlist.Rule{
		{Pattern: "ads.example.com"},
		{Pattern: "tracker.example.com"},
		{Pattern: "*.ad.doubleclick.net"},
		{Pattern: "malware.example.org"},
		{Pattern: "*.analytics.google.com"},
	}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		b.Fatal(err)
	}

	names := []string{
		"ads.example.com",
		"safe.example.com",
		"foo.ad.doubleclick.net",
		"www.google.com",
		"sub.analytics.google.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dfa.Match(names[i%len(names)])
	}
}

func BenchmarkCompile(b *testing.B) {
	rules := make([]filterlist.Rule, 100)
	for i := range rules {
		rules[i] = filterlist.Rule{Pattern: "subdomain" + string(rune('a'+i%26)) + ".example.com"}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CompileRules(rules, CompileOptions{})
		if err != nil {
			b.Fatal(err)
		}
	}
}
