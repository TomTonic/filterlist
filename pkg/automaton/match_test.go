package automaton

import (
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// Basic match tests
// ---------------------------------------------------------------------------

// TestMatchLiteral verifies that users get exact host blocking for literal
// rules in the automaton package by asserting that only the configured literal
// names match.
func TestMatchLiteral(t *testing.T) {
	rules := []Pattern{
		{Expr: "ads.example.com", RuleID: 1},
		{Expr: "tracker.example.com"},
	}
	dfa, err := Compile(rules, CompileOptions{})
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

// TestDFAStateCanHaveMultipleOutgoingEdges verifies that users compiling rules
// with different next characters still get all matches in the automaton package
// after subset construction and minimization.
//
// This test covers the exported DFA transition layout.
//
// It asserts that one DFA state can expose multiple outgoing transitions, which
// is why the DFA keeps its dense per-alphabet transition array.
func TestDFAStateCanHaveMultipleOutgoingEdges(t *testing.T) {
	dfa, err := Compile([]Pattern{{Expr: "a", RuleID: 1}, {Expr: "b", RuleID: 2}}, CompileOptions{})
	if err != nil {
		t.Fatalf("Compile(): %v", err)
	}

	aNext := dfa.start.Trans[runeToIndex('a')]
	bNext := dfa.start.Trans[runeToIndex('b')]
	if aNext == nil || bNext == nil {
		t.Fatalf("expected start state to have outgoing edges for both 'a' and 'b'")
	}
	if aNext == bNext {
		t.Fatalf("expected distinct DFA targets for 'a' and 'b'")
	}
}

// TestMatchWildcard verifies that users get subdomain matching for wildcard
// rules in the automaton package by asserting that matching prefixes pass and
// unrelated names do not.
func TestMatchWildcard(t *testing.T) {
	rules := []Pattern{
		{Expr: "*.ads.example.com"},
	}
	dfa, err := Compile(rules, CompileOptions{})
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

// TestMatchWildcardMiddle verifies that users can match wildcard segments
// inside labels in the automaton package by asserting that ads* patterns cover
// the intended hostnames.
func TestMatchWildcardMiddle(t *testing.T) {
	rules := []Pattern{
		{Expr: "ads*.example.com"},
	}
	dfa, err := Compile(rules, CompileOptions{})
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

// TestMatchMultipleRules verifies that users can combine several patterns in
// one compiled automaton in the automaton package by asserting that each
// configured rule matches while safe names do not.
func TestMatchMultipleRules(t *testing.T) {
	rules := []Pattern{
		{Expr: "ads.example.com", RuleID: 1},
		{Expr: "*.tracker.example.com"},
		{Expr: "malware.example.com"},
	}
	dfa, err := Compile(rules, CompileOptions{})
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

// TestMatchRuleIDs verifies that users can trace a match back to all
// contributing rules in the automaton package by asserting that duplicate
// patterns preserve both rule IDs.
func TestMatchRuleIDs(t *testing.T) {
	rules := []Pattern{
		{Expr: "ads.example.com", RuleID: 0},
		{Expr: "ads.example.com", RuleID: 1}, // same pattern, different ID
	}
	dfa, err := Compile(rules, CompileOptions{})
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

// TestMatchEmpty verifies that users do not get accidental matches from an
// empty ruleset in the automaton package by asserting that an empty DFA rejects
// arbitrary input.
func TestMatchEmpty(t *testing.T) {
	dfa, err := Compile(nil, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	matched, _ := dfa.Match("anything")
	if matched {
		t.Error("empty DFA should not match")
	}
}

// TestMatchNilDFA verifies that callers can safely handle an uninitialized
// automaton in the automaton package by asserting that a nil DFA returns no
// match and no rule IDs.
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

// TestMatchNonDNSCharacters verifies that malformed query strings do not crash
// or spuriously match in the automaton package by asserting that unsupported
// characters produce clean non-matches.
func TestMatchNonDNSCharacters(t *testing.T) {
	rules := []Pattern{{Expr: "example.com"}}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Non-DNS chars should cause immediate non-match, never panic
	inputs := []string{
		"EXAMPLE.COM",
		"example.com/path",
		"example.com:8080",
		"example com",
		"example\x00com",
		"exämple.com",
	}
	for _, input := range inputs {
		matched, _ := dfa.Match(input)
		if matched {
			t.Errorf("Match(%q) = true, want false (non-DNS input)", input)
		}
	}
}

// TestMatchEmptyInput verifies that users do not get false positives for empty
// queries in the automaton package by asserting that non-empty patterns reject
// empty input.
func TestMatchEmptyInput(t *testing.T) {
	rules := []Pattern{{Expr: "example.com"}}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	matched, _ := dfa.Match("")
	if matched {
		t.Error("empty input should not match non-empty pattern")
	}
}

// TestMatchWildcardOnly verifies that users can intentionally match any
// DNS-style name with a pure wildcard rule in the automaton package by
// asserting that DNS input matches and unsupported input does not.
func TestMatchWildcardOnly(t *testing.T) {
	rules := []Pattern{{Expr: "*"}}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// * matches zero or more DNS chars — everything matches
	for _, input := range []string{"", "a", "example.com", "a.b.c.d.e"} {
		matched, _ := dfa.Match(input)
		if !matched {
			t.Errorf("wildcard-only pattern should match %q", input)
		}
	}

	// Non-DNS chars still don't match
	matched, _ := dfa.Match("UPPER")
	if matched {
		t.Error("wildcard should not match non-DNS characters")
	}
}

// TestMatchAllDNSCharsInDomain verifies that users can compile and match names
// containing the full supported alphabet in the automaton package by asserting
// that every allowed DNS character survives compilation and matching.
func TestMatchAllDNSCharsInDomain(t *testing.T) {
	// A domain containing every allowed DNS char
	domain := "abcdefghijklmnopqrstuvwxyz0123456789-."
	rules := []Pattern{{Expr: domain}}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	matched, _ := dfa.Match(domain)
	if !matched {
		t.Error("should match domain containing all DNS chars")
	}
}

// ---------------------------------------------------------------------------
// Overlapping / subset patterns
// ---------------------------------------------------------------------------

// TestMatchOverlappingPatterns verifies that users keep all applicable rule
// attributions when rules overlap in the automaton package by asserting that a
// specific hostname reports both the literal and wildcard rule IDs.
func TestMatchOverlappingPatterns(t *testing.T) {
	rules := []Pattern{
		{Expr: "*.example.com", RuleID: 0},
		{Expr: "ads.example.com", RuleID: 1},
	}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// "ads.example.com" matches both patterns
	matched, ruleIDs := dfa.Match("ads.example.com")
	if !matched {
		t.Fatal("expected match")
	}
	if len(ruleIDs) != 2 {
		t.Errorf("expected 2 ruleIDs for overlapping match, got %d", len(ruleIDs))
	}

	// "other.example.com" matches only the wildcard
	matched, ruleIDs = dfa.Match("other.example.com")
	if !matched {
		t.Fatal("expected match via wildcard")
	}
	if len(ruleIDs) != 1 {
		t.Errorf("expected 1 ruleID for wildcard-only match, got %d", len(ruleIDs))
	}
}

// TestMatchConsecutiveWildcards verifies that users can combine adjacent
// wildcard behavior in the automaton package by asserting that *.* patterns
// match dotted names and still reject missing separators.
func TestMatchConsecutiveWildcards(t *testing.T) {
	// Pattern with multiple wildcards
	rules := []Pattern{{Expr: "*.*"}}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		match bool
	}{
		{"a.b", true},
		{"foo.bar", true},
		{".a", true},
		{"a.", true},
		{".", true},
		{"", false}, // needs at least a '.'
	}
	for _, tt := range tests {
		matched, _ := dfa.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) with *.*: got %v, want %v", tt.input, matched, tt.match)
		}
	}
}

// ---------------------------------------------------------------------------
// Large automaton tests
// ---------------------------------------------------------------------------

// TestLargeAutomatonManyLiteralRules verifies that users can compile and match
// a large literal blocklist in the automaton package by asserting end-to-end
// correctness across many distinct host rules.
func TestLargeAutomatonManyLiteralRules(t *testing.T) {
	n := scaledHeavyTestCount(5000, 1000)
	rules := make([]Pattern, n)
	for i := range n {
		rules[i] = Pattern{Expr: fmt.Sprintf("host%d.example.com", i), RuleID: uint32(i)}
	}

	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatalf("Compile with %d patterns: %v", n, err)
	}

	t.Logf("DFA states for %d literal rules: %d", n, dfa.StateCount())

	// Verify all patterns match
	for i := range n {
		name := fmt.Sprintf("host%d.example.com", i)
		matched, ruleIDs := dfa.Match(name)
		if !matched {
			t.Fatalf("expected match for %q (rule %d)", name, i)
		}
		if len(ruleIDs) != 1 || ruleIDs[0] != uint32(i) {
			t.Errorf("Match(%q) ruleIDs = %v, want [%d]", name, ruleIDs, i)
		}
	}

	// Verify non-patterns don't match
	for _, name := range []string{"nothere.example.com", "host-1.example.com", "example.com"} {
		matched, _ := dfa.Match(name)
		if matched {
			t.Errorf("expected no match for %q", name)
		}
	}
}

// TestLargeAutomatonManyWildcardRules verifies that users can compile and match
// a large wildcard blocklist in the automaton package by asserting correct
// wildcard hits across many generated domains.
func TestLargeAutomatonManyWildcardRules(t *testing.T) {
	n := scaledHeavyTestCount(1000, 250)
	rules := make([]Pattern, n)
	for i := range n {
		rules[i] = Pattern{Expr: fmt.Sprintf("*.ad%d.example.com", i)}
	}

	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatalf("Compile with %d wildcard patterns: %v", n, err)
	}

	t.Logf("DFA states for %d wildcard rules: %d", n, dfa.StateCount())

	// Verify wildcard matches
	for i := range n {
		name := fmt.Sprintf("sub.ad%d.example.com", i)
		matched, _ := dfa.Match(name)
		if !matched {
			t.Fatalf("expected wildcard match for %q", name)
		}
	}

	// Verify non-matches
	matched, _ := dfa.Match("sub.notpresent.example.com")
	if matched {
		t.Error("expected no match for non-existent wildcard domain")
	}
}

// TestLargeAutomatonMixedRules verifies that users can combine large literal
// and wildcard rule sets in one compiled automaton by asserting that both kinds
// of rules still match correctly.
func TestLargeAutomatonMixedRules(t *testing.T) {
	// Mix of literal and wildcard rules
	var rules []Pattern
	literalCount := scaledHeavyTestCount(500, 200)
	wildcardCount := scaledHeavyTestCount(200, 80)
	for i := range literalCount {
		rules = append(rules, Pattern{Expr: fmt.Sprintf("ads%d.example.com", i)})
	}
	for i := range wildcardCount {
		rules = append(rules, Pattern{Expr: fmt.Sprintf("*.tracker%d.example.com", i)})
	}

	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("DFA states for %d mixed rules: %d", literalCount+wildcardCount, dfa.StateCount())

	// Verify literal matches
	for i := range literalCount {
		matched, _ := dfa.Match(fmt.Sprintf("ads%d.example.com", i))
		if !matched {
			t.Fatalf("expected literal match at index %d", i)
		}
	}

	// Verify wildcard matches
	for i := range wildcardCount {
		matched, _ := dfa.Match(fmt.Sprintf("sub.tracker%d.example.com", i))
		if !matched {
			t.Fatalf("expected wildcard match at index %d", i)
		}
	}

	// Verify non-matches
	matched, _ := dfa.Match("safe.example.com")
	if matched {
		t.Error("expected no match for safe.example.com")
	}
}

// TestLargeAutomatonRuleAttributionPreserved verifies that users can still
// trace large compiled rule sets back to their original entries in the
// automaton package by asserting that each unique rule keeps its own ID.
func TestLargeAutomatonRuleAttributionPreserved(t *testing.T) {
	// After minimization with many rules, each rule must keep its ID
	n := scaledHeavyTestCount(200, 100)
	rules := make([]Pattern, n)
	for i := range n {
		// Each pattern is unique enough that no two share the same accept state
		rules[i] = Pattern{Expr: fmt.Sprintf("unique%d.test.com", i), RuleID: uint32(i)}
	}

	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for i := range n {
		name := fmt.Sprintf("unique%d.test.com", i)
		matched, ruleIDs := dfa.Match(name)
		if !matched {
			t.Fatalf("expected match for %q", name)
		}
		if len(ruleIDs) != 1 || ruleIDs[0] != uint32(i) {
			t.Errorf("Match(%q) ruleIDs = %v, want [%d]", name, ruleIDs, i)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

// TestSingleCharPattern verifies that users can compile the smallest literal
// rule in the automaton package by asserting that a one-character pattern
// matches only that exact input.
func TestSingleCharPattern(t *testing.T) {
	rules := []Pattern{{Expr: "a"}}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	matched, _ := dfa.Match("a")
	if !matched {
		t.Error("should match single char 'a'")
	}
	matched, _ = dfa.Match("b")
	if matched {
		t.Error("should not match 'b'")
	}
	matched, _ = dfa.Match("ab")
	if matched {
		t.Error("should not match 'ab'")
	}
}

// TestDuplicatePatternsDifferentRuleIDs verifies that users keep all
// contributing IDs when the same rule appears multiple times in the automaton
// package by asserting that duplicate patterns return every originating rule
// ID.
func TestDuplicatePatternsDifferentRuleIDs(t *testing.T) {
	rules := []Pattern{
		{Expr: "x.com", RuleID: 0},
		{Expr: "x.com", RuleID: 1},
		{Expr: "x.com", RuleID: 2},
	}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	matched, ruleIDs := dfa.Match("x.com")
	if !matched {
		t.Fatal("expected match")
	}
	if len(ruleIDs) != 3 {
		t.Errorf("expected 3 ruleIDs, got %d: %v", len(ruleIDs), ruleIDs)
	}
}

// TestEmptyPatternWildcard verifies that users can intentionally allow an
// empty-string wildcard match in the automaton package by asserting that the
// standalone wildcard accepts empty input.
func TestEmptyPatternWildcard(t *testing.T) {
	// Wildcard pattern matches empty string
	rules := []Pattern{{Expr: "*"}}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	matched, _ := dfa.Match("")
	if !matched {
		t.Error("* should match empty string")
	}
}

// TestWildcardAtEnd verifies that users can match suffix variations with a
// trailing wildcard in the automaton package by asserting that ads.* covers
// dotted continuations but not missing separators.
func TestWildcardAtEnd(t *testing.T) {
	rules := []Pattern{{Expr: "ads.*"}}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		match bool
	}{
		{"ads.com", true},
		{"ads.net", true},
		{"ads.co.uk", true},
		{"ads.", true},
		{"ads", false}, // needs at least the dot after "ads"
	}
	for _, tt := range tests {
		matched, _ := dfa.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) with ads.*: got %v, want %v", tt.input, matched, tt.match)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkMatch(b *testing.B) {
	rules := []Pattern{
		{Expr: "ads.example.com", RuleID: 1},
		{Expr: "tracker.example.com"},
		{Expr: "*.ad.doubleclick.net"},
		{Expr: "malware.example.org"},
		{Expr: "*.analytics.google.com"},
	}
	dfa, err := Compile(rules, CompileOptions{})
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

func BenchmarkMatchLargeAutomaton(b *testing.B) {
	const n = 5000
	rules := make([]Pattern, n)
	for i := range n {
		rules[i] = Pattern{Expr: fmt.Sprintf("host%d.example.com", i), RuleID: uint32(i)}
	}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		b.Fatal(err)
	}

	names := []string{
		"host0.example.com",
		"host2500.example.com",
		"host4999.example.com",
		"nothere.example.com",
		"www.google.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dfa.Match(names[i%len(names)])
	}
}
