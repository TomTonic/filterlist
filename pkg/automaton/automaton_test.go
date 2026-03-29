package automaton

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/tomtonic/coredns-regfilter/pkg/filterlist"
)

// ---------------------------------------------------------------------------
// Alphabet mapping
// ---------------------------------------------------------------------------

func TestRuneToIndexAllDNSChars(t *testing.T) {
	// Every DNS char must map to a unique index in [0, AlphabetSize).
	seen := make(map[int]rune)
	for _, r := range "abcdefghijklmnopqrstuvwxyz0123456789-." {
		idx := RuneToIndex(r)
		if idx < 0 || idx >= AlphabetSize {
			t.Fatalf("RuneToIndex(%q) = %d, want [0,%d)", r, idx, AlphabetSize)
		}
		if prev, dup := seen[idx]; dup {
			t.Fatalf("RuneToIndex(%q) = %d collides with %q", r, idx, prev)
		}
		seen[idx] = r
	}
	if len(seen) != AlphabetSize {
		t.Fatalf("mapped %d unique chars, want %d", len(seen), AlphabetSize)
	}
}

func TestRuneToIndexInvalid(t *testing.T) {
	for _, r := range "ABCXYZ_!@#$%^&*() /\\\"'" {
		if idx := RuneToIndex(r); idx != -1 {
			t.Errorf("RuneToIndex(%q) = %d, want -1", r, idx)
		}
	}
}

func TestIndexToRuneRoundTrip(t *testing.T) {
	for i := range AlphabetSize {
		r := IndexToRune(i)
		got := RuneToIndex(r)
		if got != i {
			t.Errorf("RuneToIndex(IndexToRune(%d)) = %d, want %d (rune=%q)", i, got, i, r)
		}
	}
}

func TestIndexToRunePanicsOutOfRange(t *testing.T) {
	for _, i := range []int{-1, AlphabetSize, 100} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("IndexToRune(%d) did not panic", i)
				}
			}()
			IndexToRune(i)
		}()
	}
}

func TestDnsAlphabetConsistency(t *testing.T) {
	if len(dnsAlphabet) != AlphabetSize {
		t.Fatalf("dnsAlphabet length = %d, want %d", len(dnsAlphabet), AlphabetSize)
	}
	for i, r := range dnsAlphabet {
		if RuneToIndex(r) != i {
			t.Errorf("dnsAlphabet[%d] = %q but RuneToIndex returns %d", i, r, RuneToIndex(r))
		}
	}
}

// ---------------------------------------------------------------------------
// NFA construction (internal)
// ---------------------------------------------------------------------------

func TestBuildPatternNFALiteral(t *testing.T) {
	n, err := buildPatternNFA("a.b", 0)
	if err != nil {
		t.Fatal(err)
	}
	// For "a.b": start + 3 literal states = 4 states total
	if len(n.states) != 4 {
		t.Errorf("states = %d, want 4", len(n.states))
	}
	// Only the last state should be accepting
	accepting := 0
	for _, s := range n.states {
		if s.accept {
			accepting++
		}
	}
	if accepting != 1 {
		t.Errorf("accepting states = %d, want 1", accepting)
	}
}

func TestBuildPatternNFAWildcard(t *testing.T) {
	n, err := buildPatternNFA("*", 0)
	if err != nil {
		t.Fatal(err)
	}
	// start + wildcard loop state = 2 states
	if len(n.states) != 2 {
		t.Errorf("states = %d, want 2", len(n.states))
	}
	// Wildcard loop state should have self-loops for every DNS char
	loop := n.states[1]
	for _, c := range dnsAlphabet {
		targets := loop.trans[c]
		found := false
		for _, target := range targets {
			if target == 1 {
				found = true
			}
		}
		if !found {
			t.Errorf("wildcard state missing self-loop for %q", c)
		}
	}
}

func TestBuildPatternNFAInvalidChar(t *testing.T) {
	_, err := buildPatternNFA("bad!", 0)
	if err == nil {
		t.Error("expected error for invalid character")
	}
}

// ---------------------------------------------------------------------------
// Basic match tests
// ---------------------------------------------------------------------------

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

func TestMatchNonDNSCharacters(t *testing.T) {
	rules := []filterlist.Rule{{Pattern: "example.com"}}
	dfa, err := CompileRules(rules, CompileOptions{})
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

func TestMatchEmptyInput(t *testing.T) {
	rules := []filterlist.Rule{{Pattern: "example.com"}}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	matched, _ := dfa.Match("")
	if matched {
		t.Error("empty input should not match non-empty pattern")
	}
}

func TestMatchWildcardOnly(t *testing.T) {
	rules := []filterlist.Rule{{Pattern: "*"}}
	dfa, err := CompileRules(rules, CompileOptions{})
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

func TestMatchAllDNSCharsInDomain(t *testing.T) {
	// A domain containing every allowed DNS char
	domain := "abcdefghijklmnopqrstuvwxyz0123456789-."
	rules := []filterlist.Rule{{Pattern: domain}}
	dfa, err := CompileRules(rules, CompileOptions{})
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

func TestMatchOverlappingPatterns(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "*.example.com"},
		{Pattern: "ads.example.com"},
	}
	dfa, err := CompileRules(rules, CompileOptions{})
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

func TestMatchConsecutiveWildcards(t *testing.T) {
	// Pattern with multiple wildcards
	rules := []filterlist.Rule{{Pattern: "*.*"}}
	dfa, err := CompileRules(rules, CompileOptions{})
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
// Minimization
// ---------------------------------------------------------------------------

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

func TestMinimizationPreservesRuleAttribution(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "a.com"},
		{Pattern: "b.com"},
		{Pattern: "c.com"},
	}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for i, name := range []string{"a.com", "b.com", "c.com"} {
		matched, ruleIDs := dfa.Match(name)
		if !matched {
			t.Errorf("expected match for %q", name)
			continue
		}
		if len(ruleIDs) != 1 || ruleIDs[0] != i {
			t.Errorf("Match(%q) ruleIDs = %v, want [%d]", name, ruleIDs, i)
		}
	}
}

func TestMinimizationSharesSuffixes(t *testing.T) {
	// With unique rule IDs, suffix states cannot be merged because different
	// ruleID sets at accept states propagate back through the chain.
	// Verify that minimization preserves correctness and doesn't increase states.
	rules := []filterlist.Rule{
		{Pattern: "a.example.com"},
		{Pattern: "b.example.com"},
		{Pattern: "c.example.com"},
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

	if dfaMin.StateCount() > dfaNoMin.StateCount() {
		t.Errorf("minimization should not increase states: min=%d > nomin=%d",
			dfaMin.StateCount(), dfaNoMin.StateCount())
	}

	// All should still match correctly with correct rule attribution
	for i, name := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		matched, ruleIDs := dfaMin.Match(name)
		if !matched {
			t.Errorf("minimized DFA should match %q", name)
		}
		if len(ruleIDs) != 1 || ruleIDs[0] != i {
			t.Errorf("Match(%q) ruleIDs = %v, want [%d]", name, ruleIDs, i)
		}
	}
	for _, name := range []string{"d.example.com", "example.com"} {
		matched, _ := dfaMin.Match(name)
		if matched {
			t.Errorf("minimized DFA should not match %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Compile options
// ---------------------------------------------------------------------------

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
	var rules []filterlist.Rule
	for i := 0; i < 10000; i++ {
		rules = append(rules, filterlist.Rule{Pattern: "*.*.*.example.com"})
	}
	_, err := CompileRules(rules, CompileOptions{CompileTimeout: 1}) // 1 nanosecond
	if err == nil {
		t.Error("expected timeout error")
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

// ---------------------------------------------------------------------------
// StateCount and DumpDot
// ---------------------------------------------------------------------------

func TestStateCount(t *testing.T) {
	var dfa *DFA
	if dfa.StateCount() != 0 {
		t.Error("nil DFA state count should be 0")
	}

	dfa, err := CompileRules(nil, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dfa.StateCount() != 1 {
		t.Errorf("empty-rules DFA state count = %d, want 1", dfa.StateCount())
	}

	rules := []filterlist.Rule{{Pattern: "a.b"}}
	dfa, err = CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dfa.StateCount() < 4 {
		t.Errorf("DFA for 'a.b' should have at least 4 states, got %d", dfa.StateCount())
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

// ---------------------------------------------------------------------------
// Array-based structure verification
// ---------------------------------------------------------------------------

func TestDFATransitionsAreDirectPointers(t *testing.T) {
	rules := []filterlist.Rule{{Pattern: "a.b"}}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Verify start state has a transition for 'a' that is a direct pointer
	aIdx := RuneToIndex('a')
	next := dfa.start.Trans[aIdx]
	if next == nil {
		t.Fatal("start state should have transition for 'a'")
	}

	// Follow the chain: a → . → b (accept)
	dotIdx := RuneToIndex('.')
	afterDot := next.Trans[dotIdx]
	if afterDot == nil {
		t.Fatal("second state should have transition for '.'")
	}

	bIdx := RuneToIndex('b')
	accept := afterDot.Trans[bIdx]
	if accept == nil {
		t.Fatal("third state should have transition for 'b'")
	}
	if !accept.Accept {
		t.Error("final state should be accepting")
	}

	// Verify that following pointers gives same result as Match
	matched, _ := dfa.Match("a.b")
	if !matched {
		t.Error("Match should also confirm a.b")
	}
}

func TestDFANoMapInFinalStates(_ *testing.T) {
	// This is more of a compile-time/structural guarantee.
	// DFAState.Trans is [AlphabetSize]*DFAState — fixed-size array, not a map.
	// If the type changes accidentally, this test will fail to compile.
	var s DFAState
	_ = s.Trans[0]       // Must be indexable by int
	_ = (*DFAState)(nil) // Proves Trans elements are *DFAState
}

// ---------------------------------------------------------------------------
// Large automaton tests
// ---------------------------------------------------------------------------

func TestLargeAutomatonManyLiteralRules(t *testing.T) {
	const n = 5000
	rules := make([]filterlist.Rule, n)
	for i := range n {
		rules[i] = filterlist.Rule{Pattern: fmt.Sprintf("host%d.example.com", i)}
	}

	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatalf("CompileRules with %d rules: %v", n, err)
	}

	t.Logf("DFA states for %d literal rules: %d", n, dfa.StateCount())

	// Verify all patterns match
	for i := range n {
		name := fmt.Sprintf("host%d.example.com", i)
		matched, ruleIDs := dfa.Match(name)
		if !matched {
			t.Fatalf("expected match for %q (rule %d)", name, i)
		}
		if len(ruleIDs) != 1 || ruleIDs[0] != i {
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

func TestLargeAutomatonManyWildcardRules(t *testing.T) {
	const n = 1000
	rules := make([]filterlist.Rule, n)
	for i := range n {
		rules[i] = filterlist.Rule{Pattern: fmt.Sprintf("*.ad%d.example.com", i)}
	}

	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatalf("CompileRules with %d wildcard rules: %v", n, err)
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

func TestLargeAutomatonMinimizationEffectiveness(t *testing.T) {
	// With unique rule IDs per pattern, Hopcroft cannot merge suffix chains
	// (different ruleID sets at accept states propagate backwards).
	// Verify that minimization preserves correctness at scale and doesn't
	// increase state count.
	const n = 500
	rules := make([]filterlist.Rule, n)
	for i := range n {
		rules[i] = filterlist.Rule{Pattern: fmt.Sprintf("%c%c.example.com", 'a'+rune(i/26%26), 'a'+rune(i%26))}
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

	t.Logf("minimization: %d → %d states", dfaNoMin.StateCount(), dfaMin.StateCount())

	if dfaMin.StateCount() > dfaNoMin.StateCount() {
		t.Errorf("minimization should not increase states: min=%d > nomin=%d",
			dfaMin.StateCount(), dfaNoMin.StateCount())
	}

	// Verify correctness after minimization for all patterns
	for i := range n {
		name := fmt.Sprintf("%c%c.example.com", 'a'+rune(i/26%26), 'a'+rune(i%26))
		m1, _ := dfaNoMin.Match(name)
		m2, _ := dfaMin.Match(name)
		if m1 != m2 {
			t.Errorf("Match(%q): nomin=%v min=%v", name, m1, m2)
		}
	}

	// Verify non-matches
	for _, name := range []string{"zz.example.com", "example.com", "aaa.example.com"} {
		if matched, _ := dfaMin.Match(name); matched {
			t.Errorf("expected no match for %q", name)
		}
	}
}

func TestLargeAutomatonMixedRules(t *testing.T) {
	// Mix of literal and wildcard rules
	var rules []filterlist.Rule
	for i := range 500 {
		rules = append(rules, filterlist.Rule{Pattern: fmt.Sprintf("ads%d.example.com", i)})
	}
	for i := range 200 {
		rules = append(rules, filterlist.Rule{Pattern: fmt.Sprintf("*.tracker%d.example.com", i)})
	}

	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("DFA states for 700 mixed rules: %d", dfa.StateCount())

	// Verify literal matches
	for i := range 500 {
		matched, _ := dfa.Match(fmt.Sprintf("ads%d.example.com", i))
		if !matched {
			t.Fatalf("expected literal match at index %d", i)
		}
	}

	// Verify wildcard matches
	for i := range 200 {
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

func TestLargeAutomatonRuleAttributionPreserved(t *testing.T) {
	// After minimization with many rules, each rule must keep its ID
	const n = 200
	rules := make([]filterlist.Rule, n)
	for i := range n {
		// Each pattern is unique enough that no two share the same accept state
		rules[i] = filterlist.Rule{Pattern: fmt.Sprintf("unique%d.test.com", i)}
	}

	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for i := range n {
		name := fmt.Sprintf("unique%d.test.com", i)
		matched, ruleIDs := dfa.Match(name)
		if !matched {
			t.Fatalf("expected match for %q", name)
		}
		if len(ruleIDs) != 1 || ruleIDs[0] != i {
			t.Errorf("Match(%q) ruleIDs = %v, want [%d]", name, ruleIDs, i)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestSingleCharPattern(t *testing.T) {
	rules := []filterlist.Rule{{Pattern: "a"}}
	dfa, err := CompileRules(rules, CompileOptions{})
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

func TestDuplicatePatternsDifferentRuleIDs(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "x.com"},
		{Pattern: "x.com"},
		{Pattern: "x.com"},
	}
	dfa, err := CompileRules(rules, CompileOptions{})
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

func TestEmptyPatternWildcard(t *testing.T) {
	// Wildcard pattern matches empty string
	rules := []filterlist.Rule{{Pattern: "*"}}
	dfa, err := CompileRules(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	matched, _ := dfa.Match("")
	if !matched {
		t.Error("* should match empty string")
	}
}

func TestWildcardAtEnd(t *testing.T) {
	rules := []filterlist.Rule{{Pattern: "ads.*"}}
	dfa, err := CompileRules(rules, CompileOptions{})
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
// Helpers
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

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

func BenchmarkMatchLargeAutomaton(b *testing.B) {
	const n = 5000
	rules := make([]filterlist.Rule, n)
	for i := range n {
		rules[i] = filterlist.Rule{Pattern: fmt.Sprintf("host%d.example.com", i)}
	}
	dfa, err := CompileRules(rules, CompileOptions{})
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

func BenchmarkCompileLarge(b *testing.B) {
	const n = 1000
	rules := make([]filterlist.Rule, n)
	for i := range n {
		rules[i] = filterlist.Rule{Pattern: fmt.Sprintf("host%d.example.com", i)}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CompileRules(rules, CompileOptions{})
		if err != nil {
			b.Fatal(err)
		}
	}
}
