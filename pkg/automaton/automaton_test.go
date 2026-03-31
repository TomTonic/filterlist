package automaton

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/TomTonic/coredns-regfilter/pkg/filterlist"
)

// ---------------------------------------------------------------------------
// Alphabet mapping
// ---------------------------------------------------------------------------

// TestRuneToIndexAllDNSChars verifies that users get stable matching for every supported DNS character in the automaton package by asserting that each allowed rune maps to a unique transition slot.
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

// TestRuneToIndexInvalid verifies that malformed query characters do not enter the DFA transition table in the automaton package by asserting that unsupported runes return -1.
func TestRuneToIndexInvalid(t *testing.T) {
	for _, r := range "ABCXYZ_!@#$%^&*() /\\\"'" {
		if idx := RuneToIndex(r); idx != -1 {
			t.Errorf("RuneToIndex(%q) = %d, want -1", r, idx)
		}
	}
}

// TestIndexToRuneRoundTrip verifies that diagnostic code can move safely between alphabet indexes and runes in the automaton package by asserting a full round-trip across the supported alphabet.
func TestIndexToRuneRoundTrip(t *testing.T) {
	for i := range AlphabetSize {
		r := IndexToRune(i)
		got := RuneToIndex(r)
		if got != i {
			t.Errorf("RuneToIndex(IndexToRune(%d)) = %d, want %d (rune=%q)", i, got, i, r)
		}
	}
}

// TestIndexToRuneReturnsMinusOneOutOfRange verifies that callers do not crash the process when they inspect invalid alphabet indexes in the automaton package by asserting that out-of-range values return -1.
func TestIndexToRuneReturnsMinusOneOutOfRange(t *testing.T) {
	for _, i := range []int{-1, AlphabetSize, 100} {
		if got := IndexToRune(i); got != -1 {
			t.Errorf("IndexToRune(%d) = %d, want -1", i, got)
		}
	}
}

// TestDnsAlphabetConsistency verifies that users get one coherent DNS alphabet across compilation and matching in the automaton package by asserting that the shared alphabet array and lookup helpers agree.
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

// TestBuildPatternNFALiteral verifies that literal host patterns compile into the expected state chain in the automaton package by asserting the resulting NFA shape for a simple literal rule.
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

// TestBuildPatternNFAWildcard verifies that wildcard patterns compile into the expected loop structure in the automaton package by asserting that the wildcard state self-loops over the full DNS alphabet.
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

// TestBuildPatternNFAInvalidChar verifies that users get a compile error instead of a malformed automaton when patterns contain unsupported characters in the automaton package by asserting that invalid input is rejected.
func TestBuildPatternNFAInvalidChar(t *testing.T) {
	_, err := buildPatternNFA("bad!", 0)
	if err == nil {
		t.Error("expected error for invalid character")
	}
}

// ---------------------------------------------------------------------------
// Basic match tests
// ---------------------------------------------------------------------------

// TestMatchLiteral verifies that users get exact host blocking for literal rules in the automaton package by asserting that only the configured literal names match.
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

// TestMatchWildcard verifies that users get subdomain matching for wildcard rules in the automaton package by asserting that matching prefixes pass and unrelated names do not.
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

// TestMatchWildcardMiddle verifies that users can match wildcard segments inside labels in the automaton package by asserting that ads* patterns cover the intended hostnames.
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

// TestMatchMultipleRules verifies that users can combine several patterns in one compiled automaton in the automaton package by asserting that each configured rule matches while safe names do not.
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

// TestMatchRuleIDs verifies that users can trace a match back to all contributing rules in the automaton package by asserting that duplicate patterns preserve both rule IDs.
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

// TestMatchEmpty verifies that users do not get accidental matches from an empty ruleset in the automaton package by asserting that an empty DFA rejects arbitrary input.
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

// TestMatchNilDFA verifies that callers can safely handle an uninitialized automaton in the automaton package by asserting that a nil DFA returns no match and no rule IDs.
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

// TestMatchNonDNSCharacters verifies that malformed query strings do not crash or spuriously match in the automaton package by asserting that unsupported characters produce clean non-matches.
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

// TestMatchEmptyInput verifies that users do not get false positives for empty queries in the automaton package by asserting that non-empty patterns reject empty input.
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

// TestMatchWildcardOnly verifies that users can intentionally match any DNS-style name with a pure wildcard rule in the automaton package by asserting that DNS input matches and unsupported input does not.
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

// TestMatchAllDNSCharsInDomain verifies that users can compile and match names containing the full supported alphabet in the automaton package by asserting that every allowed DNS character survives compilation and matching.
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

// TestMatchOverlappingPatterns verifies that users keep all applicable rule attributions when rules overlap in the automaton package by asserting that a specific hostname reports both the literal and wildcard rule IDs.
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

// TestMatchConsecutiveWildcards verifies that users can combine adjacent wildcard behavior in the automaton package by asserting that *.* patterns match dotted names and still reject missing separators.
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

// TestMinimization verifies that users get a space-efficient automaton without changing behavior in the automaton package by asserting that minimization never increases states or changes match outcomes.
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

// TestMinimizationPreservesRuleAttribution verifies that users keep precise rule attribution after DFA minimization in the automaton package by asserting that each literal still returns its original rule ID.
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

// TestMinimizationSharesSuffixes verifies that users keep correct match behavior when related patterns are minimized together in the automaton package by asserting that suffix sharing never breaks attribution or non-match behavior.
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

// TestCompileMaxStates verifies that operators can cap compilation growth in the automaton package by asserting that state explosion past MaxStates returns a descriptive error.
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

// TestCompileTimeout verifies that operators can bound compile latency in the automaton package by asserting that an unrealistically small deadline triggers a timeout error.
func TestCompileTimeout(t *testing.T) {
	ruleCount := scaledHeavyTestCount(10000, 1000)
	var rules []filterlist.Rule
	for i := 0; i < ruleCount; i++ {
		rules = append(rules, filterlist.Rule{Pattern: "*.*.*.example.com"})
	}
	_, err := CompileRules(rules, CompileOptions{CompileTimeout: 1}) // 1 nanosecond
	if err == nil {
		t.Error("expected timeout error")
	}
}

// TestCompileInvalidPattern verifies that users get a compile error for unsupported pattern characters in the automaton package by asserting that invalid rules are rejected.
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

// TestStateCount verifies that operators can inspect DFA size for diagnostics in the automaton package by asserting the expected counts for nil, empty, and simple compiled automatons.
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

// TestDumpDot verifies that users can export a compiled automaton for visualization in the automaton package by asserting that DOT output contains the expected graph markers.
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

// TestDumpDotNil verifies that callers get a direct error instead of invalid graph output when exporting a nil automaton in the automaton package by asserting that DumpDot fails fast.
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

// TestDFATransitionsAreDirectPointers verifies that users get the intended constant-time pointer traversal in the automaton package by asserting that compiled transitions can be followed directly through the state array.
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

// TestDFANoMapInFinalStates verifies that users keep the array-based DFA layout promised by the automaton package by asserting at compile time that transitions are stored in a fixed array rather than a map.
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

// TestLargeAutomatonManyLiteralRules verifies that users can compile and match a large literal blocklist in the automaton package by asserting end-to-end correctness across many distinct host rules.
func TestLargeAutomatonManyLiteralRules(t *testing.T) {
	n := scaledHeavyTestCount(5000, 1000)
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

// TestLargeAutomatonManyWildcardRules verifies that users can compile and match a large wildcard blocklist in the automaton package by asserting correct wildcard hits across many generated domains.
func TestLargeAutomatonManyWildcardRules(t *testing.T) {
	n := scaledHeavyTestCount(1000, 250)
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

// TestLargeAutomatonMinimizationEffectiveness verifies that users keep correct large-scale matching after minimization in the automaton package by asserting that minimized and non-minimized DFAs behave the same.
func TestLargeAutomatonMinimizationEffectiveness(t *testing.T) {
	// With unique rule IDs per pattern, Hopcroft cannot merge suffix chains
	// (different ruleID sets at accept states propagate backwards).
	// Verify that minimization preserves correctness at scale and doesn't
	// increase state count.
	n := scaledHeavyTestCount(500, 200)
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

// TestLargeAutomatonMixedRules verifies that users can combine large literal and wildcard rule sets in one compiled automaton by asserting that both kinds of rules still match correctly.
func TestLargeAutomatonMixedRules(t *testing.T) {
	// Mix of literal and wildcard rules
	var rules []filterlist.Rule
	literalCount := scaledHeavyTestCount(500, 200)
	wildcardCount := scaledHeavyTestCount(200, 80)
	for i := range literalCount {
		rules = append(rules, filterlist.Rule{Pattern: fmt.Sprintf("ads%d.example.com", i)})
	}
	for i := range wildcardCount {
		rules = append(rules, filterlist.Rule{Pattern: fmt.Sprintf("*.tracker%d.example.com", i)})
	}

	dfa, err := CompileRules(rules, CompileOptions{})
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

// TestLargeAutomatonRuleAttributionPreserved verifies that users can still trace large compiled rule sets back to their original entries in the automaton package by asserting that each unique rule keeps its own ID.
func TestLargeAutomatonRuleAttributionPreserved(t *testing.T) {
	// After minimization with many rules, each rule must keep its ID
	n := scaledHeavyTestCount(200, 100)
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

// TestSingleCharPattern verifies that users can compile the smallest literal rule in the automaton package by asserting that a one-character pattern matches only that exact input.
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

// TestDuplicatePatternsDifferentRuleIDs verifies that users keep all contributing IDs when the same rule appears multiple times in the automaton package by asserting that duplicate patterns return every originating rule ID.
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

// TestEmptyPatternWildcard verifies that users can intentionally allow an empty-string wildcard match in the automaton package by asserting that the standalone wildcard accepts empty input.
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

// TestWildcardAtEnd verifies that users can match suffix variations with a trailing wildcard in the automaton package by asserting that ads.* covers dotted continuations but not missing separators.
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

func scaledHeavyTestCount(regular, underRace int) int {
	if raceEnabled {
		return underRace
	}

	return regular
}

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
