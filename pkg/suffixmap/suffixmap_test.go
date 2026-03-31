package suffixmap

import (
	"fmt"
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// TestNewNilMap verifies that callers can safely create a SuffixMap from a nil
// input in the suffixmap package by asserting that the result is valid and
// never matches.
func TestNewNilMap(t *testing.T) {
	sm := New(nil)
	if sm == nil {
		t.Fatal("New(nil) should return non-nil SuffixMap")
	}
	if sm.Len() != 0 {
		t.Errorf("Len() = %d, want 0", sm.Len())
	}
	matched, ids := sm.Match("example.com")
	if matched {
		t.Error("nil-map SuffixMap should not match")
	}
	if ids != nil {
		t.Errorf("expected nil ruleIDs, got %v", ids)
	}
}

// TestNewEmptyMap verifies that an empty entries map produces a valid SuffixMap
// in the suffixmap package by asserting that it never matches any query.
func TestNewEmptyMap(t *testing.T) {
	sm := New(map[string][]uint32{})
	if sm.Len() != 0 {
		t.Errorf("Len() = %d, want 0", sm.Len())
	}
	matched, _ := sm.Match("anything.com")
	if matched {
		t.Error("empty SuffixMap should not match")
	}
}

// TestLen verifies that Len reports the correct number of stored patterns
// in the suffixmap package by asserting the count for various map sizes.
func TestLen(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string][]uint32
		want    int
	}{
		{"nil", nil, 0},
		{"empty", map[string][]uint32{}, 0},
		{"one", map[string][]uint32{"a.com": {0}}, 1},
		{"three", map[string][]uint32{"a.com": {0}, "b.com": {1}, "c.com": {2}}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := New(tt.entries)
			if got := sm.Len(); got != tt.want {
				t.Errorf("Len() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestLenNilReceiver verifies that Len is safe to call on a nil SuffixMap
// in the suffixmap package by asserting that it returns 0.
func TestLenNilReceiver(t *testing.T) {
	var sm *SuffixMap
	if sm.Len() != 0 {
		t.Error("nil receiver Len() should be 0")
	}
}

// ---------------------------------------------------------------------------
// Exact matching (domain equals pattern)
// ---------------------------------------------------------------------------

// TestMatchExact verifies that users get exact domain blocking when the query
// matches a stored pattern exactly in the suffixmap package by asserting that
// only the matching domain returns true.
func TestMatchExact(t *testing.T) {
	sm := New(map[string][]uint32{
		"ads.example.com":     {0},
		"tracker.example.com": {1},
	})

	tests := []struct {
		input string
		match bool
	}{
		{"ads.example.com", true},
		{"tracker.example.com", true},
		{"safe.example.com", false},
		{"example.com", false},
		{"com", false},
	}
	for _, tt := range tests {
		matched, _ := sm.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, matched, tt.match)
		}
	}
}

// ---------------------------------------------------------------------------
// Suffix (subdomain) matching – the core ||domain^ semantics
// ---------------------------------------------------------------------------

// TestMatchSubdomain verifies that a stored pattern blocks all its subdomains
// in the suffixmap package by asserting that subdomain queries match and
// that non-subdomain queries do not.
func TestMatchSubdomain(t *testing.T) {
	sm := New(map[string][]uint32{
		"example.com": {0},
	})

	tests := []struct {
		input string
		match bool
		desc  string
	}{
		{"example.com", true, "exact match"},
		{"ads.example.com", true, "one level subdomain"},
		{"www.ads.example.com", true, "two level subdomain"},
		{"a.b.c.d.example.com", true, "deep subdomain"},

		{"notexample.com", false, "different domain sharing suffix string"},
		{"myexample.com", false, "prefix-extended domain"},
		{"example.com.evil.org", false, "domain used as subdomain of another"},
		{"example.co", false, "truncated TLD"},
		{"example.comm", false, "extended TLD"},
		{"com", false, "only TLD"},
		{"", false, "empty input"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			matched, _ := sm.Match(tt.input)
			if matched != tt.match {
				t.Errorf("Match(%q) = %v, want %v", tt.input, matched, tt.match)
			}
		})
	}
}

// TestMatchSubdomainMultiplePatterns verifies that users get subdomain blocking
// for each stored pattern independently in the suffixmap package by asserting
// that each pattern's subdomains match while unrelated domains do not.
func TestMatchSubdomainMultiplePatterns(t *testing.T) {
	sm := New(map[string][]uint32{
		"ads.example.com":     {0},
		"tracker.example.com": {1},
	})

	tests := []struct {
		input string
		match bool
	}{
		{"ads.example.com", true},
		{"sub.ads.example.com", true},
		{"tracker.example.com", true},
		{"sub.tracker.example.com", true},
		{"example.com", false},
		{"safe.example.com", false},
	}
	for _, tt := range tests {
		matched, _ := sm.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, matched, tt.match)
		}
	}
}

// TestMatchParentAndChild verifies overlapping parent/child pattern behavior
// in the suffixmap package by asserting that both the parent and more specific
// child pattern produce rule IDs when a deep subdomain matches both.
func TestMatchParentAndChild(t *testing.T) {
	sm := New(map[string][]uint32{
		"example.com":     {0},
		"ads.example.com": {1},
	})

	// A deep subdomain matches both the parent and the child pattern.
	matched, ids := sm.Match("sub.ads.example.com")
	if !matched {
		t.Fatal("expected match for sub.ads.example.com")
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) != 2 || ids[0] != 0 || ids[1] != 1 {
		t.Errorf("expected ruleIDs [0, 1], got %v", ids)
	}

	// Direct match on child only returns the child's rule ID and the
	// parent's rule ID (because ads.example.com is a subdomain of example.com).
	matched, ids = sm.Match("ads.example.com")
	if !matched {
		t.Fatal("expected match for ads.example.com")
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) != 2 || ids[0] != 0 || ids[1] != 1 {
		t.Errorf("expected ruleIDs [0, 1], got %v", ids)
	}

	// The parent domain itself matches only its own pattern.
	matched, ids = sm.Match("example.com")
	if !matched {
		t.Fatal("expected match for example.com")
	}
	if len(ids) != 1 || ids[0] != 0 {
		t.Errorf("expected ruleIDs [0], got %v", ids)
	}
}

// ---------------------------------------------------------------------------
// Rule ID attribution
// ---------------------------------------------------------------------------

// TestMatchRuleIDs verifies that matching returns the correct rule IDs
// in the suffixmap package by asserting correct attribution for
// single and duplicate patterns.
func TestMatchRuleIDs(t *testing.T) {
	sm := New(map[string][]uint32{
		"ads.example.com": {0, 5}, // two rules produce the same pattern
		"tracker.net":     {2},
	})

	matched, ids := sm.Match("ads.example.com")
	if !matched {
		t.Fatal("expected match")
	}
	if len(ids) != 2 || ids[0] != 0 || ids[1] != 5 {
		t.Errorf("expected ruleIDs [0, 5], got %v", ids)
	}

	matched, ids = sm.Match("sub.tracker.net")
	if !matched {
		t.Fatal("expected match for subdomain of tracker.net")
	}
	if len(ids) != 1 || ids[0] != 2 {
		t.Errorf("expected ruleIDs [2], got %v", ids)
	}
}

// ---------------------------------------------------------------------------
// Nil receiver safety
// ---------------------------------------------------------------------------

// TestMatchNilReceiver verifies that Match is safe to call on a nil SuffixMap
// in the suffixmap package by asserting it returns no match and nil IDs.
func TestMatchNilReceiver(t *testing.T) {
	var sm *SuffixMap
	matched, ids := sm.Match("example.com")
	if matched {
		t.Error("nil receiver should not match")
	}
	if ids != nil {
		t.Error("nil receiver should return nil ruleIDs")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

// TestMatchSingleLabel verifies that single-label domains work correctly
// in the suffixmap package by asserting that a TLD-like pattern matches
// itself and its subdomains.
func TestMatchSingleLabel(t *testing.T) {
	sm := New(map[string][]uint32{
		"com": {0},
	})

	tests := []struct {
		input string
		match bool
	}{
		{"com", true},
		{"example.com", true},
		{"sub.example.com", true},
		{"org", false},
		{"", false},
	}
	for _, tt := range tests {
		matched, _ := sm.Match(tt.input)
		if matched != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, matched, tt.match)
		}
	}
}

// TestMatchEmptyInput verifies that empty queries never match in the suffixmap
// package by asserting that even a "catch-all" TLD pattern rejects empty input.
func TestMatchEmptyInput(t *testing.T) {
	sm := New(map[string][]uint32{
		"com": {0},
	})
	matched, _ := sm.Match("")
	if matched {
		t.Error("empty input should not match")
	}
}

// TestMatchTrailingDot verifies that trailing-dot queries are handled
// correctly in the suffixmap package by asserting the expected match behavior.
func TestMatchTrailingDot(t *testing.T) {
	// Our patterns do not have trailing dots. A query with a trailing dot
	// should not match because the suffix walk will find "example.com."
	// which is not in the map. This is fine — callers are expected to
	// normalize the query before calling Match.
	sm := New(map[string][]uint32{
		"example.com": {0},
	})
	matched, _ := sm.Match("example.com.")
	if matched {
		t.Error("trailing-dot query should not match (callers must normalize)")
	}
}

// TestMatchLargeMap verifies that suffix lookup works correctly with many
// entries in the suffixmap package by asserting correct matching across
// thousands of unique patterns.
func TestMatchLargeMap(t *testing.T) {
	entries := make(map[string][]uint32, 5000)
	for i := range 5000 {
		entries[fmt.Sprintf("host%d.example.com", i)] = []uint32{uint32(i)}
	}
	sm := New(entries)

	for i := range 5000 {
		name := fmt.Sprintf("host%d.example.com", i)
		matched, ids := sm.Match(name)
		if !matched {
			t.Fatalf("expected match for %q", name)
		}
		if len(ids) != 1 || ids[0] != uint32(i) {
			t.Errorf("Match(%q) ruleIDs = %v, want [%d]", name, ids, i)
		}

		// Subdomain should also match
		subName := fmt.Sprintf("sub.host%d.example.com", i)
		matched, ids = sm.Match(subName)
		if !matched {
			t.Fatalf("expected subdomain match for %q", subName)
		}
		if len(ids) != 1 || ids[0] != uint32(i) {
			t.Errorf("Match(%q) ruleIDs = %v, want [%d]", subName, ids, i)
		}
	}

	// Non-existent
	matched, _ := sm.Match("nothere.example.com")
	if matched {
		t.Error("expected no match for non-existent pattern")
	}
}

// TestMatchNoFalsePositiveFromPartialLabel verifies that suffix lookup only
// matches at label boundaries in the suffixmap package by asserting that
// "ample.com" does not match when "example.com" is stored.
func TestMatchNoFalsePositiveFromPartialLabel(t *testing.T) {
	sm := New(map[string][]uint32{
		"example.com": {0},
	})

	// "badexample.com" must NOT match — "example.com" is not a suffix at
	// a label boundary.
	shouldNotMatch := []string{
		"badexample.com",
		"xexample.com",
		"1example.com",
		"-example.com",
	}
	for _, input := range shouldNotMatch {
		matched, _ := sm.Match(input)
		if matched {
			t.Errorf("Match(%q) = true, want false (partial label match)", input)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

// BenchmarkMatch measures suffix lookup performance for realistic domain
// queries against a moderately sized pattern set.
func BenchmarkMatch(b *testing.B) {
	entries := make(map[string][]uint32, 1000)
	for i := range 1000 {
		entries[fmt.Sprintf("host%d.example.com", i)] = []uint32{uint32(i)}
	}
	sm := New(entries)

	queries := []string{
		"host500.example.com",     // exact match
		"sub.host500.example.com", // subdomain match (one extra label)
		"a.b.host500.example.com", // subdomain match (two extra labels)
		"nothere.example.com",     // miss
		"host500.other.com",       // miss (wrong parent)
	}

	b.ResetTimer()
	for i := range b.N {
		q := queries[i%len(queries)]
		sm.Match(q)
	}
}
