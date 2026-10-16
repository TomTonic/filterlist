package benchfixture

import (
	"strings"
	"testing"
)

// TestReadDomainsSkipsHeaderAndBlanks verifies that the query population for
// the runtime comparisons contains exactly the domains of the top-domain
// list, so that no header text or empty line is ever looked up as a query.
//
// This covers the CSV reading of the shared benchmark fixture package.
//
// It feeds a small CSV with a header row and a blank line and asserts the
// domains come back in order without either.
func TestReadDomainsSkipsHeaderAndBlanks(t *testing.T) {
	got, err := readDomains(strings.NewReader("domain\nexample.com\n\n  example.org  \n"))
	if err != nil {
		t.Fatalf("readDomains error: %v", err)
	}
	if want := []string{"example.com", "example.org"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("readDomains = %q, want %q", got, want)
	}
}

// TestReadDomainsRejectsEmptyInput verifies that a comparison cannot silently
// run on an empty query population.
//
// This covers the CSV reading of the shared benchmark fixture package.
//
// It feeds a CSV holding only a header and expects an error.
func TestReadDomainsRejectsEmptyInput(t *testing.T) {
	if _, err := readDomains(strings.NewReader("domain\n")); err == nil {
		t.Fatal("readDomains accepted a list without domains")
	}
}

// TestSequenceIsDeterministicAndInRange verifies that every candidate of a
// runtime comparison, in every process, answers the same queries.
//
// This covers the query sequence of the shared benchmark fixture package.
//
// It draws the same sequence twice, asserts both are equal and every index is
// in range, and asserts invalid arguments are rejected.
func TestSequenceIsDeterministicAndInRange(t *testing.T) {
	a, err := Sequence(1000, 7, 42)
	if err != nil {
		t.Fatalf("Sequence error: %v", err)
	}
	b, _ := Sequence(1000, 7, 42)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("sequences differ at %d: %d != %d", i, a[i], b[i])
		}
		if a[i] >= 7 {
			t.Fatalf("index %d out of range at %d", a[i], i)
		}
	}
	for _, tc := range []struct{ length, count int }{{0, 7}, {10, 0}, {-1, 7}} {
		if _, err := Sequence(tc.length, tc.count, 1); err == nil {
			t.Errorf("Sequence(%d, %d) accepted invalid arguments", tc.length, tc.count)
		}
	}
}

// TestWalkerWrapsAround verifies that a candidate keeps cycling through its
// query sequence across batches instead of running past its end.
//
// This covers the query walker of the shared benchmark fixture package.
//
// It walks three queries five times and asserts the order wraps.
func TestWalkerWrapsAround(t *testing.T) {
	w := NewWalker(Queries([]string{"a", "b", "c"}, []uint32{2, 0, 1}))
	var got []string
	for range 5 {
		got = append(got, w.Next())
	}
	if s := strings.Join(got, ""); s != "cabca" {
		t.Fatalf("walk = %q, want %q", s, "cabca")
	}
}

// TestQueriesFollowSequence verifies that the runtime comparisons look up
// exactly the domains the sequence selects, in its order and repetitions.
//
// This covers the query materialization of the shared benchmark fixture
// package.
//
// It materializes a sequence with a repeated index and compares the result
// with the selected domains.
func TestQueriesFollowSequence(t *testing.T) {
	got := Queries([]string{"one.example", "two.example", "x.org"}, []uint32{1, 2, 1, 0})
	if s := strings.Join(got, ","); s != "two.example,x.org,two.example,one.example" {
		t.Fatalf("Queries = %q", s)
	}
}

// TestReversedPatternLowercasesAndReverses verifies that the reversed DFA
// patterns used by the layout comparisons are the ones the matcher compiles,
// so that the comparisons measure the DFA the plugin really runs.
//
// This covers the pattern conversion of the shared benchmark fixture package.
//
// It converts a mixed-case wildcard pattern and checks the result.
func TestReversedPatternLowercasesAndReverses(t *testing.T) {
	if got := ReversedPattern("Ads*.Example.COM"); got != "moc.elpmaxe.*sda" {
		t.Fatalf("ReversedPattern = %q", got)
	}
}

// TestSequenceLengthHonoursEnvironment verifies that users can choose the
// query sequence length of the runtime comparisons, and that a malformed
// value falls back to the default instead of breaking the run.
//
// This covers the configuration of the shared benchmark fixture package.
//
// It sets the variable to a valid and an invalid value in turn.
func TestSequenceLengthHonoursEnvironment(t *testing.T) {
	t.Setenv(SequenceEnvVar, "1234")
	if got := SequenceLength(); got != 1234 {
		t.Fatalf("SequenceLength = %d, want 1234", got)
	}
	t.Setenv(SequenceEnvVar, "nope")
	if got := SequenceLength(); got != DefaultSequenceLength {
		t.Fatalf("SequenceLength = %d, want default", got)
	}
}

// TestFixturesLoad verifies that the bundled realistic fixtures are present
// and parse, so that a long comparison run does not fail only in its child
// processes.
//
// This covers the file loading of the shared benchmark fixture package.
//
// It loads the deny rules and the top-domain list and checks both are
// non-empty and contain no allow rules.
func TestFixturesLoad(t *testing.T) {
	rules, err := DenylistRules()
	if err != nil {
		t.Fatalf("DenylistRules error: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no deny rules loaded")
	}
	for _, r := range rules {
		if r.IsAllow {
			t.Fatalf("allow rule %q in deny rules", r.Pattern)
		}
	}
	domains, err := TopDomains()
	if err != nil {
		t.Fatalf("TopDomains error: %v", err)
	}
	if len(domains) < 1000 {
		t.Fatalf("only %d domains loaded", len(domains))
	}
}
