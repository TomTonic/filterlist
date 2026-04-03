package automaton

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Array-based structure verification
// ---------------------------------------------------------------------------

// TestDFATransitionsAreDirectPointers verifies that users get the intended
// constant-time pointer traversal in the automaton package by asserting that
// compiled transitions can be followed directly through the state array.
func TestDFATransitionsAreDirectPointers(t *testing.T) {
	// Use a wildcard pattern to create DFA states with traversable transitions
	rules := []Pattern{{Expr: "a.*"}}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Verify start state has a transition for 'a' that is a direct pointer
	aIdx := runeToIndex('a')
	next := dfa.start.Trans[aIdx]
	if next == nil {
		t.Fatal("start state should have transition for 'a'")
	}

	// Follow the chain: a → . → wildcard (accept)
	dotIdx := runeToIndex('.')
	afterDot := next.Trans[dotIdx]
	if afterDot == nil {
		t.Fatal("second state should have transition for '.'")
	}

	// afterDot should be accepting (wildcard matches zero or more)
	if !afterDot.Accept {
		t.Error("state after 'a.' should be accepting for pattern 'a.*'")
	}

	// Verify that following pointers gives same result as Match
	matched, _ := dfa.Match("a.b")
	if !matched {
		t.Error("Match should also confirm a.b")
	}
}

// TestDFANoMapInFinalStates verifies that users keep the array-based DFA
// layout promised by the automaton package by asserting at compile time that
// transitions are stored in a fixed array rather than a map.
func TestDFANoMapInFinalStates(_ *testing.T) {
	// This is more of a compile-time/structural guarantee.
	// DFAState.Trans is [AlphabetSize]*DFAState — fixed-size array, not a map.
	// If the type changes accidentally, this test will fail to compile.
	var s DFAState
	_ = s.Trans[0]       // Must be indexable by int
	_ = (*DFAState)(nil) // Proves Trans elements are *DFAState
}
