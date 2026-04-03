package automaton

import (
	"bytes"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// StateCount and DumpDot
// ---------------------------------------------------------------------------

// TestStateCount verifies that operators can inspect DFA size for diagnostics
// in the automaton package by asserting expected counts for nil, empty, literal,
// and wildcard automatons.
func TestStateCount(t *testing.T) {
	var dfa *DFA
	if dfa.StateCount() != 0 {
		t.Error("nil DFA state count should be 0")
	}

	dfa, err := Compile(nil, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dfa.StateCount() != 0 {
		t.Errorf("empty-patterns DFA state count = %d, want 0", dfa.StateCount())
	}

	// Literal patterns now compile into DFA states like any other pattern
	literalPatterns := []Pattern{{Expr: "a.b"}}
	dfa, err = Compile(literalPatterns, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dfa.StateCount() < 2 {
		t.Errorf("literal pattern DFA should have at least 2 states, got %d", dfa.StateCount())
	}

	// Wildcard pattern compiles into DFA states
	wildcardPatterns := []Pattern{{Expr: "*.b"}}
	dfa, err = Compile(wildcardPatterns, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dfa.StateCount() < 2 {
		t.Errorf("wildcard DFA for '*.b' should have at least 2 states, got %d", dfa.StateCount())
	}
}

// TestDumpDot verifies that users can export a compiled automaton for
// visualization in the automaton package by asserting that DOT output contains
// the expected graph markers.
func TestDumpDot(t *testing.T) {
	// Use a wildcard pattern so it compiles into DFA states for DOT output
	rules := []Pattern{{Expr: "*.b"}}
	dfa, err := Compile(rules, CompileOptions{})
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

// TestDumpDotNil verifies that callers get a direct error instead of invalid
// graph output when exporting a nil automaton in the automaton package by
// asserting that DumpDot fails fast.
func TestDumpDotNil(t *testing.T) {
	var dfa *DFA
	err := dfa.DumpDot(&bytes.Buffer{})
	if err == nil {
		t.Error("expected error for nil DFA")
	}
}
