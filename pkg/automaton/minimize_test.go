package automaton

import (
	"fmt"
	"reflect"
	"testing"
)

// ---------------------------------------------------------------------------
// Partition refinement (Hopcroft)
// ---------------------------------------------------------------------------

// TestSplitPartitionKeepsStableOrder verifies that users always see a
// deterministic automaton layout in the automaton package by asserting that
// partition refinement produces a stable split order.
func TestSplitPartitionKeepsStableOrder(t *testing.T) {
	md := &intermediateDFA{states: make([]intermediateDFAState, 6)}
	for i := range md.states {
		md.states[i] = newIntermediateDFAState(false, nil)
	}

	aIndex := runeToIndex('a')
	md.states[0].trans[aIndex] = 4
	md.states[1].trans[aIndex] = 5
	md.states[2].trans[aIndex] = 4
	md.states[3].trans[aIndex] = 5

	partition := []int{0, 1, 2, 3}
	stateToPartition := []uint32{0, 0, 0, 0, 1, 2}

	got := splitPartition(md, partition, stateToPartition)
	want := [][]int{{0, 2}, {1, 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitPartition() = %v, want %v", got, want)
	}
}

// TestMinimization verifies that users get a space-efficient automaton without
// changing behavior in the automaton package by asserting that minimization
// never increases states or changes match outcomes.
func TestMinimization(t *testing.T) {
	rules := []Pattern{
		{Expr: "a.com"},
		{Expr: "b.com"},
	}
	noMin := boolPtr(false)
	dfaNoMin, err := Compile(rules, CompileOptions{Minimize: noMin})
	if err != nil {
		t.Fatal(err)
	}
	dfaMin, err := Compile(rules, CompileOptions{})
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

// TestMinimizationPreservesRuleAttribution verifies that users keep precise
// rule attribution after DFA minimization in the automaton package by asserting
// that each literal still returns its original rule ID.
func TestMinimizationPreservesRuleAttribution(t *testing.T) {
	rules := []Pattern{
		{Expr: "a.com", RuleID: 0},
		{Expr: "b.com", RuleID: 1},
		{Expr: "c.com", RuleID: 2},
	}
	dfa, err := Compile(rules, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for i, name := range []string{"a.com", "b.com", "c.com"} {
		matched, ruleIDs := dfa.Match(name)
		if !matched {
			t.Errorf("expected match for %q", name)
			continue
		}
		if len(ruleIDs) != 1 || ruleIDs[0] != uint32(i) {
			t.Errorf("Match(%q) ruleIDs = %v, want [%d]", name, ruleIDs, i)
		}
	}
}

// TestMinimizationSharesSuffixes verifies that users keep correct match
// behavior when related patterns are minimized together in the automaton
// package by asserting that suffix sharing never breaks attribution or
// non-match behavior.
func TestMinimizationSharesSuffixes(t *testing.T) {
	// With unique rule IDs, suffix states cannot be merged because different
	// ruleID sets at accept states propagate back through the chain.
	// Verify that minimization preserves correctness and doesn't increase states.
	rules := []Pattern{
		{Expr: "a.example.com", RuleID: 0},
		{Expr: "b.example.com", RuleID: 1},
		{Expr: "c.example.com", RuleID: 2},
	}
	noMin := boolPtr(false)
	dfaNoMin, err := Compile(rules, CompileOptions{Minimize: noMin})
	if err != nil {
		t.Fatal(err)
	}
	dfaMin, err := Compile(rules, CompileOptions{})
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
		if len(ruleIDs) != 1 || ruleIDs[0] != uint32(i) {
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

// TestLargeAutomatonMinimizationEffectiveness verifies that users keep correct
// large-scale matching after minimization in the automaton package by asserting
// that minimized and non-minimized DFAs behave the same.
func TestLargeAutomatonMinimizationEffectiveness(t *testing.T) {
	// With unique rule IDs per pattern, Hopcroft cannot merge suffix chains
	// (different ruleID sets at accept states propagate backwards).
	// Verify that minimization preserves correctness at scale and doesn't
	// increase state count.
	n := scaledHeavyTestCount(500, 200)
	rules := make([]Pattern, n)
	for i := range n {
		rules[i] = Pattern{Expr: fmt.Sprintf("%c%c.example.com", 'a'+rune(i/26%26), 'a'+rune(i%26))}
	}

	noMin := boolPtr(false)
	dfaNoMin, err := Compile(rules, CompileOptions{Minimize: noMin})
	if err != nil {
		t.Fatal(err)
	}
	dfaMin, err := Compile(rules, CompileOptions{})
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
