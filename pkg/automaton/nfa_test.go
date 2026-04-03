package automaton

import (
	"testing"
	"unsafe"
)

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
		if s.isAccept() {
			accepting++
		}
	}
	if accepting != 1 {
		t.Errorf("accepting states = %d, want 1", accepting)
	}
}

// TestBuildPatternNFAWildcard verifies that wildcard patterns compile into an efficient DNS-class loop in the automaton package by asserting that the wildcard state uses the dedicated anyDNS path instead of materializing 38 explicit rune transitions.
func TestBuildPatternNFAWildcard(t *testing.T) {
	n, err := buildPatternNFA("*", 0)
	if err != nil {
		t.Fatal(err)
	}
	// start + wildcard loop state = 2 states
	if len(n.states) != 2 {
		t.Errorf("states = %d, want 2", len(n.states))
	}
	// Wildcard loop state should use the compact DNS-class loop.
	loop := n.states[1]
	if !loop.hasAnyDNSTransition() || loop.anyDNSTo != 1 {
		t.Fatalf("wildcard anyDNS target = (%v, %d), want (true, 1)", loop.hasAnyDNSTransition(), loop.anyDNSTo)
	}
	if loop.hasLiteralTransition() {
		t.Fatalf("wildcard literal transition unexpectedly present: index %d -> %d", loop.literalIndex, loop.literalTo)
	}
	if eps := n.states[0].epsilon; len(eps) != 1 || eps[0] != 1 {
		t.Fatalf("start epsilon transitions = %v, want [1]", eps)
	}
}

// TestNFAStateFitsOneCacheLineOn64Bit verifies that automaton compilation keeps
// its per-state transition metadata dense enough for cache-friendly scans on
// mainstream 64-bit deployments.
//
// This test covers the internal Thompson NFA state layout.
//
// It asserts that nfaState stays within one 64-byte cache line on 64-bit
// platforms after packing flags and transition metadata.
func TestNFAStateFitsOneCacheLineOn64Bit(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("cache-line size assertion is only relevant for 64-bit layouts")
	}

	if size := unsafe.Sizeof(nfaState{}); size > 64 {
		t.Fatalf("unsafe.Sizeof(nfaState{}) = %d, want <= 64", size)
	}
}

// TestBuildPatternNFAInvalidChar verifies that users get a compile error instead of a malformed automaton when patterns contain unsupported characters in the automaton package by asserting that invalid input is rejected.
func TestBuildPatternNFAInvalidChar(t *testing.T) {
	_, err := buildPatternNFA("bad!", 0)
	if err == nil {
		t.Error("expected error for invalid character")
	}
}

// TestCombineNFAsAddsStartEpsilonFanOut verifies that users can compile many
// independent rules into one automaton in the automaton package without losing
// any pattern entry points.
//
// This test covers the NFA merge step before subset construction.
//
// It asserts that the combined start state fans out via epsilon transitions to
// each sub-NFA start state.
func TestCombineNFAsAddsStartEpsilonFanOut(t *testing.T) {
	first, err := buildPatternNFA("a", 1)
	if err != nil {
		t.Fatalf("buildPatternNFA(first): %v", err)
	}
	second, err := buildPatternNFA("b", 2)
	if err != nil {
		t.Fatalf("buildPatternNFA(second): %v", err)
	}

	combined, err := combineNFAs([]*nfa{first, second})
	if err != nil {
		t.Fatalf("combineNFAs: %v", err)
	}
	eps := combined.states[combined.start].epsilon
	if len(eps) != 2 {
		t.Fatalf("combined start epsilon fan-out = %v, want 2 entries", eps)
	}
}
