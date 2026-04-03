package automaton

import (
	"slices"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// closureArena
// ---------------------------------------------------------------------------

// TestClosureArenaCloneRefAndDeref verifies that the bump allocator used
// during subset construction correctly stores and retrieves NFA-state closures
// in the automaton package.
//
// It covers the happy path (small slices carved from a shared block) and the
// oversized-slice fallback (dedicated block allocation).
func TestClosureArenaCloneRefAndDeref(t *testing.T) {
	var a closureArena

	t.Run("empty slice returns zero ref", func(t *testing.T) {
		ref := a.cloneRef(nil)
		if ref.length != 0 {
			t.Fatalf("cloneRef(nil).length = %d, want 0", ref.length)
		}
		got := a.deref(ref)
		if got != nil {
			t.Fatalf("deref(zero ref) = %v, want nil", got)
		}
	})

	t.Run("small slices share a block", func(t *testing.T) {
		src1 := []uint32{10, 20, 30}
		src2 := []uint32{40, 50}
		ref1 := a.cloneRef(src1)
		ref2 := a.cloneRef(src2)

		got1 := a.deref(ref1)
		got2 := a.deref(ref2)
		if !slices.Equal(got1, src1) {
			t.Fatalf("deref(ref1) = %v, want %v", got1, src1)
		}
		if !slices.Equal(got2, src2) {
			t.Fatalf("deref(ref2) = %v, want %v", got2, src2)
		}
		// Both should be in the same arena block.
		if ref1.blockIdx != ref2.blockIdx {
			t.Fatalf("expected same blockIdx, got %d and %d", ref1.blockIdx, ref2.blockIdx)
		}
	})

	t.Run("oversized slice gets dedicated block", func(t *testing.T) {
		big := make([]uint32, closureArenaBlockSize+1)
		for i := range big {
			big[i] = uint32(i) //nolint:gosec // test data
		}
		ref := a.cloneRef(big)
		got := a.deref(ref)
		if !slices.Equal(got, big) {
			t.Fatal("deref(oversized ref) does not match source")
		}
	})

	t.Run("clone is independent of source", func(t *testing.T) {
		src := []uint32{1, 2, 3}
		ref := a.cloneRef(src)
		src[0] = 999
		got := a.deref(ref)
		if got[0] == 999 {
			t.Fatal("arena data should not alias source slice")
		}
	})
}

// TestClosureArenaBlockRollover verifies that the arena allocates a new block
// when the current one is exhausted, keeping previously stored data intact.
func TestClosureArenaBlockRollover(t *testing.T) {
	var a closureArena
	// Fill first block almost completely.
	filler := make([]uint32, closureArenaBlockSize-2)
	ref1 := a.cloneRef(filler)
	// Next allocation exceeds remaining space → triggers new block.
	src := []uint32{42, 43, 44}
	ref2 := a.cloneRef(src)

	if ref1.blockIdx == ref2.blockIdx {
		t.Fatalf("expected different blocks after rollover, both in block %d", ref1.blockIdx)
	}
	got := a.deref(ref2)
	if !slices.Equal(got, src) {
		t.Fatalf("deref after rollover = %v, want %v", got, src)
	}
}

// ---------------------------------------------------------------------------
// stateSetMap
// ---------------------------------------------------------------------------

// TestStateSetMapInsertAndLookup verifies that the two-tier hash map used to
// deduplicate DFA state closures in the automaton package correctly stores and
// retrieves entries, including collision-promoted overflow entries.
func TestStateSetMapInsertAndLookup(t *testing.T) {
	var arena closureArena
	sm := newStateSetMap(16, &arena)

	// Insert a first entry.
	c1 := []uint32{1, 2, 3}
	h1 := closureHash(c1)
	ref1 := arena.cloneRef(c1)
	sm.insert(h1, ref1, 0)

	// Lookup should find it.
	id, ok := sm.lookup(h1, c1)
	if !ok || id != 0 {
		t.Fatalf("lookup(c1) = (%d, %v), want (0, true)", id, ok)
	}

	// A different closure with a different hash should not be found.
	c2 := []uint32{4, 5}
	h2 := closureHash(c2)
	_, ok = sm.lookup(h2, c2)
	if ok {
		t.Fatal("lookup(c2) should not succeed before insert")
	}

	// Insert c2 and verify.
	ref2 := arena.cloneRef(c2)
	sm.insert(h2, ref2, 1)
	id, ok = sm.lookup(h2, c2)
	if !ok || id != 1 {
		t.Fatalf("lookup(c2) = (%d, %v), want (1, true)", id, ok)
	}
}

// TestStateSetMapCollisionPromotion verifies that when two distinct closures
// produce the same hash, both are correctly promoted to the overflow map and
// remain retrievable.
func TestStateSetMapCollisionPromotion(t *testing.T) {
	var arena closureArena
	sm := newStateSetMap(8, &arena)

	// Force a collision by using the same hash for two different closures.
	fakeHash := uint64(12345)
	c1 := []uint32{10, 20}
	c2 := []uint32{30, 40}

	ref1 := arena.cloneRef(c1)
	ref2 := arena.cloneRef(c2)

	sm.insert(fakeHash, ref1, 0)
	sm.insert(fakeHash, ref2, 1)

	// Both should be retrievable via overflow.
	id, ok := sm.lookup(fakeHash, c1)
	if !ok || id != 0 {
		t.Fatalf("lookup(c1 via overflow) = (%d, %v), want (0, true)", id, ok)
	}
	id, ok = sm.lookup(fakeHash, c2)
	if !ok || id != 1 {
		t.Fatalf("lookup(c2 via overflow) = (%d, %v), want (1, true)", id, ok)
	}

	// A third closure with the same hash should also be inserted into overflow.
	c3 := []uint32{50, 60}
	ref3 := arena.cloneRef(c3)
	sm.insert(fakeHash, ref3, 2)

	id, ok = sm.lookup(fakeHash, c3)
	if !ok || id != 2 {
		t.Fatalf("lookup(c3 via overflow) = (%d, %v), want (2, true)", id, ok)
	}

	// An unknown closure with the same hash should not match.
	cUnknown := []uint32{70, 80}
	_, ok = sm.lookup(fakeHash, cUnknown)
	if ok {
		t.Fatal("lookup for unknown closure with colliding hash should return false")
	}
}

// TestStateSetMapPrimaryMismatch verifies that lookup returns false when the
// primary entry exists but holds a different closure (no overflow yet).
func TestStateSetMapPrimaryMismatch(t *testing.T) {
	var arena closureArena
	sm := newStateSetMap(8, &arena)

	c1 := []uint32{1, 2}
	h := closureHash(c1)
	ref1 := arena.cloneRef(c1)
	sm.insert(h, ref1, 0)

	// Query with the same hash but a different closure exercises the
	// "primary exists but doesn't match" branch.
	cDifferent := []uint32{9, 9}
	_, ok := sm.lookup(h, cDifferent)
	if ok {
		t.Fatal("lookup should return false when primary closure doesn't match")
	}
}

// ---------------------------------------------------------------------------
// closureHash
// ---------------------------------------------------------------------------

// TestClosureHashDeterministic verifies that the hash function used as a
// stateSetMap key is deterministic and distinguishes different inputs.
func TestClosureHashDeterministic(t *testing.T) {
	a := []uint32{1, 2, 3}
	b := []uint32{3, 2, 1}
	c := []uint32{1, 2, 3}

	ha := closureHash(a)
	hb := closureHash(b)
	hc := closureHash(c)

	if ha != hc {
		t.Fatalf("closureHash(%v) != closureHash(%v): %d vs %d", a, c, ha, hc)
	}
	if ha == hb {
		t.Fatalf("closureHash(%v) == closureHash(%v) (order should matter)", a, b)
	}
	if closureHash(nil) == closureHash([]uint32{0}) {
		t.Fatal("closureHash(nil) should differ from closureHash([0])")
	}
}

// ---------------------------------------------------------------------------
// sortedUnion
// ---------------------------------------------------------------------------

// TestSortedUnion verifies that the sorted-merge helper used during subset
// construction in the automaton package correctly produces a deduplicated,
// sorted union of two input slices.
func TestSortedUnion(t *testing.T) {
	cases := []struct {
		name string
		a, b []uint32
		want []uint32
	}{
		{"both empty", nil, nil, nil},
		{"left empty", nil, []uint32{1, 2}, []uint32{1, 2}},
		{"right empty", []uint32{3, 4}, nil, []uint32{3, 4}},
		{"disjoint", []uint32{1, 3}, []uint32{2, 4}, []uint32{1, 2, 3, 4}},
		{"overlap", []uint32{1, 2, 4}, []uint32{2, 3, 4}, []uint32{1, 2, 3, 4}},
		{"identical", []uint32{5, 10}, []uint32{5, 10}, []uint32{5, 10}},
		{"interleaved", []uint32{1, 5, 9}, []uint32{2, 6, 10}, []uint32{1, 2, 5, 6, 9, 10}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf []uint32
			got := sortedUnion(tc.a, tc.b, &buf)
			if len(tc.want) == 0 && len(got) == 0 {
				return // both nil/empty is fine
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("sortedUnion(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// computeAccept
// ---------------------------------------------------------------------------

// TestComputeAccept verifies that the accept-flag and rule-ID aggregation
// used during subset construction correctly merges rule attribution from
// multiple NFA states in the automaton package.
func TestComputeAccept(t *testing.T) {
	n := &nfa{states: make([]nfaState, 4)}
	// State 0: not accept
	// State 1: accept with rule 10
	n.states[1].setAccept(true)
	n.states[1].ruleIDs = []uint32{10}
	// State 2: accept with rule 20
	n.states[2].setAccept(true)
	n.states[2].ruleIDs = []uint32{20}
	// State 3: accept with rules 10, 30 (overlaps with state 1)
	n.states[3].setAccept(true)
	n.states[3].ruleIDs = []uint32{10, 30}

	t.Run("no accept states", func(t *testing.T) {
		accept, ruleIDs := computeAccept(n, []uint32{0})
		if accept {
			t.Fatal("expected non-accept")
		}
		if len(ruleIDs) != 0 {
			t.Fatalf("ruleIDs = %v, want empty", ruleIDs)
		}
	})

	t.Run("single accept state", func(t *testing.T) {
		accept, ruleIDs := computeAccept(n, []uint32{0, 1})
		if !accept {
			t.Fatal("expected accept")
		}
		if !slices.Equal(ruleIDs, []uint32{10}) {
			t.Fatalf("ruleIDs = %v, want [10]", ruleIDs)
		}
	})

	t.Run("merged and deduplicated", func(t *testing.T) {
		accept, ruleIDs := computeAccept(n, []uint32{1, 2, 3})
		if !accept {
			t.Fatal("expected accept")
		}
		want := []uint32{10, 20, 30}
		if !slices.Equal(ruleIDs, want) {
			t.Fatalf("ruleIDs = %v, want %v", ruleIDs, want)
		}
	})
}

// ---------------------------------------------------------------------------
// intermediateDFA
// ---------------------------------------------------------------------------

// TestIntermediateDFAAddAndQuery verifies that the SoA-based intermediate DFA
// used during compilation in the automaton package correctly adds states,
// initialises transitions to noTransitionState, and provides correct per-state
// transition slices.
func TestIntermediateDFAAddAndQuery(t *testing.T) {
	md := &intermediateDFA{
		ruleIDs: make(map[int][]uint32),
	}
	md.addState(false, nil)
	md.addState(true, []uint32{7})

	if md.stateCount() != 2 {
		t.Fatalf("stateCount() = %d, want 2", md.stateCount())
	}
	if md.accept[0] {
		t.Fatal("state 0 should not be accepting")
	}
	if !md.accept[1] {
		t.Fatal("state 1 should be accepting")
	}
	if !slices.Equal(md.ruleIDs[1], []uint32{7}) {
		t.Fatalf("state 1 ruleIDs = %v, want [7]", md.ruleIDs[1])
	}
	// All transitions should be noTransitionState.
	for _, target := range md.stateTrans(0) {
		if target != noTransitionState {
			t.Fatalf("expected noTransitionState, got %d", target)
		}
	}
}

// ---------------------------------------------------------------------------
// subsetConstruction (integration-level)
// ---------------------------------------------------------------------------

// TestSubsetConstructionSimpleLiteral verifies that a single literal pattern
// produces a correct deterministic DFA via subset construction in the
// automaton package.
func TestSubsetConstructionSimpleLiteral(t *testing.T) {
	n, err := buildPatternNFA("ab", 0)
	if err != nil {
		t.Fatal(err)
	}
	md, err := subsetConstruction(n, 0, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if md.stateCount() < 3 {
		t.Fatalf("expected at least 3 DFA states for 'ab', got %d", md.stateCount())
	}
	// Convert and verify matching.
	dfa := md.toDFA()
	if matched, _ := dfa.Match("ab"); !matched {
		t.Fatal("DFA should match 'ab'")
	}
	if matched, _ := dfa.Match("a"); matched {
		t.Fatal("DFA should not match 'a'")
	}
}

// TestSubsetConstructionMaxStates verifies that the state cap correctly
// aborts compilation with an error when exceeded.
func TestSubsetConstructionMaxStates(t *testing.T) {
	n, err := buildPatternNFA("*a*b*", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = subsetConstruction(n, 5, time.Time{})
	if err == nil {
		t.Fatal("expected MaxStates error")
	}
}

// TestSubsetConstructionTimeout verifies that subset construction respects
// the deadline parameter and returns a timeout error.
func TestSubsetConstructionTimeout(t *testing.T) {
	n, err := buildPatternNFA("*a*b*c*d*", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Set an already-expired deadline.
	past := time.Now().Add(-1 * time.Second)
	_, err = subsetConstruction(n, 0, past)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

// TestSubsetConstructionWildcard verifies that wildcard patterns produce a
// DFA that matches multi-character input via subset construction.
func TestSubsetConstructionWildcard(t *testing.T) {
	patNFA, err := buildPatternNFA("*.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := combineNFAs([]*nfa{patNFA})
	if err != nil {
		t.Fatal(err)
	}
	md, err := subsetConstruction(combined, 0, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	dfa := md.toDFA()
	if matched, _ := dfa.Match("example.com"); !matched {
		t.Fatal("DFA should match 'example.com'")
	}
	if matched, _ := dfa.Match("a.b.com"); !matched {
		t.Fatal("DFA should match 'a.b.com'")
	}
	// "*" is zero-or-more, so ".com" matches "*.com".
	if matched, _ := dfa.Match(".com"); !matched {
		t.Fatal("DFA should match '.com' (wildcard is zero-or-more)")
	}
	if matched, _ := dfa.Match("com"); matched {
		t.Fatal("DFA should not match 'com' (missing '.' separator)")
	}
}

// TestSubsetConstructionMultiplePatterns verifies that combining several
// patterns produces a DFA that matches exactly the expected inputs.
func TestSubsetConstructionMultiplePatterns(t *testing.T) {
	nfas := make([]*nfa, 3)
	for i, pat := range []string{"a.com", "b.com", "c.com"} {
		var err error
		nfas[i], err = buildPatternNFA(pat, uint32(i)) //nolint:gosec // test loop index
		if err != nil {
			t.Fatal(err)
		}
	}
	combined, err := combineNFAs(nfas)
	if err != nil {
		t.Fatal(err)
	}
	md, err := subsetConstruction(combined, 0, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	dfa := md.toDFA()

	for _, name := range []string{"a.com", "b.com", "c.com"} {
		if matched, _ := dfa.Match(name); !matched {
			t.Errorf("DFA should match %q", name)
		}
	}
	for _, name := range []string{"d.com", "a.co", ""} {
		if matched, _ := dfa.Match(name); matched {
			t.Errorf("DFA should not match %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// subsetTransitionScratch
// ---------------------------------------------------------------------------

// TestSubsetTransitionScratchCollectAndReset verifies that the reusable
// scratch buffer correctly records NFA transitions and resets between uses
// in the automaton package.
func TestSubsetTransitionScratchCollectAndReset(t *testing.T) {
	n := &nfa{states: make([]nfaState, 0, 4)}
	// State 0: literal 'a' → 1
	s0 := n.addState()
	s1 := n.addState()
	if err := n.addTrans(s0, 'a', s1); err != nil {
		t.Fatal(err)
	}
	// State 2: wildcard → 3
	s2 := n.addState()
	s3 := n.addState()
	n.addAnyDNSTrans(s2, s3)

	var scratch subsetTransitionScratch
	scratch.collect(n, []uint32{uint32(s0), uint32(s2)}) //nolint:gosec // test values

	if scratch.activeLiteralMask == 0 {
		t.Fatal("expected non-zero literal mask after collect")
	}
	if len(scratch.wildcardTargets) != 1 || scratch.wildcardTargets[0] != uint32(s3) { //nolint:gosec // test
		t.Fatalf("wildcardTargets = %v, want [%d]", scratch.wildcardTargets, s3)
	}

	// After reset, everything should be cleared.
	scratch.reset()
	if scratch.activeLiteralMask != 0 {
		t.Fatal("expected zero literal mask after reset")
	}
	if len(scratch.wildcardTargets) != 0 {
		t.Fatal("expected empty wildcardTargets after reset")
	}
}
