package automaton

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Subset construction internals
// ---------------------------------------------------------------------------

// TestMakeSetKeyUsesFixedWidthEncoding verifies that users compiling different
// wildcard state subsets never lose matches through accidental DFA-state
// merging in the automaton package.
//
// This test covers the internal subset-construction key builder.
//
// It asserts that each state ID occupies a fixed-width slot and that byte-like
// values such as 0xfe,0x0d and 0x0f,0xed produce different concatenated keys.
func TestMakeSetKeyUsesFixedWidthEncoding(t *testing.T) {
	left := []int{0xfe, 0x0d}
	right := []int{0x0f, 0xed}
	var buf []byte
	leftKey, err := makeSetKey(&buf, left)
	if err != nil {
		t.Fatalf("makeSetKey(%v) error = %v", left, err)
	}
	rightKey, err := makeSetKey(&buf, right)
	if err != nil {
		t.Fatalf("makeSetKey(%v) error = %v", right, err)
	}

	if len(leftKey) != 8 {
		t.Fatalf("len(makeSetKey(%v)) = %d, want 8", left, len(leftKey))
	}
	if leftKey == rightKey {
		t.Fatalf("makeSetKey(%v) unexpectedly matched makeSetKey(%v)", left, right)
	}

	wantLeft := string([]byte{0xfe, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00})
	if leftKey != wantLeft {
		t.Fatalf("makeSetKey(%v) = % x, want % x", left, []byte(leftKey), []byte(wantLeft))
	}
}

// TestMakeSetKeyRejectsOutOfRangeStates verifies that invalid internal state
// IDs fail fast in the automaton package instead of silently aliasing a valid
// DFA subset key.
//
// This test covers the fixed-width key encoder used during subset construction.
//
// It asserts that negative state IDs are rejected with an error.
func TestMakeSetKeyRejectsOutOfRangeStates(t *testing.T) {
	var buf []byte
	if _, err := makeSetKey(&buf, []int{-1}); err == nil {
		t.Fatal("makeSetKey should reject negative state ids")
	}
}
