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
	left := []uint32{0xfe, 0x0d}
	right := []uint32{0x0f, 0xed}
	var buf []byte
	leftKey := makeSetKey(&buf, left)
	rightKey := makeSetKey(&buf, right)

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

// TestMakeSetKeyLargeValues verifies that large uint32 state IDs are encoded
// correctly in the automaton package.
//
// This test covers the fixed-width key encoder used during subset construction.
//
// It asserts that the maximum uint32 value is encoded correctly.
func TestMakeSetKeyLargeValues(t *testing.T) {
	var buf []byte
	key := makeSetKey(&buf, []uint32{0xFFFFFFFF})
	want := string([]byte{0xff, 0xff, 0xff, 0xff})
	if key != want {
		t.Fatalf("makeSetKey(0xFFFFFFFF) = % x, want % x", []byte(key), []byte(want))
	}
}
