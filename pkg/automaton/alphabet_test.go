package automaton

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Alphabet mapping
// ---------------------------------------------------------------------------

// TestRuneToIndexAllDNSChars verifies that users get stable matching for every supported DNS character in the automaton package by asserting that each allowed rune maps to a unique transition slot.
func TestRuneToIndexAllDNSChars(t *testing.T) {
	// Every DNS char must map to a unique index in [0, AlphabetSize).
	seen := make(map[byte]rune)
	for _, r := range "abcdefghijklmnopqrstuvwxyz0123456789-." {
		idx := runeToIndex(r)
		if idx == noAlphabetIndex || int(idx) >= AlphabetSize {
			t.Fatalf("runeToIndex(%q) = %d, want [0,%d)", r, idx, AlphabetSize)
		}
		if prev, dup := seen[idx]; dup {
			t.Fatalf("runeToIndex(%q) = %d collides with %q", r, idx, prev)
		}
		seen[idx] = r
	}
	if len(seen) != AlphabetSize {
		t.Fatalf("mapped %d unique chars, want %d", len(seen), AlphabetSize)
	}
}

// TestRuneToIndexInvalid verifies that malformed query characters do not enter the DFA transition table in the automaton package by asserting that unsupported runes return noAlphabetIndex (0xFF).
func TestRuneToIndexInvalid(t *testing.T) {
	for _, r := range "ABCXYZ_!@#$%^&*() /\\\"'" {
		if idx := runeToIndex(r); idx != noAlphabetIndex {
			t.Errorf("runeToIndex(%q) = %d, want noAlphabetIndex", r, idx)
		}
	}
}

// TestIndexToRuneRoundTrip verifies that diagnostic code can move safely between alphabet indexes and runes in the automaton package by asserting a full round-trip across the supported alphabet.
func TestIndexToRuneRoundTrip(t *testing.T) {
	for i := range AlphabetSize {
		r := indexToRune(i)
		got := runeToIndex(r)
		if int(got) != i {
			t.Errorf("runeToIndex(indexToRune(%d)) = %d, want %d (rune=%q)", i, got, i, r)
		}
	}
}

// TestIndexToRuneReturnsMinusOneOutOfRange verifies that callers do not crash the process when they inspect invalid alphabet indexes in the automaton package by asserting that out-of-range values return -1.
func TestIndexToRuneReturnsMinusOneOutOfRange(t *testing.T) {
	for _, i := range []int{-1, AlphabetSize, 100} {
		if got := indexToRune(i); got != -1 {
			t.Errorf("indexToRune(%d) = %d, want -1", i, got)
		}
	}
}

// TestDnsAlphabetConsistency verifies that users get one coherent DNS alphabet across compilation and matching in the automaton package by asserting that the shared alphabet array and lookup helpers agree.
func TestDnsAlphabetConsistency(t *testing.T) {
	if len(dnsAlphabet) != AlphabetSize {
		t.Fatalf("dnsAlphabet length = %d, want %d", len(dnsAlphabet), AlphabetSize)
	}
	for i, r := range dnsAlphabet {
		if int(runeToIndex(r)) != i {
			t.Errorf("dnsAlphabet[%d] = %q but runeToIndex returns %d", i, r, runeToIndex(r))
		}
	}
}
