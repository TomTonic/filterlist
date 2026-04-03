package automaton

// AlphabetSize is the number of distinct characters in the DNS transition
// alphabet: the 26 lowercase letters (a-z), 10 digits (0-9), hyphen ('-'),
// and dot ('.').
//
// Every [DFAState] transition array and every intermediate state during
// compilation is sized to exactly AlphabetSize slots, so changing this
// constant reshapes the entire automaton. The value 38 keeps each
// DFAState.Trans array at 38 pointers (304 bytes on 64-bit), which fits
// comfortably inside a few cache lines.
const AlphabetSize = 38

// noAlphabetIndex is the sentinel returned by [runeToIndex] for characters
// outside the DNS alphabet. Using 0xFF avoids collision with valid indexes
// (0–37) while remaining a single-byte constant for cheap comparisons.
const noAlphabetIndex byte = 0xFF

// noTransitionState is the uint32 sentinel that marks "no transition" in the
// intermediate DFA arrays during subset construction and Hopcroft
// minimization. math.MaxUint32 is chosen because valid state IDs start at 0
// and grow upward, so collision is impossible in practice.
const noTransitionState uint32 = 0xFFFFFFFF

// dnsAlphabet lists all valid DNS characters in transition-index order.
// Index 0–25 = 'a'–'z', 26–35 = '0'–'9', 36 = '-', 37 = '.'.
var dnsAlphabet [AlphabetSize]rune

func init() {
	for i := range AlphabetSize {
		dnsAlphabet[i] = indexToRune(i)
	}
}

// runeToIndex maps a DNS character to its transition-array index.
//
// The r parameter must be a lowercase DNS character (a-z, 0-9, '-', or '.').
// Returns a byte in [0, [AlphabetSize]) for valid characters, or
// [noAlphabetIndex] (0xFF) for anything outside the alphabet.
//
// This function is on the hot path of both [DFA.Match] and NFA construction,
// so it uses a switch ladder rather than a lookup table — the compiler turns
// the sequential ranges into efficient conditional jumps.
func runeToIndex(r rune) byte {
	switch {
	case r >= 'a' && r <= 'z':
		return byte(r - 'a') //nolint:gosec // r∈['a','z'], r-'a'∈[0,25] fits byte
	case r >= '0' && r <= '9':
		return 26 + byte(r-'0') //nolint:gosec // r∈['0','9'], 26+r-'0'∈[26,35] fits byte
	case r == '-':
		return 36
	case r == '.':
		return 37
	default:
		return noAlphabetIndex
	}
}

// indexToRune maps a transition-array index back to its DNS character.
//
// The i parameter must be in the inclusive range [0, [AlphabetSize]).
// Returns the DNS rune at that position, or -1 when i is out of range.
// Mainly used for diagnostics such as Graphviz DOT output (see [DFA.DumpDot]).
func indexToRune(i int) rune {
	switch {
	case i >= 0 && i <= 25:
		return rune('a' + i)
	case i >= 26 && i <= 35:
		return rune('0' + i - 26)
	case i == 36:
		return '-'
	case i == 37:
		return '.'
	default:
		return -1
	}
}
