package automaton

// DFAState is one state in the compiled deterministic finite automaton.
//
// Transitions are stored in a fixed-size array indexed by [runeToIndex],
// with nil entries indicating no transition (dead end). Each non-nil entry
// is a direct pointer to the successor [DFAState] — no map lookups, no index
// indirection, just a single pointer chase per input character at match time.
//
// # Memory Layout
//
// On 64-bit systems each DFAState is 38 pointers (304 B) for Trans, one bool
// (Accept), and a slice header (RuleIDs). Keeping Trans as a fixed array
// rather than a map or sparse structure ensures that the CPU prefetcher can
// stride through transition lookups predictably. All states are allocated in
// a single contiguous []DFAState slice inside [DFA], further improving spatial
// locality.
type DFAState struct {
	Trans   [AlphabetSize]*DFAState
	Accept  bool
	RuleIDs []uint32 // which filter rules led to this accept state
}

// DFA is a compiled deterministic finite automaton for domain name matching.
//
// States reside in a single contiguous slice for cache locality, and
// transitions are direct pointers between elements of that slice — no map
// lookups or index indirection at match time.
//
// Create a DFA with [Compile]; query it with [DFA.Match].
type DFA struct {
	start  *DFAState
	states []DFAState
}

// Match checks whether input is accepted by the compiled DFA and returns the
// matching rule IDs.
//
// The input parameter should be a lowercase DNS domain name. Match traverses
// the DFA one rune at a time in O(n) where n = len(input). It returns false
// immediately when a rune falls outside the DNS alphabet or leads to a dead
// end (nil transition pointer).
//
// A nil or empty DFA always returns (false, nil).
func (d *DFA) Match(input string) (matched bool, ruleIDs []uint32) {
	if d == nil || d.start == nil {
		return false, nil
	}
	s := d.start
	for _, r := range input {
		idx := runeToIndex(r)
		if idx == noAlphabetIndex {
			return false, nil
		}
		s = s.Trans[idx]
		if s == nil {
			return false, nil
		}
	}
	if s.Accept {
		return true, s.RuleIDs
	}
	return false, nil
}

// StateCount reports how many DFA states are currently allocated.
//
// Returns 0 for a nil receiver or an empty DFA. Callers typically use this
// for metrics, diagnostics, and capacity planning.
func (d *DFA) StateCount() int {
	if d == nil {
		return 0
	}
	return len(d.states)
}

// toDFA converts an intermediate DFA (used during compilation) to the
// exported pointer-based [DFA].
//
// The conversion allocates all [DFAState] values in a single contiguous slice
// and then patches transition entries to point directly into that slice.
// This two-pass approach (first allocate, then link) produces a DFA whose
// transitions are bare pointers — exactly one dereference per input rune.
func (md *intermediateDFA) toDFA() *DFA {
	d := &DFA{states: make([]DFAState, len(md.states))}

	// Pass 1: copy accept flags and rule IDs.
	for i := range md.states {
		ms := &md.states[i]
		d.states[i].Accept = ms.accept
		d.states[i].RuleIDs = ms.ruleIDs
	}

	// Pass 2: patch transition pointers into the contiguous slice.
	for i := range md.states {
		ms := &md.states[i]
		for idx, target := range ms.trans {
			if target != noTransitionState {
				d.states[i].Trans[idx] = &d.states[target]
			}
		}
	}

	d.start = &d.states[md.start]
	return d
}
