package automaton

import (
	"fmt"
	"slices"
)

// epsilon is the sentinel rune for epsilon (ε) transitions in the NFA.
// Using rune 0 avoids collision with any valid DNS character.
const epsilon rune = 0

// ---- NFA state flags ----
//
// Packing boolean attributes into flag bits keeps nfaState small. On 64-bit
// systems the critical scalar fields (literalTo, anyDNSTo, literalIndex,
// flags) fit in 10 bytes, leaving the two slice headers at known offsets.
// This layout was chosen after profiling showed that reducing nfaState size
// materially improves cache utilization during epsilon closure and subset
// construction.

const (
	nfaFlagHasLiteral uint8 = 1 << iota // state has a labeled literal transition
	nfaFlagHasAnyDNS                    // state has a wildcard (any-DNS-char) transition
	nfaFlagAccept                       // state is an accept state
)

// nfaState is one node in the Thompson NFA.
//
// Thompson construction in this package produces at most one literal outgoing
// edge per state, plus optional epsilon fan-out and an optional "any DNS
// character" loop. Storing those paths directly in scalar fields is markedly
// smaller and more cache-friendly than allocating a general-purpose map for
// every state.
//
// # Field Layout
//
//   - literalTo:    target state ID for the single labeled literal transition
//   - anyDNSTo:     target state ID for the wildcard (any-char) transition
//   - literalIndex: which alphabet slot the literal transition uses
//   - flags:        packed booleans (hasLiteral, hasAnyDNS, accept)
//   - epsilon:      fan-out targets for ε-transitions (typically 0–2 entries)
//   - ruleIDs:      non-nil only on accept states; identifies originating rules
type nfaState struct {
	literalTo    uint32
	anyDNSTo     uint32
	literalIndex byte
	flags        byte
	epsilon      []uint32
	ruleIDs      []uint32
}

func (s *nfaState) hasLiteralTransition() bool { return s.flags&nfaFlagHasLiteral != 0 }
func (s *nfaState) hasAnyDNSTransition() bool  { return s.flags&nfaFlagHasAnyDNS != 0 }
func (s *nfaState) isAccept() bool             { return s.flags&nfaFlagAccept != 0 }

func (s *nfaState) setAccept(accept bool) {
	if accept {
		s.flags |= nfaFlagAccept
		return
	}
	s.flags &^= nfaFlagAccept
}

// nfa holds the complete Thompson NFA before subset construction.
type nfa struct {
	states []nfaState
	start  int
}

// addState appends a fresh state with no transitions and returns its ID.
func (n *nfa) addState() int {
	id := len(n.states)
	n.states = append(n.states, nfaState{
		literalTo: noTransitionState,
		anyDNSTo:  noTransitionState,
	})
	return id
}

// addTrans records a labeled transition from one NFA state to another.
// Pass [epsilon] (rune 0) for ε-transitions, or a valid DNS character.
func (n *nfa) addTrans(from int, r rune, to int) error {
	state := &n.states[from]
	if r == epsilon {
		state.epsilon = append(state.epsilon, uint32(to)) //nolint:gosec // to=addState()≥0, fits uint32
		return nil
	}

	idx := runeToIndex(r)
	if idx == noAlphabetIndex {
		return fmt.Errorf("unsupported character %q in pattern", r)
	}

	state.literalIndex = idx
	state.literalTo = uint32(to) //nolint:gosec // to=addState()≥0, fits uint32
	state.flags |= nfaFlagHasLiteral
	return nil
}

// addAnyDNSTrans records a wildcard transition taken for any supported DNS
// character.
func (n *nfa) addAnyDNSTrans(from int, to int) {
	n.states[from].anyDNSTo = uint32(to) //nolint:gosec // to=addState()≥0, fits uint32
	n.states[from].flags |= nfaFlagHasAnyDNS
}

// buildPatternNFA constructs a Thompson NFA for a single filter pattern.
//
// The pattern parameter uses the package's minimal pattern language: literal
// DNS characters and '*' for zero-or-more DNS characters. The ruleID is
// stored on the NFA's final accept state so it survives through subset
// construction and minimization into the exported [DFA].
//
// Returns an error when the pattern contains characters outside the alphabet.
func buildPatternNFA(pattern string, ruleID uint32) (*nfa, error) {
	n := &nfa{states: make([]nfaState, 0, len(pattern)+2)}
	start := n.addState()
	n.start = start

	current := start
	for _, r := range pattern {
		switch {
		case r == '*':
			// Wildcard: ε-transition to a self-looping state that accepts any
			// DNS character, implementing zero-or-more matching.
			loopState := n.addState()
			if err := n.addTrans(current, epsilon, loopState); err != nil {
				return nil, err
			}
			n.addAnyDNSTrans(loopState, loopState)
			current = loopState
		case runeToIndex(r) != noAlphabetIndex:
			next := n.addState()
			if err := n.addTrans(current, r, next); err != nil {
				return nil, err
			}
			current = next
		default:
			return nil, fmt.Errorf("unsupported character %q in pattern", r)
		}
	}

	// Mark final state as accept.
	n.states[current].setAccept(true)
	n.states[current].ruleIDs = []uint32{ruleID}
	return n, nil
}

// combineNFAs merges multiple NFAs into one by creating a new start state
// with ε-transitions to each sub-NFA's original start.
//
// State IDs are rewritten with an offset so the combined NFA's state slice
// is contiguous. The resulting NFA is ready for [subsetConstruction].
func combineNFAs(nfas []*nfa) (*nfa, error) {
	totalStates := 1 // one extra for the new shared start state
	for _, sub := range nfas {
		totalStates += len(sub.states)
	}
	combined := &nfa{states: make([]nfaState, 0, totalStates)}
	newStart := combined.addState()
	combined.start = newStart

	for _, sub := range nfas {
		offset := uint32(len(combined.states)) //nolint:gosec // len() is always ≥0
		// Copy states without transitions first.
		for _, s := range sub.states {
			newID := combined.addState()
			combined.states[newID].setAccept(s.isAccept())
			combined.states[newID].ruleIDs = append([]uint32(nil), s.ruleIDs...)
		}
		// Rewrite transitions with the offset applied.
		for i, s := range sub.states {
			iOff := i + int(offset)
			for _, t := range s.epsilon {
				if err := combined.addTrans(iOff, epsilon, int(t+offset)); err != nil {
					return nil, err
				}
			}
			if s.hasLiteralTransition() {
				combined.states[iOff].literalIndex = s.literalIndex
				combined.states[iOff].literalTo = s.literalTo + offset
				combined.states[iOff].flags |= nfaFlagHasLiteral
			}
			if s.hasAnyDNSTransition() {
				combined.states[iOff].anyDNSTo = s.anyDNSTo + offset
				combined.states[iOff].flags |= nfaFlagHasAnyDNS
			}
		}
		// ε-transition from the shared start to this sub-NFA's start.
		if err := combined.addTrans(newStart, epsilon, sub.start+int(offset)); err != nil {
			return nil, err
		}
	}
	return combined, nil
}

// ---- Epsilon closure ----

// closureScratch provides reusable working memory for repeated
// [epsilonClosure] calls during subset construction.
//
// NFA state IDs are contiguous slice indices, so a dense marks array with a
// running stamp replaces a hash set. Incrementing the stamp between calls
// "clears" all marks in O(1) without touching memory, which is critical when
// closure is called once per DFA state × alphabet symbol.
type closureScratch struct {
	marks  []uint32 // indexed by NFA state ID; entry == stamp means "visited"
	stamp  uint32   // current generation; incremented per closure call
	stack  []int    // DFS traversal stack (reused across calls)
	result []int    // sorted closure output (reused across calls)
	keyBuf []byte   // scratch buffer for [makeSetKey]
}

// newClosureScratch preallocates reusable state for repeated epsilon closures.
//
// The stateCount parameter must equal the number of NFA states so the marks
// array is sized correctly. Call this once before entering the subset
// construction loop.
func newClosureScratch(stateCount int) *closureScratch {
	return &closureScratch{marks: make([]uint32, stateCount)}
}

// epsilonClosure computes the set of NFA states reachable from states via
// zero or more ε-transitions.
//
// The returned slice is sorted and backed by cs.result (shared across calls).
// Callers must consume or clone it before the next call.
func epsilonClosure(cs *closureScratch, n *nfa, states []int) []int {
	cs.stamp++
	if cs.stamp == 0 {
		// Stamp wrapped around — reset all marks.
		clear(cs.marks)
		cs.stamp = 1
	}

	stack := cs.stack[:0]
	result := cs.result[:0]

	for _, s := range states {
		if cs.marks[s] == cs.stamp {
			continue
		}
		cs.marks[s] = cs.stamp
		stack = append(stack, s)
	}

	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		result = append(result, s)
		for _, t := range n.states[s].epsilon {
			if cs.marks[t] == cs.stamp {
				continue
			}
			cs.marks[t] = cs.stamp
			stack = append(stack, int(t))
		}
	}

	slices.Sort(result)
	cs.stack = stack
	cs.result = result
	return result
}
