package automaton

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"slices"
	"time"
)

// ---- Intermediate DFA ----
//
// The intermediate DFA is used only during compilation (subset construction
// and Hopcroft minimization). It stores transitions as [AlphabetSize]uint32
// arrays of state IDs rather than pointers, because states are frequently
// appended to a growing slice whose address may change. After minimization,
// [intermediateDFA.toDFA] converts this representation into the exported
// pointer-based [DFA].

// intermediateDFAState is one state in the temporary DFA built during subset
// construction.
//
// Transitions are uint32 state IDs (or [noTransitionState] for dead ends)
// in a fixed-size array indexed by alphabet position, keeping cache behavior
// predictable during the tight loops of subset construction.
type intermediateDFAState struct {
	trans   [AlphabetSize]uint32
	accept  bool
	ruleIDs []uint32
}

// intermediateDFA is the temporary DFA used during subset construction and
// Hopcroft minimization before conversion to the exported [DFA].
type intermediateDFA struct {
	start  int
	states []intermediateDFAState
}

// newIntermediateDFAState creates a fresh intermediate state with all
// transitions set to [noTransitionState].
func newIntermediateDFAState(accept bool, ruleIDs []uint32) intermediateDFAState {
	s := intermediateDFAState{
		accept:  accept,
		ruleIDs: ruleIDs,
	}
	for i := range s.trans {
		s.trans[i] = noTransitionState
	}
	return s
}

// ---- Subset (Powerset) Construction ----
//
// The classic powerset construction converts a combined NFA into a
// deterministic intermediate DFA. Each DFA state represents a set of NFA
// states (its epsilon closure). A worklist drives exploration: for each
// unprocessed DFA state and every alphabet symbol, the algorithm computes
// the closure of the NFA states reachable via that symbol and either reuses
// an existing DFA state whose closure matches or creates a new one.
//
// Wildcards interact with literal transitions: when an NFA state set contains
// both wildcard and literal edges on the same symbol, the resulting DFA
// transition merges both target sets (see the main loop in subsetConstruction).

// subsetWorkItem pairs a DFA state ID with the NFA states it represents.
type subsetWorkItem struct {
	id     uint32
	states []int
}

// subsetTransitionScratch collects outgoing NFA transitions for a set of
// NFA states without allocating fresh slices on each call.
//
// The activeLiteralMask is a 64-bit bitmask tracking which alphabet slots
// have at least one literal target. Because AlphabetSize == 38 < 64, every
// slot fits in one uint64, and iterating only set bits avoids scanning all
// 38 slots when most are empty.
type subsetTransitionScratch struct {
	activeLiteralMask uint64
	literalTargets    [AlphabetSize][]int
	wildcardTargets   []int
	moved             []int // scratch for merging wildcard + literal targets
}

func (s *subsetTransitionScratch) reset() {
	mask := s.activeLiteralMask
	for mask != 0 {
		idx := bits.TrailingZeros64(mask)
		s.literalTargets[idx] = s.literalTargets[idx][:0]
		mask &^= uint64(1) << idx
	}
	s.activeLiteralMask = 0
	s.wildcardTargets = s.wildcardTargets[:0]
	s.moved = s.moved[:0]
}

// collect scans the NFA states belonging to one DFA state and records their
// outgoing transitions into the scratch buffers.
func (s *subsetTransitionScratch) collect(n *nfa, states []int) {
	s.reset()
	for _, stateID := range states {
		state := &n.states[stateID]
		if state.hasLiteralTransition() {
			idx := int(state.literalIndex)
			s.activeLiteralMask |= uint64(1) << idx
			s.literalTargets[idx] = append(s.literalTargets[idx], int(state.literalTo))
		}
		if state.hasAnyDNSTransition() {
			s.wildcardTargets = append(s.wildcardTargets, int(state.anyDNSTo))
		}
	}
}

// subsetBuilder holds the mutable state shared during subset construction,
// avoiding closure captures and reducing parameter passing.
type subsetBuilder struct {
	nfa         *nfa
	md          *intermediateDFA
	closures    *closureScratch
	stateMap    map[string]uint32
	worklist    []subsetWorkItem
	transitions subsetTransitionScratch
	maxStates   int
}

// getOrCreateState returns the uint32 DFA-state ID for the epsilon closure of
// source, creating a new state when no matching closure exists yet.
//
// The source parameter is a list of NFA state IDs whose epsilon closure forms
// the DFA state. Returns an error when the set-key encoding fails or
// MaxStates would be exceeded.
func (b *subsetBuilder) getOrCreateState(source []int) (uint32, error) {
	closure := epsilonClosure(b.closures, b.nfa, source)
	key, err := makeSetKey(&b.closures.keyBuf, closure)
	if err != nil {
		return 0, err
	}
	if existingID, exists := b.stateMap[key]; exists {
		return existingID, nil
	}
	if b.maxStates > 0 && len(b.md.states) >= b.maxStates {
		return 0, fmt.Errorf("automaton: exceeded MaxStates limit (%d)", b.maxStates)
	}
	newID := uint32(len(b.md.states)) //nolint:gosec // bounded by maxStates, len() is always ≥0
	b.stateMap[key] = newID
	accept, ruleIDs := computeAccept(b.nfa, closure)
	b.md.states = append(b.md.states, newIntermediateDFAState(accept, ruleIDs))
	b.worklist = append(b.worklist, subsetWorkItem{id: newID, states: slices.Clone(closure)})
	return newID, nil
}

// subsetConstruction converts a combined NFA into a deterministic intermediate
// DFA using the classic powerset (subset) construction algorithm.
//
// Each DFA state represents a set of NFA states (its epsilon closure). The
// algorithm maintains a worklist of unprocessed DFA states and explores
// transitions for every alphabet symbol until no new state sets appear.
//
// The maxStates parameter caps the number of DFA states to prevent
// combinatorial explosion (0 = unlimited). The deadline parameter triggers a
// timeout error when exceeded (zero value = no timeout).
func subsetConstruction(n *nfa, maxStates int, deadline time.Time) (*intermediateDFA, error) {
	md := &intermediateDFA{states: make([]intermediateDFAState, 0, 1024)}
	b := &subsetBuilder{
		nfa:       n,
		md:        md,
		closures:  newClosureScratch(len(n.states)),
		stateMap:  make(map[string]uint32, 1024),
		maxStates: maxStates,
	}

	startResult := epsilonClosure(b.closures, n, []int{n.start})
	startKey, err := makeSetKey(&b.closures.keyBuf, startResult)
	if err != nil {
		return nil, err
	}
	b.stateMap[startKey] = 0
	md.start = 0

	accept, ruleIDs := computeAccept(n, startResult)
	md.states = append(md.states, newIntermediateDFAState(accept, ruleIDs))
	b.worklist = append(b.worklist, subsetWorkItem{id: 0, states: slices.Clone(startResult)})

	for len(b.worklist) > 0 {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, errors.New("automaton: subset construction timeout")
		}

		currentItem := b.worklist[0]
		b.worklist = b.worklist[1:]
		current := currentItem.states
		currentID := currentItem.id
		b.transitions.collect(n, current)

		// If any NFA states in this set have wildcard transitions, the
		// default for every alphabet symbol points to the wildcard closure.
		if len(b.transitions.wildcardTargets) > 0 {
			wildcardID, wErr := b.getOrCreateState(b.transitions.wildcardTargets)
			if wErr != nil {
				return nil, wErr
			}
			for idx := range AlphabetSize {
				md.states[currentID].trans[idx] = wildcardID
			}
		}

		// Override specific alphabet slots that also have literal transitions.
		mask := b.transitions.activeLiteralMask
		for mask != 0 {
			idx := bits.TrailingZeros64(mask)
			mask &^= uint64(1) << idx

			literalTargets := b.transitions.literalTargets[idx]
			if len(b.transitions.wildcardTargets) == 0 {
				stateID, stateErr := b.getOrCreateState(literalTargets)
				if stateErr != nil {
					return nil, stateErr
				}
				md.states[currentID].trans[idx] = stateID
				continue
			}

			// Merge wildcard and literal targets into one closure.
			moved := b.transitions.moved[:0]
			moved = append(moved, b.transitions.wildcardTargets...)
			moved = append(moved, literalTargets...)
			b.transitions.moved = moved[:0]

			stateID, stateErr := b.getOrCreateState(moved)
			if stateErr != nil {
				return nil, stateErr
			}
			md.states[currentID].trans[idx] = stateID
		}
	}

	return md, nil
}

// computeAccept derives the accept flag and merged rule IDs for a DFA state
// that represents the given set of NFA states.
func computeAccept(n *nfa, stateSet []int) (accept bool, ruleIDs []uint32) {
	for _, s := range stateSet {
		if n.states[s].isAccept() {
			accept = true
			ruleIDs = append(ruleIDs, n.states[s].ruleIDs...)
		}
	}
	if len(ruleIDs) > 1 {
		slices.Sort(ruleIDs)
		ruleIDs = slices.Compact(ruleIDs)
	}
	return accept, ruleIDs
}

// makeSetKey serializes a sorted NFA state set into a deterministic binary
// key for the state-map lookup during subset construction.
//
// Each state ID occupies a fixed four-byte little-endian slot, so
// concatenated keys are unambiguous without delimiter characters or
// variable-length encoding. The buf parameter is a reusable scratch buffer
// to reduce allocations.
func makeSetKey(buf *[]byte, states []int) (string, error) {
	b := (*buf)[:0]
	for _, s := range states {
		var err error
		b, err = appendFixedUint32(b, s)
		if err != nil {
			return "", err
		}
	}
	*buf = b
	return string(b), nil
}

// appendFixedUint32 appends a 4-byte little-endian encoding of value to buf.
func appendFixedUint32(buf []byte, value int) ([]byte, error) {
	if value < 0 || value > math.MaxUint32 {
		return nil, fmt.Errorf("automaton: state id %d out of uint32 range", value)
	}

	return append(buf,
		byte(value&0xff),
		byte(value>>8&0xff),
		byte(value>>16&0xff),
		byte(value>>24&0xff),
	), nil
}
