package automaton

import (
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"time"
)

// ---- Intermediate DFA ----
//
// The intermediate DFA is used only during compilation (subset construction
// and Hopcroft minimization). It uses a structure-of-arrays (SoA) layout:
// transitions are stored in a flat []uint32 slice (pointer-free, invisible
// to the GC), while accept flags and rule IDs live in separate slices.
// This separation dramatically reduces GC scan work because the transition
// array — by far the largest allocation — contains no pointers.
//
// After minimization, [intermediateDFA.toDFA] converts this representation
// into the exported pointer-based [DFA].

// intermediateDFA is the temporary DFA used during subset construction and
// Hopcroft minimization before conversion to the exported [DFA].
//
// Transitions are stored in a flat []uint32 slice of length
// stateCount × [AlphabetSize]. State i's transitions occupy
// trans[i*AlphabetSize : (i+1)*AlphabetSize]. Unused slots hold
// [noTransitionState].
type intermediateDFA struct {
	start   int
	trans   []uint32         // flat: stateCount * AlphabetSize (pointer-free)
	accept  []bool           // per state (pointer-free)
	ruleIDs map[int][]uint32 // only accept states (sparse → tiny GC footprint)
}

// noTransBlock is a pre-initialised block of [noTransitionState] values used
// to initialise new state transition slots via append.
var noTransBlock [AlphabetSize]uint32

func init() {
	for i := range noTransBlock {
		noTransBlock[i] = noTransitionState
	}
}

// stateCount returns the number of states in the intermediate DFA.
func (md *intermediateDFA) stateCount() int { return len(md.accept) }

// addState appends a new state with all transitions set to
// [noTransitionState].
func (md *intermediateDFA) addState(accept bool, ruleIDs []uint32) {
	id := len(md.accept)
	md.accept = append(md.accept, accept)
	md.trans = append(md.trans, noTransBlock[:]...)
	if len(ruleIDs) > 0 {
		md.ruleIDs[id] = ruleIDs
	}
}

// stateTrans returns the AlphabetSize-length transition slice for state i.
func (md *intermediateDFA) stateTrans(state int) []uint32 {
	base := state * AlphabetSize
	return md.trans[base : base+AlphabetSize : base+AlphabetSize]
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

// subsetTransitionScratch collects outgoing NFA transitions for a set of
// NFA states without allocating fresh slices on each call.
//
// The activeLiteralMask is a 64-bit bitmask tracking which alphabet slots
// have at least one literal target. Because AlphabetSize == 38 < 64, every
// slot fits in one uint64, and iterating only set bits avoids scanning all
// 38 slots when most are empty.
type subsetTransitionScratch struct {
	activeLiteralMask uint64
	literalTargets    [AlphabetSize][]uint32
	wildcardTargets   []uint32
	moved             []uint32 // scratch for merging wildcard + literal targets
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
func (s *subsetTransitionScratch) collect(n *nfa, states []uint32) {
	s.reset()
	for _, stateID := range states {
		state := &n.states[stateID]
		if state.hasLiteralTransition() {
			idx := int(state.literalIndex)
			s.activeLiteralMask |= uint64(1) << idx
			s.literalTargets[idx] = append(s.literalTargets[idx], state.literalTo)
		}
		if state.hasAnyDNSTransition() {
			s.wildcardTargets = append(s.wildcardTargets, state.anyDNSTo)
		}
	}
}

// ---- Closure Arena ----
//
// closureArena is a bump allocator for []uint32 closure slices. It carves
// sub-slices from large contiguous blocks, turning millions of individual
// heap allocations into a handful of block allocations.
//
// The [arenaRef] type provides a pointer-free handle to data inside the
// arena. Storing arenaRef values (instead of []uint32 slices) in the
// state-set map and worklist makes those containers invisible to the GC,
// because arenaRef contains only value-type fields.

const closureArenaBlockSize = 1 << 21 // 2 Mi uint32 per block ≈ 8 MiB

// arenaRef is a pointer-free reference to a closure stored in a
// [closureArena]. All fields are value types, so slices and maps of
// arenaRef are not scanned by the GC.
type arenaRef struct {
	blockIdx uint16
	offset   uint32
	length   uint32
}

type closureArena struct {
	blocks  [][]uint32
	current []uint32
	offset  int
}

// cloneRef copies src into the arena and returns a pointer-free reference.
func (a *closureArena) cloneRef(src []uint32) arenaRef {
	n := len(src)
	if n == 0 {
		return arenaRef{}
	}
	if n > closureArenaBlockSize {
		blk := make([]uint32, n)
		copy(blk, src)
		idx := len(a.blocks)
		a.blocks = append(a.blocks, blk)
		return arenaRef{blockIdx: uint16(idx), offset: 0, length: uint32(n)} //nolint:gosec // idx < 65535 in practice
	}
	if a.offset+n > len(a.current) {
		a.current = make([]uint32, closureArenaBlockSize)
		a.blocks = append(a.blocks, a.current)
		a.offset = 0
	}
	idx := len(a.blocks) - 1
	off := a.offset
	copy(a.current[off:off+n], src)
	a.offset += n
	return arenaRef{blockIdx: uint16(idx), offset: uint32(off), length: uint32(n)} //nolint:gosec // idx bounded, off < blockSize
}

// deref resolves a reference back to a []uint32 slice.
func (a *closureArena) deref(ref arenaRef) []uint32 {
	if ref.length == 0 {
		return nil
	}
	end := ref.offset + ref.length
	return a.blocks[ref.blockIdx][ref.offset:end:end]
}

// ---- State Set Map ----
//
// The state set map provides O(1)-expected lookup from NFA-state-set closures
// to DFA-state IDs. It uses a fast FNV hash of the sorted closure as the
// primary map key (uint64), which is dramatically cheaper than hashing
// variable-length serialised byte strings.
//
// Both the primary key (uint64) and value ([stateSetEntry]) are pointer-free,
// so the GC skips the entire primary map — critical when the map holds
// millions of entries.

// stateSetEntry pairs an arena reference to a sorted NFA-state-set closure
// with its DFA-state ID. All fields are value types (pointer-free).
type stateSetEntry struct {
	ref     arenaRef
	stateID uint32
}

// stateSetMap is a two-tier hash table from NFA-state closures to DFA-state
// IDs. The primary map stores one entry per hash inline (no slice
// allocation). On the rare hash collision the entry is promoted to the
// overflow map, which uses the traditional slice-of-entries approach.
type stateSetMap struct {
	arena    *closureArena
	primary  map[uint64]stateSetEntry   // pointer-free key+value → GC skips
	overflow map[uint64][]stateSetEntry // rare collisions only
}

func newStateSetMap(initialCap int, arena *closureArena) *stateSetMap {
	return &stateSetMap{arena: arena, primary: make(map[uint64]stateSetEntry, initialCap)}
}

func (sm *stateSetMap) lookup(h uint64, sorted []uint32) (uint32, bool) {
	if e, ok := sm.primary[h]; ok {
		if slices.Equal(sm.arena.deref(e.ref), sorted) {
			return e.stateID, true
		}
		return 0, false
	}
	for _, e := range sm.overflow[h] {
		if slices.Equal(sm.arena.deref(e.ref), sorted) {
			return e.stateID, true
		}
	}
	return 0, false
}

func (sm *stateSetMap) insert(h uint64, ref arenaRef, stateID uint32) {
	entry := stateSetEntry{ref: ref, stateID: stateID}

	if ov, hasOv := sm.overflow[h]; hasOv {
		sm.overflow[h] = append(ov, entry)
		return
	}
	if e, exists := sm.primary[h]; !exists {
		sm.primary[h] = entry
	} else {
		// Hash collision — promote to overflow.
		if sm.overflow == nil {
			sm.overflow = make(map[uint64][]stateSetEntry)
		}
		sm.overflow[h] = []stateSetEntry{e, entry}
		delete(sm.primary, h)
	}
}

// closureHash computes a fast FNV-1a hash of a sorted NFA state set.
func closureHash(states []uint32) uint64 {
	h := uint64(14695981039346656037) // FNV-1a offset basis
	for _, s := range states {
		h ^= uint64(s)
		h *= 1099511628211 // FNV-1a prime
	}
	return h
}

// subsetWorkItem pairs a DFA state ID with a pointer-free arena reference
// to the NFA states it represents. All fields are value types, so slices
// of subsetWorkItem are invisible to the GC.
type subsetWorkItem struct {
	id  uint32
	ref arenaRef
}

// subsetBuilder holds the mutable state shared during subset construction,
// avoiding closure captures and reducing parameter passing.
type subsetBuilder struct {
	nfa         *nfa
	md          *intermediateDFA
	closures    *closureScratch
	stateMap    *stateSetMap
	worklist    []subsetWorkItem
	transitions subsetTransitionScratch
	maxStates   int
	arena       closureArena
}

// lookupOrCreateState returns the DFA-state ID for the given epsilon closure,
// creating a new state when no matching closure exists yet. Unlike
// getOrCreateState, the caller must provide a pre-computed closure.
//
// Lookup uses a uint64 FNV hash for O(1)-expected map access, with full
// sorted-closure comparison on the rare collision.
func (b *subsetBuilder) lookupOrCreateState(closure []uint32) (uint32, error) {
	h := closureHash(closure)
	if existingID, exists := b.stateMap.lookup(h, closure); exists {
		return existingID, nil
	}
	if b.maxStates > 0 && b.md.stateCount() >= b.maxStates {
		return 0, fmt.Errorf("automaton: exceeded MaxStates limit (%d)", b.maxStates)
	}
	newID := uint32(b.md.stateCount()) //nolint:gosec // bounded by maxStates, stateCount() is always ≥0
	ref := b.arena.cloneRef(closure)
	b.stateMap.insert(h, ref, newID)
	accept, ruleIDs := computeAccept(b.nfa, closure)
	b.md.addState(accept, ruleIDs)
	b.worklist = append(b.worklist, subsetWorkItem{id: newID, ref: ref})
	return newID, nil
}

// getOrCreateState computes the epsilon closure of source and then looks up
// or creates the corresponding DFA state.
func (b *subsetBuilder) getOrCreateState(source []uint32) (uint32, error) {
	closure := epsilonClosure(b.closures, b.nfa, source)
	return b.lookupOrCreateState(closure)
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
	// Pre-allocate with generous capacity to reduce growslice overhead.
	// Real-world filter lists typically produce O(100K–10M) DFA states.
	// When MaxStates is set, cap the pre-allocation to avoid wasting memory
	// on compilations that are expected to stay small.
	const initialDFACap = 1 << 22 // 4 Mi states
	preallocCap := initialDFACap
	if maxStates > 0 && maxStates < initialDFACap {
		preallocCap = maxStates * 2
		if preallocCap < 1024 {
			preallocCap = 1024
		}
	}
	md := &intermediateDFA{
		trans:   make([]uint32, 0, preallocCap*AlphabetSize),
		accept:  make([]bool, 0, preallocCap),
		ruleIDs: make(map[int][]uint32),
	}
	b := &subsetBuilder{
		nfa:       n,
		md:        md,
		closures:  newClosureScratch(len(n.states)),
		worklist:  make([]subsetWorkItem, 0, preallocCap),
		maxStates: maxStates,
	}
	b.stateMap = newStateSetMap(preallocCap, &b.arena)

	startResult := epsilonClosure(b.closures, n, []uint32{uint32(n.start)}) //nolint:gosec // n.start is always ≥0
	startRef := b.arena.cloneRef(startResult)
	b.stateMap.insert(closureHash(startResult), startRef, 0)
	md.start = 0

	accept, ruleIDs := computeAccept(n, startResult)
	md.addState(accept, ruleIDs)
	b.worklist = append(b.worklist, subsetWorkItem{id: 0, ref: startRef})

	// Scratch buffer for caching the wildcard closure per work item.
	// Computing epsilonClosure(wildcardTargets) once and merging it with
	// each literal closure via sortedUnion avoids redundant epsilon
	// expansions of the (often large) wildcard state set.
	var wcClosureBuf []uint32
	var mergeBuf []uint32

	for len(b.worklist) > 0 {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, errors.New("automaton: subset construction timeout")
		}

		currentItem := b.worklist[0]
		b.worklist = b.worklist[1:]
		current := b.arena.deref(currentItem.ref)
		currentID := currentItem.id
		b.transitions.collect(n, current)

		curTrans := md.stateTrans(int(currentID))

		// If any NFA states in this set have wildcard transitions, the
		// default for every alphabet symbol points to the wildcard closure.
		if len(b.transitions.wildcardTargets) > 0 {
			wcClosure := epsilonClosure(b.closures, n, b.transitions.wildcardTargets)

			// Cache the wildcard closure before the next epsilonClosure call
			// overwrites cs.result.
			wcClosureBuf = append(wcClosureBuf[:0], wcClosure...)

			wildcardID, wErr := b.lookupOrCreateState(wcClosure)
			if wErr != nil {
				return nil, wErr
			}
			for idx := range AlphabetSize {
				curTrans[idx] = wildcardID
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
				curTrans[idx] = stateID
				continue
			}

			// Compute the literal-only closure and merge with the cached
			// wildcard closure. This is cheaper than recomputing the full
			// epsilon closure of the concatenated target list because the
			// wildcard closure (often large) is computed only once per
			// work item.
			litClosure := epsilonClosure(b.closures, n, literalTargets)
			merged := sortedUnion(wcClosureBuf, litClosure, &mergeBuf)

			stateID, stateErr := b.lookupOrCreateState(merged)
			if stateErr != nil {
				return nil, stateErr
			}
			curTrans[idx] = stateID
		}
	}

	return md, nil
}

// computeAccept derives the accept flag and merged rule IDs for a DFA state
// that represents the given set of NFA states.
func computeAccept(n *nfa, stateSet []uint32) (accept bool, ruleIDs []uint32) {
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

// makeSetKeyBytes serializes a sorted NFA state set into a deterministic
// binary key. Each state ID occupies a fixed four-byte little-endian slot so
// concatenated keys are unambiguous. The buf parameter is a reusable scratch
// buffer to reduce allocations.
//
// Callers that need a string key for map storage should wrap the result with
// string(b). For map reads, Go optimises m[string(b)] to avoid heap
// allocation.
func makeSetKeyBytes(buf *[]byte, states []uint32) []byte {
	b := (*buf)[:0]
	for _, s := range states {
		b = append(b,
			byte(s&0xff),
			byte(s>>8&0xff),
			byte(s>>16&0xff),
			byte(s>>24&0xff),
		)
	}
	*buf = b
	return b
}

// makeSetKey serializes a sorted NFA state set into a deterministic binary
// key for the state-map lookup during subset construction.
//
// Each state ID occupies a fixed four-byte little-endian slot, so
// concatenated keys are unambiguous without delimiter characters or
// variable-length encoding. The buf parameter is a reusable scratch buffer
// to reduce allocations.
func makeSetKey(buf *[]byte, states []uint32) string {
	b := makeSetKeyBytes(buf, states)
	return string(b)
}

// sortedUnion merges two sorted, duplicate-free uint32 slices into one sorted,
// duplicate-free result. It uses buf as scratch space to avoid per-call
// allocation.
func sortedUnion(a, b []uint32, buf *[]uint32) []uint32 {
	out := (*buf)[:0]
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			out = append(out, a[i])
			i++
		case a[i] > b[j]:
			out = append(out, b[j])
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	out = append(out, a[i:]...)
	out = append(out, b[j:]...)
	*buf = out
	return out
}
