package automaton

import (
	"runtime"
	"sync"
)

// byteIndex maps ASCII byte values to alphabet indices for fast backward
// iteration in [DFA.MatchDomain]. Using a 256-byte lookup table avoids the
// switch ladder and rune conversion overhead of [runeToIndex] in the hot loop.
var byteIndex [256]byte

func init() {
	for i := range byteIndex {
		byteIndex[i] = noAlphabetIndex
	}
	for r := byte('a'); r <= byte('z'); r++ {
		byteIndex[r] = r - 'a'
	}
	for r := byte('A'); r <= byte('Z'); r++ {
		byteIndex[r] = r - 'A'
	}
	for r := byte('0'); r <= byte('9'); r++ {
		byteIndex[r] = 26 + r - '0'
	}
	byteIndex['-'] = 36
	byteIndex['.'] = 37
}

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

type ruleSpan struct {
	start int
	len   int
}

// transAcceptBit marks the target state as accepting. Stored in bit 31
// of each d.trans entry alongside the target state index in bits 0–30.
const transAcceptBit uint32 = 1 << 31

// transStateMask extracts the target state index (bits 0–30).
const transStateMask uint32 = transAcceptBit - 1

// DFA is a compiled deterministic finite automaton for domain name matching.
//
// The runtime layout encodes each transition as a uint32 with the target
// state index in bits 0–30 and the target's accept flag in bit 31.
// [noTransitionState] (0xFFFFFFFF) represents "no transition".
// Embedding the accept flag lets [DFA.MatchDomain] check acceptance from
// the same value it already loaded for the transition — no separate array
// access needed at domain-boundary positions.
//
// [byteIndex] maps both upper- and lowercase ASCII letters to the same
// alphabet index, making [DFA.Match] and [DFA.MatchDomain] inherently
// case-insensitive. Callers need not lowercase their input.
//
// The pointer-linked state graph is still materialized in [states] and
// [start] for tests and diagnostics.
//
// Create a DFA with [Compile]; query it with [DFA.Match].
type DFA struct {
	start      *DFAState
	states     []DFAState
	startIndex int
	trans      []uint32 // (acceptBit<<31) | targetStateIndex
	accept     []bool
	ruleSpans  []ruleSpan
	ruleIDData []uint32
}

// Match checks whether input is accepted by the compiled DFA and returns the
// matching rule IDs.
//
// The input parameter should be a DNS domain name. Case is handled
// transparently by [byteIndex]. Match traverses the DFA one byte at a time
// in O(n) where n = len(input). It returns false immediately when a byte
// falls outside the DNS alphabet or leads to a dead end.
//
// A nil or empty DFA always returns (false, nil).
func (d *DFA) Match(input string) (matched bool, ruleIDs []uint32) {
	if d == nil || len(d.accept) == 0 {
		return false, nil
	}

	trans := d.trans
	state := d.startIndex
	n := len(input)

	if n == 0 {
		if d.accept[state] {
			return true, d.ruleIDsForState(state)
		}
		return false, nil
	}

	var lastP uint32
	for i := 0; i < n; i++ {
		idx := byteIndex[input[i]]
		if idx == noAlphabetIndex {
			return false, nil
		}
		lastP = trans[state*AlphabetSize+int(idx)]
		if lastP == noTransitionState {
			return false, nil
		}
		state = int(lastP & transStateMask)
	}
	if lastP&transAcceptBit != 0 {
		return true, d.ruleIDsForState(state)
	}
	return false, nil
}

// MatchDomain checks whether the DFA — compiled from reversed patterns —
// matches the given domain name with ||domain^ anchoring semantics.
//
// Instead of reversing the input string (which would allocate), MatchDomain
// walks the input bytes from right to left, feeding them into the DFA one
// character at a time. This is equivalent to feeding the reversed input in
// forward order.
//
// A match is recorded whenever the DFA reaches an accepting state at a domain
// boundary, defined as:
//   - the beginning of the input (i == 0, meaning the entire name matched), or
//   - immediately after a '.' label separator (input[i-1] == '.').
//
// This boundary logic replaces the old approach of generating synthetic
// "*.<pattern>" variants for every rule, which caused exponential DFA state
// explosion when the original pattern already contained wildcards.
//
// Each d.trans entry stores the target state index in bits 0–30 and the
// accept flag in bit 31, so boundary accept checks read the already-loaded
// transition value — no separate d.accept array access required.
//
// The input parameter should be a DNS domain name without trailing dot.
// Case is handled transparently by [byteIndex]. A nil or empty DFA always
// returns (false, nil).
//
// Typical callers are [matcher.Matcher.Match] and other high-level entry
// points that compile reversed patterns via [Compile]. For raw exact-match
// semantics on non-reversed patterns, use [DFA.Match] instead.
func (d *DFA) MatchDomain(input string) (matched bool, ruleIDs []uint32) {
	if d == nil || len(d.accept) == 0 {
		return false, nil
	}

	trans := d.trans
	state := d.startIndex
	n := len(input)

	if n == 0 {
		if d.accept[state] {
			return true, d.ruleIDsForState(state)
		}
		return false, nil
	}

	firstState := -1

	for i := n - 1; i >= 0; i-- {
		idx := byteIndex[input[i]]
		if idx == noAlphabetIndex {
			break
		}
		p := trans[state*AlphabetSize+int(idx)]
		if p == noTransitionState {
			break
		}
		state = int(p & transStateMask)

		if i > 0 && input[i-1] != '.' {
			continue
		}
		if p&transAcceptBit == 0 {
			continue
		}

		ids := d.ruleIDsForState(state)
		switch {
		case !matched:
			matched = true
			firstState = state
		case ruleIDs == nil:
			firstIDs := d.ruleIDsForState(firstState)
			// Second boundary hit — allocate and merge both sets.
			ruleIDs = make([]uint32, 0, len(firstIDs)+len(ids))
			ruleIDs = append(ruleIDs, firstIDs...)
			ruleIDs = appendUniqueIDs(ruleIDs, ids)
		default:
			ruleIDs = appendUniqueIDs(ruleIDs, ids)
		}
	}

	if ruleIDs != nil {
		return matched, ruleIDs
	}
	if firstState >= 0 {
		return true, d.ruleIDsForState(firstState)
	}
	return false, nil
}

func (d *DFA) ruleIDsForState(state int) []uint32 {
	span := d.ruleSpans[state]
	if span.len == 0 {
		return nil
	}
	return d.ruleIDData[span.start : span.start+span.len]
}

// appendUniqueIDs appends rule IDs from src to dst, skipping duplicates.
// The expected cardinality is tiny (1–3 IDs per match), so a linear scan
// is faster than a hash set.
func appendUniqueIDs(dst, src []uint32) []uint32 {
	for _, id := range src {
		dup := false
		for _, existing := range dst {
			if existing == id {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, id)
		}
	}
	return dst
}

// StateCount reports how many DFA states are currently allocated.
//
// Returns 0 for a nil receiver or an empty DFA. Callers typically use this
// for metrics, diagnostics, and capacity planning.
func (d *DFA) StateCount() int {
	if d == nil {
		return 0
	}
	return len(d.accept)
}

// toDFA converts an intermediate DFA (used during compilation) to the
// exported [DFA].
//
// The conversion allocates all [DFAState] values in a single contiguous slice
// and patches transition entries to point directly into that slice. Once the
// pointer-based representation is built, the flat transition table is
// re-encoded in-place to store pre-multiplied base offsets
// (targetState × [AlphabetSize]) with the accept flag in bit 31. This
// encoding is consumed by [DFA.Match] and [DFA.MatchDomain] at runtime.
//
// For large state counts the patching work is distributed across goroutines,
// where each goroutine processes a disjoint chunk of the state slice.
func (md *intermediateDFA) toDFA() *DFA {
	n := md.stateCount()
	d := &DFA{
		startIndex: md.start,
		trans:      make([]uint32, len(md.trans)),
		accept:     make([]bool, len(md.accept)),
		ruleSpans:  make([]ruleSpan, n),
		states:     make([]DFAState, n),
	}

	if n == 0 {
		return d
	}

	copy(d.trans, md.trans)
	copy(d.accept, md.accept)

	totalRuleIDs := 0
	for _, ids := range md.ruleIDs {
		totalRuleIDs += len(ids)
	}
	if totalRuleIDs > 0 {
		d.ruleIDData = make([]uint32, 0, totalRuleIDs)
	}
	for i := range n {
		ids := md.ruleIDs[i]
		if len(ids) == 0 {
			continue
		}
		start := len(d.ruleIDData)
		d.ruleIDData = append(d.ruleIDData, ids...)
		d.ruleSpans[i] = ruleSpan{start: start, len: len(ids)}
	}

	// Build pointer-based state graph from raw state indices in d.trans.
	numWorkers := runtime.GOMAXPROCS(0)

	if n >= numWorkers*64 && numWorkers > 1 {
		chunkSize := (n + numWorkers - 1) / numWorkers
		var wg sync.WaitGroup
		for w := range numWorkers {
			lo := w * chunkSize
			if lo >= n {
				break
			}
			hi := min(lo+chunkSize, n)
			wg.Add(1)
			go func(lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					ds := &d.states[i]
					ds.Accept = d.accept[i]
					ds.RuleIDs = d.ruleIDsForState(i)
					trans := d.trans[i*AlphabetSize : (i+1)*AlphabetSize]
					for idx, target := range trans {
						if target != noTransitionState {
							ds.Trans[idx] = &d.states[target]
						}
					}
				}
			}(lo, hi)
		}
		wg.Wait()
	} else {
		for i := range n {
			d.states[i].Accept = d.accept[i]
			d.states[i].RuleIDs = d.ruleIDsForState(i)
		}
		for i := range n {
			trans := d.trans[i*AlphabetSize : (i+1)*AlphabetSize]
			for idx, target := range trans {
				if target != noTransitionState {
					d.states[i].Trans[idx] = &d.states[target]
				}
			}
		}
	}

	d.start = &d.states[d.startIndex]

	// Re-encode d.trans in-place: set the accept bit (bit 31) for each
	// transition whose target state is accepting. After this point d.trans
	// entries are consumed only by Match/MatchDomain.
	for i, t := range d.trans {
		if t != noTransitionState {
			target := int(t) //nolint:gosec // bounded by state count
			if d.accept[target] {
				d.trans[i] = t | transAcceptBit
			}
		}
	}

	return d
}
