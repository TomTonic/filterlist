package automaton

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

type ruleSpan struct {
	start int
	len   int
}

// transAcceptBit marks the target state as accepting. Stored in bit 31
// of each d.trans entry alongside the target's row offset in bits 0–30.
const transAcceptBit uint32 = 1 << 31

// transOffsetMask extracts the target's row offset (bits 0–30).
const transOffsetMask uint32 = transAcceptBit - 1

// maxRuntimeStates is the largest state count whose row offsets
// (state × [AlphabetSize]) still fit in bits 0–30 of a transition entry.
const maxRuntimeStates = int(transOffsetMask / AlphabetSize)

// DFA is a compiled deterministic finite automaton for domain name matching.
//
// The runtime layout is one flat []uint32 table of [AlphabetSize] entries per
// state. Each entry holds the target's row offset in that table (target
// state × [AlphabetSize]) in bits 0–30 and the target's accept flag in bit
// 31; [noTransitionState] (0xFFFFFFFF) represents "no transition".
//
// Every lookup step depends on the entry the previous step loaded. With row
// offsets the next address is that entry plus the alphabet index; with state
// indices it would need a multiply-add first. Embedding the accept flag lets
// [DFA.MatchDomain] check acceptance from the value it already loaded instead
// of reading a separate accept array at each label boundary.
//
// TestLayoutDecisions in this package measures both choices across 40
// processes on the realistic denylist samples. On an Apple M1 Pro, against
// state indices with accept bit, row offsets save about 6% per lookup on the
// small wildcard DFA of hybrid mode and make no measurable difference on the
// large DFA of dfa mode, where memory latency dominates; the accept bit saves
// about 1% against an accept array. A pointer-linked state graph is 16%
// faster on the small DFA, but 5% slower on the large one and needs twice
// the memory.
//
// [byteIndex] maps both upper- and lowercase ASCII letters to the same
// alphabet index, making [DFA.Match] and [DFA.MatchDomain] inherently
// case-insensitive. Callers need not lowercase their input.
//
// Create a DFA with [Compile]; query it with [DFA.Match].
type DFA struct {
	startOffset int      // row offset of the start state in trans
	trans       []uint32 // (acceptBit<<31) | targetState*AlphabetSize
	accept      []bool
	ruleSpans   []ruleSpan
	ruleIDData  []uint32
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
	off := d.startOffset
	n := len(input)

	if n == 0 {
		return d.startResult()
	}

	var lastP uint32
	for i := 0; i < n; i++ {
		idx := byteIndex[input[i]]
		if idx == noAlphabetIndex {
			return false, nil
		}
		lastP = trans[off+int(idx)]
		if lastP == noTransitionState {
			return false, nil
		}
		off = int(lastP & transOffsetMask)
	}
	if lastP&transAcceptBit != 0 {
		return true, d.ruleIDsForState(off / AlphabetSize)
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
// Each d.trans entry stores the target's row offset in bits 0–30 and its
// accept flag in bit 31, so boundary accept checks read the already-loaded
// transition value, and the state index needed for the rule IDs is computed
// only on a match.
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
	off := d.startOffset
	n := len(input)

	if n == 0 {
		return d.startResult()
	}

	firstState := -1

	for i := n - 1; i >= 0; i-- {
		idx := byteIndex[input[i]]
		if idx == noAlphabetIndex {
			break
		}
		p := trans[off+int(idx)]
		if p == noTransitionState {
			break
		}
		off = int(p & transOffsetMask)

		if i > 0 && input[i-1] != '.' {
			continue
		}
		if p&transAcceptBit == 0 {
			continue
		}

		state := off / AlphabetSize
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

// startResult answers an empty input, which matches if the start state
// accepts; it is the one lookup that never loads a transition.
func (d *DFA) startResult() (matched bool, ruleIDs []uint32) {
	state := d.startOffset / AlphabetSize
	if !d.accept[state] {
		return false, nil
	}
	return true, d.ruleIDsForState(state)
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
// The conversion copies the flat transition table, accept flags, and rule ID
// spans into the final runtime layout. Transition entries are then re-encoded
// in-place from target state indices to row offsets (target × [AlphabetSize])
// with the target's accept flag in bit 31. This encoding is consumed directly
// by [DFA.Match] and [DFA.MatchDomain].
//
// The intermediate DFA must not have more than [maxRuntimeStates] states, or
// the row offsets overflow; [Compile] checks this before calling toDFA.
func (md *intermediateDFA) toDFA() *DFA {
	n := md.stateCount()
	d := &DFA{
		startOffset: md.start * AlphabetSize,
		trans:       make([]uint32, len(md.trans)),
		accept:      make([]bool, len(md.accept)),
		ruleSpans:   make([]ruleSpan, n),
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

	// Re-encode d.trans in-place: replace each target state index by its row
	// offset and set the accept bit (bit 31) if the target accepts. After this
	// point d.trans entries are consumed only by Match/MatchDomain.
	for i, t := range d.trans {
		if t != noTransitionState {
			p := t * AlphabetSize
			if d.accept[t] {
				p |= transAcceptBit
			}
			d.trans[i] = p
		}
	}

	return d
}
