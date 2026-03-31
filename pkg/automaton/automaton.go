// Package automaton compiles domain filter patterns into a cache-optimized,
// array-based deterministic finite automaton (DFA) with rule attribution.
//
// The compilation pipeline is: Thompson NFA → subset construction → Hopcroft
// minimization → contiguous-slice DFA with direct-pointer transitions.
//
// The supported pattern language is intentionally small:
//   - Literal characters: a-z, 0-9, '-', '.'
//   - Wildcard: '*' matches zero or more DNS characters
//   - Patterns are implicitly anchored (full match)
//
// Example usage:
//
//	dfa, err := automaton.Compile(patterns, automaton.CompileOptions{})
//	matched, ruleIDs := dfa.Match("ads.example.com")
package automaton

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Logger receives progress messages during DFA compilation.
// The watcher and CoreDNS plugin pass their logger here so users
// see what is happening during potentially long compilations.
type Logger interface {
	Infof(format string, args ...interface{})
}

func nopLogf(string, ...interface{}) {}

// AlphabetSize is the number of characters in the DNS alphabet (a-z, 0-9, '-', '.').
const AlphabetSize = 38

// dnsAlphabet lists all valid DNS characters in index order.
var dnsAlphabet [AlphabetSize]rune

func init() {
	for i := range AlphabetSize {
		dnsAlphabet[i] = IndexToRune(i)
	}
}

// RuneToIndex maps r to its DFA transition index.
//
// The r parameter must be a lowercase DNS character from the supported
// alphabet a-z, 0-9, '-', or '.'. The return value is the array index used by
// DFAState.Trans, or -1 when r is outside that alphabet. Callers typically use
// RuneToIndex on hot matching paths before following a transition.
func RuneToIndex(r rune) int {
	switch {
	case r >= 'a' && r <= 'z':
		return int(r - 'a')
	case r >= '0' && r <= '9':
		return 26 + int(r-'0')
	case r == '-':
		return 36
	case r == '.':
		return 37
	default:
		return -1
	}
}

// IndexToRune maps i back to the DNS character used at that transition slot.
//
// The i parameter must be in the inclusive range [0, AlphabetSize). The return
// value is the DNS rune stored at that index, or -1 when i is outside the
// supported alphabet. This is mainly useful for diagnostics such as DOT output
// and test assertions rather than the runtime match path.
func IndexToRune(i int) rune {
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

// ---- NFA ----

const epsilon rune = 0 // epsilon transitions use rune 0
const noTransitionState = -1

// nfaState is one node in the Thompson NFA with labeled transitions.
//
// Literal and epsilon transitions stay sparse in trans. Wildcard loops use
// anyDNS so '*' does not have to materialize 38 explicit rune transitions.
type nfaState struct {
	trans   map[rune][]int // rune -> list of target state IDs
	anyDNS  []int          // transitions taken for any DNS character
	accept  bool
	ruleIDs []uint32
}

// nfa holds the complete non-deterministic finite automaton before subset construction.
type nfa struct {
	states []nfaState
	start  int
}

// newNFA allocates an empty NFA with no states.
func newNFA() *nfa {
	return &nfa{}
}

// addState appends a fresh state and returns its ID.
func (n *nfa) addState() int {
	id := len(n.states)
	n.states = append(n.states, nfaState{trans: make(map[rune][]int)})
	return id
}

// addTrans records a labeled transition from one NFA state to another.
func (n *nfa) addTrans(from int, r rune, to int) {
	n.states[from].trans[r] = append(n.states[from].trans[r], to)
}

// addAnyDNSTrans records a transition taken for any supported DNS character.
func (n *nfa) addAnyDNSTrans(from int, to int) {
	n.states[from].anyDNS = append(n.states[from].anyDNS, to)
}

// buildPatternNFA constructs a Thompson NFA for a single pattern.
// Pattern language: literal chars, '.' literal, '*' = zero-or-more DNS chars.
func buildPatternNFA(pattern string, ruleID uint32) (*nfa, error) {
	n := newNFA()
	start := n.addState()
	n.start = start

	current := start
	for _, r := range pattern {
		switch {
		case r == '*':
			// Wildcard: self-loop on the DNS character class.
			loopState := n.addState()
			n.addTrans(current, epsilon, loopState)
			n.addAnyDNSTrans(loopState, loopState)
			current = loopState
		case RuneToIndex(r) >= 0:
			next := n.addState()
			n.addTrans(current, r, next)
			current = next
		default:
			return nil, fmt.Errorf("unsupported character %q in pattern", r)
		}
	}

	// Mark final state as accept
	n.states[current].accept = true
	n.states[current].ruleIDs = []uint32{ruleID}
	return n, nil
}

// combineNFAs merges multiple NFAs into one with a new start state connected
// via epsilon transitions.
func combineNFAs(nfas []*nfa) *nfa {
	combined := newNFA()
	newStart := combined.addState()
	combined.start = newStart

	for _, sub := range nfas {
		offset := len(combined.states)
		// Copy all states
		for _, s := range sub.states {
			newID := combined.addState()
			combined.states[newID].accept = s.accept
			combined.states[newID].ruleIDs = append([]uint32(nil), s.ruleIDs...)
		}
		// Rewrite transitions with offset
		for i, s := range sub.states {
			for r, targets := range s.trans {
				for _, t := range targets {
					combined.addTrans(i+offset, r, t+offset)
				}
			}
			for _, t := range s.anyDNS {
				combined.addAnyDNSTrans(i+offset, t+offset)
			}
		}
		// Epsilon from new start to sub's start
		combined.addTrans(newStart, epsilon, sub.start+offset)
	}
	return combined
}

// epsilonClosure computes the set of states reachable from the given set via
// epsilon transitions (BFS).
func epsilonClosure(n *nfa, states []int) []int {
	visited := make(map[int]bool)
	stack := make([]int, len(states))
	copy(stack, states)
	for _, s := range states {
		visited[s] = true
	}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, t := range n.states[s].trans[epsilon] {
			if !visited[t] {
				visited[t] = true
				stack = append(stack, t)
			}
		}
	}
	result := make([]int, 0, len(visited))
	for s := range visited {
		result = append(result, s)
	}
	sort.Ints(result)
	return result
}

// ---- Intermediate DFA (used only during construction and minimization) ----

// intermediateDFAState is one state in the intermediate DFA.
//
// Transitions are stored in a compact, fixed-size array indexed by
// RuneToIndex to reduce heap churn during subset construction and Hopcroft
// minimization.
type intermediateDFAState struct {
	trans   [AlphabetSize]int
	accept  bool
	ruleIDs []uint32
}

// intermediateDFA is the temporary DFA used during subset construction and
// Hopcroft minimization before conversion to the exported pointer-based DFA.
type intermediateDFA struct {
	start  int
	states []intermediateDFAState
}

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

// ---- Exported DFA (array-based, cache-optimized) ----

// DFAState represents a single state in the deterministic finite automaton.
// Transitions are stored in a fixed-size array indexed by [RuneToIndex],
// with nil entries indicating no transition (dead end). Each non-nil entry
// is a direct pointer to the successor state — no map lookups or index
// indirection at match time.
type DFAState struct {
	Trans   [AlphabetSize]*DFAState
	Accept  bool
	RuleIDs []uint32 // which rules led to this accept state
}

// DFA is an array-based deterministic finite automaton compiled from domain
// filter patterns. States reside in a single contiguous slice for cache
// locality and transitions are direct pointers — no map lookups or index
// indirection at match time.
type DFA struct {
	start  *DFAState
	states []DFAState
}

// CompileOptions controls the compilation process.
type CompileOptions struct {
	// MaxStates limits the number of DFA states. 0 means no limit.
	MaxStates int
	// Minimize enables Hopcroft minimization (default: true via zero value handling).
	Minimize *bool
	// CompileTimeout is the maximum time allowed for compilation.
	CompileTimeout time.Duration
	// Logger receives progress messages during compilation. May be nil.
	Logger Logger
}

// shouldMinimize returns whether Hopcroft minimization is enabled for these options.
func shouldMinimize(opts CompileOptions) bool {
	if opts.Minimize == nil {
		return true // default to minimize
	}
	return *opts.Minimize
}

// Pattern pairs a canonical filter pattern string with its rule ID.
type Pattern struct {
	Expr   string // canonical pattern (lowercase DNS chars and '*')
	RuleID uint32 // caller-assigned identifier for match attribution
}

// Compile compiles patterns into a minimized DFA ready for repeated Match
// calls.
//
// Each Pattern carries a lowercase expression string from the supported
// alphabet (a-z, 0-9, '-', '.', '*') and a caller-assigned rule ID that is
// preserved in accept states for match attribution. The opts parameter
// controls state limits, Hopcroft minimization, an optional compile timeout,
// and a progress logger.
//
// On failure Compile returns an error describing invalid patterns, timeout
// exhaustion, or MaxStates violations.
func Compile(patterns []Pattern, opts CompileOptions) (*DFA, error) {
	logf := nopLogf
	if opts.Logger != nil {
		logf = opts.Logger.Infof
	}

	if len(patterns) == 0 {
		logf("automaton: 0 patterns, nothing to compile")
		return &DFA{}, nil
	}

	started := time.Now()
	deadline := time.Time{}
	if opts.CompileTimeout > 0 {
		deadline = time.Now().Add(opts.CompileTimeout)
	}

	// Build per-pattern NFAs.
	logf("automaton: building %d NFAs...", len(patterns))
	nfaStart := time.Now()
	nfas := make([]*nfa, 0, len(patterns))
	for i, p := range patterns {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, fmt.Errorf("automaton: compile timeout after %d/%d patterns", i, len(patterns))
		}
		expr := strings.ToLower(p.Expr)
		n, err := buildPatternNFA(expr, p.RuleID)
		if err != nil {
			return nil, fmt.Errorf("automaton: pattern %d: %w", i, err)
		}
		nfas = append(nfas, n)
	}
	logf("automaton: NFA build: %v", time.Since(nfaStart))

	// Combine into single NFA.
	combineStart := time.Now()
	combined := combineNFAs(nfas)
	logf("automaton: NFA combine: %v (%d NFA states)", time.Since(combineStart), len(combined.states))

	// Subset construction: NFA → map-based DFA.
	logf("automaton: starting subset construction...")
	subsetStart := time.Now()
	md, err := subsetConstruction(combined, opts.MaxStates, deadline)
	if err != nil {
		return nil, err
	}
	logf("automaton: subset construction: %v (%d DFA states)", time.Since(subsetStart), len(md.states))

	// Hopcroft minimization.
	if shouldMinimize(opts) {
		logf("automaton: starting Hopcroft minimization (%d states)...", len(md.states))
		hopcroftStart := time.Now()
		beforeStates := len(md.states)
		md = hopcroftMinimize(md)
		logf("automaton: Hopcroft minimization: %v (%d → %d states)",
			time.Since(hopcroftStart), beforeStates, len(md.states))
	}

	// Convert to array/pointer-based DFA.
	dfa := md.toDFA()
	logf("automaton: compiled %d patterns in %v (%d DFA states)",
		len(patterns), time.Since(started), dfa.StateCount())
	return dfa, nil
}

// toDFA converts an internal intermediate DFA to the exported pointer-based DFA.
func (md *intermediateDFA) toDFA() *DFA {
	d := &DFA{states: make([]DFAState, len(md.states))}

	for i := range md.states {
		ms := &md.states[i]
		d.states[i].Accept = ms.accept
		d.states[i].RuleIDs = ms.ruleIDs
	}

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

// subsetConstruction converts an NFA to an intermediate DFA using the classic algorithm.
func subsetConstruction(n *nfa, maxStates int, deadline time.Time) (*intermediateDFA, error) {
	md := &intermediateDFA{}

	stateMap := make(map[string]int)

	startClosure := epsilonClosure(n, []int{n.start})
	startKey := makeSetKey(startClosure)
	stateMap[startKey] = 0
	md.start = 0

	accept, ruleIDs := computeAccept(n, startClosure)
	md.states = append(md.states, newIntermediateDFAState(accept, ruleIDs))

	worklist := [][]int{startClosure}

	for len(worklist) > 0 {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, errors.New("automaton: subset construction timeout")
		}

		current := worklist[0]
		worklist = worklist[1:]
		currentKey := makeSetKey(current)
		currentID := stateMap[currentKey]

		for _, c := range dnsAlphabet {
			var moved []int
			for _, s := range current {
				moved = append(moved, n.states[s].trans[c]...)
				moved = append(moved, n.states[s].anyDNS...)
			}
			if len(moved) == 0 {
				continue
			}
			closure := epsilonClosure(n, moved)
			key := makeSetKey(closure)

			if _, exists := stateMap[key]; !exists {
				if maxStates > 0 && len(md.states) >= maxStates {
					return nil, fmt.Errorf("automaton: exceeded MaxStates limit (%d)", maxStates)
				}
				newID := len(md.states)
				stateMap[key] = newID
				a, rids := computeAccept(n, closure)
				md.states = append(md.states, newIntermediateDFAState(a, rids))
				worklist = append(worklist, closure)
			}

			md.states[currentID].trans[RuneToIndex(c)] = stateMap[key]
		}
	}

	return md, nil
}

// computeAccept derives the accept flag and merged rule IDs for a DFA state set.
func computeAccept(n *nfa, stateSet []int) (accept bool, ruleIDs []uint32) {
	seen := make(map[uint32]bool)
	for _, s := range stateSet {
		if n.states[s].accept {
			accept = true
			for _, id := range n.states[s].ruleIDs {
				if !seen[id] {
					seen[id] = true
					ruleIDs = append(ruleIDs, id)
				}
			}
		}
	}
	sort.Slice(ruleIDs, func(i, j int) bool { return ruleIDs[i] < ruleIDs[j] })
	return accept, ruleIDs
}

// makeSetKey serializes a sorted state set into a string key for the state map.
func makeSetKey(states []int) string {
	buf := make([]byte, 0, len(states)*6)
	for i, s := range states {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = strconv.AppendInt(buf, int64(s), 10)
	}
	return string(buf)
}

// ---- Hopcroft Minimization ----

// hopcroftMinimize merges equivalent states to produce a minimal DFA.
func hopcroftMinimize(md *intermediateDFA) *intermediateDFA {
	n := len(md.states)
	if n <= 1 {
		return md
	}

	// Initial partition: accept states vs non-accept states
	// Further split accept states by ruleID sets for correct attribution.
	partitionMap := make(map[string][]int)
	for i := range md.states {
		s := &md.states[i]
		key := "N"
		if s.accept {
			key = "A:" + ruleIDsKey(s.ruleIDs)
		}
		partitionMap[key] = append(partitionMap[key], i)
	}

	partitions := make([][]int, 0, len(partitionMap))
	for _, p := range partitionMap {
		partitions = append(partitions, p)
	}

	// stateToPartition: state -> partition index
	stateToPartition := make([]int, n)
	updateMapping := func() {
		for pi, p := range partitions {
			for _, s := range p {
				stateToPartition[s] = pi
			}
		}
	}
	updateMapping()

	// Hopcroft refinement
	changed := true
	for changed {
		changed = false
		var newPartitions [][]int
		for _, p := range partitions {
			split := splitPartition(md, p, stateToPartition)
			if len(split) > 1 {
				changed = true
			}
			newPartitions = append(newPartitions, split...)
		}
		partitions = newPartitions
		updateMapping()
	}

	// Build minimized intermediateDFA.
	minMD := &intermediateDFA{}
	partitionID := make(map[int]int)
	for pi := range partitions {
		partitionID[pi] = pi
	}
	minMD.states = make([]intermediateDFAState, len(partitions))
	for pi, p := range partitions {
		rep := p[0]
		minMD.states[pi] = newIntermediateDFAState(md.states[rep].accept, md.states[rep].ruleIDs)
		for idx, target := range md.states[rep].trans {
			if target != noTransitionState {
				minMD.states[pi].trans[idx] = partitionID[stateToPartition[target]]
			}
		}
	}
	minMD.start = partitionID[stateToPartition[md.start]]

	return minMD
}

// splitPartition refines one partition group by transition signature.
func splitPartition(md *intermediateDFA, partition, stateToPartition []int) [][]int {
	if len(partition) <= 1 {
		return [][]int{partition}
	}

	groups := make(map[string][]int)
	for _, s := range partition {
		key := mapTransitionSig(md, s, stateToPartition)
		groups[key] = append(groups[key], s)
	}

	result := make([][]int, 0, len(groups))
	for _, g := range groups {
		result = append(result, g)
	}
	return result
}

// mapTransitionSig computes a canonical transition fingerprint for partition refinement.
func mapTransitionSig(md *intermediateDFA, state int, stateToPartition []int) string {
	buf := make([]byte, 0, AlphabetSize*8)
	for idx, target := range md.states[state].trans {
		if target != noTransitionState {
			buf = strconv.AppendInt(buf, int64(idx), 10)
			buf = append(buf, ':')
			buf = strconv.AppendInt(buf, int64(stateToPartition[target]), 10)
			buf = append(buf, ',')
		}
	}
	return string(buf)
}

// ruleIDsKey serializes rule IDs into a string key for accept-state partitioning.
func ruleIDsKey(ids []uint32) string {
	buf := make([]byte, 0, len(ids)*4)
	for i, id := range ids {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = strconv.AppendUint(buf, uint64(id), 10)
	}
	return string(buf)
}

// ---- Match ----

// Match checks whether input is accepted by the compiled DFA.
//
// The input parameter should already be normalized to lowercase DNS form.
// Match returns whether the input matched any pattern, together with the
// matching rule IDs. The DFA traversal is O(n) in the length of input.
func (d *DFA) Match(input string) (matched bool, ruleIDs []uint32) {
	if d == nil || d.start == nil {
		return false, nil
	}
	s := d.start
	for _, r := range input {
		idx := RuneToIndex(r)
		if idx < 0 {
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
// It returns 0 for a nil receiver or an empty DFA. Callers typically use
// this for metrics, diagnostics, and capacity planning.
func (d *DFA) StateCount() int {
	if d == nil {
		return 0
	}
	return len(d.states)
}

// ---- DOT output ----

// DumpDot writes a Graphviz DOT representation of the DFA to w.
//
// The w parameter receives a directed graph that visualizes state transitions,
// accepting states, and rule attribution. DumpDot returns an error when d is
// nil or when writing to w fails. It is mainly intended for CLI debugging and
// offline inspection of compiled filter behavior.
func (d *DFA) DumpDot(w io.Writer) error {
	if d == nil {
		return errors.New("nil DFA")
	}
	if d.start == nil {
		_, err := fmt.Fprintln(w, "digraph DFA {\n  rankdir=LR;\n  empty [shape=note, label=\"empty DFA\"];\n}")
		return err
	}

	// Build pointer → index map for output
	stateIdx := make(map[*DFAState]int, len(d.states))
	for i := range d.states {
		stateIdx[&d.states[i]] = i
	}

	if _, err := fmt.Fprintln(w, "digraph DFA {"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  rankdir=LR;"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  start [shape=point];\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  start -> s%d;\n", stateIdx[d.start]); err != nil {
		return err
	}

	for i := range d.states {
		s := &d.states[i]
		shape := "circle"
		if s.Accept {
			shape = "doublecircle"
		}
		label := fmt.Sprintf("s%d", i)
		if s.Accept && len(s.RuleIDs) > 0 {
			label = fmt.Sprintf("s%d\\nrules:%v", i, s.RuleIDs)
		}
		if _, err := fmt.Fprintf(w, "  s%d [shape=%s, label=\"%s\"];\n", i, shape, label); err != nil {
			return err
		}

		// Group transitions by target to make cleaner labels
		targetChars := make(map[int][]rune)
		for idx, target := range s.Trans {
			if target != nil {
				targetChars[stateIdx[target]] = append(targetChars[stateIdx[target]], IndexToRune(idx))
			}
		}
		for target, chars := range targetChars {
			sort.Slice(chars, func(a, b int) bool { return chars[a] < chars[b] })
			label := compactRuneLabel(chars)
			if _, err := fmt.Fprintf(w, "  s%d -> s%d [label=\"%s\"];\n", i, target, label); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "}"); err != nil {
		return err
	}
	return nil
}

// compactRuneLabel formats a character set into a human-readable DOT edge label.
func compactRuneLabel(chars []rune) string {
	if len(chars) == AlphabetSize {
		return "[dns]"
	}
	if len(chars) > 10 {
		return fmt.Sprintf("[%d chars]", len(chars))
	}
	var b strings.Builder
	for _, c := range chars {
		b.WriteRune(c)
	}
	return b.String()
}
