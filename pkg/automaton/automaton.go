// Package automaton provides compilation of domain filter patterns into a
// single minimized DFA with rule attribution (Thompson NFA → subset construction
// → Hopcroft minimization).
//
// The supported pattern language is intentionally small:
//   - Literal characters: a-z, 0-9, '-', '.'
//   - Wildcard: '*' matches zero or more DNS characters
//   - Patterns are implicitly anchored (full match)
//
// The final DFA uses a cache-optimized, array-based representation: each state
// stores a fixed-size transition array indexed by [RuneToIndex], with direct
// pointers to successor states. No maps are used at match time.
//
// Example usage:
//
//	dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{})
//	matched, ruleIDs := dfa.Match("ads.example.com")
package automaton

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/tomtonic/coredns-regfilter/internal/util"
	"github.com/tomtonic/coredns-regfilter/pkg/filterlist"
)

// AlphabetSize is the number of characters in the DNS alphabet (a-z, 0-9, '-', '.').
const AlphabetSize = 38

// dnsAlphabet lists all valid DNS characters in index order.
var dnsAlphabet [AlphabetSize]rune

func init() {
	for i := range AlphabetSize {
		dnsAlphabet[i] = IndexToRune(i)
	}
}

// RuneToIndex maps a DNS character to its transition-array index (0–37).
// Returns -1 for characters outside the DNS alphabet.
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

// IndexToRune maps a transition-array index (0–37) back to its DNS character.
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
		panic(fmt.Sprintf("automaton: IndexToRune: index %d out of range [0,%d)", i, AlphabetSize))
	}
}

// ---- NFA ----

const epsilon rune = 0 // epsilon transitions use rune 0

type nfaState struct {
	trans   map[rune][]int // rune -> list of target state IDs
	accept  bool
	ruleIDs []int
}

type nfa struct {
	states []nfaState
	start  int
}

func newNFA() *nfa {
	return &nfa{}
}

func (n *nfa) addState() int {
	id := len(n.states)
	n.states = append(n.states, nfaState{trans: make(map[rune][]int)})
	return id
}

func (n *nfa) addTrans(from int, r rune, to int) {
	n.states[from].trans[r] = append(n.states[from].trans[r], to)
}

// buildPatternNFA constructs a Thompson NFA for a single pattern.
// Pattern language: literal chars, '.' literal, '*' = zero-or-more DNS chars.
func buildPatternNFA(pattern string, ruleID int) (*nfa, error) {
	n := newNFA()
	start := n.addState()
	n.start = start

	current := start
	for _, r := range pattern {
		switch {
		case r == '*':
			// Wildcard: self-loop on all DNS chars
			loopState := n.addState()
			n.addTrans(current, epsilon, loopState)
			for _, c := range dnsAlphabet {
				n.addTrans(loopState, c, loopState)
			}
			current = loopState
		case util.IsDNSChar(r):
			next := n.addState()
			n.addTrans(current, r, next)
			current = next
		default:
			return nil, fmt.Errorf("unsupported character %q in pattern", r)
		}
	}

	// Mark final state as accept
	n.states[current].accept = true
	n.states[current].ruleIDs = []int{ruleID}
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
			combined.states[newID].ruleIDs = append([]int(nil), s.ruleIDs...)
		}
		// Rewrite transitions with offset
		for i, s := range sub.states {
			for r, targets := range s.trans {
				for _, t := range targets {
					combined.addTrans(i+offset, r, t+offset)
				}
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

// ---- Map-based DFA (used only during construction and minimization) ----

type mapDFAState struct {
	trans   map[rune]int
	accept  bool
	ruleIDs []int
}

type mapDFA struct {
	start  int
	states []mapDFAState
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
	RuleIDs []int // which rules led to this accept state
}

// DFA is a deterministic finite automaton compiled from filter rules.
// All states reside in a single contiguous slice for cache locality.
// Transitions are direct pointers between states.
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
}

func shouldMinimize(opts CompileOptions) bool {
	if opts.Minimize == nil {
		return true // default to minimize
	}
	return *opts.Minimize
}

// CompileRules compiles filterlist rules into a single minimized DFA.
func CompileRules(rules []filterlist.Rule, opts CompileOptions) (*DFA, error) {
	if len(rules) == 0 {
		d := &DFA{states: make([]DFAState, 1)}
		d.start = &d.states[0]
		return d, nil
	}

	deadline := time.Time{}
	if opts.CompileTimeout > 0 {
		deadline = time.Now().Add(opts.CompileTimeout)
	}

	// Build per-rule NFAs
	var nfas []*nfa
	for i, rule := range rules {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, fmt.Errorf("automaton: compile timeout after %d/%d rules", i, len(rules))
		}
		pattern := strings.ToLower(rule.Pattern)
		n, err := buildPatternNFA(pattern, i)
		if err != nil {
			return nil, fmt.Errorf("automaton: rule %d (%s): %w", i, rule.Source, err)
		}
		nfas = append(nfas, n)
	}

	// Combine into single NFA
	combined := combineNFAs(nfas)

	// Subset construction: NFA → map-based DFA
	md, err := subsetConstruction(combined, opts.MaxStates, deadline)
	if err != nil {
		return nil, err
	}

	// Hopcroft minimization
	if shouldMinimize(opts) {
		md = hopcroftMinimize(md)
	}

	// Convert to array/pointer-based DFA
	return md.toDFA(), nil
}

// toDFA converts an internal map-based DFA to the exported pointer-based DFA.
func (md *mapDFA) toDFA() *DFA {
	d := &DFA{states: make([]DFAState, len(md.states))}

	for i, ms := range md.states {
		d.states[i].Accept = ms.accept
		d.states[i].RuleIDs = ms.ruleIDs
	}

	for i, ms := range md.states {
		for r, target := range ms.trans {
			idx := RuneToIndex(r)
			if idx >= 0 {
				d.states[i].Trans[idx] = &d.states[target]
			}
		}
	}

	d.start = &d.states[md.start]
	return d
}

// subsetConstruction converts an NFA to a map-based DFA using the classic algorithm.
func subsetConstruction(n *nfa, maxStates int, deadline time.Time) (*mapDFA, error) {
	md := &mapDFA{}

	stateMap := make(map[string]int)

	startClosure := epsilonClosure(n, []int{n.start})
	startKey := makeSetKey(startClosure)
	stateMap[startKey] = 0
	md.start = 0

	accept, ruleIDs := computeAccept(n, startClosure)
	md.states = append(md.states, mapDFAState{
		trans:   make(map[rune]int),
		accept:  accept,
		ruleIDs: ruleIDs,
	})

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
				md.states = append(md.states, mapDFAState{
					trans:   make(map[rune]int),
					accept:  a,
					ruleIDs: rids,
				})
				worklist = append(worklist, closure)
			}

			md.states[currentID].trans[c] = stateMap[key]
		}
	}

	return md, nil
}

func computeAccept(n *nfa, stateSet []int) (accept bool, ruleIDs []int) {
	seen := make(map[int]bool)
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
	sort.Ints(ruleIDs)
	return accept, ruleIDs
}

func makeSetKey(states []int) string {
	var b strings.Builder
	for i, s := range states {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", s)
	}
	return b.String()
}

// ---- Hopcroft Minimization ----

func hopcroftMinimize(md *mapDFA) *mapDFA {
	n := len(md.states)
	if n <= 1 {
		return md
	}

	// Initial partition: accept states vs non-accept states
	// Further split accept states by ruleID sets for correct attribution.
	partitionMap := make(map[string][]int)
	for i, s := range md.states {
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

	// Build minimized mapDFA
	minMD := &mapDFA{}
	partitionID := make(map[int]int)
	for pi := range partitions {
		partitionID[pi] = pi
	}
	minMD.states = make([]mapDFAState, len(partitions))
	for pi, p := range partitions {
		rep := p[0]
		minMD.states[pi] = mapDFAState{
			trans:   make(map[rune]int),
			accept:  md.states[rep].accept,
			ruleIDs: md.states[rep].ruleIDs,
		}
		for r, target := range md.states[rep].trans {
			minMD.states[pi].trans[r] = partitionID[stateToPartition[target]]
		}
	}
	minMD.start = partitionID[stateToPartition[md.start]]

	return minMD
}

func splitPartition(md *mapDFA, partition, stateToPartition []int) [][]int {
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

func mapTransitionSig(md *mapDFA, state int, stateToPartition []int) string {
	var b strings.Builder
	for _, c := range dnsAlphabet {
		target, ok := md.states[state].trans[c]
		if ok {
			fmt.Fprintf(&b, "%c:%d,", c, stateToPartition[target])
		}
	}
	return b.String()
}

func ruleIDsKey(ids []int) string {
	var b strings.Builder
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", id)
	}
	return b.String()
}

// ---- Match ----

// Match tests whether the input string is accepted by the DFA.
// Returns whether a match was found and the associated rule IDs.
// Uses direct pointer traversal with no map lookups.
func (d *DFA) Match(input string) (matched bool, ruleIDs []int) {
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
	return s.Accept, s.RuleIDs
}

// StateCount returns the number of states in the DFA.
func (d *DFA) StateCount() int {
	if d == nil {
		return 0
	}
	return len(d.states)
}

// ---- DOT output ----

// DumpDot writes a Graphviz DOT representation of the DFA to w.
func (d *DFA) DumpDot(w io.Writer) error {
	if d == nil {
		return errors.New("nil DFA")
	}

	// Build pointer → index map for output
	stateIdx := make(map[*DFAState]int, len(d.states))
	for i := range d.states {
		stateIdx[&d.states[i]] = i
	}

	fmt.Fprintln(w, "digraph DFA {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintf(w, "  start [shape=point];\n")
	fmt.Fprintf(w, "  start -> s%d;\n", stateIdx[d.start])

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
		fmt.Fprintf(w, "  s%d [shape=%s, label=\"%s\"];\n", i, shape, label)

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
			fmt.Fprintf(w, "  s%d -> s%d [label=\"%s\"];\n", i, target, label)
		}
	}

	fmt.Fprintln(w, "}")
	return nil
}

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
