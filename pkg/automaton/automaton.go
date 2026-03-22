// Package automaton provides compilation of domain filter patterns into a
// single minimized DFA with rule attribution (Thompson NFA → subset construction
// → Hopcroft minimization).
//
// The supported pattern language is intentionally small:
//   - Literal characters: a-z, 0-9, '-', '.'
//   - Wildcard: '*' matches zero or more DNS characters
//   - Patterns are implicitly anchored (full match)
//
// Example usage:
//
//	dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{})
//	matched, ruleIDs := dfa.Match("ads.example.com")
package automaton

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/tomtonic/coredns-regfilter/internal/util"
	"github.com/tomtonic/coredns-regfilter/pkg/filterlist"
)

// dnsAlphabet is the set of characters allowed in DNS names.
var dnsAlphabet []rune

func init() {
	for r := 'a'; r <= 'z'; r++ {
		dnsAlphabet = append(dnsAlphabet, r)
	}
	for r := '0'; r <= '9'; r++ {
		dnsAlphabet = append(dnsAlphabet, r)
	}
	dnsAlphabet = append(dnsAlphabet, '-', '.')
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
		if r == '*' {
			// Wildcard: self-loop on all DNS chars
			loopState := n.addState()
			n.addTrans(current, epsilon, loopState)
			for _, c := range dnsAlphabet {
				n.addTrans(loopState, c, loopState)
			}
			current = loopState
		} else if util.IsDNSChar(r) {
			next := n.addState()
			n.addTrans(current, r, next)
			current = next
		} else {
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

// ---- DFA ----

// DFAState represents a single state in the deterministic finite automaton.
type DFAState struct {
	Trans   map[rune]int // character -> next state ID
	Accept  bool
	RuleIDs []int // which rules led to this accept state
}

// DFA is a deterministic finite automaton with rule attribution.
type DFA struct {
	Start  int
	States []DFAState
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
		return &DFA{States: []DFAState{{Trans: make(map[rune]int)}}}, nil
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

	// Subset construction: NFA → DFA
	dfa, err := subsetConstruction(combined, opts.MaxStates, deadline)
	if err != nil {
		return nil, err
	}

	// Hopcroft minimization
	if shouldMinimize(opts) {
		dfa = hopcroftMinimize(dfa)
	}

	return dfa, nil
}

// subsetConstruction converts an NFA to a DFA using the classic algorithm.
func subsetConstruction(n *nfa, maxStates int, deadline time.Time) (*DFA, error) {
	dfa := &DFA{}

	// State set -> DFA state ID mapping
	stateMap := make(map[string]int)

	startClosure := epsilonClosure(n, []int{n.start})
	startKey := makeSetKey(startClosure)
	stateMap[startKey] = 0
	dfa.Start = 0

	// Compute accept and ruleIDs for start state
	accept, ruleIDs := computeAccept(n, startClosure)
	dfa.States = append(dfa.States, DFAState{
		Trans:   make(map[rune]int),
		Accept:  accept,
		RuleIDs: ruleIDs,
	})

	worklist := [][]int{startClosure}

	for len(worklist) > 0 {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, fmt.Errorf("automaton: subset construction timeout")
		}

		current := worklist[0]
		worklist = worklist[1:]
		currentKey := makeSetKey(current)
		currentID := stateMap[currentKey]

		for _, c := range dnsAlphabet {
			// Compute move(current, c) then epsilon-closure
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
				if maxStates > 0 && len(dfa.States) >= maxStates {
					return nil, fmt.Errorf("automaton: exceeded MaxStates limit (%d)", maxStates)
				}
				newID := len(dfa.States)
				stateMap[key] = newID
				a, rids := computeAccept(n, closure)
				dfa.States = append(dfa.States, DFAState{
					Trans:   make(map[rune]int),
					Accept:  a,
					RuleIDs: rids,
				})
				worklist = append(worklist, closure)
			}

			dfa.States[currentID].Trans[c] = stateMap[key]
		}
	}

	return dfa, nil
}

func computeAccept(n *nfa, stateSet []int) (bool, []int) {
	accept := false
	var ruleIDs []int
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
	// States are already sorted
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

func hopcroftMinimize(dfa *DFA) *DFA {
	n := len(dfa.States)
	if n <= 1 {
		return dfa
	}

	// Initial partition: accept states vs non-accept states
	// Further split accept states by ruleID sets for correct attribution.
	partitionMap := make(map[string][]int)
	for i, s := range dfa.States {
		key := "N"
		if s.Accept {
			key = "A:" + ruleIDsKey(s.RuleIDs)
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
			split := splitPartition(dfa, p, stateToPartition)
			if len(split) > 1 {
				changed = true
			}
			newPartitions = append(newPartitions, split...)
		}
		partitions = newPartitions
		updateMapping()
	}

	// Build minimized DFA
	minDFA := &DFA{}
	partitionID := make(map[int]int) // old partition index -> new state ID
	for pi := range partitions {
		partitionID[pi] = pi
	}
	minDFA.States = make([]DFAState, len(partitions))
	for pi, p := range partitions {
		rep := p[0]
		minDFA.States[pi] = DFAState{
			Trans:   make(map[rune]int),
			Accept:  dfa.States[rep].Accept,
			RuleIDs: dfa.States[rep].RuleIDs,
		}
		for r, target := range dfa.States[rep].Trans {
			minDFA.States[pi].Trans[r] = partitionID[stateToPartition[target]]
		}
	}
	minDFA.Start = partitionID[stateToPartition[dfa.Start]]

	return minDFA
}

func splitPartition(dfa *DFA, partition []int, stateToPartition []int) [][]int {
	if len(partition) <= 1 {
		return [][]int{partition}
	}

	// Group states by their transition signature.
	groups := make(map[string][]int)
	for _, s := range partition {
		key := transitionSig(dfa, s, stateToPartition)
		groups[key] = append(groups[key], s)
	}

	result := make([][]int, 0, len(groups))
	for _, g := range groups {
		result = append(result, g)
	}
	return result
}

func transitionSig(dfa *DFA, state int, stateToPartition []int) string {
	var b strings.Builder
	for _, c := range dnsAlphabet {
		target, ok := dfa.States[state].Trans[c]
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
func (d *DFA) Match(input string) (bool, []int) {
	if d == nil || len(d.States) == 0 {
		return false, nil
	}

	state := d.Start
	for _, r := range input {
		next, ok := d.States[state].Trans[r]
		if !ok {
			return false, nil
		}
		state = next
	}
	s := d.States[state]
	return s.Accept, s.RuleIDs
}

// StateCount returns the number of states in the DFA.
func (d *DFA) StateCount() int {
	if d == nil {
		return 0
	}
	return len(d.States)
}

// ---- DOT output ----

// DumpDot writes a Graphviz DOT representation of the DFA to w.
func (d *DFA) DumpDot(w io.Writer) error {
	if d == nil {
		return fmt.Errorf("nil DFA")
	}

	fmt.Fprintln(w, "digraph DFA {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintf(w, "  start [shape=point];\n")
	fmt.Fprintf(w, "  start -> s%d;\n", d.Start)

	for i, s := range d.States {
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
		for r, target := range s.Trans {
			targetChars[target] = append(targetChars[target], r)
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
	if len(chars) == len(dnsAlphabet) {
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
