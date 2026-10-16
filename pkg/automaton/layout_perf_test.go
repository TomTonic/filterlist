package automaton

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/TomTonic/filterlist/internal/benchfixture"
	"github.com/TomTonic/rtcompare"
	"github.com/TomTonic/rtcompare/multiproc"
)

// This file measures the runtime layout of [DFA] against the layouts it
// replaced, with rtcompare's multi-process protocol, so that every layout
// decision rests on a measurement that holds across processes (see the
// rtcompare HOWTO, "One process is one observation"). The current layout
// stores each target's row offset (target × [AlphabetSize]) with its accept
// flag in bit 31. The alternatives, each differing from it in one decision:
//
//   - state indices with accept bit, the layout from 8fdd432 until the row
//     offsets replaced it: one multiply-add more per lookup step, see
//     flatVariant.matchIndexBit;
//   - state indices with accept array, the layout from 13d5b36 until 8fdd432,
//     see flatVariant.matchIndexArray;
//   - row offsets with accept array instead of accept bit, see
//     flatVariant.matchOffsetArray;
//   - the pointer-linked state graph before 13d5b36 ([AlphabetSize] pointers
//     per state, twice the memory of the table), see ptrDFA.
//
// A control pair runs the current code on a fresh copy of its own table: the
// variants' tables are fresh copies too, so a difference the control shows is
// one of memory placement that the variants' differences contain as well.
//
// The variants are built from a compiled DFA, so that all of them encode the
// same automaton. The replaced layouts are faithful copies of the code they
// replaced; the flat variants share the rule-ID merging of boundaryHits,
// which runs only on accepting label boundaries.

// ptrState is the pointer-linked state of the layout before 13d5b36.
type ptrState struct {
	trans   [AlphabetSize]*ptrState
	accept  bool
	ruleIDs []uint32
}

// ptrDFA is the pointer-linked DFA before 13d5b36, rebuilt from a compiled
// DFA; its states lie in one contiguous slice, as they did then.
type ptrDFA struct {
	start  *ptrState
	states []ptrState
}

// targetState decodes the target state index of a current transition entry,
// which must not be noTransitionState.
func targetState(t uint32) uint32 {
	return (t & transOffsetMask) / AlphabetSize
}

// newPtrDFA rebuilds the pointer-linked layout from d, so that both layouts
// encode the same automaton.
func newPtrDFA(d *DFA) *ptrDFA {
	n := d.StateCount()
	p := &ptrDFA{states: make([]ptrState, n)}
	for i := range n {
		s := &p.states[i]
		s.accept = d.accept[i]
		s.ruleIDs = d.ruleIDsForState(i)
		for c := range AlphabetSize {
			if t := d.trans[i*AlphabetSize+c]; t != noTransitionState {
				s.trans[c] = &p.states[targetState(t)]
			}
		}
	}
	if n > 0 {
		p.start = &p.states[d.startOffset/AlphabetSize]
	}
	return p
}

// matchDomain is DFA.MatchDomain as it was before 13d5b36: one pointer chase
// per input byte, accept flag and rule IDs read from the state itself.
func (p *ptrDFA) matchDomain(input string) (matched bool, ruleIDs []uint32) {
	if p.start == nil {
		return false, nil
	}
	s := p.start
	n := len(input)
	if n == 0 {
		if s.accept {
			return true, s.ruleIDs
		}
		return false, nil
	}

	var firstIDs []uint32
	for i := n - 1; i >= 0; i-- {
		idx := byteIndex[input[i]]
		if idx == noAlphabetIndex {
			break
		}
		next := s.trans[idx]
		if next == nil {
			break
		}
		s = next

		if s.accept && (i == 0 || input[i-1] == '.') {
			switch {
			case !matched:
				matched = true
				firstIDs = s.ruleIDs
			case ruleIDs == nil:
				ruleIDs = make([]uint32, 0, len(firstIDs)+len(s.ruleIDs))
				ruleIDs = append(ruleIDs, firstIDs...)
				ruleIDs = appendUniqueIDs(ruleIDs, s.ruleIDs)
			default:
				ruleIDs = appendUniqueIDs(ruleIDs, s.ruleIDs)
			}
		}
	}
	if ruleIDs != nil {
		return matched, ruleIDs
	}
	return matched, firstIDs
}

// flatVariant is a flat-table layout variant built from a compiled DFA. It
// owns its transition table, built in the candidate's builder; accept flags
// and rule IDs are read from the DFA it was built from. start is the start
// state's index or row offset, matching the encoding of trans.
type flatVariant struct {
	d     *DFA
	trans []uint32
	start int
}

// newIndexVariant builds a table of target state indices, with the target's
// accept flag in bit 31 if acceptBit is set: the layout from 8fdd432 with
// the bit, the one from 13d5b36 without it.
func newIndexVariant(d *DFA, acceptBit bool) *flatVariant {
	trans := make([]uint32, len(d.trans))
	for i, t := range d.trans {
		if t != noTransitionState {
			target := targetState(t)
			t = target
			if acceptBit && d.accept[target] {
				t |= transAcceptBit
			}
		}
		trans[i] = t
	}
	return &flatVariant{d: d, trans: trans, start: d.startOffset / AlphabetSize}
}

// newOffsetArrayVariant builds the current table of row offsets without the
// accept bit.
func newOffsetArrayVariant(d *DFA) *flatVariant {
	trans := make([]uint32, len(d.trans))
	for i, t := range d.trans {
		if t != noTransitionState {
			t &= transOffsetMask
		}
		trans[i] = t
	}
	return &flatVariant{d: d, trans: trans, start: d.startOffset}
}

// boundaryHits collects the rule IDs of the accepting label boundaries of one
// lookup exactly as DFA.MatchDomain does: the first boundary's IDs are
// returned without allocating, later ones are merged without duplicates.
type boundaryHits struct {
	d     *DFA
	first int
	ids   []uint32
}

func (h *boundaryHits) add(state int) {
	switch {
	case h.first < 0:
		h.first = state
	case h.ids == nil:
		firstIDs, ids := h.d.ruleIDsForState(h.first), h.d.ruleIDsForState(state)
		h.ids = make([]uint32, 0, len(firstIDs)+len(ids))
		h.ids = append(h.ids, firstIDs...)
		h.ids = appendUniqueIDs(h.ids, ids)
	default:
		h.ids = appendUniqueIDs(h.ids, h.d.ruleIDsForState(state))
	}
}

func (h *boundaryHits) result() (bool, []uint32) {
	if h.ids != nil {
		return true, h.ids
	}
	if h.first >= 0 {
		return true, h.d.ruleIDsForState(h.first)
	}
	return false, nil
}

// emptyResult answers the lookups that never enter the loop: an empty DFA,
// and an empty input, which matches if the start state accepts.
func (v *flatVariant) emptyResult() (bool, []uint32) {
	if len(v.d.accept) == 0 {
		return false, nil
	}
	return v.d.startResult()
}

// matchIndexBit is DFA.MatchDomain as it was from 8fdd432 until the row
// offsets: state indices with accept bit, so the next address needs a mask
// and a multiply-add after each load.
func (v *flatVariant) matchIndexBit(input string) (bool, []uint32) {
	n := len(input)
	if n == 0 || len(v.d.accept) == 0 {
		return v.emptyResult()
	}
	trans := v.trans
	state := v.start
	h := boundaryHits{d: v.d, first: -1}
	for i := n - 1; i >= 0; i-- {
		idx := byteIndex[input[i]]
		if idx == noAlphabetIndex {
			break
		}
		next := trans[state*AlphabetSize+int(idx)]
		if next == noTransitionState {
			break
		}
		state = int(next & transOffsetMask)
		if i > 0 && input[i-1] != '.' {
			continue
		}
		if next&transAcceptBit == 0 {
			continue
		}
		h.add(state)
	}
	return h.result()
}

// matchIndexArray is DFA.MatchDomain as it was between 13d5b36 and 8fdd432:
// state indices, accept flag read from the accept array at label boundaries.
func (v *flatVariant) matchIndexArray(input string) (bool, []uint32) {
	n := len(input)
	if n == 0 || len(v.d.accept) == 0 {
		return v.emptyResult()
	}
	trans, accept := v.trans, v.d.accept
	state := v.start
	h := boundaryHits{d: v.d, first: -1}
	for i := n - 1; i >= 0; i-- {
		idx := byteIndex[input[i]]
		if idx == noAlphabetIndex {
			break
		}
		next := trans[state*AlphabetSize+int(idx)]
		if next == noTransitionState {
			break
		}
		state = int(next)
		if i > 0 && input[i-1] != '.' {
			continue
		}
		if !accept[state] {
			continue
		}
		h.add(state)
	}
	return h.result()
}

// matchOffsetArray walks row offsets without accept bit: the next address
// needs only an add after each load, but every label boundary reads the
// accept array at off / AlphabetSize.
func (v *flatVariant) matchOffsetArray(input string) (bool, []uint32) {
	n := len(input)
	if n == 0 || len(v.d.accept) == 0 {
		return v.emptyResult()
	}
	trans, accept := v.trans, v.d.accept
	off := v.start
	h := boundaryHits{d: v.d, first: -1}
	for i := n - 1; i >= 0; i-- {
		idx := byteIndex[input[i]]
		if idx == noAlphabetIndex {
			break
		}
		next := trans[off+int(idx)]
		if next == noTransitionState {
			break
		}
		off = int(next)
		if i > 0 && input[i-1] != '.' {
			continue
		}
		state := off / AlphabetSize
		if !accept[state] {
			continue
		}
		h.add(state)
	}
	return h.result()
}

// layoutSink keeps the compiler from discarding the lookups of a batch.
var layoutSink int

// layoutFixture is what every process of the layout comparison builds once,
// after rtcompare has perturbed its heap: the query population and the two
// DFAs the plugin runs, the one of matcher_mode dfa (every rule) and the one
// of matcher_mode hybrid (wildcard rules only).
type layoutFixture struct {
	walker   *benchfixture.Walker // shared by both candidates, see [benchfixture.Walker]
	full     *DFA
	wildcard *DFA
}

// loadLayoutFixture builds the fixture the way the matcher would build its
// DFAs, so that the layouts are compared on the automata the plugin really
// queries.
func loadLayoutFixture() (*layoutFixture, error) {
	rules, err := benchfixture.DenylistRules()
	if err != nil {
		return nil, err
	}
	domains, err := benchfixture.TopDomains()
	if err != nil {
		return nil, err
	}
	seq, err := benchfixture.Sequence(benchfixture.SequenceLength(), len(domains), benchfixture.SequenceSeed)
	if err != nil {
		return nil, err
	}

	all := make([]Pattern, 0, len(rules))
	var wildcards []Pattern
	for i, r := range rules {
		p := Pattern{Expr: benchfixture.ReversedPattern(r.Pattern), RuleID: uint32(i)} //nolint:gosec // rule count is far below 2^32
		all = append(all, p)
		if strings.Contains(r.Pattern, "*") {
			wildcards = append(wildcards, p)
		}
	}
	full, err := Compile(all, CompileOptions{})
	if err != nil {
		return nil, fmt.Errorf("compile full DFA: %w", err)
	}
	wildcard, err := Compile(wildcards, CompileOptions{})
	if err != nil {
		return nil, fmt.Errorf("compile wildcard DFA: %w", err)
	}
	walker := benchfixture.NewWalker(benchfixture.Queries(domains, seq))
	return &layoutFixture{walker: walker, full: full, wildcard: wildcard}, nil
}

// currentCandidate measures the current layout: DFA.MatchDomain.
func currentCandidate(fx *layoutFixture, d *DFA) rtcompare.Candidate {
	w := fx.walker
	return rtcompare.Candidate{Name: "offset+acceptbit", Batch: func(n uint64) {
		hits := 0
		for range n {
			if hit, _ := d.MatchDomain(w.Next()); hit {
				hits++
			}
		}
		layoutSink += hits
	}}
}

// copyCandidate is the control: the current code on a fresh copy of the
// transition table, allocated in the builder as every variant's table is.
// Any difference it shows against currentCandidate comes from where the
// table lies in memory, not from code, and bounds what the variants'
// differences can be trusted for.
func copyCandidate(fx *layoutFixture, d *DFA) rtcompare.Candidate {
	c := *d
	c.trans = slices.Clone(d.trans)
	w := fx.walker
	return rtcompare.Candidate{Name: "offset+acceptbit (copied table)", Batch: func(n uint64) {
		hits := 0
		for range n {
			if hit, _ := c.MatchDomain(w.Next()); hit {
				hits++
			}
		}
		layoutSink += hits
	}}
}

// indexBitCandidate measures the layout from 8fdd432, built in the builder
// so that its table is allocated after the heap perturbation and in the
// alternating build order; so are the other variants'.
func indexBitCandidate(fx *layoutFixture, d *DFA) rtcompare.Candidate {
	v := newIndexVariant(d, true)
	w := fx.walker
	return rtcompare.Candidate{Name: "index+acceptbit", Batch: func(n uint64) {
		hits := 0
		for range n {
			if hit, _ := v.matchIndexBit(w.Next()); hit {
				hits++
			}
		}
		layoutSink += hits
	}}
}

// indexArrayCandidate measures the layout from 13d5b36.
func indexArrayCandidate(fx *layoutFixture, d *DFA) rtcompare.Candidate {
	v := newIndexVariant(d, false)
	w := fx.walker
	return rtcompare.Candidate{Name: "index+acceptarray", Batch: func(n uint64) {
		hits := 0
		for range n {
			if hit, _ := v.matchIndexArray(w.Next()); hit {
				hits++
			}
		}
		layoutSink += hits
	}}
}

// offsetArrayCandidate measures row offsets with accept array.
func offsetArrayCandidate(fx *layoutFixture, d *DFA) rtcompare.Candidate {
	v := newOffsetArrayVariant(d)
	w := fx.walker
	return rtcompare.Candidate{Name: "offset+acceptarray", Batch: func(n uint64) {
		hits := 0
		for range n {
			if hit, _ := v.matchOffsetArray(w.Next()); hit {
				hits++
			}
		}
		layoutSink += hits
	}}
}

// pointerCandidate measures the layout before 13d5b36. The pointer graph is
// built here, inside the builder, so that it is allocated after the heap
// perturbation and in the alternating build order.
func pointerCandidate(fx *layoutFixture, d *DFA) rtcompare.Candidate {
	p := newPtrDFA(d)
	w := fx.walker
	return rtcompare.Candidate{Name: "pointer-graph", Batch: func(n uint64) {
		hits := 0
		for range n {
			if hit, _ := p.matchDomain(w.Next()); hit {
				hits++
			}
		}
		layoutSink += hits
	}}
}

// TestLayoutDecisions verifies, for operators who care about query latency,
// that the way the compiled DFA sits in memory is the fastest of the layouts
// the project has used or considered: row offsets with accept bit, against
// state indices with accept bit or accept array, row offsets with accept
// array, and the pointer-linked state graph.
//
// This is the multi-process runtime comparison of the automaton package's
// lookup path, on the realistic denylist DFAs of both matcher modes and a
// uniform pseudo-random sequence over the Cloudflare top one million domains.
// It runs only with FILTERLIST_PERF=1 and takes several minutes; the children
// re-run this test function, which is why everything is built inside the
// builders.
//
// For every comparison, candidate A is the current layout and B the
// alternative; a positive pooled difference means the current layout needs
// less time per lookup. The test reports the pooled results and fails only if
// the harness itself fails.
func TestLayoutDecisions(t *testing.T) {
	if !benchfixture.Enabled() {
		t.Skipf("set %s=1 to run the multi-process layout comparison", benchfixture.EnvVar)
	}

	var (
		once   sync.Once
		fx     *layoutFixture
		fxErr  error
		loaded = func() *layoutFixture {
			once.Do(func() { fx, fxErr = loadLayoutFixture() })
			if fxErr != nil {
				// A builder cannot return an error; the child's failure is
				// reported by the parent with this message.
				panic(fxErr)
			}
			return fx
		}
	)
	// Ten A/A runs per process suffice: the pooled noise floor counts each
	// process once, by the mean of its A/A differences. Batches twice as long
	// as the default keep bootstrap ties rare at lookups of a few ns.
	opts := rtcompare.CompareOptions{
		ValidationRuns: 10,
		Collect:        rtcompare.CollectOptions{MaxQuantizationError: rtcompare.DefaultMaxQuantizationError / 2},
	}
	pair := func(name string, dfa func(*layoutFixture) *DFA,
		b func(*layoutFixture, *DFA) rtcompare.Candidate,
	) multiproc.Pair {
		return multiproc.Pair{
			Name:    name,
			A:       func() rtcompare.Candidate { f := loaded(); return currentCandidate(f, dfa(f)) },
			B:       func() rtcompare.Candidate { f := loaded(); return b(f, dfa(f)) },
			Options: opts,
		}
	}
	full := func(f *layoutFixture) *DFA { return f.full }
	wildcard := func(f *layoutFixture) *DFA { return f.wildcard }

	// The differences on the large DFA are around one percent, so the run
	// asks for intervals of ±0.5 points instead of the default ±2, which
	// takes it to up to 40 processes.
	res := multiproc.RunTest(t, multiproc.Options{AbsPrecision: 0.005, Progress: progressLogger(t)},
		pair("dfa-mode: control, current vs copied table", full, copyCandidate),
		pair("dfa-mode: current vs index+accept bit", full, indexBitCandidate),
		pair("dfa-mode: current vs index+accept array", full, indexArrayCandidate),
		pair("dfa-mode: current vs offset+accept array", full, offsetArrayCandidate),
		pair("dfa-mode: current vs pointer graph", full, pointerCandidate),
		pair("hybrid-wildcards: control, current vs copied table", wildcard, copyCandidate),
		pair("hybrid-wildcards: current vs index+accept bit", wildcard, indexBitCandidate),
		pair("hybrid-wildcards: current vs index+accept array", wildcard, indexArrayCandidate),
		pair("hybrid-wildcards: current vs offset+accept array", wildcard, offsetArrayCandidate),
		pair("hybrid-wildcards: current vs pointer graph", wildcard, pointerCandidate),
	)
	fmt.Printf("\nTestLayoutDecisions (A = current layout: row offsets with accept bit)\n%s\n", res)
}

// progressLogger reports each finished process, so that a run of several
// minutes shows it is alive.
func progressLogger(t *testing.T) func(multiproc.Results) {
	return func(r multiproc.Results) {
		t.Logf("%d processes done", r.Processes)
	}
}

// TestLayoutVariantsAgree guards the layout comparison: it verifies that the
// alternative layouts it measures answer every query exactly as the current
// DFA does, so that the comparison measures layout and nothing else.
//
// This covers the test-only layouts of the automaton package: the pointer
// graph, state indices with accept bit or accept array, and row offsets with
// accept array.
//
// It compiles a pattern set with nested label-boundary matches and the
// realistic wildcard DFA, and asserts that every lookup returns the same
// match flag and rule IDs as DFA.MatchDomain for every query.
func TestLayoutVariantsAgree(t *testing.T) {
	small, err := Compile([]Pattern{
		{Expr: "moc.elpmaxe", RuleID: 1},
		{Expr: "moc.elpmaxe.sda", RuleID: 2},
		{Expr: "moc.*", RuleID: 3},
		{Expr: "gro.*kcart*", RuleID: 4},
	}, CompileOptions{})
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}
	queries := []string{"", "example.com", "ads.example.com", "x.ads.example.com", "Ads.Example.COM",
		"tracker.org", "my-tracking.org", "example.net", "bad_char.com", "com"}
	assertLayoutsAgree(t, small, queries)

	if testing.Short() {
		return
	}
	rules, err := benchfixture.DenylistRules()
	if err != nil {
		t.Fatalf("DenylistRules error: %v", err)
	}
	var wildcards []Pattern
	for i, r := range rules {
		if strings.Contains(r.Pattern, "*") {
			wildcards = append(wildcards, Pattern{Expr: benchfixture.ReversedPattern(r.Pattern), RuleID: uint32(i)}) //nolint:gosec // rule count is far below 2^32
		}
	}
	realistic, err := Compile(wildcards, CompileOptions{})
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}
	domains, err := benchfixture.TopDomains()
	if err != nil {
		t.Fatalf("TopDomains error: %v", err)
	}
	assertLayoutsAgree(t, realistic, domains[:min(len(domains), 50_000)])
}

// assertLayoutsAgree compares every layout's lookup with DFA.MatchDomain on
// every query.
func assertLayoutsAgree(t *testing.T, d *DFA, queries []string) {
	t.Helper()
	ptr := newPtrDFA(d)
	indexBit := newIndexVariant(d, true)
	indexArray := newIndexVariant(d, false)
	offsetArray := newOffsetArrayVariant(d)
	variants := []struct {
		name  string
		match func(string) (bool, []uint32)
	}{
		{"pointer graph", ptr.matchDomain},
		{"index+accept bit", indexBit.matchIndexBit},
		{"index+accept array", indexArray.matchIndexArray},
		{"offset+accept array", offsetArray.matchOffsetArray},
	}
	for _, q := range queries {
		wantHit, wantIDs := d.MatchDomain(q)
		for _, v := range variants {
			hit, ids := v.match(q)
			if hit != wantHit || fmt.Sprint(ids) != fmt.Sprint(wantIDs) {
				t.Fatalf("%s: %q = %v %v, want %v %v", v.name, q, hit, ids, wantHit, wantIDs)
			}
		}
	}
}
