package filterlist_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/TomTonic/filterlist/internal/benchfixture"
	"github.com/TomTonic/filterlist/pkg/listparser"
	"github.com/TomTonic/filterlist/pkg/matcher"
	"github.com/TomTonic/rtcompare"
	"github.com/TomTonic/rtcompare/multiproc"
)

// lookupSink keeps the compiler from discarding the lookups of a batch (see
// the rtcompare HOWTO, "The one rule for writing your Batch function").
var lookupSink int

// lookupFixture is what every process of the comparison loads once, after
// rtcompare has perturbed its heap.
type lookupFixture struct {
	rules  []listparser.Rule
	walker *benchfixture.Walker // shared by both candidates, see [benchfixture.Walker]
}

// loadLookupFixture loads the realistic deny rules and the query sequence.
func loadLookupFixture() (*lookupFixture, error) {
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
	walker := benchfixture.NewWalker(benchfixture.Queries(domains, seq))
	return &lookupFixture{rules: rules, walker: walker}, nil
}

// matcherCandidate compiles the fixture's rules in the given mode and measures
// Matcher.Match over the query sequence. Each candidate compiles its own
// matcher inside its builder, so that the two land in memory in the order and
// heap layout multiproc chooses for the process.
func matcherCandidate(fx *lookupFixture, mode matcher.Mode) rtcompare.Candidate {
	m, err := matcher.CompileRules(fx.rules, matcher.CompileOptions{
		MaxStates: realisticBenchmarkMaxStates,
		Mode:      mode,
	})
	if err != nil {
		// A builder cannot return an error; the parent reports the child's
		// failure with this message.
		panic(fmt.Sprintf("CompileRules(%s): %v", mode, err))
	}
	w := fx.walker
	return rtcompare.Candidate{Name: string(mode), Batch: func(n uint64) {
		hits := 0
		for range n {
			if hit, _ := m.Match(w.Next()); hit {
				hits++
			}
		}
		lookupSink += hits
	}}
}

// TestSequenceMapVsDFA answers, for operators choosing a matcher_mode,
// whether matcher_mode dfa really answers queries faster than the default
// hybrid mode, and by how much.
//
// This is the multi-process runtime comparison of the matcher package's two
// modes on the realistic denylist samples, queried with a uniform
// pseudo-random sequence over the Cloudflare top one million domains (length
// set by BENCH_SEQ_SIZE, default 100000). The data is far larger than the CPU
// caches, so a single process is a single observation of the heap layout;
// rtcompare's multiproc package runs the comparison in several processes with
// perturbed heaps and alternating build order, and pools them. It runs only
// with FILTERLIST_PERF=1 and takes several minutes; the children re-run this
// test function, which is why everything is built inside the builders.
//
// Candidate A is matcher_mode dfa, candidate B matcher_mode hybrid; a
// positive pooled difference means dfa mode needs less time per lookup. The
// test prints the pooled result and fails only if the harness itself fails.
func TestSequenceMapVsDFA(t *testing.T) {
	if !benchfixture.Enabled() {
		t.Skipf("set %s=1 to run the multi-process matcher mode comparison", benchfixture.EnvVar)
	}

	var (
		once  sync.Once
		fx    *lookupFixture
		fxErr error
	)
	loaded := func() *lookupFixture {
		once.Do(func() { fx, fxErr = loadLookupFixture() })
		if fxErr != nil {
			panic(fxErr)
		}
		return fx
	}

	res := multiproc.RunTest(t, multiproc.Options{
		Progress: func(r multiproc.Results) { t.Logf("%d processes done", r.Processes) },
	}, multiproc.Pair{
		Name: fmt.Sprintf("dfa vs hybrid, seq=%d", benchfixture.SequenceLength()),
		A:    func() rtcompare.Candidate { return matcherCandidate(loaded(), matcher.ModeDFA) },
		B:    func() rtcompare.Candidate { return matcherCandidate(loaded(), matcher.ModeHybrid) },
		// See TestLayoutDecisions in pkg/automaton for the choice of options.
		Options: rtcompare.CompareOptions{
			ValidationRuns: 10,
			Collect:        rtcompare.CollectOptions{MaxQuantizationError: rtcompare.DefaultMaxQuantizationError / 2},
			Thresholds:     []float64{0.05},
		},
	})
	fmt.Printf("\nTestSequenceMapVsDFA (A = matcher_mode dfa, B = matcher_mode hybrid)\n%s\n", res)
}
