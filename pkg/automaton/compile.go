package automaton

import (
	"fmt"
	"strings"
	"time"
)

// Logger receives progress messages during DFA compilation.
//
// Callers such as the watcher and CoreDNS plugin pass their logger here so
// operators see what is happening during potentially long compilations.
// A nil Logger is safe — [Compile] silences output in that case.
type Logger interface {
	Infof(format string, args ...interface{})
}

func nopLogf(string, ...interface{}) {}

// CompileOptions controls the DFA compilation pipeline.
//
// Zero-value defaults are safe: minimization is enabled, no state cap, no
// timeout, and no logging.
type CompileOptions struct {
	// MaxStates limits the number of intermediate DFA states during subset
	// construction. When exceeded, Compile returns an error. 0 means no limit.
	MaxStates int

	// Minimize enables Hopcroft minimization after subset construction.
	// nil (default) and *true both enable it; only *false disables it.
	Minimize *bool

	// CompileTimeout is the maximum wall-clock time allowed for the entire
	// compilation. Zero means no timeout. Checked between pipeline stages
	// and inside tight loops.
	CompileTimeout time.Duration

	// Logger receives progress messages during compilation. May be nil.
	Logger Logger
}

// shouldMinimize returns whether Hopcroft minimization is enabled for these
// options. The default (nil pointer) is true.
func shouldMinimize(opts CompileOptions) bool {
	if opts.Minimize == nil {
		return true // default to minimize
	}
	return *opts.Minimize
}

// Pattern pairs a canonical filter expression with a caller-assigned rule ID.
//
// Expr is a lowercase DNS pattern using the supported alphabet (a-z, 0-9,
// '-', '.', '*'). RuleID is preserved through compilation into the DFA's
// accept states so callers can trace a match back to its originating filter
// rule.
type Pattern struct {
	Expr   string // canonical pattern (lowercase DNS chars and '*')
	RuleID uint32 // caller-assigned identifier for match attribution
}

// Compile transforms a set of filter patterns into a minimized, pointer-based
// [DFA] ready for repeated [DFA.Match] calls.
//
// Each [Pattern] carries a lowercase expression string and a caller-assigned
// rule ID that is preserved in accept states for match attribution.
//
// The pipeline is:
//  1. Build one Thompson NFA per pattern ([buildPatternNFA])
//  2. Combine all NFAs via epsilon fan-out ([combineNFAs])
//  3. Subset (powerset) construction → deterministic DFA ([subsetConstruction])
//  4. Optionally minimize via Hopcroft's algorithm ([hopcroftMinimize])
//  5. Convert to the exported pointer-based [DFA]
//
// On failure Compile returns an error describing invalid patterns, timeout
// exhaustion, or MaxStates violations. An empty pattern slice produces a
// valid but empty DFA that matches nothing.
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

	// Phase 1: Build per-pattern NFAs.
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

	// Phase 2: Combine into single NFA.
	combineStart := time.Now()
	combined, err := combineNFAs(nfas)
	if err != nil {
		return nil, err
	}
	logf("automaton: NFA combine: %v (%d NFA states)", time.Since(combineStart), len(combined.states))

	// Phase 3: Subset construction (NFA → intermediate DFA).
	logf("automaton: starting subset construction...")
	subsetStart := time.Now()
	md, err := subsetConstruction(combined, opts.MaxStates, deadline)
	if err != nil {
		return nil, err
	}
	logf("automaton: subset construction: %v (%d DFA states)", time.Since(subsetStart), len(md.states))

	// Phase 4: Hopcroft minimization.
	if shouldMinimize(opts) {
		logf("automaton: starting Hopcroft minimization (%d states)...", len(md.states))
		hopcroftStart := time.Now()
		beforeStates := len(md.states)
		md = hopcroftMinimize(md)
		logf("automaton: Hopcroft minimization: %v (%d → %d states)",
			time.Since(hopcroftStart), beforeStates, len(md.states))
	}

	// Phase 5: Convert to pointer-based DFA.
	dfa := md.toDFA()
	logf("automaton: compiled %d patterns in %v (%d DFA states)",
		len(patterns), time.Since(started), dfa.StateCount())
	return dfa, nil
}
