// Package matcher composes a [suffixmap.SuffixMap] for literal domain patterns
// and an [automaton.DFA] for wildcard patterns into a single match interface.
//
// Filter list rules are split at compile time: patterns without wildcards are
// stored in a hash-based suffix map for O(k) lookup (k = number of DNS labels),
// while patterns containing '*' are compiled into a minimized DFA for O(n)
// matching (n = input length). This hybrid approach keeps compilation fast for
// the vast majority of rules (typically 99%+ are literal) while retaining full
// wildcard support.
//
// Example usage:
//
//	m, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: 200000})
//	if err != nil { ... }
//	matched, ruleIDs := m.Match("ads.example.com")
package matcher

import (
	"fmt"
	"strings"
	"time"

	"github.com/TomTonic/coredns-regfilter/pkg/automaton"
	"github.com/TomTonic/coredns-regfilter/pkg/filterlist"
	"github.com/TomTonic/coredns-regfilter/pkg/suffixmap"
)

// Logger receives progress messages during compilation.
// Callers typically pass their watcher or plugin logger here.
type Logger interface {
	Infof(format string, args ...interface{})
}

// CompileOptions controls compilation behavior.
//
// MaxStates limits the DFA state count during subset construction (0 = no limit).
// CompileTimeout aborts compilation if the deadline is exceeded.
// Minimize can be set to false to skip Hopcroft minimization (defaults to true).
// Logger receives progress messages; nil silences output.
type CompileOptions struct {
	MaxStates      int
	CompileTimeout time.Duration
	Minimize       *bool
	Logger         Logger
}

// Matcher holds a compiled suffix map for literal patterns and a DFA for
// wildcard patterns. It is safe for concurrent reads after construction.
type Matcher struct {
	literals *suffixmap.SuffixMap
	dfa      *automaton.DFA
}

// CompileRules splits rules into literal and wildcard patterns, builds a
// suffix map for the literals, and compiles the wildcards into a DFA.
//
// The rules parameter contains parsed filter list entries. Each rule's Pattern
// field is inspected: patterns without '*' are treated as literal domain
// suffixes; patterns containing '*' are compiled through the automaton package.
// Rule indices are used as rule IDs for match attribution.
//
// Returns an error if DFA compilation fails (e.g. state limit exceeded or
// timeout). An empty rule set produces a valid Matcher that never matches.
func CompileRules(rules []filterlist.Rule, opts CompileOptions) (*Matcher, error) {
	logf := nopLogf
	if opts.Logger != nil {
		logf = opts.Logger.Infof
	}

	// Split rules into literals and wildcards.
	literalEntries := make(map[string][]uint32)
	var wildcardPatterns []automaton.Pattern

	for i, r := range rules {
		pattern := strings.ToLower(r.Pattern)
		if strings.Contains(pattern, "*") {
			wildcardPatterns = append(wildcardPatterns, automaton.Pattern{
				Expr:   pattern,
				RuleID: uint32(i),
			})
		} else {
			literalEntries[pattern] = append(literalEntries[pattern], uint32(i))
		}
	}

	logf("matcher: %d rules → %d literal, %d wildcard",
		len(rules), len(literalEntries), len(wildcardPatterns))

	// Build suffix map for literals.
	sm := suffixmap.New(literalEntries)

	// Compile wildcards into DFA.
	var dfa *automaton.DFA
	if len(wildcardPatterns) > 0 {
		var err error
		dfa, err = automaton.Compile(wildcardPatterns, automaton.CompileOptions{
			MaxStates:      opts.MaxStates,
			CompileTimeout: opts.CompileTimeout,
			Minimize:       opts.Minimize,
			Logger:         adaptLogger(opts.Logger),
		})
		if err != nil {
			return nil, fmt.Errorf("matcher: compile wildcards: %w", err)
		}
	}

	return &Matcher{literals: sm, dfa: dfa}, nil
}

// Match checks input against both the literal suffix map and the wildcard DFA.
//
// The input parameter should be a lowercase domain name without trailing dot.
// Returns true if any stored pattern matches, along with all matching rule IDs.
// The suffix map is checked first; if both literal and wildcard patterns match,
// all rule IDs are combined.
func (m *Matcher) Match(input string) (matched bool, ruleIDs []uint32) {
	if m == nil {
		return false, nil
	}

	input = strings.ToLower(input)

	if m.literals != nil {
		if hit, ids := m.literals.Match(input); hit {
			matched = true
			ruleIDs = append(ruleIDs, ids...)
		}
	}

	if m.dfa != nil {
		if hit, ids := m.dfa.Match(input); hit {
			matched = true
			ruleIDs = append(ruleIDs, ids...)
		}
	}

	return matched, ruleIDs
}

// StateCount returns the number of DFA states for the wildcard patterns.
// Returns 0 when no wildcard patterns were compiled.
func (m *Matcher) StateCount() int {
	if m == nil || m.dfa == nil {
		return 0
	}
	return m.dfa.StateCount()
}

// LiteralCount returns the number of distinct literal domain patterns in the
// suffix map.
func (m *Matcher) LiteralCount() int {
	if m == nil || m.literals == nil {
		return 0
	}
	return m.literals.Len()
}

// DumpDot writes the wildcard DFA as a Graphviz DOT graph to w.
// Returns an error if no DFA was compiled.
func (m *Matcher) DumpDot(w interface{ Write([]byte) (int, error) }) error {
	if m == nil || m.dfa == nil {
		return fmt.Errorf("matcher: no wildcard DFA to dump")
	}
	return m.dfa.DumpDot(w)
}

func nopLogf(string, ...interface{}) {}

// automatonLogAdapter adapts a matcher.Logger to automaton.Logger.
type automatonLogAdapter struct {
	inner Logger
}

// Infof delegates compile-progress messages to the matcher logger.
func (a *automatonLogAdapter) Infof(format string, args ...interface{}) {
	a.inner.Infof(format, args...)
}

func adaptLogger(l Logger) automaton.Logger {
	if l == nil {
		return nil
	}
	return &automatonLogAdapter{inner: l}
}
