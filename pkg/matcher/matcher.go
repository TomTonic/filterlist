// Package matcher composes DNS rule matchers into a single match interface.
//
// By default the package uses a hybrid representation: patterns without
// wildcards are stored in a hash-based suffix map for O(k) lookup (k = number
// of DNS labels), while patterns containing '*' are compiled into a minimized
// DFA for O(n) matching (n = input length). This keeps compilation fast for the
// vast majority of rules (typically 99%+ are literal) while retaining full
// wildcard support.
//
// Callers can also request a pure DFA representation that compiles every rule
// into one automaton. In that mode literal suffix rules are expanded so the DFA
// preserves the same ||domain^ semantics as the default suffix-map path.
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

	"github.com/TomTonic/filterlist/pkg/automaton"
	"github.com/TomTonic/filterlist/pkg/listparser"
	"github.com/TomTonic/filterlist/pkg/suffixmap"
)

// Logger receives progress messages during compilation.
// Callers typically pass their watcher or plugin logger here.
type Logger interface {
	Infof(format string, args ...interface{})
}

// Mode selects how the matcher represents parsed rules at runtime.
//
// ModeHybrid stores literal rules in a suffix map and compiles only wildcard
// rules into a DFA. ModeDFA compiles every rule into one DFA. To preserve the
// suffix semantics of literal rules, ModeDFA expands each literal domain into
// an exact-match pattern and a subdomain pattern.
type Mode string

const (
	// ModeHybrid keeps literal domains in the suffix map and uses the DFA only
	// for wildcard patterns. This is the default mode.
	ModeHybrid Mode = "hybrid"

	// ModeDFA compiles all rules into a single DFA, including literal domain
	// rules expanded to cover both the exact host and its subdomains.
	ModeDFA Mode = "dfa"
)

// ParseMode validates a textual matcher mode and returns its canonical form.
//
// Accepted values are "hybrid", "dfa", and "pure_dfa". The latter is kept as
// a compatibility alias and normalizes to ModeDFA.
func ParseMode(value string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(ModeHybrid):
		return ModeHybrid, nil
	case string(ModeDFA), "pure_dfa":
		return ModeDFA, nil
	default:
		return "", fmt.Errorf("unknown matcher mode %q (must be hybrid or dfa)", value)
	}
}

// CompileOptions controls compilation behavior.
//
// MaxStates limits the DFA state count during subset construction (0 = no limit).
// CompileTimeout aborts compilation if the deadline is exceeded.
// Minimize can be set to false to skip Hopcroft minimization (defaults to true).
// Mode selects the runtime representation for compiled rules. The zero value
// defaults to ModeHybrid.
// Logger receives progress messages; nil silences output.
type CompileOptions struct {
	MaxStates      int
	CompileTimeout time.Duration
	Minimize       *bool
	Mode           Mode
	Logger         Logger
}

// Matcher holds the compiled runtime structures for one ruleset. Depending on
// the selected mode it may use a suffix map, a DFA, or both. It is safe for
// concurrent reads after construction.
type Matcher struct {
	literals     *suffixmap.SuffixMap
	dfa          *automaton.DFA
	literalCount int
}

// CompileRules compiles parsed rules into the runtime representation selected
// by opts.Mode.
//
// The rules parameter contains parsed filter list entries. Each rule's Pattern
// field is inspected and lowercased. In the default hybrid mode, patterns
// without '*' are treated as literal domain suffixes and stored in the suffix
// map, while patterns containing '*' are compiled through the automaton
// package. In pure DFA mode, every rule is compiled through the automaton and
// literal rules are expanded to preserve suffix semantics. Rule indices are
// used as rule IDs for match attribution.
//
// Returns an error if DFA compilation fails (e.g. state limit exceeded or
// timeout). An empty rule set produces a valid Matcher that never matches.
func CompileRules(rules []listparser.Rule, opts CompileOptions) (*Matcher, error) {
	logf := nopLogf
	if opts.Logger != nil {
		logf = opts.Logger.Infof
	}

	mode := normalizeMode(opts.Mode)

	// Split rules into literals and wildcards.
	literalEntries := make(map[string][]uint32)
	var wildcardPatterns []automaton.Pattern

	for i, r := range rules {
		pattern := strings.ToLower(r.Pattern)
		if strings.Contains(pattern, "*") {
			wildcardPatterns = appendDFAPatternVariants(wildcardPatterns, pattern, uint32(i))
		} else {
			literalEntries[pattern] = append(literalEntries[pattern], uint32(i))
		}
	}

	logf("matcher: %d rules → %d literal, %d wildcard, mode=%s",
		len(rules), len(literalEntries), len(wildcardPatterns), mode)

	if mode == ModeDFA {
		dfa, err := automaton.Compile(buildDFAPatterns(rules), automaton.CompileOptions{
			MaxStates:      opts.MaxStates,
			CompileTimeout: opts.CompileTimeout,
			Minimize:       opts.Minimize,
			Logger:         adaptLogger(opts.Logger),
		})
		if err != nil {
			return nil, fmt.Errorf("matcher: compile DFA: %w", err)
		}

		return &Matcher{dfa: dfa, literalCount: len(literalEntries)}, nil
	}

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

	return &Matcher{literals: sm, dfa: dfa, literalCount: len(literalEntries)}, nil
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

// StateCount returns the number of DFA states held by the matcher.
// Returns 0 when no DFA was compiled.
func (m *Matcher) StateCount() int {
	if m == nil || m.dfa == nil {
		return 0
	}
	return m.dfa.StateCount()
}

// LiteralCount returns the number of distinct literal domain patterns in the
// compiled rule set, regardless of whether they are backed by the suffix map
// or expanded into the DFA.
func (m *Matcher) LiteralCount() int {
	if m == nil {
		return 0
	}
	return m.literalCount
}

func normalizeMode(mode Mode) Mode {
	parsed, err := ParseMode(string(mode))
	if err != nil {
		return ModeHybrid
	}
	return parsed
}

// buildDFAPatterns expands rules into DFA patterns that preserve the
// repository's suffix semantics for host-style filters.
func buildDFAPatterns(rules []listparser.Rule) []automaton.Pattern {
	patterns := make([]automaton.Pattern, 0, len(rules)*2)
	for i, rule := range rules {
		pattern := strings.ToLower(rule.Pattern)
		patterns = appendDFAPatternVariants(patterns, pattern, uint32(i))
	}
	return patterns
}

// appendDFAPatternVariants adds the exact DFA pattern plus, when required, a
// synthetic subdomain variant so DFA-backed matching preserves ||domain^
// semantics for both literal and wildcard host rules.
func appendDFAPatternVariants(patterns []automaton.Pattern, pattern string, ruleID uint32) []automaton.Pattern {
	patterns = append(patterns, automaton.Pattern{Expr: pattern, RuleID: ruleID})
	if needsSubdomainVariant(pattern) {
		patterns = append(patterns, automaton.Pattern{Expr: "*." + pattern, RuleID: ruleID})
	}
	return patterns
}

func needsSubdomainVariant(pattern string) bool {
	if !strings.Contains(pattern, ".") {
		return false
	}
	return !strings.HasPrefix(pattern, "*.")
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
