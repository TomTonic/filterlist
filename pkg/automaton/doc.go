// Package automaton compiles domain filter patterns into a cache-optimized,
// array-based deterministic finite automaton (DFA) with rule attribution.
//
// # Compilation Pipeline
//
// The pipeline follows classic automaton theory in five stages:
//
//  1. Thompson NFA construction — each pattern becomes a small NFA (nfa.go)
//  2. NFA combination — individual NFAs merge via epsilon fan-out (nfa.go)
//  3. Subset (powerset) construction — NFA → deterministic DFA (subset.go)
//  4. Hopcroft minimization — merge equivalent DFA states (minimize.go)
//  5. Runtime DFA — compact transition tables plus exported state graph (dfa.go)
//
// # Pattern Language
//
// The supported pattern language is intentionally small:
//   - Literal characters: a-z, 0-9, '-', '.'
//   - Wildcard: '*' matches zero or more DNS characters
//   - Patterns are implicitly anchored (full match required)
//
// # Reversed-Pattern Domain Matching
//
// Callers that need ||domain^ anchoring semantics (matching a domain and all
// of its subdomains) should store patterns in reversed form and query the DFA
// through [DFA.MatchDomain] instead of [DFA.Match]. MatchDomain walks the
// input name from right to left and records a hit whenever an accepting state
// coincides with a DNS label boundary ('.' or start-of-name). This replaces
// the older approach of generating synthetic "*.<pattern>" variants, which
// caused exponential DFA state growth when the pattern already contained
// wildcards.
//
// # Performance Design
//
// Every design choice in the runtime [DFA] favors O(n) match-time performance:
//   - Runtime transitions live in one compact flat []uint32 table
//   - Accept flags and rule IDs are split into dense side arrays for locality
//   - [DFA.Match] and [DFA.MatchDomain] use byte-indexed hot loops
//   - Exported [DFAState] values are still materialized for tests and diagnostics
//   - NFA states use bit-packed flags to improve cache utilization
//
// # File Organization
//
//   - alphabet.go — DNS character ↔ transition-index mapping
//   - nfa.go      — Thompson NFA types and ε-closure
//   - subset.go   — powerset (subset) construction
//   - minimize.go — Hopcroft partition-refinement minimization
//   - dfa.go      — exported [DFA] / [DFAState] types, [DFA.Match] and [DFA.MatchDomain]
//   - dot.go      — Graphviz DOT export ([DFA.DumpDot])
//   - compile.go  — pipeline orchestration ([Compile])
//
// # Example
//
//	dfa, err := automaton.Compile(patterns, automaton.CompileOptions{})
//	matched, ruleIDs := dfa.Match("ads.example.com")
package automaton
