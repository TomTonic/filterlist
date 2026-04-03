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
//  5. Pointer-based DFA — contiguous-slice DFA with direct pointers (dfa.go)
//
// # Pattern Language
//
// The supported pattern language is intentionally small:
//   - Literal characters: a-z, 0-9, '-', '.'
//   - Wildcard: '*' matches zero or more DNS characters
//   - Patterns are implicitly anchored (full match required)
//
// # Performance Design
//
// Every design choice in the exported [DFA] favors O(n) match-time performance:
//   - Transitions are [AlphabetSize]*DFAState fixed arrays (no map lookups)
//   - All [DFAState] values live in one contiguous []DFAState slice
//   - Direct pointer chasing replaces index indirection
//   - NFA states use bit-packed flags to improve cache utilization
//
// # File Organization
//
//   - alphabet.go — DNS character ↔ transition-index mapping
//   - nfa.go      — Thompson NFA types and ε-closure
//   - subset.go   — powerset (subset) construction
//   - minimize.go — Hopcroft partition-refinement minimization
//   - dfa.go      — exported [DFA] / [DFAState] types and [DFA.Match]
//   - dot.go      — Graphviz DOT export ([DFA.DumpDot])
//   - compile.go  — pipeline orchestration ([Compile])
//
// # Example
//
//	dfa, err := automaton.Compile(patterns, automaton.CompileOptions{})
//	matched, ruleIDs := dfa.Match("ads.example.com")
package automaton
