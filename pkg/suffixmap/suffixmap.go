// Package suffixmap provides a domain-suffix lookup table that implements
// the ||domain^ anchor semantics from AdGuard and ABP filter lists.
//
// A pattern "example.com" matches "example.com" itself and every subdomain
// such as "ads.example.com" or "www.ads.example.com", but not
// "notexample.com" (must be a label-boundary match). Lookups are performed
// by walking the DNS labels of the query from left to right, probing the
// map at each suffix. The maximum number of probes equals the number of
// labels in the query (typically 2–4 for real-world DNS names).
//
// This package is intentionally decoupled from the automaton and filterlist
// packages so it can be tested and reasoned about in isolation.
package suffixmap

import "strings"

// SuffixMap stores domain patterns and matches queries against them using
// domain-suffix semantics.
//
// The zero value is not usable; create instances via [New].
type SuffixMap struct {
	m map[string][]uint32
}

// New creates a SuffixMap from the given entries.
//
// Each entry maps a canonicalized domain pattern (lowercase, no wildcards)
// to its rule IDs. The entries map is owned by the SuffixMap after the call;
// callers must not modify it afterwards. Passing a nil or empty map creates
// a valid but empty SuffixMap that never matches.
func New(entries map[string][]uint32) *SuffixMap {
	if entries == nil {
		entries = map[string][]uint32{}
	}
	return &SuffixMap{m: entries}
}

// Len returns the number of distinct domain patterns stored.
func (s *SuffixMap) Len() int {
	if s == nil {
		return 0
	}
	return len(s.m)
}

// Match checks whether input matches any stored pattern via domain-suffix
// lookup.
//
// For a query like "sub.ads.example.com" the method probes the following
// suffixes in order:
//
//	"sub.ads.example.com"
//	"ads.example.com"
//	"example.com"
//	"com"
//
// If any of these is present in the map, the query matches. When multiple
// suffixes match (e.g. both "ads.example.com" and "example.com" are
// stored), all corresponding rule IDs are returned.
//
// The input parameter should be a lowercase DNS name. Match returns false
// and nil when no pattern matches.
func (s *SuffixMap) Match(input string) (matched bool, ruleIDs []uint32) {
	if s == nil || len(s.m) == 0 {
		return false, nil
	}

	for suffix := input; suffix != ""; {
		if ids, ok := s.m[suffix]; ok {
			matched = true
			ruleIDs = append(ruleIDs, ids...)
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		suffix = suffix[dot+1:]
	}

	return matched, ruleIDs
}
