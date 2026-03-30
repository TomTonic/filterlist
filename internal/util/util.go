// Package util provides small helper functions for domain normalization and
// safe string handling used throughout the regfilter project.
package util

import (
	"strings"

	"golang.org/x/net/idna"
)

// NormalizeDomain canonicalizes name for DNS-oriented lookups.
//
// The name parameter may be any domain string received from configuration,
// filter parsing, or DNS queries. The return value is the lowercase form with
// a single trailing dot removed. Callers typically use NormalizeDomain before
// DFA matching so equivalent spellings share one canonical representation.
func NormalizeDomain(name string) string {
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	return name
}

// IsDNSChar reports whether r belongs to the supported DNS matching alphabet.
//
// The r parameter may be any rune. The return value is true only for lowercase
// letters, digits, hyphen, and dot, which are the characters supported by the
// parser and automaton compiler. Use this helper when validating patterns or
// filtering query input before compilation.
func IsDNSChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '.'
}

// IsValidDNSName reports whether name uses only supported DNS pattern characters.
//
// The name parameter is checked after lowercasing and may also contain '*'
// because wildcard patterns are supported by the filter language. The return
// value is false for empty strings or names containing spaces, underscores, or
// other unsupported characters. Callers use this before promoting parsed text
// into canonical filter rules.
func IsValidDNSName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range strings.ToLower(name) {
		if !IsDNSChar(r) && r != '*' {
			return false
		}
	}
	return true
}

// ToASCII converts name into its ASCII DNS representation.
//
// The name parameter may contain Unicode labels from user-maintained filter
// lists. The return value is the punycode/ASCII form used on the wire, or an
// error when the input is not a valid IDNA lookup name. Callers typically use
// ToASCII while normalizing filter rules so Unicode domains match DNS queries
// reliably.
func ToASCII(name string) (string, error) {
	return idna.Lookup.ToASCII(name)
}
