// Package util provides small helper functions for domain normalization and
// safe string handling used throughout the regfilter project.
package util

import "strings"

// NormalizeDomain lowercases and removes a trailing dot from a DNS name.
func NormalizeDomain(name string) string {
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	return name
}

// IsDNSChar returns true if r is a valid DNS label character (a-z, 0-9, '-', '.').
func IsDNSChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '.'
}

// IsValidDNSName checks whether the given string contains only valid DNS
// characters (after lowercasing).
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
