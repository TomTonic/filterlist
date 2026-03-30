package util

import "testing"

// TestNormalizeDomain verifies that users get stable lowercase DNS names when
// input passes through the shared normalization helpers.
//
// This test covers the util package domain normalization behavior.
//
// It asserts that trailing dots are removed and casing is normalized without
// altering already canonical names.
func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Example.COM.", "example.com"},
		{"example.com", "example.com"},
		{"SUB.Example.Org.", "sub.example.org"},
		{"", ""},
		{".", ""},
		{"A", "a"},
	}
	for _, tt := range tests {
		got := NormalizeDomain(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestIsDNSChar verifies that only DNS-safe characters are accepted by the
// low-level alphabet helper used by parsing and matching code.
//
// This test covers the util package character validation helper.
//
// It asserts that lowercase DNS characters pass and obvious invalid runes do
// not.
func TestIsDNSChar(t *testing.T) {
	for _, r := range "abcdefghijklmnopqrstuvwxyz0123456789-." {
		if !IsDNSChar(r) {
			t.Errorf("IsDNSChar(%c) = false, want true", r)
		}
	}
	for _, r := range "ABCXYZ_!@# " {
		if IsDNSChar(r) {
			t.Errorf("IsDNSChar(%c) = true, want false", r)
		}
	}
}

// TestIsValidDNSName verifies that callers can distinguish supported DNS-style
// patterns from malformed names before compilation.
//
// This test covers the util package whole-name validation helper.
//
// It asserts that wildcard-aware DNS names are accepted and malformed input is
// rejected.
func TestIsValidDNSName(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"example.com", true},
		{"*.example.com", true},
		{"a-b.com", true},
		{"", false},
		{"ex ample.com", false},
		{"exam_ple.com", false},
	}
	for _, tt := range tests {
		got := IsValidDNSName(tt.input)
		if got != tt.want {
			t.Errorf("IsValidDNSName(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// TestToASCII verifies that internationalized domains are converted into the
// ASCII form that DNS queries and filter matching actually use.
//
// This test covers the util package IDNA conversion helper.
//
// It asserts that ASCII domains pass through unchanged and Unicode labels are
// mapped to their expected punycode representation.
func TestToASCII(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Pure ASCII passes through unchanged
		{"example.com", "example.com"},
		{"sub.example.com", "sub.example.com"},
		// German Umlauts
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"bücher.example.com", "xn--bcher-kva.example.com"},
		{"süddeutsche.de", "xn--sddeutsche-9db.de"},
		// Mixed: subdomain with Umlaut
		{"ads.münchen.de", "ads.xn--mnchen-3ya.de"},
		// Other scripts
		{"例え.jp", "xn--r8jz45g.jp"},
	}
	for _, tt := range tests {
		got, err := ToASCII(tt.input)
		if err != nil {
			t.Errorf("ToASCII(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ToASCII(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
