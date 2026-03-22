package util

import "testing"

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
