package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFilterFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error: %v", path, err)
	}
}

// TestRunWithoutArgsShowsUsage verifies that operators get actionable CLI help when they invoke the checker without arguments by asserting that run returns a failure code and prints usage text.
func TestRunWithoutArgsShowsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "regfilter-check") {
		t.Fatalf("stderr = %q, want usage output", stderr.String())
	}
}

// TestRunHelpReturnsZero verifies that operators can request command help without triggering an error path in the CLI package by asserting that the help command returns zero and prints usage text.
func TestRunHelpReturnsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(help) code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "dump-dot") {
		t.Fatalf("stderr = %q, want command list", stderr.String())
	}
}

// TestRunRejectsUnknownCommand verifies that operators get immediate feedback for unsupported CLI invocations by asserting that unknown commands return a failure code and mention the invalid command.
func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run(bogus) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown command: bogus") {
		t.Fatalf("stderr = %q, want unknown command message", stderr.String())
	}
}

// TestRunValidateCompilesRules verifies that operators can validate filter directories from the CLI package by asserting that run reports parsed rules, emits parser warnings, and returns success for compilable input.
func TestRunValidateCompilesRules(t *testing.T) {
	blDir := t.TempDir()
	writeFilterFile(t, blDir, "rules.txt", "||ads.example.com^\n## cosmetic\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"validate", "--blacklist", blDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(validate) code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "[blacklist] DFA compiled") {
		t.Fatalf("stdout = %q, want compile summary", stdout.String())
	}
	if !strings.Contains(stderr.String(), "WARN:") {
		t.Fatalf("stderr = %q, want parser warning", stderr.String())
	}
}

// TestRunMatchReportsPolicyDecision verifies that users can inspect allow, deny, and pass decisions from the CLI package by asserting that run returns the documented exit codes and result strings for each case.
func TestRunMatchReportsPolicyDecision(t *testing.T) {
	wlDir := t.TempDir()
	blDir := t.TempDir()
	writeFilterFile(t, wlDir, "allow.txt", "||safe.example.com^\n")
	writeFilterFile(t, blDir, "deny.txt", "||ads.example.com^\n")

	tests := []struct {
		name      string
		args      []string
		wantCode  int
		wantToken string
	}{
		{
			name:      "whitelisted",
			args:      []string{"match", "--whitelist", wlDir, "--blacklist", blDir, "--name", "safe.example.com"},
			wantCode:  0,
			wantToken: "WHITELISTED",
		},
		{
			name:      "blacklisted",
			args:      []string{"match", "--whitelist", wlDir, "--blacklist", blDir, "--name", "ads.example.com"},
			wantCode:  1,
			wantToken: "BLACKLISTED",
		},
		{
			name:      "allowed",
			args:      []string{"match", "--whitelist", wlDir, "--blacklist", blDir, "--name", "clean.example.com"},
			wantCode:  0,
			wantToken: "ALLOWED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("run(match) code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantToken) {
				t.Fatalf("stdout = %q, want token %q", stdout.String(), tt.wantToken)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty output", stderr.String())
			}
		})
	}
}

// TestRunDumpDotWritesOutput verifies that operators can export compiled automatons from the CLI package by asserting that run writes a DOT file containing the expected graph header.
func TestRunDumpDotWritesOutput(t *testing.T) {
	blDir := t.TempDir()
	outDir := t.TempDir()
	writeFilterFile(t, blDir, "deny.txt", "||ads.example.com^\n")
	outPath := filepath.Join(outDir, "blacklist.dot")

	var stdout, stderr bytes.Buffer
	code := run([]string{"dump-dot", "--blacklist", blDir, "--out", filepath.Join(outDir, "unused.dot") + "," + outPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(dump-dot) code = %d, want 0", code)
	}
	content, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", outPath, err)
	}
	if !strings.Contains(string(content), "digraph DFA") {
		t.Fatalf("DOT output = %q, want graph header", string(content))
	}
	if !strings.Contains(stdout.String(), "DOT written") {
		t.Fatalf("stdout = %q, want success output", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty output", stderr.String())
	}
}

// TestNormalizeDomain verifies that operators get stable lowercase DNS names
// when domain input passes through the CLI normalization path.
//
// This test covers the regfilter-check CLI's domain normalization helper.
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
		got := normalizeDomain(tt.input)
		if got != tt.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
