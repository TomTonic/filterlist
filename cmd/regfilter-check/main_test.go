package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TomTonic/coredns-regfilter/pkg/filterlist"
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
	writeFilterFile(t, blDir, "rules.txt", "||ads.example.com^\nexample.com##.ad-banner\n")

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
	writeFilterFile(t, wlDir, "allow.txt", "@@||safe.example.com^\n")
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
			wantToken: "WHITELISTED rule=allow.txt:1 (safe.example.com)",
		},
		{
			name:      "blacklisted",
			args:      []string{"match", "--whitelist", wlDir, "--blacklist", blDir, "--name", "ads.example.com"},
			wantCode:  1,
			wantToken: "BLACKLISTED rule=deny.txt:1 (ads.example.com)",
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
			if strings.Contains(stderr.String(), "WARN:") || strings.Contains(stderr.String(), "ERROR:") {
				t.Fatalf("stderr = %q, want no warnings or errors", stderr.String())
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
	if strings.Contains(stderr.String(), "WARN:") || strings.Contains(stderr.String(), "ERROR:") {
		t.Fatalf("stderr = %q, want no warnings or errors", stderr.String())
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

// TestShortSource verifies that operators see concise rule references in CLI
// match output by asserting that shortSource strips directory prefixes and
// preserves the line number suffix.
func TestShortSource(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/var/dns/blacklist/ads.txt:42", "ads.txt:42"},
		{"rules.txt:1", "rules.txt:1"},
		{"/a/b/c/list.hosts:100", "list.hosts:100"},
		{"", "unknown"},
		{"nolineinfo", "nolineinfo"},
	}
	for _, tt := range tests {
		got := shortSource(tt.input)
		if got != tt.want {
			t.Errorf("shortSource(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestWriteRuleDetail verifies that the CLI match command shows the rule source
// and pattern for matched queries by asserting that writeRuleDetail formats the
// first matching rule ID into a human-readable reference.
func TestWriteRuleDetail(t *testing.T) {
	tests := []struct {
		name     string
		ruleIDs  []int
		sources  []string
		patterns []string
		want     string
	}{
		{
			name:     "shows source and pattern",
			ruleIDs:  []int{0},
			sources:  []string{"/etc/bl/deny.txt:3"},
			patterns: []string{"ads.example.com"},
			want:     " rule=deny.txt:3 (ads.example.com)",
		},
		{
			name:     "shows source without pattern",
			ruleIDs:  []int{0},
			sources:  []string{"/etc/bl/deny.txt:3"},
			patterns: []string{""},
			want:     " rule=deny.txt:3",
		},
		{
			name:    "empty ruleIDs produces no output",
			ruleIDs: nil,
			sources: []string{"/etc/bl/deny.txt:3"},
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeRuleDetail(&buf, tt.ruleIDs, tt.sources, tt.patterns)
			if got := buf.String(); got != tt.want {
				t.Errorf("writeRuleDetail() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFilterRulesForList verifies that the CLI uses the same @@ filtering
// semantics as the watcher: blacklist directories exclude exception rules,
// and whitelist directories select only @@ rules by default or non-@@ rules
// when inverted.
//
// This test covers the filterRulesForList and keepRules helpers.
//
// It asserts each combination of label and invert flag against a mixed set
// of allow and deny rules.
func TestFilterRulesForList(t *testing.T) {
	rules := []filterlist.Rule{
		{Pattern: "block.example.com", IsAllow: false},
		{Pattern: "allow.example.com", IsAllow: true},
	}

	tests := []struct {
		name    string
		label   string
		invert  bool
		wantLen int
		wantPat string
	}{
		{"blacklist keeps non-@@ rules", "blacklist", false, 1, "block.example.com"},
		{"whitelist default keeps @@ rules", "whitelist", false, 1, "allow.example.com"},
		{"whitelist inverted keeps non-@@ rules", "whitelist", true, 1, "block.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterRulesForList(rules, tt.label, tt.invert)
			if len(got) != tt.wantLen {
				t.Fatalf("filterRulesForList len = %d, want %d", len(got), tt.wantLen)
			}
			if got[0].Pattern != tt.wantPat {
				t.Fatalf("filterRulesForList[0].Pattern = %q, want %q", got[0].Pattern, tt.wantPat)
			}
		})
	}
}

// TestRunMatchInvertWhitelist verifies that the --invert-whitelist flag changes
// which rules from the whitelist directory are compiled by asserting that
// ||domain^ entries are used for whitelisting when the flag is set.
func TestRunMatchInvertWhitelist(t *testing.T) {
	wlDir := t.TempDir()
	blDir := t.TempDir()
	writeFilterFile(t, wlDir, "allow.txt", "||safe.example.com^\n")
	writeFilterFile(t, blDir, "deny.txt", "||safe.example.com^\n||ads.example.com^\n")

	// Without --invert-whitelist: ||safe.example.com^ has IsAllow=false, so it
	// is filtered out of the whitelist. safe.example.com ends up BLACKLISTED.
	var stdout, stderr bytes.Buffer
	code := run([]string{"match", "--whitelist", wlDir, "--blacklist", blDir, "--name", "safe.example.com"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("without invert: code = %d, want 1 (BLACKLISTED)", code)
	}
	if !strings.Contains(stdout.String(), "BLACKLISTED") {
		t.Fatalf("without invert: stdout = %q, want BLACKLISTED", stdout.String())
	}

	// With --invert-whitelist: ||safe.example.com^ is now a whitelist entry.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"match", "--whitelist", wlDir, "--blacklist", blDir, "--invert-whitelist", "--name", "safe.example.com"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("with invert: code = %d, want 0 (WHITELISTED)", code)
	}
	if !strings.Contains(stdout.String(), "WHITELISTED") {
		t.Fatalf("with invert: stdout = %q, want WHITELISTED", stdout.String())
	}
}
