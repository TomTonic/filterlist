package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//nolint:unparam // name parameter intentionally kept for test API parity
func writeFilterFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error: %v", path, err)
	}
}

// TestRunWithoutArgsShowsUsage verifies that operators get actionable CLI help
// when they invoke the checker without arguments.
//
// This test covers the top-level command dispatch in filterlist-check.
//
// It asserts that run returns a failure code and prints usage text.
func TestRunWithoutArgsShowsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "filterlist-check") {
		t.Fatalf("stderr = %q, want usage output", stderr.String())
	}
}

// TestRunHelpReturnsZero verifies that operators can request command help
// without triggering an error path.
//
// This test covers the top-level help handling in filterlist-check.
//
// It asserts that the help command returns zero and prints command usage.
func TestRunHelpReturnsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(help) code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "validate") {
		t.Fatalf("stderr = %q, want command list", stderr.String())
	}
}

// TestRunRejectsUnknownCommand verifies that operators get immediate feedback
// for unsupported CLI invocations.
//
// This test covers unknown-command handling in filterlist-check.
//
// It asserts that unknown commands return a failure code and include the
// invalid command in stderr output.
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

// TestRunValidateCompilesRules verifies that operators can validate list
// directories from the CLI.
//
// This test covers the validate command path in filterlist-check.
//
// It asserts that parsing and compilation both succeed for a valid list file.
func TestRunValidateCompilesRules(t *testing.T) {
	listDir := t.TempDir()
	writeFilterFile(t, listDir, "rules.txt", "||ads.example.com^\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"validate", "--list", listDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(validate) code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "compiled:") {
		t.Fatalf("stdout = %q, want compile summary", stdout.String())
	}
	if strings.Contains(stderr.String(), "ERROR:") {
		t.Fatalf("stderr = %q, want no errors", stderr.String())
	}
}

// TestRunValidateRequiresAtLeastOneList verifies that operators cannot run the
// validator without list input.
//
// This test covers input validation for the validate command flags.
//
// It asserts that the command returns a failure code and a clear error message
// when --list is missing.
func TestRunValidateRequiresAtLeastOneList(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"validate"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run(validate) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "at least one --list DIR is required") {
		t.Fatalf("stderr = %q, want missing list message", stderr.String())
	}
}

// TestRunValidateRejectsNegativeMaxStates verifies that operators receive a
// clear validation error for invalid state limits.
//
// This test covers flag validation in the validate command path.
//
// It asserts that --max-states < 0 is rejected.
func TestRunValidateRejectsNegativeMaxStates(t *testing.T) {
	listDir := t.TempDir()
	writeFilterFile(t, listDir, "rules.txt", "||ads.example.com^\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"validate", "--list", listDir, "--max-states", "-1"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run(validate) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--max-states must be >= 0") {
		t.Fatalf("stderr = %q, want max-states validation message", stderr.String())
	}
}

// TestRunValidateAcceptsUncappedMaxStates verifies that operators can
// explicitly disable DFA state capping during offline validation.
//
// This test covers the validate command flag handling for max state limits.
//
// It asserts that --max-states 0 is accepted and still compiles valid input.
func TestRunValidateAcceptsUncappedMaxStates(t *testing.T) {
	listDir := t.TempDir()
	writeFilterFile(t, listDir, "rules.txt", "||ads.example.com^\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"validate", "--list", listDir, "--max-states", "0"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(validate) code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "compiled:") {
		t.Fatalf("stdout = %q, want compile summary", stdout.String())
	}
}

// TestRunValidateAcceptsDFAMatcherMode verifies that operators can validate
// list directories using the pure-DFA matcher mode from the CLI.
//
// This test covers the validate command flag handling for matcher-mode.
//
// It asserts that --matcher-mode dfa succeeds and reports the selected mode in
// the compile summary.
func TestRunValidateAcceptsDFAMatcherMode(t *testing.T) {
	listDir := t.TempDir()
	writeFilterFile(t, listDir, "rules.txt", "||ads.example.com^\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"validate", "--list", listDir, "--matcher-mode", "dfa"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(validate --matcher-mode dfa) code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "mode=dfa") {
		t.Fatalf("stdout = %q, want mode=dfa compile summary", stdout.String())
	}
	if strings.Contains(stderr.String(), "ERROR:") {
		t.Fatalf("stderr = %q, want no errors", stderr.String())
	}
}

// TestRunValidateRejectsInvalidMatcherMode verifies that operators receive a
// clear validation error for unsupported matcher modes.
//
// This test covers validation of the validate command's matcher-mode flag.
//
// It asserts that values other than hybrid or dfa cause the command to fail.
func TestRunValidateRejectsInvalidMatcherMode(t *testing.T) {
	listDir := t.TempDir()
	writeFilterFile(t, listDir, "rules.txt", "||ads.example.com^\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"validate", "--list", listDir, "--matcher-mode", "fast"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run(validate --matcher-mode fast) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown matcher mode") {
		t.Fatalf("stderr = %q, want matcher-mode validation message", stderr.String())
	}
}
