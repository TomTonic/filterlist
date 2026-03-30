package blockloader

import (
	"os"
	"path/filepath"
	"testing"
)

type testLogger struct {
	warnings []string
}

func (l *testLogger) Warnf(format string, _ ...interface{}) {
	l.warnings = append(l.warnings, format)
}

// TestLoadDirectory verifies that users get one combined rule set when a filter
// directory contains multiple supported files.
//
// This test covers the blockloader package directory aggregation path.
//
// It asserts that supported files are loaded, subdirectories are ignored, and
// unsupported extensions do not contribute rules.
func TestLoadDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create two filter files
	file1 := `! list 1
||ads.example.com^
||tracker.example.com^
`
	file2 := `0.0.0.0 malware.example.com
0.0.0.0 bad.example.com
`
	if err := os.WriteFile(filepath.Join(dir, "list1.txt"), []byte(file1), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "list2.hosts"), []byte(file2), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	// Create a subdir that should be skipped
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatalf("Mkdir error: %v", err)
	}
	// Create an unsupported extension file
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("not a filter"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	logger := &testLogger{}
	rules, err := LoadDirectory(dir, logger)
	if err != nil {
		t.Fatalf("LoadDirectory error: %v", err)
	}

	if len(rules) != 4 {
		t.Errorf("got %d rules, want 4", len(rules))
		for _, r := range rules {
			t.Logf("  rule: %+v", r)
		}
	}
}

// TestLoadDirectoryMissing verifies that callers see a clear error when they
// point block loading at a directory that does not exist.
//
// This test covers the blockloader package IO failure path.
//
// It asserts that LoadDirectory returns an error for a missing directory.
func TestLoadDirectoryMissing(t *testing.T) {
	_, err := LoadDirectory("/nonexistent/dir", nil)
	if err == nil {
		t.Error("expected error for missing directory")
	}
}

// TestLoadDirectoryEmpty verifies that users can keep an empty directory
// without producing synthetic rules.
//
// This test covers the blockloader package empty-directory path.
//
// It asserts that LoadDirectory returns an empty rule slice without error.
func TestLoadDirectoryEmpty(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}
	rules, err := LoadDirectory(dir, logger)
	if err != nil {
		t.Fatalf("LoadDirectory error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("got %d rules, want 0", len(rules))
	}
}

// TestIsFilterFile verifies that operators can mix common filter list filename
// conventions without manually enumerating every extension.
//
// This test covers the blockloader package file selection helper.
//
// It asserts that supported filter extensions are accepted and unrelated files
// are skipped.
func TestIsFilterFile(t *testing.T) {
	yes := []string{"list.txt", "block.list", "hosts.hosts", "rules.conf", "noext", "filters.block"}
	no := []string{"readme.md", "config.json", "data.csv"}
	for _, name := range yes {
		if !isFilterFile(name) {
			t.Errorf("isFilterFile(%q) = false, want true", name)
		}
	}
	for _, name := range no {
		if isFilterFile(name) {
			t.Errorf("isFilterFile(%q) = true, want false", name)
		}
	}
}
