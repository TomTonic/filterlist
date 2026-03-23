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
	if err := os.WriteFile(filepath.Join(dir, "list1.txt"), []byte(file1), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "list2.hosts"), []byte(file2), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	// Create a subdir that should be skipped
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatalf("Mkdir error: %v", err)
	}
	// Create an unsupported extension file
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("not a filter"), 0o644); err != nil {
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

func TestLoadDirectoryMissing(t *testing.T) {
	_, err := LoadDirectory("/nonexistent/dir", nil)
	if err == nil {
		t.Error("expected error for missing directory")
	}
}

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
