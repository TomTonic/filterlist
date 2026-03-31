package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *testLogger) Warnf(format string, args ...interface{})  { l.log(fmt.Sprintf(format, args...)) }
func (l *testLogger) Infof(format string, args ...interface{})  { l.log(fmt.Sprintf(format, args...)) }
func (l *testLogger) Errorf(format string, args ...interface{}) { l.log(fmt.Sprintf(format, args...)) }

func (l *testLogger) log(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, msg)
}

func (l *testLogger) contains(part string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, msg := range l.msgs {
		if strings.Contains(msg, part) {
			return true
		}
	}

	return false
}

// TestStartAndStop verifies that operators get an initial compiled blacklist and
// a clean shutdown path when the watcher starts on readable filter files.
//
// This test covers the watcher package lifecycle around initial compilation and
// stop handling.
//
// It asserts that Start publishes the first snapshot before returning and that
// the resulting DFA matches the seeded blacklist rule.
func TestStartAndStop(t *testing.T) {
	wlDir := t.TempDir()
	blDir := t.TempDir()
	logger := &testLogger{}

	// Write a filter file
	if err := os.WriteFile(filepath.Join(blDir, "test.txt"), []byte("||ads.example.com^\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var mu sync.Mutex
	var lastWL, lastBL Snapshot
	updateCount := 0

	stop, err := Start(&Config{
		WhitelistDir: wlDir,
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		Logger:       logger,
		OnUpdate: func(wl Snapshot, bl Snapshot) {
			mu.Lock()
			defer mu.Unlock()
			lastWL = wl
			lastBL = bl
			updateCount++
		},
	})
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			t.Errorf("stop error: %v", stopErr)
		}
	})

	// Initial compile should have been called
	mu.Lock()
	if updateCount < 1 {
		t.Error("expected at least 1 OnUpdate call from initial compile")
	}
	if lastBL.DFA == nil {
		t.Error("expected blacklist DFA after initial compile")
	}
	if lastWL.DFA != nil {
		t.Error("expected nil whitelist DFA (empty dir)")
	}
	if lastBL.RuleCount != 1 {
		t.Errorf("expected blacklist rule count 1, got %d", lastBL.RuleCount)
	}
	mu.Unlock()

	// Verify blacklist match
	if lastBL.DFA != nil {
		matched, _ := lastBL.DFA.Match("ads.example.com")
		if !matched {
			t.Error("expected blacklist to match ads.example.com")
		}
	}
	if !logger.contains("label=whitelist") || !logger.contains("status=empty") {
		t.Error("expected detailed compile summary for empty whitelist")
	}
	if !logger.contains("label=blacklist") || !logger.contains("status=ready") {
		t.Error("expected detailed compile summary for ready blacklist")
	}
}

// TestStartMissingDirs verifies that operators can keep the service running
// even when configured directories are unreadable.
//
// This test covers the watcher package fail-open startup path.
//
// It asserts that Start succeeds, reports startup errors through callbacks, and
// logs a detailed compile summary for missing directories.
func TestStartMissingDirs(t *testing.T) {
	logger := &testLogger{}
	errorCount := 0
	stop, err := Start(&Config{
		WhitelistDir: "/nonexistent/whitelist",
		BlacklistDir: "/nonexistent/blacklist",
		Logger:       logger,
		OnUpdate:     func(_ Snapshot, _ Snapshot) {},
		OnError: func(_ string, _ error) {
			errorCount++
		},
	})
	if err != nil {
		t.Fatalf("Start should not fail for unreadable configured directories: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			t.Errorf("stop error: %v", stopErr)
		}
	})
	if errorCount != 2 {
		t.Fatalf("OnError calls = %d, want 2", errorCount)
	}
	if !logger.contains("status=load_error") {
		t.Fatal("expected compile summary for missing directories")
	}
}

// TestHotReload verifies that users see newly added blacklist rules take effect
// without restarting the process.
//
// This test covers the watcher package fsnotify debounce and rebuild flow.
//
// It asserts that a new file causes the active blacklist snapshot to match the
// freshly added domain.
func TestHotReload(t *testing.T) {
	blDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(blDir, "test.txt"), []byte("||ads.example.com^\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var mu sync.Mutex
	var lastBL Snapshot
	updateCount := 0

	stop, err := Start(&Config{
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		Logger:       &testLogger{},
		OnUpdate: func(_ Snapshot, bl Snapshot) {
			mu.Lock()
			defer mu.Unlock()
			lastBL = bl
			updateCount++
		},
	})
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			t.Errorf("stop error: %v", stopErr)
		}
	})

	// Write a new file to trigger reload
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(blDir, "new.txt"), []byte("||tracker.example.com^\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	// Wait for debounce + compile
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	if lastBL.DFA != nil {
		matched, _ := lastBL.DFA.Match("tracker.example.com")
		if !matched {
			t.Error("expected blacklist to match tracker.example.com after reload")
		}
	}
	mu.Unlock()
}

// TestHotReloadKeepsPreviousDFAOnCompileFailure verifies that users keep the
// last working policy when a reload introduces unsupported rules.
//
// This test covers the watcher package rebuild error-handling path.
//
// It asserts that a failed rebuild preserves the previous compiled blacklist.
func TestHotReloadKeepsPreviousDFAOnCompileFailure(t *testing.T) {
	blDir := t.TempDir()
	path := filepath.Join(blDir, "test.txt")
	logger := &testLogger{}

	if err := os.WriteFile(path, []byte("a.b\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var mu sync.Mutex
	var lastBL Snapshot

	stop, err := Start(&Config{
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		MaxStates:    5,
		Logger:       logger,
		OnUpdate: func(_ Snapshot, bl Snapshot) {
			mu.Lock()
			defer mu.Unlock()
			lastBL = bl
		},
	})
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			t.Errorf("stop error: %v", stopErr)
		}
	})

	mu.Lock()
	if lastBL.DFA == nil {
		mu.Unlock()
		t.Fatal("expected initial blacklist DFA")
	}
	mu.Unlock()

	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(path, []byte("*.*.*.example.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if lastBL.DFA == nil {
		t.Fatal("expected previous blacklist DFA to be preserved after failed rebuild")
	}
	matched, _ := lastBL.DFA.Match("a.b")
	if !matched {
		t.Error("expected preserved blacklist DFA to keep matching the original rule")
	}
	if !logger.contains("status=compile_error") {
		t.Error("expected detailed compile summary for failed rebuild")
	}
}

// TestHotReloadClearsDFAOnEmptyLists verifies that administrators can remove
// all blacklist rules and have the active snapshot clear on the next reload.
//
// This test covers the watcher package distinction between empty successful
// reloads and failed reloads.
//
// It asserts that an empty filter file clears the blacklist DFA instead of
// keeping stale rules alive.
func TestHotReloadClearsDFAOnEmptyLists(t *testing.T) {
	blDir := t.TempDir()
	path := filepath.Join(blDir, "test.txt")

	if err := os.WriteFile(path, []byte("||ads.example.com^\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var mu sync.Mutex
	var lastBL Snapshot

	stop, err := Start(&Config{
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		Logger:       &testLogger{},
		OnUpdate: func(_ Snapshot, bl Snapshot) {
			mu.Lock()
			defer mu.Unlock()
			lastBL = bl
		},
	})
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			t.Errorf("stop error: %v", stopErr)
		}
	})

	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if lastBL.DFA != nil {
		t.Fatal("expected blacklist DFA to clear after successful empty reload")
	}
	if lastBL.RuleCount != 0 {
		t.Fatalf("expected zero rules after empty reload, got %d", lastBL.RuleCount)
	}
}

// TestIsUnder verifies that file events are attributed to the correct watched
// directory instead of neighboring paths that only share a string prefix.
//
// This test covers the watcher package path classification helper.
//
// It asserts that descendants match while sibling prefix collisions do not.
func TestIsUnder(t *testing.T) {
	tests := []struct {
		path, dir string
		want      bool
	}{
		{"/a/b/c.txt", "/a/b", true},
		{"/a/bad/c.txt", "/a/b", false},
		{"/a/b/c.txt", "/a/x", false},
		{"/a/b/c.txt", "", false},
		{"", "/a", false},
	}
	for _, tt := range tests {
		got := isUnder(tt.path, tt.dir)
		if got != tt.want {
			t.Errorf("isUnder(%q, %q) = %v, want %v", tt.path, tt.dir, got, tt.want)
		}
	}
}

// TestOnCompileCallback verifies that operators receive compile timing data for
// successful rebuilds.
//
// This test covers the watcher package observability callback path.
//
// It asserts that Start triggers OnCompile during the initial blacklist build
// and reports a positive duration.
func TestOnCompileCallback(t *testing.T) {
	blDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(blDir, "test.txt"), []byte("||ads.example.com^\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var mu sync.Mutex
	var compileCalls int
	var lastDuration time.Duration

	stop, err := Start(&Config{
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		Logger:       &testLogger{},
		OnUpdate:     func(_ Snapshot, _ Snapshot) {},
		OnCompile: func(label string, duration time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			compileCalls++
			lastDuration = duration
			if label != "blacklist" {
				t.Errorf("expected label 'blacklist', got %q", label)
			}
		},
	})
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			t.Errorf("stop error: %v", stopErr)
		}
	})

	mu.Lock()
	if compileCalls < 1 {
		t.Error("expected at least 1 OnCompile call from initial compile")
	}
	if lastDuration <= 0 {
		t.Errorf("expected positive compile duration, got %v", lastDuration)
	}
	mu.Unlock()
}

// TestBlacklistExcludesExceptionRules verifies that operators get correct
// AdGuard-compatible blocking when downloaded filter lists contain @@ exception
// rules mixed with blocking rules.
//
// This test covers the watcher rule filtering for blacklist directories.
//
// It writes a blacklist file with both @@ (exception) and || (blocking) rules
// and asserts that only the blocking rule is compiled into the DFA.
func TestBlacklistExcludesExceptionRules(t *testing.T) {
	blDir := t.TempDir()
	content := "||ads.example.com^\n@@||safe.example.com^\n"
	if err := os.WriteFile(filepath.Join(blDir, "mixed.txt"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var lastBL Snapshot
	stop, err := Start(&Config{
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		Logger:       &testLogger{},
		OnUpdate: func(_ Snapshot, bl Snapshot) {
			lastBL = bl
		},
	})
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() { _ = stop() })

	if lastBL.DFA == nil {
		t.Fatal("expected blacklist DFA")
	}
	if lastBL.RuleCount != 1 {
		t.Errorf("RuleCount = %d, want 1 (only non-@@ rule)", lastBL.RuleCount)
	}
	matched, _ := lastBL.DFA.Match("ads.example.com")
	if !matched {
		t.Error("expected blacklist to match ads.example.com")
	}
	matched, _ = lastBL.DFA.Match("safe.example.com")
	if matched {
		t.Error("expected blacklist NOT to match safe.example.com (@@-filtered)")
	}
}

// TestWhitelistDefaultKeepsExceptionRules verifies that the default whitelist
// mode compiles only @@ (exception/allow) rules into the whitelist DFA,
// following AdGuard semantics.
//
// This test covers the watcher rule filtering for whitelist directories with
// InvertWhitelist=false.
//
// It writes a whitelist file with @@ rules and asserts those are compiled.
func TestWhitelistDefaultKeepsExceptionRules(t *testing.T) {
	wlDir := t.TempDir()
	content := "@@||safe.example.com^\n||other.example.com^\n"
	if err := os.WriteFile(filepath.Join(wlDir, "allow.txt"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var lastWL Snapshot
	stop, err := Start(&Config{
		WhitelistDir: wlDir,
		Debounce:     50 * time.Millisecond,
		Logger:       &testLogger{},
		OnUpdate: func(wl Snapshot, _ Snapshot) {
			lastWL = wl
		},
	})
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() { _ = stop() })

	if lastWL.DFA == nil {
		t.Fatal("expected whitelist DFA")
	}
	if lastWL.RuleCount != 1 {
		t.Errorf("RuleCount = %d, want 1 (only @@-rule)", lastWL.RuleCount)
	}
	matched, _ := lastWL.DFA.Match("safe.example.com")
	if !matched {
		t.Error("expected whitelist to match safe.example.com")
	}
	matched, _ = lastWL.DFA.Match("other.example.com")
	if matched {
		t.Error("expected whitelist NOT to match other.example.com (non-@@ filtered out)")
	}
}

// TestWhitelistInvertedKeepsNonExceptionRules verifies that the invert_whitelist
// mode compiles ||domain^ rules (non-@@) into the whitelist DFA.
//
// This test covers the watcher rule filtering for whitelist directories with
// InvertWhitelist=true.
//
// It writes a whitelist file with both @@ and || rules and asserts that only
// the non-@@ rules are compiled.
func TestWhitelistInvertedKeepsNonExceptionRules(t *testing.T) {
	wlDir := t.TempDir()
	content := "||safe.example.com^\n@@||ignored.example.com^\n"
	if err := os.WriteFile(filepath.Join(wlDir, "allow.txt"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var lastWL Snapshot
	stop, err := Start(&Config{
		WhitelistDir:    wlDir,
		Debounce:        50 * time.Millisecond,
		Logger:          &testLogger{},
		InvertWhitelist: true,
		OnUpdate: func(wl Snapshot, _ Snapshot) {
			lastWL = wl
		},
	})
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() { _ = stop() })

	if lastWL.DFA == nil {
		t.Fatal("expected whitelist DFA")
	}
	if lastWL.RuleCount != 1 {
		t.Errorf("RuleCount = %d, want 1 (only non-@@ rule)", lastWL.RuleCount)
	}
	matched, _ := lastWL.DFA.Match("safe.example.com")
	if !matched {
		t.Error("expected inverted whitelist to match safe.example.com")
	}
	matched, _ = lastWL.DFA.Match("ignored.example.com")
	if matched {
		t.Error("expected inverted whitelist NOT to match ignored.example.com (@@-filtered)")
	}
}
