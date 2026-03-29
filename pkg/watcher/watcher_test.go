package watcher

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tomtonic/coredns-regfilter/pkg/automaton"
)

type testLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *testLogger) Warnf(format string, _ ...interface{})  { l.log(format) }
func (l *testLogger) Infof(format string, _ ...interface{})  { l.log(format) }
func (l *testLogger) Errorf(format string, _ ...interface{}) { l.log(format) }

func (l *testLogger) log(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, msg)
}

func TestStartAndStop(t *testing.T) {
	wlDir := t.TempDir()
	blDir := t.TempDir()

	// Write a filter file
	if err := os.WriteFile(filepath.Join(blDir, "test.txt"), []byte("||ads.example.com^\n"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var mu sync.Mutex
	var lastWL, lastBL *automaton.DFA
	updateCount := 0

	stop, err := Start(&Config{
		WhitelistDir: wlDir,
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		Logger:       &testLogger{},
		OnUpdate: func(wl *automaton.DFA, bl *automaton.DFA) {
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
	if lastBL == nil {
		t.Error("expected blacklist DFA after initial compile")
	}
	if lastWL != nil {
		t.Error("expected nil whitelist DFA (empty dir)")
	}
	mu.Unlock()

	// Verify blacklist match
	if lastBL != nil {
		matched, _ := lastBL.Match("ads.example.com")
		if !matched {
			t.Error("expected blacklist to match ads.example.com")
		}
	}
}

func TestStartMissingDirs(t *testing.T) {
	logger := &testLogger{}
	stop, err := Start(&Config{
		WhitelistDir: "/nonexistent/whitelist",
		BlacklistDir: "/nonexistent/blacklist",
		Logger:       logger,
		OnUpdate:     func(_ *automaton.DFA, _ *automaton.DFA) {},
	})
	if err != nil {
		t.Fatalf("Start should not fail for missing dirs: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			t.Errorf("stop error: %v", stopErr)
		}
	})
}

func TestHotReload(t *testing.T) {
	blDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(blDir, "test.txt"), []byte("||ads.example.com^\n"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var mu sync.Mutex
	var lastBL *automaton.DFA
	updateCount := 0

	stop, err := Start(&Config{
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		Logger:       &testLogger{},
		OnUpdate: func(_ *automaton.DFA, bl *automaton.DFA) {
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
	if err := os.WriteFile(filepath.Join(blDir, "new.txt"), []byte("||tracker.example.com^\n"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	// Wait for debounce + compile
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	if lastBL != nil {
		matched, _ := lastBL.Match("tracker.example.com")
		if !matched {
			t.Error("expected blacklist to match tracker.example.com after reload")
		}
	}
	mu.Unlock()
}

func TestHotReloadKeepsPreviousDFAOnCompileFailure(t *testing.T) {
	blDir := t.TempDir()
	path := filepath.Join(blDir, "test.txt")

	if err := os.WriteFile(path, []byte("||ads.example.com^\n"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var mu sync.Mutex
	var lastBL *automaton.DFA

	stop, err := Start(&Config{
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		Logger:       &testLogger{},
		OnUpdate: func(_ *automaton.DFA, bl *automaton.DFA) {
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
	if lastBL == nil {
		mu.Unlock()
		t.Fatal("expected initial blacklist DFA")
	}
	mu.Unlock()

	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(path, []byte("##.banner\n"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if lastBL == nil {
		t.Fatal("expected previous blacklist DFA to be preserved after failed rebuild")
	}
	matched, _ := lastBL.Match("ads.example.com")
	if !matched {
		t.Error("expected preserved blacklist DFA to keep matching ads.example.com")
	}
}

func TestIsUnder(t *testing.T) {
	tests := []struct {
		path, dir string
		want      bool
	}{
		{"/a/b/c.txt", "/a/b", true},
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

func TestOnCompileCallback(t *testing.T) {
	blDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(blDir, "test.txt"), []byte("||ads.example.com^\n"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var mu sync.Mutex
	var compileCalls int
	var lastDuration time.Duration

	stop, err := Start(&Config{
		BlacklistDir: blDir,
		Debounce:     50 * time.Millisecond,
		Logger:       &testLogger{},
		OnUpdate:     func(_ *automaton.DFA, _ *automaton.DFA) {},
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
