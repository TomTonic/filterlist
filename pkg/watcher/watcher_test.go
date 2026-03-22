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
	os.WriteFile(filepath.Join(blDir, "test.txt"), []byte("||ads.example.com^\n"), 0644)

	var mu sync.Mutex
	var lastWL, lastBL *automaton.DFA
	updateCount := 0

	stop, err := Start(Config{
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
	defer stop()

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
	stop, err := Start(Config{
		WhitelistDir: "/nonexistent/whitelist",
		BlacklistDir: "/nonexistent/blacklist",
		Logger:       logger,
		OnUpdate:     func(_ *automaton.DFA, _ *automaton.DFA) {},
	})
	if err != nil {
		t.Fatalf("Start should not fail for missing dirs: %v", err)
	}
	defer stop()
}

func TestHotReload(t *testing.T) {
	blDir := t.TempDir()

	os.WriteFile(filepath.Join(blDir, "test.txt"), []byte("||ads.example.com^\n"), 0644)

	var mu sync.Mutex
	var lastBL *automaton.DFA
	updateCount := 0

	stop, err := Start(Config{
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
	defer stop()

	// Write a new file to trigger reload
	time.Sleep(100 * time.Millisecond)
	os.WriteFile(filepath.Join(blDir, "new.txt"), []byte("||tracker.example.com^\n"), 0644)

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
