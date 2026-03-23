// Package watcher provides fsnotify-based directory watching with debounced
// DFA recompilation. It watches whitelist and blacklist directories and
// rebuilds DFAs atomically when files change.
package watcher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/tomtonic/coredns-regfilter/pkg/automaton"
	"github.com/tomtonic/coredns-regfilter/pkg/blockloader"
)

// Logger is a minimal logging interface.
type Logger interface {
	Warnf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type nopLogger struct{}

func (nopLogger) Warnf(string, ...interface{})  {}
func (nopLogger) Infof(string, ...interface{})  {}
func (nopLogger) Errorf(string, ...interface{}) {}

// Config configures the watcher.
type Config struct {
	WhitelistDir   string
	BlacklistDir   string
	Debounce       time.Duration
	Logger         Logger
	OnUpdate       func(whitelist *automaton.DFA, blacklist *automaton.DFA)
	MaxCompileTime time.Duration
	MaxStates      int
}

func (c *Config) defaults() {
	if c.Debounce == 0 {
		c.Debounce = 300 * time.Millisecond
	}
	if c.Logger == nil {
		c.Logger = nopLogger{}
	}
	if c.MaxCompileTime == 0 {
		c.MaxCompileTime = 30 * time.Second
	}
	if c.MaxStates == 0 {
		c.MaxStates = 200000
	}
}

// Start begins watching the configured directories and returns a stop function.
// It performs an initial compilation before returning.
func Start(cfg *Config) (stop func() error, err error) {
	if cfg == nil {
		return nil, errors.New("watcher: nil config")
	}

	cfg.defaults()

	ctx, cancel := context.WithCancel(context.Background())

	w := &dirWatcher{
		cfg:    *cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initial compile
	wlDFA := w.compileDir(cfg.WhitelistDir, "whitelist")
	blDFA := w.compileDir(cfg.BlacklistDir, "blacklist")
	if cfg.OnUpdate != nil {
		cfg.OnUpdate(wlDFA, blDFA)
	}

	// Set up fsnotify
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("watcher: create fsnotify: %w", err)
	}
	w.fsw = fsw

	// Watch directories (non-fatal if missing)
	for _, dir := range []string{cfg.WhitelistDir, cfg.BlacklistDir} {
		if dir == "" {
			continue
		}
		if err := fsw.Add(dir); err != nil {
			cfg.Logger.Warnf("watcher: cannot watch %s: %v (will not hot-reload)", dir, err)
		}
	}

	w.wg.Add(1)
	go w.loop()

	return w.stop, nil
}

type dirWatcher struct {
	cfg    Config
	ctx    context.Context
	cancel context.CancelFunc
	fsw    *fsnotify.Watcher
	wg     sync.WaitGroup

	mu        sync.Mutex // protects compileDir calls
	lastWLDFA *automaton.DFA
	lastBLDFA *automaton.DFA
}

func (w *dirWatcher) stop() error {
	w.cancel()
	err := w.fsw.Close()
	w.wg.Wait()
	return err
}

func (w *dirWatcher) loop() {
	defer w.wg.Done()

	var (
		whitelistTimer *time.Timer
		blacklistTimer *time.Timer
	)
	whitelistCh := make(chan time.Time, 1)
	blacklistCh := make(chan time.Time, 1)

	for {
		select {
		case <-w.ctx.Done():
			if whitelistTimer != nil {
				whitelistTimer.Stop()
			}
			if blacklistTimer != nil {
				blacklistTimer.Stop()
			}
			return

		case event, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			w.cfg.Logger.Infof("watcher: event %s on %s", event.Op, event.Name)

			// Determine which directory changed
			if isUnder(event.Name, w.cfg.WhitelistDir) {
				if whitelistTimer != nil {
					whitelistTimer.Stop()
				}
				whitelistTimer = time.AfterFunc(w.cfg.Debounce, func() {
					select {
					case whitelistCh <- time.Now():
					default:
					}
				})
			}
			if isUnder(event.Name, w.cfg.BlacklistDir) {
				if blacklistTimer != nil {
					blacklistTimer.Stop()
				}
				blacklistTimer = time.AfterFunc(w.cfg.Debounce, func() {
					select {
					case blacklistCh <- time.Now():
					default:
					}
				})
			}

		case <-whitelistCh:
			w.rebuild("whitelist")

		case <-blacklistCh:
			w.rebuild("blacklist")

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			w.cfg.Logger.Errorf("watcher: fsnotify error: %v", err)
		}
	}
}

func (w *dirWatcher) rebuild(which string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.cfg.Logger.Infof("watcher: rebuilding %s DFA", which)

	switch which {
	case "whitelist":
		dfa := w.compileDir(w.cfg.WhitelistDir, "whitelist")
		if dfa != nil {
			w.lastWLDFA = dfa
		} else if w.lastWLDFA != nil {
			w.cfg.Logger.Warnf("watcher: whitelist compile failed, keeping previous DFA")
			dfa = w.lastWLDFA
		}
		if w.cfg.OnUpdate != nil {
			w.cfg.OnUpdate(dfa, w.lastBLDFA)
		}

	case "blacklist":
		dfa := w.compileDir(w.cfg.BlacklistDir, "blacklist")
		if dfa != nil {
			w.lastBLDFA = dfa
		} else if w.lastBLDFA != nil {
			w.cfg.Logger.Warnf("watcher: blacklist compile failed, keeping previous DFA")
			dfa = w.lastBLDFA
		}
		if w.cfg.OnUpdate != nil {
			w.cfg.OnUpdate(w.lastWLDFA, dfa)
		}
	}
}

func (w *dirWatcher) compileDir(dir, label string) *automaton.DFA {
	if dir == "" {
		return nil
	}

	logger := filterlistLogger{w.cfg.Logger}
	rules, err := blockloader.LoadDirectory(dir, &logger)
	if err != nil {
		w.cfg.Logger.Errorf("watcher: load %s dir %s: %v", label, dir, err)
		return nil
	}

	if len(rules) == 0 {
		w.cfg.Logger.Infof("watcher: %s has no rules", label)
		return nil
	}

	start := time.Now()
	dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{
		MaxStates:      w.cfg.MaxStates,
		CompileTimeout: w.cfg.MaxCompileTime,
	})
	elapsed := time.Since(start)

	if err != nil {
		w.cfg.Logger.Errorf("watcher: compile %s failed after %v: %v", label, elapsed, err)
		return nil
	}

	w.cfg.Logger.Infof("watcher: compiled %s DFA: %d rules, %d states in %v",
		label, len(rules), dfa.StateCount(), elapsed)
	return dfa
}

// isUnder checks if path is under dir (simple prefix check).
func isUnder(path, dir string) bool {
	if dir == "" {
		return false
	}
	return len(path) >= len(dir) && path[:len(dir)] == dir
}

// filterlistLogger adapts our Logger to filterlist.Logger.
type filterlistLogger struct {
	l Logger
}

func (f *filterlistLogger) Warnf(format string, args ...interface{}) {
	f.l.Warnf(format, args...)
}
