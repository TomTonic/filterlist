// Package watcher provides fsnotify-based directory watching with debounced
// DFA recompilation. It watches whitelist and blacklist directories and
// rebuilds DFAs atomically when files change.
package watcher

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/TomTonic/coredns-regfilter/pkg/automaton"
	"github.com/TomTonic/coredns-regfilter/pkg/blockloader"
	"github.com/TomTonic/coredns-regfilter/pkg/filterlist"
)

// Logger is a minimal logging interface.
type Logger interface {
	Warnf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// nopLogger discards all log output when callers leave Logger nil.
type nopLogger struct{}

// Warnf discards watcher warnings when no logger is configured.
func (nopLogger) Warnf(string, ...interface{}) {}

// Infof discards watcher informational messages when no logger is configured.
func (nopLogger) Infof(string, ...interface{}) {}

// Errorf discards watcher errors when no logger is configured.
func (nopLogger) Errorf(string, ...interface{}) {}

// Config configures the watcher.
type Config struct {
	WhitelistDir    string
	BlacklistDir    string
	Debounce        time.Duration
	Logger          Logger
	OnUpdate        func(whitelist Snapshot, blacklist Snapshot)
	OnCompile       func(label string, duration time.Duration)
	OnError         func(label string, err error)
	MaxCompileTime  time.Duration
	MaxStates       int
	InvertWhitelist bool
}

// Snapshot describes one compiled filter set state.
type Snapshot struct {
	DFA        *automaton.DFA
	RuleCount  int
	StateCount int
	Sources    []string // rule source strings indexed by rule ID
	Patterns   []string // rule pattern strings indexed by rule ID
}

// compileStatus classifies the outcome of one load-and-compile attempt.
type compileStatus string

// Possible compile outcomes.
const (
	compileStatusDisabled     compileStatus = "disabled"
	compileStatusEmpty        compileStatus = "empty"
	compileStatusReady        compileStatus = "ready"
	compileStatusLoadError    compileStatus = "load_error"
	compileStatusCompileError compileStatus = "compile_error"
)

// compileReport captures metrics and diagnostics for a single compile run.
type compileReport struct {
	Label      string
	Dir        string
	Status     compileStatus
	RuleCount  int
	StateCount int
	Duration   time.Duration
	Err        error
}

// defaults applies operational fallback values when callers leave fields empty.
func (c *Config) defaults() {
	if c.Debounce == 0 {
		c.Debounce = 300 * time.Millisecond
	}
	if c.Debounce < 0 {
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
//
// The cfg parameter supplies watched directories, compile limits, and optional
// callbacks for update and error reporting. Start performs the first load and
// compilation before returning, but it keeps the watcher alive when directories
// are unreadable, empty, or contain only unsupported rules. Those outcomes are
// logged in detail and reported through OnError so callers can continue with
// the last known good snapshot, or with no DFA loaded yet on startup.
//
// On success the returned stop function closes the underlying fsnotify watcher
// and waits for background goroutines to exit. Start is typically used by the
// CoreDNS plugin setup path before the handler is added to the serving chain.
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
	wlSnapshot, wlReport := w.compileDir(cfg.WhitelistDir, "whitelist")
	if wlReport.Err != nil && cfg.OnError != nil {
		cfg.OnError("whitelist", wlReport.Err)
	}
	blSnapshot, blReport := w.compileDir(cfg.BlacklistDir, "blacklist")
	if blReport.Err != nil && cfg.OnError != nil {
		cfg.OnError("blacklist", blReport.Err)
	}
	w.lastWL = wlSnapshot
	w.lastBL = blSnapshot
	if cfg.OnUpdate != nil {
		cfg.OnUpdate(wlSnapshot, blSnapshot)
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

// dirWatcher holds runtime state for one pair of watched directories.
type dirWatcher struct {
	cfg    Config
	ctx    context.Context
	cancel context.CancelFunc
	fsw    *fsnotify.Watcher
	wg     sync.WaitGroup

	mu     sync.Mutex // protects compileDir calls
	lastWL Snapshot
	lastBL Snapshot
}

// stop cancels the watcher context, closes fsnotify, and waits for the loop to exit.
func (w *dirWatcher) stop() error {
	w.cancel()
	err := w.fsw.Close()
	w.wg.Wait()
	return err
}

// loop runs the debounced event loop until the context is cancelled.
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

// rebuild recompiles one filter direction and publishes the result.
func (w *dirWatcher) rebuild(which string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.cfg.Logger.Infof("watcher: rebuilding %s DFA", which)

	switch which {
	case "whitelist":
		snapshot, report := w.compileDir(w.cfg.WhitelistDir, "whitelist")
		if report.Err != nil {
			w.cfg.Logger.Warnf("watcher: whitelist compile failed, keeping previous DFA")
			if w.cfg.OnError != nil {
				w.cfg.OnError("whitelist", report.Err)
			}
			snapshot = w.lastWL
		} else {
			w.lastWL = snapshot
		}
		if w.cfg.OnUpdate != nil {
			w.cfg.OnUpdate(snapshot, w.lastBL)
		}

	case "blacklist":
		snapshot, report := w.compileDir(w.cfg.BlacklistDir, "blacklist")
		if report.Err != nil {
			w.cfg.Logger.Warnf("watcher: blacklist compile failed, keeping previous DFA")
			if w.cfg.OnError != nil {
				w.cfg.OnError("blacklist", report.Err)
			}
			snapshot = w.lastBL
		} else {
			w.lastBL = snapshot
		}
		if w.cfg.OnUpdate != nil {
			w.cfg.OnUpdate(w.lastWL, snapshot)
		}
	}
}

// compileDir loads one configured directory and turns it into a snapshot plus report.
func (w *dirWatcher) compileDir(dir, label string) (Snapshot, compileReport) {
	report := compileReport{
		Label:  label,
		Dir:    dir,
		Status: compileStatusDisabled,
	}
	started := time.Now()

	if dir == "" {
		report.Duration = time.Since(started)
		w.logCompileReport(&report)
		return Snapshot{}, report
	}

	logger := filterlistLogger{w.cfg.Logger}
	rules, err := blockloader.LoadDirectory(dir, &logger)
	if err != nil {
		report.Status = compileStatusLoadError
		report.Duration = time.Since(started)
		report.Err = fmt.Errorf("watcher: load %s dir %s: %w", label, dir, err)
		w.logCompileReport(&report)
		return Snapshot{}, report
	}

	rules = filterRulesForList(rules, label, w.cfg.InvertWhitelist)

	if len(rules) == 0 {
		report.Status = compileStatusEmpty
		report.Duration = time.Since(started)
		w.logCompileReport(&report)
		return Snapshot{}, report
	}

	report.RuleCount = len(rules)
	compileStarted := time.Now()
	dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{
		MaxStates:      w.cfg.MaxStates,
		CompileTimeout: w.cfg.MaxCompileTime,
	})
	compileElapsed := time.Since(compileStarted)
	report.Duration = time.Since(started)

	if err != nil {
		report.Status = compileStatusCompileError
		report.Err = fmt.Errorf("watcher: compile %s failed after %v: %w", label, compileElapsed, err)
		w.logCompileReport(&report)
		return Snapshot{}, report
	}

	report.Status = compileStatusReady
	report.StateCount = dfa.StateCount()
	w.logCompileReport(&report)

	if w.cfg.OnCompile != nil {
		w.cfg.OnCompile(label, compileElapsed)
	}

	return Snapshot{DFA: dfa, RuleCount: len(rules), StateCount: dfa.StateCount(), Sources: ruleSources(rules), Patterns: rulePatterns(rules)}, report
}

// logCompileReport emits one structured summary line for every compile attempt.
func (w *dirWatcher) logCompileReport(report *compileReport) {
	msg := "watcher: compile summary label=%s dir=%s status=%s rules=%d states=%d duration=%v"
	if report.Err != nil {
		w.cfg.Logger.Errorf(
			msg+" error=%v",
			report.Label,
			report.Dir,
			report.Status,
			report.RuleCount,
			report.StateCount,
			report.Duration,
			report.Err,
		)
		return
	}

	w.cfg.Logger.Infof(
		msg,
		report.Label,
		report.Dir,
		report.Status,
		report.RuleCount,
		report.StateCount,
		report.Duration,
	)
}

// isUnder checks whether path is dir itself or a descendant of dir.
func isUnder(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}

	cleanPath := filepath.Clean(path)
	cleanDir := filepath.Clean(dir)
	rel, err := filepath.Rel(cleanDir, cleanPath)
	if err != nil {
		return false
	}

	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// filterRulesForList selects the rules that belong in the compiled DFA for
// the given list label. Blacklist directories always exclude exception rules
// (@@-prefixed) so downloaded AdGuard and EasyList files work without
// conversion. Whitelist directories use the @@-prefixed rules by default
// (AdGuard semantics: @@ = allow); when invertWhitelist is true, non-@@
// rules are used instead (simpler ||domain^ syntax).
func filterRulesForList(rules []filterlist.Rule, label string, invertWhitelist bool) []filterlist.Rule {
	switch label {
	case "blacklist":
		return keepRules(rules, false)
	case "whitelist":
		if invertWhitelist {
			return keepRules(rules, false)
		}
		return keepRules(rules, true)
	default:
		return rules
	}
}

// keepRules returns the subset of rules whose IsAllow field equals wantAllow.
func keepRules(rules []filterlist.Rule, wantAllow bool) []filterlist.Rule {
	filtered := make([]filterlist.Rule, 0, len(rules))
	for _, r := range rules {
		if r.IsAllow == wantAllow {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// ruleSources extracts the Source strings from rules so callers can map
// DFA rule IDs back to file and line information for debug output.
func ruleSources(rules []filterlist.Rule) []string {
	sources := make([]string, len(rules))
	for i, r := range rules {
		sources[i] = r.Source
	}
	return sources
}

// rulePatterns extracts the Pattern strings from rules so callers can show
// the original filter expression alongside the source location in debug output.
func rulePatterns(rules []filterlist.Rule) []string {
	patterns := make([]string, len(rules))
	for i, r := range rules {
		patterns[i] = r.Pattern
	}
	return patterns
}

// filterlistLogger adapts our Logger to filterlist.Logger.
type filterlistLogger struct {
	l Logger
}

// Warnf forwards filterlist warnings into the watcher logger interface.
func (f *filterlistLogger) Warnf(format string, args ...interface{}) {
	f.l.Warnf(format, args...)
}

// Infof forwards filterlist informational messages into the watcher logger interface.
func (f *filterlistLogger) Infof(format string, args ...interface{}) {
	f.l.Infof(format, args...)
}
