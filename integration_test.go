package integration_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tomtonic/coredns-regfilter/pkg/automaton"
	"github.com/tomtonic/coredns-regfilter/pkg/blockloader"
	"github.com/tomtonic/coredns-regfilter/pkg/filterlist"
)

type testLogger struct {
	warnings []string
}

func (l *testLogger) Warnf(format string, args ...interface{}) {
	l.warnings = append(l.warnings, format)
}

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "testdata", "filterlists")
}

func TestIntegrationBlacklistCompile(t *testing.T) {
	dir := filepath.Join(testdataDir(), "blacklist")
	logger := &testLogger{}

	rules, err := blockloader.LoadDirectory(dir, logger)
	if err != nil {
		t.Fatalf("LoadDirectory error: %v", err)
	}

	if len(rules) == 0 {
		t.Fatal("expected rules from blacklist directory")
	}

	t.Logf("loaded %d rules from blacklist", len(rules))

	// Separate allow and deny rules
	var denyRules, allowRules []filterlist.Rule
	for _, r := range rules {
		if r.IsAllow {
			allowRules = append(allowRules, r)
		} else {
			denyRules = append(denyRules, r)
		}
	}

	t.Logf("deny rules: %d, allow rules: %d", len(denyRules), len(allowRules))

	dfa, err := automaton.CompileRules(denyRules, automaton.CompileOptions{})
	if err != nil {
		t.Fatalf("CompileRules error: %v", err)
	}

	t.Logf("DFA states: %d", dfa.StateCount())

	// Test expected matches
	shouldMatch := []string{
		"ads.example.com",
		"tracker.example.com",
		"malware.example.org",
		"adserver.example.com",
		"tracking.example.net",
		"spyware.example.org",
		"banner.example.com",
		"analytics.example.com",
		"telemetry.example.com",
		"pixel.example.com",
		"foo.ad.doubleclick.net",
		"sub.tracking.example.com",
	}
	for _, name := range shouldMatch {
		matched, _ := dfa.Match(name)
		if !matched {
			t.Errorf("expected blacklist to match %q", name)
		}
	}

	// Test expected non-matches
	shouldNotMatch := []string{
		"example.com",
		"safe.example.com",
		"google.com",
		"www.example.com",
	}
	for _, name := range shouldNotMatch {
		matched, _ := dfa.Match(name)
		if matched {
			t.Errorf("expected blacklist NOT to match %q", name)
		}
	}
}

func TestIntegrationWhitelistCompile(t *testing.T) {
	dir := filepath.Join(testdataDir(), "whitelist")
	logger := &testLogger{}

	rules, err := blockloader.LoadDirectory(dir, logger)
	if err != nil {
		t.Fatalf("LoadDirectory error: %v", err)
	}

	if len(rules) == 0 {
		t.Fatal("expected rules from whitelist directory")
	}

	t.Logf("loaded %d rules from whitelist", len(rules))

	dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{})
	if err != nil {
		t.Fatalf("CompileRules error: %v", err)
	}

	shouldMatch := []string{
		"safe.example.com",
		"trusted.example.org",
		"cdn.example.com",
		"api.example.com",
	}
	for _, name := range shouldMatch {
		matched, _ := dfa.Match(name)
		if !matched {
			t.Errorf("expected whitelist to match %q", name)
		}
	}

	shouldNotMatch := []string{
		"ads.example.com",
		"tracker.example.com",
		"example.com",
	}
	for _, name := range shouldNotMatch {
		matched, _ := dfa.Match(name)
		if matched {
			t.Errorf("expected whitelist NOT to match %q", name)
		}
	}
}

func TestIntegrationWhitelistPrecedence(t *testing.T) {
	// Load both lists and verify whitelist takes precedence
	blDir := filepath.Join(testdataDir(), "blacklist")
	wlDir := filepath.Join(testdataDir(), "whitelist")
	logger := &testLogger{}

	blRules, err := blockloader.LoadDirectory(blDir, logger)
	if err != nil {
		t.Fatal(err)
	}
	wlRules, err := blockloader.LoadDirectory(wlDir, logger)
	if err != nil {
		t.Fatal(err)
	}

	var denyRules []filterlist.Rule
	for _, r := range blRules {
		if !r.IsAllow {
			denyRules = append(denyRules, r)
		}
	}

	blDFA, err := automaton.CompileRules(denyRules, automaton.CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wlDFA, err := automaton.CompileRules(wlRules, automaton.CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// safe.example.com is in the whitelist
	name := "safe.example.com"
	wlMatch, _ := wlDFA.Match(name)
	if !wlMatch {
		t.Error("expected whitelist to match safe.example.com")
	}

	// ads.example.com is blacklisted but not whitelisted
	name = "ads.example.com"
	wlMatch, _ = wlDFA.Match(name)
	blMatch, _ := blDFA.Match(name)
	if wlMatch {
		t.Error("expected whitelist NOT to match ads.example.com")
	}
	if !blMatch {
		t.Error("expected blacklist to match ads.example.com")
	}
}
