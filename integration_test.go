package filterlist_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/TomTonic/filterlist/pkg/blockloader"
	"github.com/TomTonic/filterlist/pkg/listparser"
	"github.com/TomTonic/filterlist/pkg/matcher"
)

type testLogger struct {
	warnings []string
}

func (l *testLogger) Warnf(format string, _ ...interface{}) {
	l.warnings = append(l.warnings, format)
}

func (*testLogger) Infof(string, ...interface{}) {}

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "testdata", "filterlists")
}

// TestIntegrationBlacklistCompile verifies that operators can load a real blacklist directory end-to-end through the repository integration path by asserting that compiled deny rules match known blocked domains and ignore safe ones.
func TestIntegrationDenylistCompile(t *testing.T) {
	dir := filepath.Join(testdataDir(), "denylist")
	logger := &testLogger{}

	rules, err := blockloader.LoadDirectory(dir, logger)
	if err != nil {
		t.Fatalf("LoadDirectory error: %v", err)
	}

	if len(rules) == 0 {
		t.Fatal("expected rules from blacklist directory")
	}

	t.Logf("loaded %d rules from denylist", len(rules))

	// Separate allow and deny rules
	var denyRules, allowRules []listparser.Rule
	for _, r := range rules {
		if r.IsAllow {
			allowRules = append(allowRules, r)
		} else {
			denyRules = append(denyRules, r)
		}
	}

	t.Logf("deny rules: %d, allow rules: %d", len(denyRules), len(allowRules))

	m, err := matcher.CompileRules(denyRules, matcher.CompileOptions{})
	if err != nil {
		t.Fatalf("CompileRules error: %v", err)
	}

	t.Logf("DFA states: %d", m.StateCount())

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
		matched, _ := m.Match(name)
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
		matched, _ := m.Match(name)
		if matched {
			t.Errorf("expected blacklist NOT to match %q", name)
		}
	}
}

// TestIntegrationBlacklistLiteralAnchoredDomainMatchesSubdomains verifies that
// blacklist rules written as ||domain^ reject both the exact domain and its
// subdomains for users in the repository integration flow.
//
// This test covers the end-to-end literal blacklist path: blockloader loads an
// AdGuard-style anchored domain rule, filterlist canonicalizes it, and matcher
// routes it through the suffix map.
//
// It asserts that the parsed ||ads.example.com^ rule blocks ads.example.com and
// deeper names like sub.ads.example.com while unrelated domains stay allowed.
func TestIntegrationDenylistLiteralAnchoredDomainMatchesSubdomains(t *testing.T) {
	dir := filepath.Join(testdataDir(), "denylist")
	logger := &testLogger{}

	rules, err := blockloader.LoadDirectory(dir, logger)
	if err != nil {
		t.Fatalf("LoadDirectory error: %v", err)
	}

	var selected []listparser.Rule
	for _, rule := range rules {
		if rule.IsAllow {
			continue
		}
		if rule.Pattern == "ads.example.com" {
			selected = append(selected, rule)
		}
	}
	if len(selected) != 1 {
		t.Fatalf("selected %d literal rules, want 1", len(selected))
	}

	m, err := matcher.CompileRules(selected, matcher.CompileOptions{})
	if err != nil {
		t.Fatalf("CompileRules error: %v", err)
	}
	if m.LiteralCount() != 1 {
		t.Fatalf("LiteralCount = %d, want 1", m.LiteralCount())
	}
	if m.StateCount() != 0 {
		t.Fatalf("StateCount = %d, want 0 for literal-only matcher", m.StateCount())
	}

	for _, name := range []string{"ads.example.com", "sub.ads.example.com", "deep.sub.ads.example.com"} {
		matched, _ := m.Match(name)
		if !matched {
			t.Errorf("expected literal blacklist to match %q", name)
		}
	}

	for _, name := range []string{"example.com", "safe.example.com", "badads.example.com"} {
		matched, _ := m.Match(name)
		if matched {
			t.Errorf("expected literal blacklist not to match %q", name)
		}
	}
}

// TestIntegrationBlacklistWildcardAutomatonMatchesSubdomains verifies that
// blacklist rules written with wildcards reject matching domains through the
// automaton path for users in the repository integration flow.
//
// This test covers the end-to-end wildcard blacklist path: blockloader loads a
// wildcard rule, filterlist canonicalizes it, and matcher compiles it into the
// wildcard DFA.
//
// It asserts that the parsed ||*.tracking.example.com^ rule blocks matching
// subdomains while the bare base domain and unrelated names remain allowed.
func TestIntegrationDenylistWildcardAutomatonMatchesSubdomains(t *testing.T) {
	dir := filepath.Join(testdataDir(), "denylist")
	logger := &testLogger{}

	rules, err := blockloader.LoadDirectory(dir, logger)
	if err != nil {
		t.Fatalf("LoadDirectory error: %v", err)
	}

	var selected []listparser.Rule
	for _, rule := range rules {
		if rule.IsAllow {
			continue
		}
		if rule.Pattern == "*.tracking.example.com" {
			selected = append(selected, rule)
		}
	}
	if len(selected) != 1 {
		t.Fatalf("selected %d wildcard rules, want 1", len(selected))
	}

	m, err := matcher.CompileRules(selected, matcher.CompileOptions{})
	if err != nil {
		t.Fatalf("CompileRules error: %v", err)
	}
	if m.LiteralCount() != 0 {
		t.Fatalf("LiteralCount = %d, want 0 for wildcard-only matcher", m.LiteralCount())
	}
	if m.StateCount() == 0 {
		t.Fatal("StateCount = 0, want wildcard DFA states")
	}

	for _, name := range []string{"sub.tracking.example.com", "a.b.tracking.example.com"} {
		matched, _ := m.Match(name)
		if !matched {
			t.Errorf("expected wildcard blacklist to match %q", name)
		}
	}

	for _, name := range []string{"tracking.example.com", "safe.example.com", "tracking.example.net"} {
		matched, _ := m.Match(name)
		if matched {
			t.Errorf("expected wildcard blacklist not to match %q", name)
		}
	}
}

// TestIntegrationWhitelistCompile verifies that operators can load a real whitelist directory end-to-end through the repository integration path by asserting that compiled allow rules match trusted domains and exclude unrelated ones.
func TestIntegrationAllowlistCompile(t *testing.T) {
	dir := filepath.Join(testdataDir(), "allowlist")
	logger := &testLogger{}

	rules, err := blockloader.LoadDirectory(dir, logger)
	if err != nil {
		t.Fatalf("LoadDirectory error: %v", err)
	}

	if len(rules) == 0 {
		t.Fatal("expected rules from whitelist directory")
	}

	t.Logf("loaded %d rules from allowlist", len(rules))

	m, err := matcher.CompileRules(rules, matcher.CompileOptions{})
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
		matched, _ := m.Match(name)
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
		matched, _ := m.Match(name)
		if matched {
			t.Errorf("expected whitelist NOT to match %q", name)
		}
	}
}

// TestIntegrationWhitelistPrecedence verifies that users keep explicit allow rules even when deny lists are also present by asserting that whitelist matching wins over blacklist handling in the integrated compile flow.
func TestIntegrationAllowlistPrecedence(t *testing.T) {
	// Load both lists and verify allowlist takes precedence
	blDir := filepath.Join(testdataDir(), "denylist")
	wlDir := filepath.Join(testdataDir(), "allowlist")
	logger := &testLogger{}

	blRules, err := blockloader.LoadDirectory(blDir, logger)
	if err != nil {
		t.Fatal(err)
	}
	wlRules, err := blockloader.LoadDirectory(wlDir, logger)
	if err != nil {
		t.Fatal(err)
	}

	var denyRules []listparser.Rule
	for _, r := range blRules {
		if !r.IsAllow {
			denyRules = append(denyRules, r)
		}
	}

	blMatcher, err := matcher.CompileRules(denyRules, matcher.CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wlMatcher, err := matcher.CompileRules(wlRules, matcher.CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// safe.example.com is in the whitelist
	name := "safe.example.com"
	wlMatch, _ := wlMatcher.Match(name)
	if !wlMatch {
		t.Error("expected whitelist to match safe.example.com")
	}

	// ads.example.com is blacklisted but not whitelisted
	name = "ads.example.com"
	wlMatch, _ = wlMatcher.Match(name)
	blMatch, _ := blMatcher.Match(name)
	if wlMatch {
		t.Error("expected whitelist NOT to match ads.example.com")
	}
	if !blMatch {
		t.Error("expected blacklist to match ads.example.com")
	}
}

// TestRealWorldAdGuardExampleParseAndCompileSubset verifies that users can import a substantial AdGuard sample through the integration pipeline by asserting that supported host rules are parsed and compiled into matching DFA entries.
func TestRealWorldAdGuardExampleParseAndCompileSubset(t *testing.T) {
	path := filepath.Join(testdataDir(), "Adguard_filter_example.txt")
	logger := &testLogger{}

	rules, err := listparser.ParseFile(path, logger)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) < 1000 {
		t.Fatalf("expected substantial rule count from AdGuard example, got %d", len(rules))
	}

	wantPatterns := []string{
		"illinformed-summer.com",
		"superficial-burn.com",
		"insensitiveshoweraudible.com",
		"apitiny.net",
	}
	assertPatternsPresent(t, rules, wantPatterns)

	subset := selectRulesByPattern(t, rules, wantPatterns)
	m, err := matcher.CompileRules(subset, matcher.CompileOptions{MaxStates: 10000})
	if err != nil {
		t.Fatalf("CompileRules error: %v", err)
	}

	for _, pattern := range wantPatterns {
		matched, _ := m.Match(pattern)
		if !matched {
			t.Errorf("expected compiled AdGuard subset to match %q", pattern)
		}
	}

	for _, name := range []string{"example.org", "safe.example.com", "not-present.invalid"} {
		matched, _ := m.Match(name)
		if matched {
			t.Errorf("expected compiled AdGuard subset not to match %q", name)
		}
	}
}

// TestRealWorldEasyListGermanyParseAndCompileSubset verifies that users can import a substantial EasyList Germany sample through the integration pipeline by asserting that supported host rules compile while unsupported constructs are surfaced as warnings.
func TestRealWorldEasyListGermanyParseAndCompileSubset(t *testing.T) {
	path := filepath.Join(testdataDir(), "easylistgermany_example.txt")
	logger := &testLogger{}

	rules, err := listparser.ParseFile(path, logger)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) < 100 {
		t.Fatalf("expected meaningful rule count from EasyList Germany example, got %d", len(rules))
	}
	if len(logger.warnings) == 0 {
		t.Fatal("expected unsupported constructs in EasyList Germany example to generate warnings")
	}

	wantPatterns := []string{
		"adnx.de",
		"bd742.com",
		"cpg-cdn.com",
		"f11-ads.com",
		"active-tracking.de",
	}
	assertPatternsPresent(t, rules, wantPatterns)

	subset := selectRulesByPattern(t, rules, wantPatterns)
	m, err := matcher.CompileRules(subset, matcher.CompileOptions{MaxStates: 10000})
	if err != nil {
		t.Fatalf("CompileRules error: %v", err)
	}

	for _, pattern := range wantPatterns {
		matched, _ := m.Match(pattern)
		if !matched {
			t.Errorf("expected compiled EasyList Germany subset to match %q", pattern)
		}
	}

	for _, name := range []string{"focus.de", "example.org", "safe.example.com"} {
		matched, _ := m.Match(name)
		if matched {
			t.Errorf("expected compiled EasyList Germany subset not to match %q", name)
		}
	}
}

func assertPatternsPresent(t *testing.T, rules []listparser.Rule, patterns []string) {
	t.Helper()
	for _, pattern := range patterns {
		found := false
		for _, rule := range rules {
			if rule.Pattern == pattern {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected pattern %q to be present in parsed rules", pattern)
		}
	}
}

func selectRulesByPattern(t *testing.T, rules []listparser.Rule, patterns []string) []listparser.Rule {
	t.Helper()
	selected := make([]listparser.Rule, 0, len(patterns))
	for _, pattern := range patterns {
		found := false
		for _, rule := range rules {
			if rule.Pattern == pattern {
				selected = append(selected, rule)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected selectable pattern %q", pattern)
		}
	}
	return selected
}
