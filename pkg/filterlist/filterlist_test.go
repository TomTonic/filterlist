package filterlist

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLineSkip(t *testing.T) {
	skips := []string{
		"",
		"   ",
		"! This is a comment",
		"# hosts comment",
		"[Adblock Plus 2.0]",
	}
	for _, line := range skips {
		_, err := ParseLine(line)
		if err != errSkip {
			t.Errorf("ParseLine(%q) error = %v, want errSkip", line, err)
		}
	}
}

func TestParseLineAdGuardDomain(t *testing.T) {
	tests := []struct {
		input   string
		pattern string
		isAllow bool
	}{
		{"||example.com^", "example.com", false},
		{"||sub.example.com^", "sub.example.com", false},
		{"||ADS.Example.COM^", "ads.example.com", false},
		{"||example.com^|", "example.com", false},
		{"||example.com", "example.com", false},
		{"example.com", "example.com", false},
		// Wildcards
		{"||*.ads.example.com^", "*.ads.example.com", false},
		{"||ads*.example.com^", "ads*.example.com", false},
	}
	for _, tt := range tests {
		rule, err := ParseLine(tt.input)
		if err != nil {
			t.Errorf("ParseLine(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if rule.Pattern != tt.pattern {
			t.Errorf("ParseLine(%q) pattern = %q, want %q", tt.input, rule.Pattern, tt.pattern)
		}
		if rule.IsAllow != tt.isAllow {
			t.Errorf("ParseLine(%q) isAllow = %v, want %v", tt.input, rule.IsAllow, tt.isAllow)
		}
	}
}

func TestParseLineException(t *testing.T) {
	tests := []struct {
		input   string
		pattern string
	}{
		{"@@||example.com^", "example.com"},
		{"@@||safe.example.com^", "safe.example.com"},
		{"@@example.com", "example.com"},
	}
	for _, tt := range tests {
		rule, err := ParseLine(tt.input)
		if err != nil {
			t.Errorf("ParseLine(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if !rule.IsAllow {
			t.Errorf("ParseLine(%q) isAllow = false, want true", tt.input)
		}
		if rule.Pattern != tt.pattern {
			t.Errorf("ParseLine(%q) pattern = %q, want %q", tt.input, rule.Pattern, tt.pattern)
		}
	}
}

func TestParseLineHosts(t *testing.T) {
	tests := []struct {
		input   string
		pattern string
	}{
		{"0.0.0.0 example.com", "example.com"},
		{"127.0.0.1 example.com", "example.com"},
		{"::1 example.com", "example.com"},
		{"0.0.0.0 ADS.Example.COM", "ads.example.com"},
		{"0.0.0.0 tracker.example.com # comment ignored by hosts", "tracker.example.com"},
	}
	for _, tt := range tests {
		rule, err := ParseLine(tt.input)
		if err != nil {
			t.Errorf("ParseLine(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if rule.Pattern != tt.pattern {
			t.Errorf("ParseLine(%q) pattern = %q, want %q", tt.input, rule.Pattern, tt.pattern)
		}
		if rule.IsAllow {
			t.Errorf("ParseLine(%q) isAllow = true, want false", tt.input)
		}
	}
}

func TestParseLineHostsSkipLocalhost(t *testing.T) {
	lines := []string{
		"127.0.0.1 localhost",
		"0.0.0.0 localhost.localdomain",
		"::1 ip6-localhost",
	}
	for _, line := range lines {
		_, err := ParseLine(line)
		if err != errSkip {
			t.Errorf("ParseLine(%q) expected errSkip for localhost entry, got %v", line, err)
		}
	}
}

func TestParseLineUnsupported(t *testing.T) {
	unsupported := []string{
		"##.ad-banner",
		"#@#.ad-banner",
		"#%#//scriptlet('abort-on-property-read', 'alert')",
		"$$script[tag-content=\"banner\"]",
		"example.com##.ad-banner",
		"example.com#@#.ad-banner",
		"example.com#?#.ad-banner",
		"||example.com^$script",
		"||example.com^$domain=other.com",
		"/ads/banner",
		"||example.com/path^",
	}
	for _, line := range unsupported {
		_, err := ParseLine(line)
		if err == nil || err == errSkip {
			t.Errorf("ParseLine(%q) expected non-skip error, got %v", line, err)
		}
	}
}

func TestParseFileEasyListGermanyLogsUnsupportedNonNetworkRules(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "filterlists", "easylistgermany_example.txt")

	var warnings []string
	logger := &testLogger{warnFunc: func(format string, args ...interface{}) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}}

	rules, err := ParseFile(path, logger)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("expected parsed rules from easylist germany example")
	}

	assertContainsWarning(t, warnings, "unsupported non-network rule: ###Ad_Win2day")
	assertContainsWarning(t, warnings, "unsupported non-network rule: ##.Werbung")
	assertContainsWarning(t, warnings, "unsupported modifier in rule: @@||windowspro.de^$~third-party,xmlhttprequest")
	assertContainsPattern(t, rules, "adnx.de")
	assertContainsPattern(t, rules, "active-tracking.de")
	assertContainsPattern(t, rules, "windows-pro.net")
	assertNotContainsPattern(t, rules, "windowspro.de")
	assertNotContainsPattern(t, rules, "ableitungsrechner.net")
}

func TestParseFileAdGuardExampleRecognizesSupportedNetworkRules(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "filterlists", "Adguard_filter_example.txt")

	var warnings []string
	logger := &testLogger{warnFunc: func(format string, args ...interface{}) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}}

	rules, err := ParseFile(path, logger)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) < 1000 {
		t.Fatalf("expected substantial parsed rule count from adguard example, got %d", len(rules))
	}

	assertContainsPattern(t, rules, "adsrvmedia.adk2.co")
	assertContainsAllowPattern(t, rules, "ad.10010.com")
	assertContainsAllowPattern(t, rules, "img.ads.tvb.com")
	assertNotContainsWarning(t, warnings, "unsupported modifier in rule: ||adsrvmedia.adk2.co^$important")
	assertNotContainsWarning(t, warnings, "unsupported modifier in rule: @@||ad.10010.com^")
}

func assertContainsWarning(t *testing.T, warnings []string, want string) {
	t.Helper()

	for _, warning := range warnings {
		if strings.Contains(warning, want) {
			return
		}
	}

	t.Fatalf("expected warning containing %q", want)
}

func assertContainsPattern(t *testing.T, rules []Rule, want string) {
	t.Helper()

	for _, rule := range rules {
		if rule.Pattern == want && !rule.IsAllow {
			return
		}
	}

	t.Fatalf("expected parsed blocking rule %q", want)
}

func assertContainsAllowPattern(t *testing.T, rules []Rule, want string) {
	t.Helper()

	for _, rule := range rules {
		if rule.Pattern == want && rule.IsAllow {
			return
		}
	}

	t.Fatalf("expected parsed allow rule %q", want)
}

func assertNotContainsPattern(t *testing.T, rules []Rule, want string) {
	t.Helper()

	for _, rule := range rules {
		if rule.Pattern == want {
			t.Fatalf("did not expect parsed rule %q", want)
		}
	}
}

func assertNotContainsWarning(t *testing.T, warnings []string, want string) {
	t.Helper()

	for _, warning := range warnings {
		if strings.Contains(warning, want) {
			t.Fatalf("did not expect warning containing %q", want)
		}
	}
}

func TestParseLineSingleLabel(t *testing.T) {
	_, err := ParseLine("ads")
	if err == nil {
		t.Error("ParseLine(\"ads\") expected error for single label")
	}
}

func TestParseLineModifiersAllowed(t *testing.T) {
	allowed := []string{
		"||example.com^$important",
		"||example.com^$document",
		"||example.com^$all",
		"||example.com^$first-party",
		"||example.com^$third-party",
		"||example.com^$important,document",
	}
	for _, line := range allowed {
		rule, err := ParseLine(line)
		if err != nil {
			t.Errorf("ParseLine(%q) unexpected error: %v", line, err)
			continue
		}
		if rule.Pattern != "example.com" {
			t.Errorf("ParseLine(%q) pattern = %q, want example.com", line, rule.Pattern)
		}
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	content := `! AdGuard filter list
||ads.example.com^
||tracker.example.com^
! exception
@@||safe.example.com^
0.0.0.0 malware.example.com
invalid##rule
`
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	var warnings []string
	logger := &testLogger{warnFunc: func(format string, args ...interface{}) {
		warnings = append(warnings, format)
	}}

	rules, err := ParseFile(path, logger)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}

	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(rules))
	}
	if len(warnings) != 1 {
		t.Errorf("got %d warnings, want 1", len(warnings))
	}

	// Verify sources are set
	for _, r := range rules {
		if r.Source == "" {
			t.Errorf("rule %q has empty source", r.Pattern)
		}
	}

	// Verify the allow rule
	allowCount := 0
	for _, r := range rules {
		if r.IsAllow {
			allowCount++
		}
	}
	if allowCount != 1 {
		t.Errorf("got %d allow rules, want 1", allowCount)
	}
}

func TestParseFileMissing(t *testing.T) {
	_, err := ParseFile("/nonexistent/file.txt", nil)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

type testLogger struct {
	warnFunc func(format string, args ...interface{})
}

func (l *testLogger) Warnf(format string, args ...interface{}) {
	if l.warnFunc != nil {
		l.warnFunc(format, args...)
	}
}
