package filterlist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseLineSkip verifies that users can keep comments and blank lines in filter lists without creating bogus rules in the filterlist parser by asserting that such lines are skipped silently.
func TestParseLineSkip(t *testing.T) {
	skips := []string{
		"",
		"   ",
		"! This is a comment",
		"# hosts comment",
		"# comment with ## inside",
		"[Adblock Plus 2.0]",
	}
	for _, line := range skips {
		_, err := ParseLine(line)
		if !errors.Is(err, errSkip) {
			t.Errorf("ParseLine(%q) error = %v, want errSkip", line, err)
		}
	}
}

// TestParseLineAdGuardDomain verifies that users can import standard AdGuard host rules in the filterlist parser by asserting that anchored domain syntax becomes the expected canonical pattern.
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

// TestParseLineException verifies that users can declare allow-list exceptions in the filterlist parser by asserting that @@ rules are marked as allow rules with the expected pattern.
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

// TestParseLineHosts verifies that users can import classic hosts-file deny entries in the filterlist parser by asserting that supported IP-plus-domain lines become canonical rules.
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

// TestParseLineHostsSkipLocalhost verifies that users do not accidentally block loopback aliases in the filterlist parser by asserting that localhost-style hosts entries are skipped.
func TestParseLineHostsSkipLocalhost(t *testing.T) {
	lines := []string{
		"127.0.0.1 localhost",
		"0.0.0.0 localhost.localdomain",
		"::1 ip6-localhost",
	}
	for _, line := range lines {
		_, err := ParseLine(line)
		if !errors.Is(err, errSkip) {
			t.Errorf("ParseLine(%q) expected errSkip for localhost entry, got %v", line, err)
		}
	}
}

// TestParseLineUnsupported verifies that users get explicit feedback for rule families that cannot be represented at DNS time in the filterlist parser by asserting that unsupported lines return non-skip errors.
func TestParseLineUnsupported(t *testing.T) {
	unsupported := []string{
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
		if err == nil || errors.Is(err, errSkip) {
			t.Errorf("ParseLine(%q) expected non-skip error, got %v", line, err)
		}
	}
}

// TestParseLineBareCosmeticRulesSkipped verifies that browser-only cosmetic rules are ignored instead of misparsed as DNS policy in the filterlist parser by asserting that cosmetic syntax is rejected.
func TestParseLineBareCosmeticRulesSkipped(t *testing.T) {
	// Bare cosmetic rules starting with # are silently skipped (irrelevant for DNS).
	skipped := []string{
		"##.ad-banner",
		"#@#.ad-banner",
		"#%#//scriptlet('abort-on-property-read', 'alert')",
		"###Ad_Win2day",
	}
	for _, line := range skipped {
		_, err := ParseLine(line)
		if !errors.Is(err, errSkip) {
			t.Errorf("ParseLine(%q) = %v, want errSkip", line, err)
		}
	}
}

// TestParseFileEasyListGermanyLogsUnsupportedNonNetworkRules verifies that users importing real EasyList Germany data get warnings for unsupported non-network syntax in the filterlist package by asserting that such constructs are logged.
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

	// Bare cosmetic rules starting with # are silently skipped for DNS (no warning).
	// Domain-prefixed cosmetic rules still produce warnings.
	assertContainsWarning(t, warnings, "unsupported non-network rule: ping-timeout.de#@##Advertisements")
	assertContainsWarning(t, warnings, "unsupported modifier in rule: @@||windowspro.de^$~third-party,xmlhttprequest")
	assertContainsPattern(t, rules, "adnx.de")
	assertContainsPattern(t, rules, "active-tracking.de")
	assertContainsPattern(t, rules, "windows-pro.net")
	assertNotContainsPattern(t, rules, "windowspro.de")
	assertNotContainsPattern(t, rules, "ableitungsrechner.net")
}

// TestParseFileAdGuardExampleRecognizesSupportedNetworkRules verifies that users importing real AdGuard data keep the supported host-based subset in the filterlist package by asserting that representative network rules are parsed.
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

// TestParseLineSingleLabel verifies that users are protected from overly broad bare host fragments in the filterlist parser by asserting that single-label rules without anchors are rejected.
func TestParseLineSingleLabel(t *testing.T) {
	_, err := ParseLine("ads")
	if err == nil {
		t.Error("ParseLine(\"ads\") expected error for single label")
	}
}

// TestParseLineModifiersAllowed verifies that users can keep selected no-op modifiers in the filterlist parser by asserting that supported modifiers do not prevent canonical domain extraction.
func TestParseLineModifiersAllowed(t *testing.T) {
	allowed := []string{
		"||example.com^$important",
		"||example.com^$document",
		"||example.com^$all",
		"||example.com^$first-party",
		"||example.com^$third-party",
		"||example.com^$important,document",
		"||example.com^$badfilter",
		"||example.com^$match-case",
		"||example.com^$popup",
		"||example.com^$important,badfilter",
		"||example.com^$match-case,third-party",
		"||example.com^$1p",
		"||example.com^$3p",
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

// TestParseFile verifies that users can parse mixed allow, deny, and hosts-style input from one file in the filterlist package by asserting that valid rules are kept and unsupported lines only generate warnings.
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
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var warnings []string
	logger := &testLogger{warnFunc: func(format string, _ ...interface{}) {
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

// TestParseFileMissing verifies that users get a direct IO error when a configured list file is absent in the filterlist package by asserting that ParseFile fails for missing paths.
func TestParseFileMissing(t *testing.T) {
	_, err := ParseFile("/nonexistent/file.txt", nil)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// TestParseLineHashCommentsWithMarkers verifies that users can keep hosts-style comments containing filter syntax fragments in the filterlist parser by asserting that leading hash comments are still skipped.
func TestParseLineHashCommentsWithMarkers(t *testing.T) {
	// Hosts-style comments that happen to contain ## or other cosmetic markers
	// must be treated as comments, not as unsupported non-network rules.
	comments := []string{
		"# comment with ## inside",
		"# tracking ## info",
		"# example.com##.ad-banner",
		"# this has #@# in it",
		"# test #%# scriptlet",
		"# $$script marker",
		"#comment no space",
	}
	for _, line := range comments {
		_, err := ParseLine(line)
		if !errors.Is(err, errSkip) {
			t.Errorf("ParseLine(%q) = %v, want errSkip (should be comment)", line, err)
		}
	}
}

// TestParseLineBadfilterModifier verifies that users can keep badfilter-tagged host rules in the supported subset of the filterlist parser by asserting that the base domain still parses successfully.
func TestParseLineBadfilterModifier(t *testing.T) {
	// $badfilter should be accepted as a no-op, not rejected.
	tests := []struct {
		input   string
		pattern string
		isAllow bool
	}{
		{"||tn.porngo.xxx^$badfilter", "tn.porngo.xxx", false},
		{"||example.com^$badfilter", "example.com", false},
		{"@@||example.com^$badfilter", "example.com", true},
		{"||example.com^$important,badfilter", "example.com", false},
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

// TestParseLineTrailingDollar verifies that users do not lose otherwise valid rules because of trailing modifier separators in the filterlist parser by asserting that a trailing dollar is tolerated.
func TestParseLineTrailingDollar(t *testing.T) {
	// A trailing $ with no modifiers should still parse the domain.
	rule, err := ParseLine("||example.com^$")
	if err != nil {
		t.Fatalf("ParseLine(\"||example.com^$\") unexpected error: %v", err)
	}
	if rule.Pattern != "example.com" {
		t.Errorf("pattern = %q, want \"example.com\"", rule.Pattern)
	}
}

// TestParseLineNegatedModifiers verifies that users get an explicit rejection for semantics-changing negated modifiers in the filterlist parser by asserting that such rules return errors.
func TestParseLineNegatedModifiers(t *testing.T) {
	// Negated modifiers like $~third-party should be rejected.
	unsupported := []string{
		"||example.com^$~third-party",
		"||example.com^$~third-party,xmlhttprequest",
		"||example.com^$script,domain=other.com",
	}
	for _, line := range unsupported {
		_, err := ParseLine(line)
		if err == nil || errors.Is(err, errSkip) {
			t.Errorf("ParseLine(%q) expected non-skip error for negated modifier, got %v", line, err)
		}
	}
}

// TestParseLineMultiDomainHosts verifies that users importing multi-domain hosts lines still get a deterministic primary rule in the filterlist parser by asserting that the first host is selected.
func TestParseLineMultiDomainHosts(t *testing.T) {
	// Hosts files can list multiple domains; we take the first one.
	rule, err := ParseLine("0.0.0.0 first.example.com second.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.Pattern != "first.example.com" {
		t.Errorf("pattern = %q, want \"first.example.com\"", rule.Pattern)
	}
}

// TestParseLineHostsInlineComment verifies that users can keep inline documentation after hosts entries in the filterlist parser by asserting that the leading domain is parsed correctly.
func TestParseLineHostsInlineComment(t *testing.T) {
	// Hosts files often have inline comments after the domain.
	rule, err := ParseLine("0.0.0.0 tracker.example.com # block tracker")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.Pattern != "tracker.example.com" {
		t.Errorf("pattern = %q, want \"tracker.example.com\"", rule.Pattern)
	}
}

// TestParseLineIDNUmlautDomains verifies that users can write Unicode AdGuard domains and still match DNS traffic in the filterlist parser by asserting that umlaut domains are converted to punycode.
func TestParseLineIDNUmlautDomains(t *testing.T) {
	// Internationalized domain names should be converted to Punycode.
	tests := []struct {
		input   string
		pattern string
		isAllow bool
	}{
		// AdGuard-style filters with Unicode domain names
		{"||münchen.de^", "xn--mnchen-3ya.de", false},
		{"||bücher.example.com^", "xn--bcher-kva.example.com", false},
		{"||süddeutsche.de^", "xn--sddeutsche-9db.de", false},
		// Exception rules with Unicode
		{"@@||münchen.de^", "xn--mnchen-3ya.de", true},
		// Already-encoded Punycode passes through unchanged
		{"||xn--mnchen-3ya.de^", "xn--mnchen-3ya.de", false},
		// Mixed subdomain with Umlaut
		{"||ads.münchen.de^", "ads.xn--mnchen-3ya.de", false},
		// Bare domain (no anchors)
		{"münchen.de", "xn--mnchen-3ya.de", false},
		// With modifiers
		{"||münchen.de^$important", "xn--mnchen-3ya.de", false},
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

// TestParseLineIDNHostsStyle verifies that users can write Unicode hosts entries and still produce DNS-safe rules in the filterlist parser by asserting that the hostname is converted to ASCII.
func TestParseLineIDNHostsStyle(t *testing.T) {
	// Hosts-style entries with Unicode domain names
	tests := []struct {
		input   string
		pattern string
	}{
		{"0.0.0.0 münchen.de", "xn--mnchen-3ya.de"},
		{"127.0.0.1 bücher.example.com", "xn--bcher-kva.example.com"},
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
	}
}

// TestParseLineIDNMatchesDNSQuery verifies that users get the same matching behavior for Unicode filter input and ASCII DNS queries in the end-to-end parser/compiler flow by asserting that a converted IDN rule matches the punycode query form.
func TestParseLineIDNMatchesDNSQuery(t *testing.T) {
	// End-to-end: a Unicode filter list entry must produce the same pattern
	// that a DNS query would contain (Punycode).
	runicode, err := ParseLine("||münchen.de^")
	if err != nil {
		t.Fatalf("ParseLine Unicode: %v", err)
	}
	rpuny, err := ParseLine("||xn--mnchen-3ya.de^")
	if err != nil {
		t.Fatalf("ParseLine Punycode: %v", err)
	}
	if runicode.Pattern != rpuny.Pattern {
		t.Errorf("Unicode pattern %q != Punycode pattern %q", runicode.Pattern, rpuny.Pattern)
	}
}

// TestIsDNSChar verifies that only DNS-safe characters are accepted by the
// low-level alphabet helper used by parsing and pattern validation code.
//
// This test covers the filterlist package's character validation helper.
//
// It asserts that lowercase DNS characters pass and obvious invalid runes do
// not.
func TestIsDNSChar(t *testing.T) {
	for _, r := range "abcdefghijklmnopqrstuvwxyz0123456789-." {
		if !isDNSChar(r) {
			t.Errorf("isDNSChar(%c) = false, want true", r)
		}
	}
	for _, r := range "ABCXYZ_!@# " {
		if isDNSChar(r) {
			t.Errorf("isDNSChar(%c) = true, want false", r)
		}
	}
}

// TestIsValidDNSName verifies that callers can distinguish supported DNS-style
// patterns from malformed names before compilation.
//
// This test covers the filterlist package's whole-name validation helper.
//
// It asserts that wildcard-aware DNS names are accepted and malformed input is
// rejected.
func TestIsValidDNSName(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"example.com", true},
		{"*.example.com", true},
		{"a-b.com", true},
		{"", false},
		{"ex ample.com", false},
		{"exam_ple.com", false},
	}
	for _, tt := range tests {
		got := isValidDNSName(tt.input)
		if got != tt.want {
			t.Errorf("isValidDNSName(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// TestToASCII verifies that internationalized domains are converted into the
// ASCII form that DNS queries and filter matching actually use.
//
// This test covers the filterlist package's IDNA conversion helper.
//
// It asserts that ASCII domains pass through unchanged and Unicode labels are
// mapped to their expected punycode representation.
func TestToASCII(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Pure ASCII passes through unchanged
		{"example.com", "example.com"},
		{"sub.example.com", "sub.example.com"},
		// German Umlauts
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"bücher.example.com", "xn--bcher-kva.example.com"},
		{"süddeutsche.de", "xn--sddeutsche-9db.de"},
		// Mixed: subdomain with Umlaut
		{"ads.münchen.de", "ads.xn--mnchen-3ya.de"},
		// Other scripts
		{"例え.jp", "xn--r8jz45g.jp"},
	}
	for _, tt := range tests {
		got, err := toASCII(tt.input)
		if err != nil {
			t.Errorf("toASCII(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("toASCII(%q) = %q, want %q", tt.input, got, tt.want)
		}
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
