package filterlist

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/TomTonic/filterlist/pkg/listparser"
	"github.com/TomTonic/filterlist/pkg/matcher"
	rfmetrics "github.com/TomTonic/filterlist/pkg/metrics"
)

// mockResponseWriter captures the DNS response.
type mockResponseWriter struct {
	msg    *dns.Msg
	remote net.Addr
	local  net.Addr
}

func (m *mockResponseWriter) LocalAddr() net.Addr  { return m.local }
func (m *mockResponseWriter) RemoteAddr() net.Addr { return m.remote }
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.msg = msg
	return nil
}
func (m *mockResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (m *mockResponseWriter) Close() error              { return nil }
func (m *mockResponseWriter) TsigStatus() error         { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)       {}
func (m *mockResponseWriter) Hijack()                   {}

func newMockWriter() *mockResponseWriter {
	return &mockResponseWriter{
		remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
	}
}

// mockNextHandler is a plugin handler that records if it was called.
type mockNextHandler struct {
	called bool
}

func (m *mockNextHandler) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m.called = true
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Rcode = dns.RcodeSuccess
	if err := w.WriteMsg(msg); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

func (m *mockNextHandler) Name() string { return "mock" }

func buildMatcher(t *testing.T, patterns []string) *matcher.Matcher {
	t.Helper()
	var rules []listparser.Rule
	for _, p := range patterns {
		rules = append(rules, listparser.Rule{Pattern: p})
	}
	m, err := matcher.CompileRules(rules, matcher.CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// buildMatcherWithSources compiles patterns and returns the Matcher, source strings,
// and pattern strings for use in debug-mode tests.
func buildMatcherWithSources(t *testing.T, rules []listparser.Rule) (*matcher.Matcher, []string, []string) {
	t.Helper()
	m, err := matcher.CompileRules(rules, matcher.CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sources := make([]string, len(rules))
	patterns := make([]string, len(rules))
	for i, r := range rules {
		sources[i] = r.Source
		patterns[i] = r.Pattern
	}
	return m, sources, patterns
}

func makeQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

// TestServeDNSBlacklistNXDOMAIN verifies that blocked users receive NXDOMAIN replies in the CoreDNS plugin path by asserting that a blacklist hit returns dns.RcodeNameError and does not call the next handler.
func TestServeDNSBlacklistNXDOMAIN(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{Mode: "nxdomain"},
		},
	}
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	w := newMockWriter()
	r := makeQuery("ads.example.com", dns.TypeA)

	code, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %d", code)
	}
	if next.called {
		t.Error("next handler should not be called for blocked query")
	}
}

// TestServeDNSBlacklistNullIP verifies that blocked users receive sinkhole answers in the CoreDNS plugin path by asserting that blacklist hits produce the configured A and AAAA null responses.
func TestServeDNSBlacklistNullIP(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{
				Mode:     "nullip",
				NullIPv4: net.IPv4zero,
				NullIPv6: net.IPv6zero,
				TTL:      60,
			},
		},
	}
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	// Test A query
	w := newMockWriter()
	r := makeQuery("ads.example.com", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if w.msg == nil {
		t.Fatal("no response")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record")
	}
	if !a.A.Equal(net.IPv4zero) {
		t.Errorf("expected 0.0.0.0, got %v", a.A)
	}

	// Test AAAA query
	w = newMockWriter()
	r = makeQuery("ads.example.com", dns.TypeAAAA)
	_, err = rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	aaaa, ok := w.msg.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatal("expected AAAA record")
	}
	if !aaaa.AAAA.Equal(net.IPv6zero) {
		t.Errorf("expected ::, got %v", aaaa.AAAA)
	}
}

// TestServeDNSBlacklistRefuse verifies that blocked users can receive REFUSED responses in the CoreDNS plugin path by asserting that a blacklist hit returns dns.RcodeRefused.
func TestServeDNSBlacklistRefuse(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{Mode: "refuse"},
		},
	}
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	w := newMockWriter()
	r := makeQuery("ads.example.com", dns.TypeA)
	code, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != dns.RcodeRefused {
		t.Errorf("expected REFUSED, got %d", code)
	}
}

// TestServeDNSWhitelistOverridesBlacklist verifies that explicitly allowed users are not blocked in the CoreDNS plugin path by asserting that whitelist matches bypass blacklist handling.
func TestServeDNSWhitelistOverridesBlacklist(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{Mode: "nxdomain"},
		},
	}
	// Both lists contain the same domain; whitelist takes precedence
	rf.SetAllowlist(buildMatcher(t, []string{"ads.example.com"}))
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	w := newMockWriter()
	r := makeQuery("ads.example.com", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("expected next handler to be called (whitelisted)")
	}
}

// TestServeDNSNoMatch verifies that ordinary users keep normal DNS resolution when no rule applies in the CoreDNS plugin path by asserting that unmatched queries reach the next handler.
func TestServeDNSNoMatch(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{Mode: "nxdomain"},
		},
	}
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	w := newMockWriter()
	r := makeQuery("safe.example.com", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("expected next handler for non-matched query")
	}
}

// TestServeDNSCaseInsensitive verifies that users are matched regardless of query case in the CoreDNS plugin path by asserting that mixed-case names still hit lowercase blacklist rules.
func TestServeDNSCaseInsensitive(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{Mode: "nxdomain"},
		},
	}
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	w := newMockWriter()
	r := makeQuery("ADS.Example.COM", dns.TypeA)
	code, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN for case-insensitive match, got %d", code)
	}
}

// TestServeDNSEmptyQuestion verifies that malformed or empty requests do not crash the CoreDNS plugin path by asserting that messages without questions are delegated onward.
func TestServeDNSEmptyQuestion(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{Mode: "nxdomain"},
		},
	}

	w := newMockWriter()
	r := new(dns.Msg)
	r.Question = nil

	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("expected next handler for empty question")
	}
}

// TestNormalizeName verifies that operators get canonical query names inside the plugin package by asserting that normalization lowercases names and trims trailing dots.
func TestNormalizeName(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"Example.COM.", "example.com"},
		{"test.org", "test.org"},
		{"A.", "a"},
	}
	for _, tt := range tests {
		got := normalizeName(tt.input)
		if got != tt.want {
			t.Errorf("normalizeName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func newMetrics(t *testing.T) (m *rfmetrics.Registry, promReg *prometheus.Registry) {
	t.Helper()
	promReg = prometheus.NewRegistry()
	return rfmetrics.NewRegistryWith(promReg), promReg
}

func getMatchDurationCount(t *testing.T, promReg *prometheus.Registry, result string) uint64 {
	t.Helper()
	families, err := promReg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "coredns_filterlist_match_duration_seconds" {
			for _, m := range f.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "result" && l.GetValue() == result {
						return m.GetSummary().GetSampleCount()
					}
				}
			}
		}
	}
	return 0
}

func getCounterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()

	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		t.Fatal(err)
	}

	return metric.GetCounter().GetValue()
}

func getGaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()

	var metric dto.Metric
	if err := gauge.Write(&metric); err != nil {
		t.Fatal(err)
	}

	return metric.GetGauge().GetValue()
}

// TestServeDNSMatchDurationAccept verifies that operators can observe accepted-query latency in the CoreDNS plugin metrics path by asserting that whitelist hits record an accept duration sample.
func TestServeDNSMatchDurationAccept(t *testing.T) {
	m, promReg := newMetrics(t)
	next := &mockNextHandler{}
	rf := &Plugin{
		Next:    next,
		Config:  Config{Action: ActionConfig{Mode: "nxdomain"}},
		metrics: m,
	}
	rf.SetAllowlist(buildMatcher(t, []string{"safe.example.com"}))

	w := newMockWriter()
	r := makeQuery("safe.example.com", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}

	if cnt := getMatchDurationCount(t, promReg, "accept"); cnt != 1 {
		t.Errorf("expected 1 accept observation, got %d", cnt)
	}
}

// TestServeDNSMatchDurationReject verifies that operators can observe rejected-query latency in the CoreDNS plugin metrics path by asserting that blacklist hits record a reject duration sample.
func TestServeDNSMatchDurationReject(t *testing.T) {
	m, promReg := newMetrics(t)
	next := &mockNextHandler{}
	rf := &Plugin{
		Next:    next,
		Config:  Config{Action: ActionConfig{Mode: "nxdomain"}},
		metrics: m,
	}
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	w := newMockWriter()
	r := makeQuery("ads.example.com", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}

	if cnt := getMatchDurationCount(t, promReg, "reject"); cnt != 1 {
		t.Errorf("expected 1 reject observation, got %d", cnt)
	}
}

// TestServeDNSMatchDurationPass verifies that operators can observe pass-through latency in the CoreDNS plugin metrics path by asserting that unmatched queries record a pass duration sample.
func TestServeDNSMatchDurationPass(t *testing.T) {
	m, promReg := newMetrics(t)
	next := &mockNextHandler{}
	rf := &Plugin{
		Next:    next,
		Config:  Config{Action: ActionConfig{Mode: "nxdomain"}},
		metrics: m,
	}
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	w := newMockWriter()
	r := makeQuery("clean.example.com", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}

	if cnt := getMatchDurationCount(t, promReg, "pass"); cnt != 1 {
		t.Errorf("expected 1 pass observation, got %d", cnt)
	}
}

// TestServeDNSWhitelistHitCounter verifies that operators can count successful allow-list decisions in the CoreDNS plugin metrics path by asserting that whitelist checks and hits are both incremented on an allow match.
func TestServeDNSWhitelistHitCounter(t *testing.T) {
	m, _ := newMetrics(t)
	next := &mockNextHandler{}
	rf := &Plugin{
		Next:    next,
		Config:  Config{Action: ActionConfig{Mode: "nxdomain"}},
		metrics: m,
	}
	rf.SetAllowlist(buildMatcher(t, []string{"safe.example.com"}))

	w := newMockWriter()
	r := makeQuery("safe.example.com", dns.TypeA)
	_, _ = rf.ServeDNS(context.Background(), w, r)

	if got := getCounterValue(t, m.AllowlistChecks); got != 1 {
		t.Errorf("AllowlistChecks = %v, want 1", got)
	}
	if got := getCounterValue(t, m.AllowlistHits); got != 1 {
		t.Errorf("AllowlistHits = %v, want 1", got)
	}
}

// TestServeDNSBlacklistCheckAndHitCounters verifies that operators can count deny-list decisions in the CoreDNS plugin metrics path by asserting that blacklist checks and hits are incremented after a non-whitelisted block.
func TestServeDNSBlacklistCheckAndHitCounters(t *testing.T) {
	m, _ := newMetrics(t)
	next := &mockNextHandler{}
	rf := &Plugin{
		Next:    next,
		Config:  Config{Action: ActionConfig{Mode: "nxdomain"}},
		metrics: m,
	}
	rf.SetAllowlist(buildMatcher(t, []string{"safe.example.com"}))
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	w := newMockWriter()
	r := makeQuery("ads.example.com", dns.TypeA)
	_, _ = rf.ServeDNS(context.Background(), w, r)

	if got := getCounterValue(t, m.AllowlistChecks); got != 1 {
		t.Errorf("AllowlistChecks = %v, want 1", got)
	}
	if got := getCounterValue(t, m.DenylistChecks); got != 1 {
		t.Errorf("DenylistChecks = %v, want 1", got)
	}
	if got := getCounterValue(t, m.DenylistHits); got != 1 {
		t.Errorf("DenylistHits = %v, want 1", got)
	}
}

// TestServeDNSWhitelistHitSkipsBlacklistCheck verifies that operators can trust whitelist precedence in the CoreDNS plugin metrics path by asserting that blacklist checks stay at zero when the whitelist already matched.
func TestServeDNSWhitelistHitSkipsBlacklistCheck(t *testing.T) {
	m, _ := newMetrics(t)
	next := &mockNextHandler{}
	rf := &Plugin{
		Next:    next,
		Config:  Config{Action: ActionConfig{Mode: "nxdomain"}},
		metrics: m,
	}
	rf.SetAllowlist(buildMatcher(t, []string{"safe.example.com"}))
	rf.SetDenylist(buildMatcher(t, []string{"safe.example.com"}))

	w := newMockWriter()
	r := makeQuery("safe.example.com", dns.TypeA)
	_, _ = rf.ServeDNS(context.Background(), w, r)

	if got := getCounterValue(t, m.AllowlistChecks); got != 1 {
		t.Errorf("AllowlistChecks = %v, want 1", got)
	}
	if got := getCounterValue(t, m.DenylistChecks); got != 0 {
		t.Errorf("DenylistChecks = %v, want 0", got)
	}
}

// TestStartWatcherLoadsInitialSnapshots verifies that operators get an active blacklist and populated metrics as soon as the plugin watcher starts by asserting that the initial compile loads rules, updates gauges, and can be stopped cleanly.
func TestStartWatcherLoadsInitialSnapshots(t *testing.T) {
	blDir := t.TempDir()
	path := filepath.Join(blDir, "deny.txt")
	if err := os.WriteFile(path, []byte("||ads.example.com^\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	m, _ := newMetrics(t)
	rf := &Plugin{
		Config: Config{
			DenylistDir:    blDir,
			Debounce:       50 * time.Millisecond,
			MaxStates:      1000,
			CompileTimeout: time.Second,
		},
		metrics: m,
	}

	if err := rf.StartWatcher(); err != nil {
		t.Fatalf("StartWatcher error: %v", err)
	}
	t.Cleanup(func() {
		if err := rf.Stop(); err != nil {
			t.Errorf("Stop error: %v", err)
		}
	})

	bl := rf.GetDenylist()
	if bl == nil {
		t.Fatal("expected blacklist DFA after StartWatcher")
	}
	matched, _ := bl.Match("ads.example.com")
	if !matched {
		t.Fatal("expected blacklist DFA to match seeded rule")
	}
	if got := getGaugeValue(t, m.DenylistRules); got != 1 {
		t.Fatalf("DenylistRules = %v, want 1", got)
	}
	if got := getGaugeValue(t, m.LastCompileDurationSeconds); got <= 0 {
		t.Fatalf("LastCompileDurationSeconds = %v, want > 0", got)
	}
}

// TestStartWatcherLoadsPureDFADenylist verifies that operators can enable the
// full-DFA matcher mode and still keep the same denylist suffix semantics in
// the live plugin watcher path.
//
// This test covers the plugin-to-watcher integration for matcher_mode dfa.
//
// It asserts that a literal denylist rule loaded through StartWatcher still
// blocks both the exact domain and a deeper subdomain when the runtime matcher
// is configured for pure DFA mode.
func TestStartWatcherLoadsPureDFADenylist(t *testing.T) {
	blDir := t.TempDir()
	path := filepath.Join(blDir, "deny.txt")
	if err := os.WriteFile(path, []byte("||ads.example.com^\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	rf := &Plugin{
		Config: Config{
			DenylistDir:    blDir,
			Debounce:       50 * time.Millisecond,
			MaxStates:      1000,
			CompileTimeout: time.Second,
			MatcherMode:    matcher.ModeDFA,
		},
	}

	if err := rf.StartWatcher(); err != nil {
		t.Fatalf("StartWatcher error: %v", err)
	}
	t.Cleanup(func() {
		if err := rf.Stop(); err != nil {
			t.Errorf("Stop error: %v", err)
		}
	})

	bl := rf.GetDenylist()
	if bl == nil {
		t.Fatal("expected denylist matcher after StartWatcher")
	}

	for _, name := range []string{"ads.example.com", "sub.ads.example.com"} {
		matched, _ := bl.Match(name)
		if !matched {
			t.Fatalf("expected denylist matcher to match %q in pure DFA mode", name)
		}
	}
}

// TestStartWatcherInitialFailureIncrementsCompileErrors verifies that operators can keep the plugin active while still observing startup load failures in the plugin package by asserting that StartWatcher succeeds, leaves no DFA loaded, and increments the compile error counter for unreadable directories.
func TestStartWatcherInitialFailureIncrementsCompileErrors(t *testing.T) {
	m, _ := newMetrics(t)
	rf := &Plugin{
		Config: Config{
			DenylistDir:    "/nonexistent/blacklist",
			Debounce:       50 * time.Millisecond,
			MaxStates:      1000,
			CompileTimeout: time.Second,
		},
		metrics: m,
	}

	if err := rf.StartWatcher(); err != nil {
		t.Fatalf("StartWatcher error: %v", err)
	}
	t.Cleanup(func() {
		if err := rf.Stop(); err != nil {
			t.Errorf("Stop error: %v", err)
		}
	})
	if got := getCounterValue(t, m.CompileErrors); got != 1 {
		t.Fatalf("CompileErrors = %v, want 1", got)
	}
	if rf.GetDenylist() != nil {
		t.Fatal("expected no blacklist DFA after failed initial load")
	}
}

// TestStopWithoutWatcherReturnsNil verifies that callers can always invoke plugin shutdown code safely in the plugin package by asserting that Stop succeeds even before StartWatcher was called.
func TestStopWithoutWatcherReturnsNil(t *testing.T) {
	rf := &Plugin{}
	if err := rf.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}
}

// TestSetupReturnsErrorForInvalidConfig verifies that operators get a setup error before the plugin enters service when the Corefile is invalid by asserting that setup rejects a filterlist block without directories.
func TestSetupReturnsErrorForInvalidConfig(t *testing.T) {
	c := caddy.NewTestController("dns", `filterlist { action nxdomain }`)
	if err := setup(c); err == nil {
		t.Fatal("expected setup error for invalid configuration")
	}
}

// TestSetupAllowsWatcherFailure verifies that operators can keep CoreDNS starting even when the initial filter directory is unreadable by asserting that setup remains successful.
func TestSetupAllowsWatcherFailure(t *testing.T) {
	c := caddy.NewTestController("dns", `filterlist { denylist_dir /nonexistent/blacklist }`)
	if err := setup(c); err != nil {
		t.Fatalf("expected setup to stay fail-open, got error: %v", err)
	}
}

// TestPluginLoggerForwarders verifies that watcher log callbacks can flow through the plugin logger adapter without panicking in the plugin package by asserting that each severity method is callable.
func TestPluginLoggerForwarders(_ *testing.T) {
	logger := pluginLogger{}
	logger.Warnf("warn %s", "value")
	logger.Infof("info %s", "value")
	logger.Errorf("error %s", "value")
}

// TestShortSource verifies that operators see concise rule references in debug
// output by asserting that shortSource strips directory prefixes and preserves
// the line number suffix.
func TestShortSource(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/var/dns/blacklist/ads.txt:42", "ads.txt:42"},
		{"rules.txt:1", "rules.txt:1"},
		{"/a/b/c/list.hosts:100", "list.hosts:100"},
		{"", "unknown"},
		{"nolineinfo", "nolineinfo"},
	}
	for _, tt := range tests {
		got := shortSource(tt.input)
		if got != tt.want {
			t.Errorf("shortSource(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestServeDNSDebugBlacklistMatch verifies that operators see per-query debug
// output identifying the matching blacklist rule when the debug directive is
// active.
//
// This test covers the debug logging path in ServeDNS for blacklist hits.
//
// It enables debug mode, sets up a blacklist DFA with source information, and
// asserts that a blocked query triggers the respondBlocked path (NXDOMAIN)
// without errors. The actual log output goes to CoreDNS's logger and is not
// captured here; the test verifies that debug mode does not break the match.
func TestServeDNSDebugBlacklistMatch(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{Mode: "nxdomain"},
			Debug:  true,
		},
	}
	dfa, sources, patterns := buildMatcherWithSources(t, []listparser.Rule{
		{Pattern: "ads.example.com", Source: "/etc/coredns/blacklist/deny.txt:7"},
	})
	rf.SetDenylist(dfa)
	rf.dlSources.Store(sources)
	rf.dlPatterns.Store(patterns)

	w := newMockWriter()
	r := makeQuery("ads.example.com", dns.TypeA)
	code, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %d", code)
	}
}

// TestServeDNSDebugWhitelistMatch verifies that operators see per-query debug
// output identifying the matching whitelist rule when the debug directive is
// active.
//
// This test covers the debug logging path in ServeDNS for whitelist hits.
//
// It sets up a whitelist DFA with source info and asserts that a matched query
// is forwarded to the next handler.
func TestServeDNSDebugWhitelistMatch(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{Mode: "nxdomain"},
			Debug:  true,
		},
	}
	dfa, sources, patterns := buildMatcherWithSources(t, []listparser.Rule{
		{Pattern: "safe.example.com", Source: "/etc/coredns/whitelist/allow.txt:3"},
	})
	rf.SetAllowlist(dfa)
	rf.alSources.Store(sources)
	rf.alPatterns.Store(patterns)

	w := newMockWriter()
	r := makeQuery("safe.example.com", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("expected next handler to be called (whitelisted)")
	}
}

// TestServeDNSDebugNoMatch verifies that operators see a "no match" debug line
// when neither whitelist nor blacklist match the queried name.
//
// This test covers the debug logging path in ServeDNS for unmatched queries.
//
// It enables debug mode, sets up a blacklist that does not contain the queried
// domain, and asserts that the query is forwarded to the next handler.
func TestServeDNSDebugNoMatch(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action: ActionConfig{Mode: "nxdomain"},
			Debug:  true,
		},
	}
	rf.SetDenylist(buildMatcher(t, []string{"ads.example.com"}))

	w := newMockWriter()
	r := makeQuery("clean.example.com", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("expected next handler for non-matched query")
	}
}

// ── RFC / IDNA query-name validation (isStrictDNSQueryName) ──────────────────

// ── disable_RFC_checks in ServeDNS ───────────────────────────────────────────

// TestServeDNSRFCBlocksInvalidName verifies that end users cannot resolve
// RFC 1035-non-compliant names when disable_RFC_checks is false (the default).
//
// This test covers the denylist-phase RFC precheck in ServeDNS.
//
// It asserts that a query for a name with an underscore label returns NXDOMAIN
// and does not reach the next handler.
func TestServeDNSRFCBlocksInvalidName(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action:           ActionConfig{Mode: "nxdomain"},
			DisableRFCChecks: false, // RFC checks active (default)
		},
	}

	w := newMockWriter()
	r := makeQuery("_bad.example.com.", dns.TypeA)

	code, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN for RFC-invalid name, got %d", code)
	}
	if next.called {
		t.Error("next handler must not be called for RFC-invalid name")
	}
}

// TestServeDNSRFCAllowedByDisableRFCChecks verifies that operators can
// disable the RFC name check so that legacy or non-standard names still
// resolve normally.
//
// This test covers the disable_RFC_checks config switch in ServeDNS.
//
// It asserts that a query for an RFC-invalid name (underscore label) reaches
// the next handler when disable_RFC_checks is true.
func TestServeDNSRFCAllowedByDisableRFCChecks(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action:           ActionConfig{Mode: "nxdomain"},
			DisableRFCChecks: true, // RFC checks disabled
		},
	}

	w := newMockWriter()
	r := makeQuery("_srv._tcp.example.com.", dns.TypeA)

	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("expected next handler when disable_RFC_checks is true")
	}
}

// TestServeDNSRFCUpdatesMetrics verifies that operators can observe blocked
// RFC-invalid queries through the standard denylist metrics.
//
// This test covers metric instrumentation for the RFC precheck in ServeDNS.
//
// It asserts that DenylistChecks and DenylistHits are each incremented by one
// when an RFC-invalid name is blocked by the RFC precheck.
func TestServeDNSRFCUpdatesMetrics(t *testing.T) {
	m, _ := newMetrics(t)
	next := &mockNextHandler{}
	rf := &Plugin{
		Next:    next,
		Config:  Config{Action: ActionConfig{Mode: "nxdomain"}, DisableRFCChecks: false},
		metrics: m,
	}

	w := newMockWriter()
	r := makeQuery("_bad.example.com.", dns.TypeA)
	_, _ = rf.ServeDNS(context.Background(), w, r)

	if got := getCounterValue(t, m.DenylistChecks); got != 1 {
		t.Errorf("DenylistChecks = %v, want 1", got)
	}
	if got := getCounterValue(t, m.DenylistHits); got != 1 {
		t.Errorf("DenylistHits = %v, want 1", got)
	}
}

// TestServeDNSRFCRunsAfterAllowlist verifies that allowlisted names bypass the
// RFC precheck so that operators can intentionally resolve RFC-non-compliant
// names that appear in their allowlists.
//
// This test covers the query-path ordering guarantee: allowlist → RFC check.
//
// It asserts that a name that would fail the RFC check is forwarded when it
// is present in the allowlist.
func TestServeDNSRFCRunsAfterAllowlist(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action:           ActionConfig{Mode: "nxdomain"},
			DisableRFCChecks: false,
		},
	}
	rf.SetAllowlist(buildMatcher(t, []string{"_bad.example.com"}))

	w := newMockWriter()
	r := makeQuery("_bad.example.com.", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("allowlisted name should bypass RFC check and reach next handler")
	}
}

// ── deny_non_allowlisted in ServeDNS ─────────────────────────────────────────

// TestServeDNSDenyNonAllowlistedBlocksAfterMiss verifies that end users are
// blocked when deny_non_allowlisted is true and the name is not in the
// allowlist.
//
// This test covers the deny_non_allowlisted precheck in the denylist phase.
//
// It asserts that a query for a name absent from the allowlist returns NXDOMAIN
// and does not reach the next handler.
func TestServeDNSDenyNonAllowlistedBlocksAfterMiss(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action:             ActionConfig{Mode: "nxdomain"},
			DenyNonAllowlisted: true,
			DisableRFCChecks:   true, // isolate the deny_non_allowlisted behavior
		},
	}
	rf.SetAllowlist(buildMatcher(t, []string{"safe.example.com"}))

	w := newMockWriter()
	r := makeQuery("other.example.com.", dns.TypeA)
	code, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN for non-allowlisted name, got %d", code)
	}
	if next.called {
		t.Error("next handler must not be called for non-allowlisted name")
	}
}

// TestServeDNSDenyNonAllowlistedHonorsAllowlist verifies that allowlisted names
// still resolve normally even when deny_non_allowlisted is enabled.
//
// This test covers the interaction between allowlist acceptance and the
// deny_non_allowlisted config switch.
//
// It asserts that a query for a name present in the allowlist is forwarded to
// the next handler.
func TestServeDNSDenyNonAllowlistedHonorsAllowlist(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action:             ActionConfig{Mode: "nxdomain"},
			DenyNonAllowlisted: true,
			DisableRFCChecks:   true,
		},
	}
	rf.SetAllowlist(buildMatcher(t, []string{"safe.example.com"}))

	w := newMockWriter()
	r := makeQuery("safe.example.com.", dns.TypeA)
	_, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("allowlisted name must reach next handler even with deny_non_allowlisted")
	}
}

// TestServeDNSDenyNonAllowlistedUpdatesMetrics verifies that operators can
// observe deny_non_allowlisted decisions through the denylist metrics.
//
// This test covers metric instrumentation for the deny_non_allowlisted precheck.
//
// It asserts that DenylistChecks and DenylistHits are each incremented by one
// for a query blocked by the deny_non_allowlisted precheck.
func TestServeDNSDenyNonAllowlistedUpdatesMetrics(t *testing.T) {
	m, _ := newMetrics(t)
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action:             ActionConfig{Mode: "nxdomain"},
			DenyNonAllowlisted: true,
			DisableRFCChecks:   true,
		},
		metrics: m,
	}
	rf.SetAllowlist(buildMatcher(t, []string{"safe.example.com"}))

	w := newMockWriter()
	r := makeQuery("other.example.com.", dns.TypeA)
	_, _ = rf.ServeDNS(context.Background(), w, r)

	if got := getCounterValue(t, m.DenylistChecks); got != 1 {
		t.Errorf("DenylistChecks = %v, want 1", got)
	}
	if got := getCounterValue(t, m.DenylistHits); got != 1 {
		t.Errorf("DenylistHits = %v, want 1", got)
	}
}

// TestServeDNSDenyNonAllowlistedRunsBeforeRFC verifies that deny_non_allowlisted
// takes precedence over the RFC precheck so that operators get the fastest
// possible block for non-allowlisted queries when both switches are active.
//
// This test covers the query-path ordering guarantee:
// deny_non_allowlisted → RFC check.
//
// It asserts that a non-allowlisted RFC-invalid name is still blocked (NXDOMAIN)
// when both deny_non_allowlisted and RFC checks are active, confirming that the
// deny_non_allowlisted check operates regardless of name validity.
func TestServeDNSDenyNonAllowlistedRunsBeforeRFC(t *testing.T) {
	next := &mockNextHandler{}
	rf := &Plugin{
		Next: next,
		Config: Config{
			Action:             ActionConfig{Mode: "nxdomain"},
			DenyNonAllowlisted: true,
			DisableRFCChecks:   false,
		},
	}
	rf.SetAllowlist(buildMatcher(t, []string{"safe.example.com"}))

	w := newMockWriter()
	// "_bad" is RFC-invalid and not allowlisted — blocked by deny_non_allowlisted.
	r := makeQuery("_bad.example.com.", dns.TypeA)
	code, err := rf.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %d", code)
	}
	if next.called {
		t.Error("next handler must not be called")
	}
}
