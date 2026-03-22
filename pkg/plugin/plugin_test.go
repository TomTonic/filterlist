package plugin

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/tomtonic/coredns-regfilter/pkg/automaton"
	"github.com/tomtonic/coredns-regfilter/pkg/filterlist"
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

func (m *mockNextHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m.called = true
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Rcode = dns.RcodeSuccess
	w.WriteMsg(msg)
	return dns.RcodeSuccess, nil
}

func (m *mockNextHandler) Name() string { return "mock" }

func buildDFA(t *testing.T, patterns []string) *automaton.DFA {
	t.Helper()
	var rules []filterlist.Rule
	for _, p := range patterns {
		rules = append(rules, filterlist.Rule{Pattern: p})
	}
	dfa, err := automaton.CompileRules(rules, automaton.CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return dfa
}

func makeQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func TestServeDNSBlacklistNXDOMAIN(t *testing.T) {
	next := &mockNextHandler{}
	rf := &RegFilter{
		Next: next,
		Config: PluginConfig{
			Action: ActionConfig{Mode: "nxdomain"},
		},
	}
	rf.SetBlacklist(buildDFA(t, []string{"ads.example.com"}))

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

func TestServeDNSBlacklistNullIP(t *testing.T) {
	next := &mockNextHandler{}
	rf := &RegFilter{
		Next: next,
		Config: PluginConfig{
			Action: ActionConfig{
				Mode:     "nullip",
				NullIPv4: net.IPv4zero,
				NullIPv6: net.IPv6zero,
				TTL:      60,
			},
		},
	}
	rf.SetBlacklist(buildDFA(t, []string{"ads.example.com"}))

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

func TestServeDNSBlacklistRefuse(t *testing.T) {
	next := &mockNextHandler{}
	rf := &RegFilter{
		Next: next,
		Config: PluginConfig{
			Action: ActionConfig{Mode: "refuse"},
		},
	}
	rf.SetBlacklist(buildDFA(t, []string{"ads.example.com"}))

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

func TestServeDNSWhitelistOverridesBlacklist(t *testing.T) {
	next := &mockNextHandler{}
	rf := &RegFilter{
		Next: next,
		Config: PluginConfig{
			Action: ActionConfig{Mode: "nxdomain"},
		},
	}
	// Both lists contain the same domain; whitelist takes precedence
	rf.SetWhitelist(buildDFA(t, []string{"ads.example.com"}))
	rf.SetBlacklist(buildDFA(t, []string{"ads.example.com"}))

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

func TestServeDNSNoMatch(t *testing.T) {
	next := &mockNextHandler{}
	rf := &RegFilter{
		Next: next,
		Config: PluginConfig{
			Action: ActionConfig{Mode: "nxdomain"},
		},
	}
	rf.SetBlacklist(buildDFA(t, []string{"ads.example.com"}))

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

func TestServeDNSCaseInsensitive(t *testing.T) {
	next := &mockNextHandler{}
	rf := &RegFilter{
		Next: next,
		Config: PluginConfig{
			Action: ActionConfig{Mode: "nxdomain"},
		},
	}
	rf.SetBlacklist(buildDFA(t, []string{"ads.example.com"}))

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

func TestServeDNSEmptyQuestion(t *testing.T) {
	next := &mockNextHandler{}
	rf := &RegFilter{
		Next: next,
		Config: PluginConfig{
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
