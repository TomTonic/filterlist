package filterlist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	_ "github.com/coredns/coredns/plugin/bind"  // Corefile "bind" directive used by the test server.
	_ "github.com/coredns/coredns/plugin/cache" // Real cache plugin in front of filterlist.
	"github.com/miekg/dns"
)

// chainStubName is the directive name of the test-only upstream plugin that
// terminates the plugin chain like "forward" would in production.
const chainStubName = "filterlistchainstub"

// chainStubCalls counts how many queries reached the stub upstream, i.e. were
// neither blocked by filterlist nor answered from the cache.
var chainStubCalls atomic.Int64

// chainServerMu serializes tests that start a real CoreDNS instance, because
// the directive order and the stub counter are process-wide.
var chainServerMu sync.Mutex

func init() {
	plugin.Register(chainStubName, func(c *caddy.Controller) error {
		dnsserver.GetConfig(c).AddPlugin(func(plugin.Handler) plugin.Handler {
			return chainStub{}
		})
		return nil
	})
}

// chainStub answers every A query with 192.0.2.1 and counts the call.
type chainStub struct{}

func (chainStub) Name() string { return chainStubName }

func (chainStub) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	chainStubCalls.Add(1)
	m := new(dns.Msg)
	m.SetReply(r)
	if r.Question[0].Qtype == dns.TypeA {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 1),
		})
	}
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

// startChainServer boots a real CoreDNS server on a random loopback UDP port
// with the plugin order "cache, filterlist, stub upstream" and returns its
// address. The denylist contains blocked.example and the server is stopped via
// t.Cleanup. Extra filterlist directives can be passed in filterlistOpts.
func startChainServer(t *testing.T, filterlistOpts string) string {
	t.Helper()
	chainServerMu.Lock()
	t.Cleanup(chainServerMu.Unlock)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deny.txt"), []byte("||blocked.example^\n"), 0o600); err != nil {
		t.Fatalf("write denylist: %v", err)
	}

	oldDirectives := dnsserver.Directives
	oldCaddyQuiet, oldDNSQuiet := caddy.Quiet, dnsserver.Quiet
	t.Cleanup(func() {
		dnsserver.Directives = oldDirectives
		caddy.Quiet, dnsserver.Quiet = oldCaddyQuiet, oldDNSQuiet
	})
	dnsserver.Directives = []string{"bind", "cache", "filterlist", chainStubName}
	if err := dnsserver.Register(); err != nil {
		t.Fatalf("register dns server type: %v", err)
	}
	caddy.Quiet, dnsserver.Quiet = true, true
	chainStubCalls.Store(0)

	corefile := fmt.Sprintf(".:0 {\n bind 127.0.0.1\n cache\n filterlist {\n  denylist_dir %s\n  ttl 60\n  %s\n }\n %s\n}\n",
		dir, filterlistOpts, chainStubName)
	instance, err := caddy.Start(caddy.CaddyfileInput{
		Filepath:       "Corefile",
		Contents:       []byte(corefile),
		ServerTypeName: "dns",
	})
	if err != nil {
		t.Fatalf("start CoreDNS: %v", err)
	}
	t.Cleanup(func() {
		shutdownErr := errors.Join(instance.ShutdownCallbacks()...)
		stopErr := instance.Stop()
		instance.Wait()
		if err := errors.Join(shutdownErr, stopErr); err != nil {
			t.Errorf("stop CoreDNS: %v", err)
		}
	})
	return instance.Servers()[0].LocalAddr().String()
}

// exchange sends q to addr over UDP and fails the test on transport errors.
func exchange(t *testing.T, addr string, q *dns.Msg) *dns.Msg {
	t.Helper()
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(q, addr)
	if err != nil {
		t.Fatalf("exchange %q: %v", q.Question[0].Name, err)
	}
	return resp
}

// waitForBlock polls until the freshly started server blocks name, because the
// watcher publishes the initial matchers asynchronously after startup.
func waitForBlock(t *testing.T, addr, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeTXT) // TXT is never cached as a positive stub answer.
		q.Question[0].Qclass = dns.ClassINET
		if resp := exchange(t, addr, q); resp.Rcode == dns.RcodeNameError || len(resp.Ns) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("denylist never became active for %s", name)
}

// TestChainBlockedAnswerStaysConsistentThroughCache verifies that a user whose
// resolver caches answers still gets the same sinkhole verdict on every repeat
// of a blocked lookup, and that blocked names never reach the upstream.
//
// It belongs to the CoreDNS integration of filterlist: a real CoreDNS server
// with the plugin chain "cache -> filterlist -> upstream", as in production
// deployments that place cache before filterlist. CoreDNS v1.15.0 changed what
// the cache plugin does with the AA flag and with SERVFAIL, which no mock-based
// unit test can observe.
//
// It queries a blocked name twice. Both answers must be NXDOMAIN with the
// negative-caching SOA, carry the same AA flag that filterlist sets (CoreDNS
// v1.15.0 replays the cached AA bit instead of forcing it), and the stub
// upstream must never be called.
func TestChainBlockedAnswerStaysConsistentThroughCache(t *testing.T) {
	addr := startChainServer(t, "")
	waitForBlock(t, addr, "blocked.example.")

	q := new(dns.Msg)
	q.SetQuestion("blocked.example.", dns.TypeA)

	first := exchange(t, addr, q.Copy())
	second := exchange(t, addr, q.Copy())

	tests := []struct {
		name string
		resp *dns.Msg
	}{
		{"first (uncached) blocked answer", first},
		{"second (cached) blocked answer", second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.resp.Rcode != dns.RcodeNameError {
				t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[tt.resp.Rcode])
			}
			if len(tt.resp.Answer) != 0 {
				t.Errorf("answer section = %v, want empty", tt.resp.Answer)
			}
			if len(tt.resp.Ns) != 1 || tt.resp.Ns[0].Header().Rrtype != dns.TypeSOA {
				t.Errorf("authority section = %v, want one negative-caching SOA", tt.resp.Ns)
			}
		})
	}
	if !first.Authoritative || !second.Authoritative {
		t.Errorf("AA flag differs between uncached (%v) and cached (%v) blocked answer, want both set", first.Authoritative, second.Authoritative)
	}
	if got := chainStubCalls.Load(); got != 0 {
		t.Errorf("blocked queries reached the upstream %d times, want 0", got)
	}
}

// TestChainForwardedAnswerIsCachedAndBlockingStillWorks verifies that a user
// resolving an unlisted name gets the upstream answer, repeat lookups are served
// from the cache, and blocked names stay blocked in the same server.
//
// It belongs to the CoreDNS integration of filterlist and guards the
// "no match -> next plugin" path against changes in how the CoreDNS cache and
// chain hand queries to the next handler.
//
// It asks twice for ok.example (upstream called exactly once, identical
// answer) and then for blocked.example, which must still be NXDOMAIN.
func TestChainForwardedAnswerIsCachedAndBlockingStillWorks(t *testing.T) {
	addr := startChainServer(t, "")
	waitForBlock(t, addr, "blocked.example.")
	chainStubCalls.Store(0)

	q := new(dns.Msg)
	q.SetQuestion("ok.example.", dns.TypeA)
	for i := range 2 {
		resp := exchange(t, addr, q.Copy())
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("lookup %d: rcode=%s answers=%v, want NOERROR with one A record", i, dns.RcodeToString[resp.Rcode], resp.Answer)
		}
	}
	if got := chainStubCalls.Load(); got != 1 {
		t.Errorf("upstream called %d times for two identical lookups, want 1 (second served by cache)", got)
	}

	bq := new(dns.Msg)
	bq.SetQuestion("blocked.example.", dns.TypeA)
	if resp := exchange(t, addr, bq); resp.Rcode != dns.RcodeNameError {
		t.Errorf("blocked.example rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

// TestChainEDNSOnBlockedAnswers verifies that clients using EDNS0 (resolvers,
// browsers, validating stubs) receive a well-formed EDNS response when their
// query is blocked, without unknown request options being echoed back.
//
// It belongs to the CoreDNS integration of filterlist: filterlist builds its
// reply with SetReply and never touches the OPT record, so what the client
// sees is decided by the CoreDNS server core, which changed in v1.15.0.
//
// It sends a blocked query carrying an OPT record with the DO bit, a 1232 byte
// buffer and an unknown option, and expects NXDOMAIN with an OPT record that
// keeps the DO bit but does not contain the unknown option.
func TestChainEDNSOnBlockedAnswers(t *testing.T) {
	addr := startChainServer(t, "")
	waitForBlock(t, addr, "blocked.example.")

	q := new(dns.Msg)
	q.SetQuestion("blocked.example.", dns.TypeA)
	q.SetEdns0(1232, true)
	opt := q.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2, 3}})

	resp := exchange(t, addr, q)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	ropt := resp.IsEdns0()
	if ropt == nil {
		t.Fatal("blocked response to an EDNS query has no OPT record")
	}
	if !ropt.Do() {
		t.Error("OPT record lost the DO bit")
	}
	for _, o := range ropt.Option {
		if o.Option() == 65001 {
			t.Error("unknown EDNS option was echoed back to the client")
		}
	}
}
