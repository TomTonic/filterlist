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

// chainOrders lists the plugin orders the chain tests run against: the
// recommended "filterlist before cache" and the discouraged reverse.
var chainOrders = []struct {
	name       string
	cacheFirst bool
}{
	{"filterlist before cache", false},
	{"cache before filterlist", true},
}

// startChainServer boots a real CoreDNS server on a random loopback UDP port
// and returns its address and the denylist directory. The plugin order is
// "filterlist, cache, stub upstream", or "cache, filterlist, stub upstream"
// when cacheFirst is set. The denylist contains blocked.example, is watched
// with a short debounce, and the server is stopped via t.Cleanup.
func startChainServer(t *testing.T, cacheFirst bool) (addr, denyDir string) {
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
	dnsserver.Directives = []string{"bind", "filterlist", "cache", chainStubName}
	if cacheFirst {
		dnsserver.Directives = []string{"bind", "cache", "filterlist", chainStubName}
	}
	if err := dnsserver.Register(); err != nil {
		t.Fatalf("register dns server type: %v", err)
	}
	caddy.Quiet, dnsserver.Quiet = true, true
	chainStubCalls.Store(0)

	corefile := fmt.Sprintf(".:0 {\n bind 127.0.0.1\n cache\n filterlist {\n  denylist_dir %s\n  ttl 60\n  debounce 50ms\n }\n %s\n}\n",
		dir, chainStubName)
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
	return instance.Servers()[0].LocalAddr().String(), dir
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

// waitForBlock polls until the freshly started server blocks blocked.example, because the
// watcher publishes the initial matchers asynchronously after startup.
func waitForBlock(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		q := new(dns.Msg)
		q.SetQuestion("blocked.example.", dns.TypeTXT) // TXT is never cached as a positive stub answer.
		q.Question[0].Qclass = dns.ClassINET
		if resp := exchange(t, addr, q); resp.Rcode == dns.RcodeNameError || len(resp.Ns) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("denylist never became active")
}

// TestChainBlockedAnswerStaysConsistentThroughCache verifies that a user whose
// resolver caches answers still gets the same sinkhole verdict on every repeat
// of a blocked lookup, and that blocked names never reach the upstream.
//
// It belongs to the CoreDNS integration of filterlist: a real CoreDNS server
// with the plugin chain in both orders, "filterlist -> cache -> upstream"
// (recommended) and "cache -> filterlist -> upstream". CoreDNS v1.15.0 changed
// what the cache plugin does with the AA flag and with SERVFAIL, which no
// mock-based unit test can observe.
//
// For each order it queries a blocked name twice. Both answers must be NXDOMAIN with the
// negative-caching SOA, carry the same AA flag that filterlist sets (CoreDNS
// v1.15.0 replays the cached AA bit instead of forcing it), and the stub
// upstream must never be called.
func TestChainBlockedAnswerStaysConsistentThroughCache(t *testing.T) {
	for _, order := range chainOrders {
		t.Run(order.name, func(t *testing.T) {
			checkBlockedAnswerConsistent(t, order.cacheFirst)
		})
	}
}

// checkBlockedAnswerConsistent runs the scenario of
// TestChainBlockedAnswerStaysConsistentThroughCache for one plugin order.
func checkBlockedAnswerConsistent(t *testing.T, cacheFirst bool) {
	t.Helper()
	addr, _ := startChainServer(t, cacheFirst)
	waitForBlock(t, addr)

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
	addr, _ := startChainServer(t, false)
	waitForBlock(t, addr)
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
	addr, _ := startChainServer(t, false)
	waitForBlock(t, addr)

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

// TestChainNotifyForBlockedNamePassesThrough verifies that zone maintenance
// traffic still reaches the upstream handler in a running server, even when
// the zone name is on the denylist, so filtering never interferes with zone
// transfers.
//
// It belongs to the CoreDNS integration of filterlist: CoreDNS admits NOTIFY
// by default and hands it down the plugin chain like any other message, so
// filterlist must not treat the zone name in the question as a lookup.
//
// It sends a NOTIFY for blocked.example and expects the stub upstream to be
// called exactly once and the reply not to be NXDOMAIN, while a regular QUERY
// for the same name stays blocked.
func TestChainNotifyForBlockedNamePassesThrough(t *testing.T) {
	addr, _ := startChainServer(t, false)
	waitForBlock(t, addr)
	chainStubCalls.Store(0)

	n := new(dns.Msg)
	n.SetNotify("blocked.example.")
	resp := exchange(t, addr, n)
	if resp.Rcode == dns.RcodeNameError {
		t.Error("NOTIFY for a denylisted zone was answered with NXDOMAIN by filterlist")
	}
	if got := chainStubCalls.Load(); got != 1 {
		t.Errorf("upstream called %d times for one NOTIFY, want 1", got)
	}

	q := new(dns.Msg)
	q.SetQuestion("blocked.example.", dns.TypeA)
	if resp := exchange(t, addr, q); resp.Rcode != dns.RcodeNameError {
		t.Errorf("QUERY for blocked.example rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

// TestChainListChangesTakeEffectOnlyBeforeCache verifies the operational reason
// for the recommended plugin order: an operator who adds a domain to the
// denylist wants it blocked right away, even if clients resolved it before.
//
// It belongs to the CoreDNS integration of filterlist: the hot reload of the
// filter directories is only as immediate as the position of filterlist
// relative to the cache plugin, because a cache hit never reaches plugins
// behind the cache.
//
// For each plugin order it resolves ok.example (answer is cached), appends it
// to the denylist, waits until the reload is visible through a fresh probe
// name, and asks again. With filterlist before cache the name must be blocked;
// with cache before filterlist the stale cached answer is served, which pins
// the documented downside of that order.
func TestChainListChangesTakeEffectOnlyBeforeCache(t *testing.T) {
	for _, order := range chainOrders {
		t.Run(order.name, func(t *testing.T) {
			addr, denyDir := startChainServer(t, order.cacheFirst)
			waitForBlock(t, addr)

			q := new(dns.Msg)
			q.SetQuestion("ok.example.", dns.TypeA)
			if resp := exchange(t, addr, q.Copy()); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
				t.Fatalf("initial lookup: rcode=%s answers=%v, want NOERROR with one A record", dns.RcodeToString[resp.Rcode], resp.Answer)
			}

			rules := []byte("||ok.example^\n||probe.example^\n")
			if err := os.WriteFile(filepath.Join(denyDir, "added.txt"), rules, 0o600); err != nil {
				t.Fatalf("write added denylist: %v", err)
			}
			waitForProbeBlocked(t, addr)

			resp := exchange(t, addr, q.Copy())
			blocked := resp.Rcode == dns.RcodeNameError
			if blocked == order.cacheFirst {
				t.Errorf("ok.example blocked=%v after being added to the denylist, want %v", blocked, !order.cacheFirst)
			}
		})
	}
}

// waitForProbeBlocked polls fresh names under probe.example until one is
// blocked, which proves the watcher has published the reloaded matchers. Each
// poll uses a new name so a cached answer cannot hide the reload.
func waitForProbeBlocked(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		q := new(dns.Msg)
		q.SetQuestion(fmt.Sprintf("p%d.probe.example.", i), dns.TypeTXT)
		if resp := exchange(t, addr, q); resp.Rcode == dns.RcodeNameError {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("reloaded denylist never became active")
}
