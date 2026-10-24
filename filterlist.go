// Package filterlist implements the CoreDNS filterlist plugin.
// It intercepts DNS queries and checks them against allowlist and denylist
// matchers, blocking or allowing queries according to configuration.
package filterlist

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"

	"github.com/TomTonic/filterlist/pkg/matcher"
	"github.com/TomTonic/filterlist/pkg/metrics"
	"github.com/TomTonic/filterlist/pkg/watcher"
)

var log = clog.NewWithPlugin("filterlist")

// ActionConfig describes how filterlist answers blocked DNS questions.
//
// Mode selects the response policy and must be one of nxdomain, nullip, or
// refuse. NullIPv4 and NullIPv6 provide sinkhole answers for A and AAAA
// queries when Mode is nullip, while TTL controls the cache lifetime of those
// synthetic answers.
type ActionConfig struct {
	Mode     string // "nxdomain", "nullip", "refuse"
	NullIPv4 net.IP
	NullIPv6 net.IP
	TTL      uint32
}

// Config holds the complete filterlist runtime configuration.
//
// AllowlistDir and DenylistDir point at directories containing supported
// filter list files. Action configures the DNS response for blocked names,
// while Debounce, MaxStates, and CompileTimeout bound filesystem churn and
// matcher compilation cost. InvertAllowlist controls which rules from the allowlist
// directory are compiled: by default (false) only @@-prefixed exception rules
// are used; when true, non-@@ rules (||domain^) are used instead.
//
// DenyNonAllowlisted, when true, blocks every query that was not accepted by
// the allowlist in the denylist phase — effectively a deny-all-except-listed
// policy. It runs before the denylist matcher but after allowlist evaluation.
// Default is false.
//
// DisableRFCChecks, when true, skips the RFC 1035 + IDNA query-name
// validation step that normally runs after DenyNonAllowlisted in the denylist
// phase. When false (the default), queries whose names violate RFC 1035 LDH
// syntax or the IDNA Lookup profile are blocked before the denylist matcher is
// consulted.
//
// StrictRFCNames, when true, tightens the RFC 1035 query-name validation so
// that it rejects RFC 8553 underscored labels (DNS-SD per RFC 6763, DKIM,
// DMARC, SRV, e.g. "_dns-sd._udp.example.com"). When false (the default) such
// names are accepted by the RFC check. It has no effect when DisableRFCChecks
// is true, since the whole RFC validation step is then skipped.
//
// MatcherMode selects how compiled rules are represented at runtime.
// "hybrid" (the default) keeps literal domains in a suffix map and compiles
// only wildcard patterns into a DFA. "dfa" compiles all rules into one DFA,
// which can reduce per-query lookup cost at the expense of much longer
// compile times during startup and reloads.
//
// Setup callers typically obtain Config via parseConfig.
type Config struct {
	AllowlistDir       string
	DenylistDir        string
	Action             ActionConfig
	Debounce           time.Duration
	MaxStates          int
	CompileTimeout     time.Duration
	LogQueries         bool
	InvertAllowlist    bool
	DenyNonAllowlisted bool
	DisableRFCChecks   bool
	StrictRFCNames     bool
	MatcherMode        matcher.Mode
}

// Plugin is the CoreDNS plugin handler.
//
// Each Plugin instance owns the active whitelist and blacklist matchers for one
// CoreDNS server block and swaps them atomically when reloads succeed. The
// handler is created during setup and then used on the DNS request path.
type Plugin struct {
	Next    plugin.Handler
	Config  Config
	metrics *metrics.Registry

	allowlist atomic.Value // listState
	denylist  atomic.Value // listState

	stopWatcher func() error
}

// listState is one immutable, atomically-published view of a compiled filter
// list. Bundling the matcher with its rule sources and patterns guarantees that
// a reader sees a single consistent snapshot: the rule IDs produced by matcher
// always index into the sources and patterns slices captured at the same
// compile, even if a reload swaps in a new state concurrently.
type listState struct {
	matcher  *matcher.Matcher
	sources  []string // rule source strings indexed by rule ID
	patterns []string // rule pattern strings indexed by rule ID
}

// Name reports the CoreDNS plugin name used for error wrapping and chaining.
//
// It returns the static identifier filterlist so CoreDNS can attribute handler
// failures and plugin ordering to this module.
func (rf *Plugin) Name() string { return "filterlist" }

// SetAllowlist atomically installs m as the active allowlist matcher.
//
// The m parameter may be nil to clear the allowlist after a successful reload
// that produced no allow rules. It clears any previously stored debug source
// and pattern metadata; use setAllowlist to publish a matcher together with its
// metadata. Callers normally use this from watcher update callbacks rather than
// directly from the DNS hot path.
func (rf *Plugin) SetAllowlist(m *matcher.Matcher) {
	rf.setAllowlist(m, nil, nil)
}

// SetDenylist atomically installs m as the active denylist matcher.
//
// The m parameter may be nil to clear the denylist after a successful reload
// that produced no deny rules. Like SetAllowlist it drops any debug metadata.
// This keeps readers lock-free while reload logic swaps compiled matchers in
// the background.
func (rf *Plugin) SetDenylist(m *matcher.Matcher) {
	rf.setDenylist(m, nil, nil)
}

// setAllowlist atomically publishes a complete allowlist snapshot.
//
// The matcher, sources, and patterns are stored as one listState so that
// concurrent readers always observe a self-consistent view; sources and
// patterns are indexed by the rule IDs that matcher returns.
func (rf *Plugin) setAllowlist(m *matcher.Matcher, sources, patterns []string) {
	rf.allowlist.Store(listState{matcher: m, sources: sources, patterns: patterns})
}

// setDenylist atomically publishes a complete denylist snapshot, mirroring
// setAllowlist for the deny direction.
func (rf *Plugin) setDenylist(m *matcher.Matcher, sources, patterns []string) {
	rf.denylist.Store(listState{matcher: m, sources: sources, patterns: patterns})
}

// loadAllowlist returns the current allowlist snapshot, or the zero listState
// when no allowlist has been published yet.
func (rf *Plugin) loadAllowlist() listState {
	s, _ := rf.allowlist.Load().(listState)
	return s
}

// loadDenylist returns the current denylist snapshot, or the zero listState
// when no denylist has been published yet.
func (rf *Plugin) loadDenylist() listState {
	s, _ := rf.denylist.Load().(listState)
	return s
}

// GetAllowlist returns the current allowlist matcher.
//
// The return value is nil when no allowlist has been compiled yet or when the
// last successful reload yielded no allow rules. ServeDNS uses the snapshot
// loaded via loadAllowlist on every query before consulting the denylist.
func (rf *Plugin) GetAllowlist() *matcher.Matcher {
	return rf.loadAllowlist().matcher
}

// GetDenylist returns the current denylist matcher.
//
// The return value is nil when no denylist has been compiled yet or when the
// currently loaded deny set is empty. Callers use the returned matcher as a
// read-only structure and must not mutate it.
func (rf *Plugin) GetDenylist() *matcher.Matcher {
	return rf.loadDenylist().matcher
}

// ServeDNS evaluates r against the active matchers and writes the response to w.
//
// The ctx, w, and r parameters are the standard CoreDNS request context,
// response writer, and DNS message for the current query. ServeDNS returns the
// DNS rcode written to the client together with any write error; whitelist
// matches are forwarded, blacklist matches are blocked according to Action, and
// unmatched queries are delegated to the next plugin. Messages with an opcode
// other than QUERY (NOTIFY, UPDATE) and messages without a question are never
// filtered and are passed to the next plugin unchanged.
func (rf *Plugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// Only QUERY messages carry a name a client wants to resolve. For NOTIFY and
	// UPDATE the question section names a zone, so filtering it would break zone
	// maintenance (e.g. block every UPDATE under deny_non_allowlisted).
	if len(r.Question) == 0 || r.Opcode != dns.OpcodeQuery {
		return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
	}

	start := time.Now()
	qname := r.Question[0].Name
	name := normalizeName(qname)
	qtype := r.Question[0].Qtype

	// Check allowlist first
	if al := rf.loadAllowlist(); al.matcher != nil {
		if matched, ruleIDs := al.matcher.Match(name); matched {
			rf.recordOutcome(metrics.ResultAllowlisted, start)
			if rf.Config.LogQueries {
				rf.logDebugMatch("allowlist", name, ruleIDs, al.sources, al.patterns)
			}
			return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
		}
	}

	// Denylist prechecks: run after allowlist, before the denylist matcher.
	//
	// 1. deny_non_allowlisted — when enabled, every query that missed the
	//    allowlist is blocked immediately without consulting the denylist.
	// 2. RFC / IDNA check — when enabled (disable_RFC_checks is false), queries
	//    whose names violate RFC 1035 LDH syntax or the IDNA Lookup profile are
	//    blocked. RFC 8553 underscored labels (DNS-SD, DKIM, DMARC, SRV) are
	//    accepted unless strict_rfc_names is set. This check runs after
	//    deny_non_allowlisted so that an enabled deny_non_allowlisted can
	//    short-circuit the (slightly more expensive) RFC validation for names
	//    that would be blocked anyway.
	if rf.Config.DenyNonAllowlisted {
		rf.recordOutcome(metrics.ResultBlockedUnlisted, start)
		if rf.Config.LogQueries {
			log.Infof("denylist precheck blocked name=%s reason=deny_non_allowlisted", name)
		}
		return rf.respondBlocked(w, r, qname, qtype)
	}

	if !rf.Config.DisableRFCChecks && !isStrictDNSQueryName(qname, !rf.Config.StrictRFCNames) {
		rf.recordOutcome(metrics.ResultBlockedRFC, start)
		if rf.Config.LogQueries {
			log.Infof("denylist precheck blocked name=%s reason=RFC_name_violation", name)
		}
		return rf.respondBlocked(w, r, qname, qtype)
	}

	// Check denylist
	if dl := rf.loadDenylist(); dl.matcher != nil {
		if matched, ruleIDs := dl.matcher.Match(name); matched {
			rf.recordOutcome(metrics.ResultBlockedDenylist, start)
			if rf.Config.LogQueries {
				rf.logDebugMatch("denylist", name, ruleIDs, dl.sources, dl.patterns)
			}
			return rf.respondBlocked(w, r, qname, qtype)
		}
	}

	// No match — forward to next plugin
	rf.recordOutcome(metrics.ResultForwarded, start)
	if rf.Config.LogQueries {
		log.Infof("no match name=%s", name)
	}
	return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
}

// recordOutcome records the terminal decision for one query.
//
// It increments the queries_total counter for result and observes the elapsed
// time on the match_duration histogram, bucketed by whether the query was
// forwarded or blocked. It is a no-op when metrics are disabled.
func (rf *Plugin) recordOutcome(result string, start time.Time) {
	if rf.metrics == nil {
		return
	}
	rf.metrics.Queries.WithLabelValues(result).Inc()
	latency := metrics.LatencyForwarded
	if result != metrics.ResultAllowlisted && result != metrics.ResultForwarded {
		latency = metrics.LatencyBlocked
	}
	rf.metrics.MatchDuration.WithLabelValues(latency).Observe(time.Since(start).Seconds())
}

// respondBlocked generates a blocked response based on the configured action.
func (rf *Plugin) respondBlocked(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	ttl := rf.Config.Action.TTL
	if ttl == 0 {
		ttl = 3600
	}

	switch rf.Config.Action.Mode {
	case "refuse":
		// REFUSED is a hard rejection, not a statement about the name's
		// contents, so it carries no answer and no negative-caching SOA.
		m.Rcode = dns.RcodeRefused
	case "nullip":
		m.Rcode = dns.RcodeSuccess
		switch qtype {
		case dns.TypeA:
			ip := rf.Config.Action.NullIPv4
			if ip == nil {
				ip = net.IPv4zero
			}
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip,
			})
		case dns.TypeAAAA:
			ip := rf.Config.Action.NullIPv6
			if ip == nil {
				ip = net.IPv6zero
			}
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip,
			})
		case dns.TypeHTTPS, dns.TypeSVCB:
			// Browsers query HTTPS (type 65) in parallel with A/AAAA. Rather
			// than NODATA (which relies on A/AAAA fallback), synthesize a
			// ServiceMode record whose ipv4hint/ipv6hint steer the client to
			// the sinkhole addresses directly. See issue #38.
			m.Answer = append(m.Answer, rf.syntheticSVCB(qname, qtype, ttl))
		default:
			// For all other query types (PTR, TXT, MX, SRV, ...) we return
			// NODATA: RcodeSuccess with an empty answer section. Returning
			// NXDOMAIN would assert the whole name does not exist (RFC 8020)
			// and, in RFC 8020-aware resolvers, could negative-cache the name
			// and poison the A/AAAA sinkhole answers. The SOA below bounds how
			// long the NODATA is negative-cached (RFC 2308). See issue #38.
			addNegativeCachingSOA(m, qname, ttl)
		}
	default: // "nxdomain" is the default
		m.Rcode = dns.RcodeNameError
		// Attach an SOA so resolvers know how long to negative-cache the
		// NXDOMAIN (RFC 2308) instead of re-querying aggressively.
		addNegativeCachingSOA(m, qname, ttl)
	}

	err := w.WriteMsg(m)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	return m.Rcode, nil
}

// syntheticSOAMName and syntheticSOARName are placeholder hostnames for the
// authority-section SOA of synthesized negative responses. They live under the
// reserved .invalid TLD (RFC 6761) so they can never resolve or be mistaken for
// a real zone. Only the SOA's TTL and Minimum fields carry meaning here; they
// are set to the configured block TTL to bound negative caching (RFC 2308).
const (
	syntheticSOAMName = "fake-for-negative-caching.filterlist.invalid."
	syntheticSOARName = "hostmaster.filterlist.invalid."
)

// addNegativeCachingSOA appends an authority-section SOA so resolvers can
// negative-cache an NXDOMAIN or NODATA answer for ttl seconds (RFC 2308).
// Without it the negative-cache lifetime is undefined and some stub resolvers
// (mDNSResponder, systemd-resolved) re-query aggressively instead of backing
// off. The SOA owner is the queried name itself, treated as the apex of a
// synthetic zone, so caching is scoped to exactly this blocked name.
func addNegativeCachingSOA(m *dns.Msg, qname string, ttl uint32) {
	m.Ns = append(m.Ns, &dns.SOA{
		Hdr:     dns.RR_Header{Name: qname, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      syntheticSOAMName,
		Mbox:    syntheticSOARName,
		Serial:  1,
		Refresh: ttl,
		Retry:   ttl,
		Expire:  ttl,
		Minttl:  ttl,
	})
}

// syntheticSVCB builds an HTTPS (type 65) or SVCB (type 64) record for a blocked
// name whose ipv4hint/ipv6hint point at the configured sinkhole addresses. It is
// a ServiceMode record (Priority 1, Target ".") anchored at the owner name, so a
// client with no usable hint still resolves A/AAAA at the same name and reaches
// the sinkhole. Hints are only attached when the configured address matches the
// expected family, so a misconfiguration cannot produce an unpackable record.
func (rf *Plugin) syntheticSVCB(qname string, rrtype uint16, ttl uint32) dns.RR {
	var hints []dns.SVCBKeyValue

	v4 := rf.Config.Action.NullIPv4
	if v4 == nil {
		v4 = net.IPv4zero
	}
	if v4b := v4.To4(); v4b != nil {
		hints = append(hints, &dns.SVCBIPv4Hint{Hint: []net.IP{v4b}})
	}

	v6 := rf.Config.Action.NullIPv6
	if v6 == nil {
		v6 = net.IPv6zero
	}
	if v6b := v6.To16(); v6b != nil && v6.To4() == nil {
		hints = append(hints, &dns.SVCBIPv6Hint{Hint: []net.IP{v6b}})
	}

	svcb := dns.SVCB{
		Hdr:      dns.RR_Header{Name: qname, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl},
		Priority: 1,
		Target:   ".",
		Value:    hints,
	}
	if rrtype == dns.TypeHTTPS {
		return &dns.HTTPS{SVCB: svcb}
	}
	return &svcb
}

// normalizeName lowercases the DNS name and strips the trailing root dot.
func normalizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	return name
}

// logDebugMatch logs a human-readable line when log_queries is active.
// It shows the list label, queried name, the source file:line of the first
// matching rule (basename only), and the original rule pattern in parentheses.
func (rf *Plugin) logDebugMatch(label, name string, ruleIDs []uint32, sources, patterns []string) {
	if len(ruleIDs) == 0 || len(sources) == 0 {
		log.Infof("%s match name=%s rule=unknown", label, name)
		return
	}
	id := int(ruleIDs[0])
	if id >= len(sources) {
		log.Infof("%s match name=%s rule=unknown", label, name)
		return
	}
	src := shortSource(sources[id])
	if id < len(patterns) && patterns[id] != "" {
		log.Infof("%s match name=%s rule=%s (%s)", label, name, src, patterns[id])
	} else {
		log.Infof("%s match name=%s rule=%s", label, name, src)
	}
}

// shortSource converts a "path/to/dir/list.txt:42" source string to "list.txt:42".
func shortSource(source string) string {
	if source == "" {
		return "unknown"
	}
	// Split off ":line" suffix, take basename of path, reassemble.
	if idx := strings.LastIndex(source, ":"); idx > 0 {
		return filepath.Base(source[:idx]) + source[idx:]
	}
	return filepath.Base(source)
}

// StartWatcher starts filesystem monitoring and the initial matcher load.
//
// It uses the directories and limits from rf.Config, publishes metrics for
// successful compiles and failed load or compile runs, and stores the stop
// callback for later shutdown. StartWatcher returns an error only when the
// watcher infrastructure itself cannot be started.
func (rf *Plugin) StartWatcher() error {
	stop, err := watcher.Start(&watcher.Config{
		AllowlistDir:    rf.Config.AllowlistDir,
		DenylistDir:     rf.Config.DenylistDir,
		Debounce:        rf.Config.Debounce,
		Logger:          &pluginLogger{},
		MaxCompileTime:  rf.Config.CompileTimeout,
		MaxStates:       rf.Config.MaxStates,
		InvertAllowlist: rf.Config.InvertAllowlist,
		MatcherMode:     rf.Config.MatcherMode,
		OnCompile: func(_ string, duration time.Duration) {
			if rf.metrics != nil {
				rf.metrics.CompileDuration.Observe(duration.Seconds())
				rf.metrics.LastCompileTimestamp.SetToCurrentTime()
				rf.metrics.LastCompileDurationSeconds.Set(duration.Seconds())
			}
		},
		OnError: func(_ string, _ error) {
			if rf.metrics != nil {
				rf.metrics.CompileErrors.Inc()
			}
		},
		OnUpdate: func(al watcher.Snapshot, dl watcher.Snapshot) {
			rf.setAllowlist(al.Matcher, al.Sources, al.Patterns)
			rf.setDenylist(dl.Matcher, dl.Sources, dl.Patterns)
			if rf.metrics != nil {
				rf.metrics.AllowlistRules.Set(float64(al.RuleCount))
				rf.metrics.DenylistRules.Set(float64(dl.RuleCount))
				rf.metrics.AllowlistStates.Set(float64(al.StateCount))
				rf.metrics.DenylistStates.Set(float64(dl.StateCount))
			}
			log.Infof(
				"matchers updated: allowlist_active=%v allowlist_rules=%d allowlist_states=%d denylist_active=%v denylist_rules=%d denylist_states=%d",
				al.Matcher != nil,
				al.RuleCount,
				al.StateCount,
				dl.Matcher != nil,
				dl.RuleCount,
				dl.StateCount,
			)
		},
	})
	if err != nil {
		return fmt.Errorf("filterlist: start watcher: %w", err)
	}
	rf.stopWatcher = stop
	return nil
}

// Stop stops the background watcher and releases associated resources.
//
// It returns any shutdown error reported by the watcher. Stop is typically
// invoked from the CoreDNS OnShutdown hook that is registered during setup.
func (rf *Plugin) Stop() error {
	if rf.stopWatcher != nil {
		return rf.stopWatcher()
	}
	return nil
}

// pluginLogger adapts CoreDNS log to watcher.Logger.
type pluginLogger struct{}

// Debugf forwards watcher debug messages to the CoreDNS filterlist logger.
func (pluginLogger) Debugf(format string, args ...interface{}) { log.Debugf(format, args...) }

// Warnf forwards watcher warnings to the CoreDNS filterlist logger.
func (pluginLogger) Warnf(format string, args ...interface{}) { log.Warningf(format, args...) }

// Infof forwards watcher informational messages to the CoreDNS filterlist logger.
func (pluginLogger) Infof(format string, args ...interface{}) { log.Infof(format, args...) }

// Errorf forwards watcher errors to the CoreDNS filterlist logger.
func (pluginLogger) Errorf(format string, args ...interface{}) { log.Errorf(format, args...) }
