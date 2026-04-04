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
	Debug              bool
	InvertAllowlist    bool
	DenyNonAllowlisted bool
	DisableRFCChecks   bool
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

	allowlist  atomic.Value // *matcher.Matcher
	denylist   atomic.Value // *matcher.Matcher
	alSources  atomic.Value // []string
	dlSources  atomic.Value // []string
	alPatterns atomic.Value // []string
	dlPatterns atomic.Value // []string

	stopWatcher func() error
}

// Name reports the CoreDNS plugin name used for error wrapping and chaining.
//
// It returns the static identifier filterlist so CoreDNS can attribute handler
// failures and plugin ordering to this module.
func (rf *Plugin) Name() string { return "filterlist" }

// SetAllowlist atomically installs m as the active allowlist matcher.
//
// The m parameter may be nil to clear the allowlist after a successful reload
// that produced no allow rules. Callers normally use this from watcher update
// callbacks rather than directly from the DNS hot path.
func (rf *Plugin) SetAllowlist(m *matcher.Matcher) {
	rf.allowlist.Store(m)
}

// SetDenylist atomically installs m as the active denylist matcher.
//
// The m parameter may be nil to clear the denylist after a successful reload
// that produced no deny rules. This keeps readers lock-free while reload logic
// swaps compiled matchers in the background.
func (rf *Plugin) SetDenylist(m *matcher.Matcher) {
	rf.denylist.Store(m)
}

// GetAllowlist returns the current allowlist matcher.
//
// The return value is nil when no allowlist has been compiled yet or when the
// last successful reload yielded no allow rules. ServeDNS uses this on every
// query before consulting the denylist.
func (rf *Plugin) GetAllowlist() *matcher.Matcher {
	v := rf.allowlist.Load()
	if v == nil {
		return nil
	}
	m, ok := v.(*matcher.Matcher)
	if !ok {
		return nil
	}

	return m
}

// GetDenylist returns the current denylist matcher.
//
// The return value is nil when no denylist has been compiled yet or when the
// currently loaded deny set is empty. Callers use the returned matcher as a
// read-only structure and must not mutate it.
func (rf *Plugin) GetDenylist() *matcher.Matcher {
	v := rf.denylist.Load()
	if v == nil {
		return nil
	}
	m, ok := v.(*matcher.Matcher)
	if !ok {
		return nil
	}

	return m
}

// ServeDNS evaluates r against the active matchers and writes the response to w.
//
// The ctx, w, and r parameters are the standard CoreDNS request context,
// response writer, and DNS message for the current query. ServeDNS returns the
// DNS rcode written to the client together with any write error; whitelist
// matches are forwarded, blacklist matches are blocked according to Action, and
// unmatched queries are delegated to the next plugin.
func (rf *Plugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) == 0 {
		return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
	}

	start := time.Now()
	qname := r.Question[0].Name
	name := normalizeName(qname)
	qtype := r.Question[0].Qtype

	// Check allowlist first
	if wl := rf.GetAllowlist(); wl != nil {
		if rf.metrics != nil {
			rf.metrics.AllowlistChecks.Inc()
		}
		if matched, ruleIDs := wl.Match(name); matched {
			if rf.metrics != nil {
				rf.metrics.AllowlistHits.Inc()
				elapsed := time.Since(start).Seconds()
				rf.metrics.MatchDuration.WithLabelValues("accept").Observe(elapsed)
			}
			if rf.Config.Debug {
				rf.logDebugMatch("allowlist", name, ruleIDs, rf.alSources.Load(), rf.alPatterns.Load())
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
	//    blocked. This check runs after deny_non_allowlisted so that an enabled
	//    deny_non_allowlisted can short-circuit the (slightly more expensive)
	//    RFC validation for names that would be blocked anyway.
	if rf.Config.DenyNonAllowlisted {
		if rf.metrics != nil {
			rf.metrics.DenylistChecks.Inc()
			rf.metrics.DenylistHits.Inc()
			elapsed := time.Since(start).Seconds()
			rf.metrics.MatchDuration.WithLabelValues("reject").Observe(elapsed)
		}
		if rf.Config.Debug {
			log.Infof("denylist precheck blocked name=%s reason=deny_non_allowlisted", name)
		}
		return rf.respondBlocked(w, r, qname, qtype)
	}

	if !rf.Config.DisableRFCChecks && !isStrictDNSQueryName(qname) {
		if rf.metrics != nil {
			rf.metrics.DenylistChecks.Inc()
			rf.metrics.DenylistHits.Inc()
			elapsed := time.Since(start).Seconds()
			rf.metrics.MatchDuration.WithLabelValues("reject").Observe(elapsed)
		}
		if rf.Config.Debug {
			log.Infof("denylist precheck blocked name=%s reason=RFC_name_violation", name)
		}
		return rf.respondBlocked(w, r, qname, qtype)
	}

	// Check denylist
	if bl := rf.GetDenylist(); bl != nil {
		if rf.metrics != nil {
			rf.metrics.DenylistChecks.Inc()
		}
		if matched, ruleIDs := bl.Match(name); matched {
			if rf.metrics != nil {
				rf.metrics.DenylistHits.Inc()
				elapsed := time.Since(start).Seconds()
				rf.metrics.MatchDuration.WithLabelValues("reject").Observe(elapsed)
			}
			if rf.Config.Debug {
				rf.logDebugMatch("denylist", name, ruleIDs, rf.dlSources.Load(), rf.dlPatterns.Load())
			}
			return rf.respondBlocked(w, r, qname, qtype)
		}
	}

	// No match — forward to next plugin
	if rf.metrics != nil {
		elapsed := time.Since(start).Seconds()
		rf.metrics.MatchDuration.WithLabelValues("pass").Observe(elapsed)
	}
	if rf.Config.Debug {
		log.Infof("no match name=%s", name)
	}
	return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
}

// respondBlocked generates a blocked response based on the configured action.
func (rf *Plugin) respondBlocked(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch rf.Config.Action.Mode {
	case "refuse":
		m.Rcode = dns.RcodeRefused
	case "nullip":
		m.Rcode = dns.RcodeSuccess
		ttl := rf.Config.Action.TTL
		if ttl == 0 {
			ttl = 3600
		}
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
		default:
			// For non-A/AAAA queries, return NXDOMAIN
			m.Rcode = dns.RcodeNameError
		}
	default: // "nxdomain" is the default
		m.Rcode = dns.RcodeNameError
	}

	err := w.WriteMsg(m)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	return m.Rcode, nil
}

// normalizeName lowercases the DNS name and strips the trailing root dot.
func normalizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	return name
}

// logDebugMatch logs a human-readable line when the debug directive is active.
// It shows the list label, queried name, the source file:line of the first
// matching rule (basename only), and the original rule pattern in parentheses.
func (rf *Plugin) logDebugMatch(label, name string, ruleIDs []uint32, sourcesVal, patternsVal interface{}) {
	sources, _ := sourcesVal.([]string)
	patterns, _ := patternsVal.([]string)
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
			rf.SetAllowlist(al.Matcher)
			rf.SetDenylist(dl.Matcher)
			rf.alSources.Store(al.Sources)
			rf.dlSources.Store(dl.Sources)
			rf.alPatterns.Store(al.Patterns)
			rf.dlPatterns.Store(dl.Patterns)
			if rf.metrics != nil {
				rf.metrics.AllowlistRules.Set(float64(al.RuleCount))
				rf.metrics.DenylistRules.Set(float64(dl.RuleCount))
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

// Warnf forwards watcher warnings to the CoreDNS filterlist logger.
func (pluginLogger) Warnf(format string, args ...interface{}) { log.Warningf(format, args...) }

// Infof forwards watcher informational messages to the CoreDNS filterlist logger.
func (pluginLogger) Infof(format string, args ...interface{}) { log.Infof(format, args...) }

// Errorf forwards watcher errors to the CoreDNS filterlist logger.
func (pluginLogger) Errorf(format string, args ...interface{}) { log.Errorf(format, args...) }
