// Package plugin implements the CoreDNS regfilter plugin.
// It intercepts DNS queries and checks them against whitelist and blacklist
// DFAs, blocking or allowing queries according to configuration.
package plugin

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"

	"github.com/TomTonic/coredns-regfilter/pkg/automaton"
	"github.com/TomTonic/coredns-regfilter/pkg/metrics"
	"github.com/TomTonic/coredns-regfilter/pkg/watcher"
)

var log = clog.NewWithPlugin("regfilter")

// ActionConfig describes how regfilter answers blocked DNS questions.
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

// Config holds the complete regfilter runtime configuration.
//
// WhitelistDir and BlacklistDir point at directories containing supported
// filter list files. Action configures the DNS response for blocked names,
// while Debounce, MaxStates, and CompileTimeout bound filesystem churn and DFA
// compilation cost. Setup callers typically obtain Config via parseConfig.
type Config struct {
	WhitelistDir   string
	BlacklistDir   string
	Action         ActionConfig
	Debounce       time.Duration
	MaxStates      int
	CompileTimeout time.Duration
}

// RegFilter is the CoreDNS plugin handler.
//
// Each RegFilter instance owns the active whitelist and blacklist DFAs for one
// CoreDNS server block and swaps them atomically when reloads succeed. The
// handler is created during setup and then used on the DNS request path.
type RegFilter struct {
	Next    plugin.Handler
	Config  Config
	metrics *metrics.Registry

	whitelist atomic.Value // *automaton.DFA
	blacklist atomic.Value // *automaton.DFA

	stopWatcher func() error
}

// Name reports the CoreDNS plugin name used for error wrapping and chaining.
//
// It returns the static identifier regfilter so CoreDNS can attribute handler
// failures and plugin ordering to this module.
func (rf *RegFilter) Name() string { return "regfilter" }

// SetWhitelist atomically installs d as the active whitelist automaton.
//
// The d parameter may be nil to clear the whitelist after a successful reload
// that produced no allow rules. Callers normally use this from watcher update
// callbacks rather than directly from the DNS hot path.
func (rf *RegFilter) SetWhitelist(d *automaton.DFA) {
	rf.whitelist.Store(d)
}

// SetBlacklist atomically installs d as the active blacklist automaton.
//
// The d parameter may be nil to clear the blacklist after a successful reload
// that produced no deny rules. This keeps readers lock-free while reload logic
// swaps compiled automatons in the background.
func (rf *RegFilter) SetBlacklist(d *automaton.DFA) {
	rf.blacklist.Store(d)
}

// GetWhitelist returns the current whitelist automaton.
//
// The return value is nil when no whitelist has been compiled yet or when the
// last successful reload yielded no allow rules. ServeDNS uses this on every
// query before consulting the blacklist.
func (rf *RegFilter) GetWhitelist() *automaton.DFA {
	v := rf.whitelist.Load()
	if v == nil {
		return nil
	}
	dfa, ok := v.(*automaton.DFA)
	if !ok {
		return nil
	}

	return dfa
}

// GetBlacklist returns the current blacklist automaton.
//
// The return value is nil when no blacklist has been compiled yet or when the
// currently loaded deny set is empty. Callers use the returned DFA as a
// read-only structure and must not mutate it.
func (rf *RegFilter) GetBlacklist() *automaton.DFA {
	v := rf.blacklist.Load()
	if v == nil {
		return nil
	}
	dfa, ok := v.(*automaton.DFA)
	if !ok {
		return nil
	}

	return dfa
}

// ServeDNS evaluates r against the active DFAs and writes the response to w.
//
// The ctx, w, and r parameters are the standard CoreDNS request context,
// response writer, and DNS message for the current query. ServeDNS returns the
// DNS rcode written to the client together with any write error; whitelist
// matches are forwarded, blacklist matches are blocked according to Action, and
// unmatched queries are delegated to the next plugin.
func (rf *RegFilter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) == 0 {
		return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
	}

	start := time.Now()
	qname := r.Question[0].Name
	name := normalizeName(qname)
	qtype := r.Question[0].Qtype

	// Check whitelist first
	if wl := rf.GetWhitelist(); wl != nil {
		if rf.metrics != nil {
			rf.metrics.WhitelistChecks.Inc()
		}
		if matched, _ := wl.Match(name); matched {
			if rf.metrics != nil {
				rf.metrics.WhitelistHits.Inc()
				elapsed := time.Since(start).Seconds()
				rf.metrics.MatchDuration.WithLabelValues("accept").Observe(elapsed)
			}
			log.Debugf("whitelist match: %s", name)
			return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
		}
	}

	// Check blacklist
	if bl := rf.GetBlacklist(); bl != nil {
		if rf.metrics != nil {
			rf.metrics.BlacklistChecks.Inc()
		}
		if matched, _ := bl.Match(name); matched {
			if rf.metrics != nil {
				rf.metrics.BlacklistHits.Inc()
				elapsed := time.Since(start).Seconds()
				rf.metrics.MatchDuration.WithLabelValues("reject").Observe(elapsed)
			}
			log.Debugf("blacklist match: %s", name)
			return rf.respondBlocked(w, r, qname, qtype)
		}
	}

	// No match — forward to next plugin
	if rf.metrics != nil {
		elapsed := time.Since(start).Seconds()
		rf.metrics.MatchDuration.WithLabelValues("pass").Observe(elapsed)
	}
	return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
}

// respondBlocked generates a blocked response based on the configured action.
func (rf *RegFilter) respondBlocked(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16) (int, error) {
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

func normalizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	return name
}

// StartWatcher starts filesystem monitoring and the initial DFA load.
//
// It uses the directories and limits from rf.Config, publishes metrics for
// successful compiles and failed load or compile runs, and stores the stop
// callback for later shutdown. StartWatcher returns an error only when the
// watcher infrastructure itself cannot be started.
func (rf *RegFilter) StartWatcher() error {
	stop, err := watcher.Start(&watcher.Config{
		WhitelistDir:   rf.Config.WhitelistDir,
		BlacklistDir:   rf.Config.BlacklistDir,
		Debounce:       rf.Config.Debounce,
		Logger:         &pluginLogger{},
		MaxCompileTime: rf.Config.CompileTimeout,
		MaxStates:      rf.Config.MaxStates,
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
		OnUpdate: func(wl watcher.Snapshot, bl watcher.Snapshot) {
			rf.SetWhitelist(wl.DFA)
			rf.SetBlacklist(bl.DFA)
			if rf.metrics != nil {
				rf.metrics.WhitelistRules.Set(float64(wl.RuleCount))
				rf.metrics.BlacklistRules.Set(float64(bl.RuleCount))
			}
			log.Infof(
				"DFAs updated: whitelist_active=%v whitelist_rules=%d whitelist_states=%d blacklist_active=%v blacklist_rules=%d blacklist_states=%d",
				wl.DFA != nil,
				wl.RuleCount,
				wl.StateCount,
				bl.DFA != nil,
				bl.RuleCount,
				bl.StateCount,
			)
		},
	})
	if err != nil {
		return fmt.Errorf("regfilter: start watcher: %w", err)
	}
	rf.stopWatcher = stop
	return nil
}

// Stop stops the background watcher and releases associated resources.
//
// It returns any shutdown error reported by the watcher. Stop is typically
// invoked from the CoreDNS OnShutdown hook that is registered during setup.
func (rf *RegFilter) Stop() error {
	if rf.stopWatcher != nil {
		return rf.stopWatcher()
	}
	return nil
}

// pluginLogger adapts CoreDNS log to watcher.Logger.
type pluginLogger struct{}

// Warnf forwards watcher warnings to the CoreDNS regfilter logger.
func (pluginLogger) Warnf(format string, args ...interface{}) { log.Warningf(format, args...) }

// Infof forwards watcher informational messages to the CoreDNS regfilter logger.
func (pluginLogger) Infof(format string, args ...interface{}) { log.Infof(format, args...) }

// Errorf forwards watcher errors to the CoreDNS regfilter logger.
func (pluginLogger) Errorf(format string, args ...interface{}) { log.Errorf(format, args...) }
