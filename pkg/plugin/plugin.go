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

	"github.com/tomtonic/coredns-regfilter/pkg/automaton"
	"github.com/tomtonic/coredns-regfilter/pkg/metrics"
	"github.com/tomtonic/coredns-regfilter/pkg/watcher"
)

var log = clog.NewWithPlugin("regfilter")

// ActionConfig controls how blocked queries are responded to.
type ActionConfig struct {
	Mode     string // "nxdomain", "nullip", "refuse"
	NullIPv4 net.IP
	NullIPv6 net.IP
	TTL      uint32
}

// Config holds all configuration for the regfilter plugin.
type Config struct {
	WhitelistDir   string
	BlacklistDir   string
	Action         ActionConfig
	Debounce       time.Duration
	MaxStates      int
	CompileTimeout time.Duration
}

// RegFilter is the CoreDNS plugin handler.
type RegFilter struct {
	Next    plugin.Handler
	Config  Config
	metrics *metrics.Registry

	whitelist atomic.Value // *automaton.DFA
	blacklist atomic.Value // *automaton.DFA

	stopWatcher func() error
}

// Name implements the plugin.Handler interface.
func (rf *RegFilter) Name() string { return "regfilter" }

// SetWhitelist atomically stores a new whitelist DFA.
func (rf *RegFilter) SetWhitelist(d *automaton.DFA) {
	rf.whitelist.Store(d)
}

// SetBlacklist atomically stores a new blacklist DFA.
func (rf *RegFilter) SetBlacklist(d *automaton.DFA) {
	rf.blacklist.Store(d)
}

// GetWhitelist returns the current whitelist DFA (may be nil).
func (rf *RegFilter) GetWhitelist() *automaton.DFA {
	v := rf.whitelist.Load()
	if v == nil {
		return nil
	}
	return v.(*automaton.DFA)
}

// GetBlacklist returns the current blacklist DFA (may be nil).
func (rf *RegFilter) GetBlacklist() *automaton.DFA {
	v := rf.blacklist.Load()
	if v == nil {
		return nil
	}
	return v.(*automaton.DFA)
}

// ServeDNS implements the plugin.Handler interface.
func (rf *RegFilter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) == 0 {
		return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
	}

	qname := r.Question[0].Name
	name := normalizeName(qname)
	qtype := r.Question[0].Qtype

	// Check whitelist first
	if wl := rf.GetWhitelist(); wl != nil {
		if matched, _ := wl.Match(name); matched {
			if rf.metrics != nil {
				rf.metrics.WhitelistHits.Inc()
			}
			log.Debugf("whitelist match: %s", name)
			return plugin.NextOrFailure(rf.Name(), rf.Next, ctx, w, r)
		}
	}

	// Check blacklist
	if bl := rf.GetBlacklist(); bl != nil {
		if matched, _ := bl.Match(name); matched {
			if rf.metrics != nil {
				rf.metrics.BlacklistHits.Inc()
			}
			log.Debugf("blacklist match: %s", name)
			return rf.respondBlocked(w, r, qname, qtype)
		}
	}

	// No match — forward to next plugin
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

// StartWatcher initializes the filesystem watcher for hot-reloading DFAs.
func (rf *RegFilter) StartWatcher() error {
	stop, err := watcher.Start(watcher.Config{
		WhitelistDir:   rf.Config.WhitelistDir,
		BlacklistDir:   rf.Config.BlacklistDir,
		Debounce:       rf.Config.Debounce,
		Logger:         &pluginLogger{},
		MaxCompileTime: rf.Config.CompileTimeout,
		MaxStates:      rf.Config.MaxStates,
		OnUpdate: func(wl *automaton.DFA, bl *automaton.DFA) {
			rf.SetWhitelist(wl)
			rf.SetBlacklist(bl)
			if rf.metrics != nil {
				if wl != nil {
					rf.metrics.WhitelistRules.Set(float64(wl.StateCount()))
				} else {
					rf.metrics.WhitelistRules.Set(0)
				}
				if bl != nil {
					rf.metrics.BlacklistRules.Set(float64(bl.StateCount()))
				} else {
					rf.metrics.BlacklistRules.Set(0)
				}
			}
			log.Infof("DFAs updated: whitelist=%v blacklist=%v",
				wl != nil, bl != nil)
		},
	})
	if err != nil {
		return fmt.Errorf("regfilter: start watcher: %w", err)
	}
	rf.stopWatcher = stop
	return nil
}

// Stop cleanly shuts down the watcher.
func (rf *RegFilter) Stop() error {
	if rf.stopWatcher != nil {
		return rf.stopWatcher()
	}
	return nil
}

// pluginLogger adapts CoreDNS log to watcher.Logger.
type pluginLogger struct{}

func (pluginLogger) Warnf(format string, args ...interface{})  { log.Warningf(format, args...) }
func (pluginLogger) Infof(format string, args ...interface{})  { log.Infof(format, args...) }
func (pluginLogger) Errorf(format string, args ...interface{}) { log.Errorf(format, args...) }
