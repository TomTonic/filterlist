package plugin

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	rfmetrics "github.com/tomtonic/coredns-regfilter/pkg/metrics"
)

func init() {
	plugin.Register("regfilter", setup)
}

func setup(c *caddy.Controller) error {
	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error("regfilter", err)
	}

	rf := &RegFilter{
		Config:  cfg,
		metrics: rfmetrics.NewRegistry(),
	}

	if err := rf.StartWatcher(); err != nil {
		return plugin.Error("regfilter", err)
	}

	// Register shutdown hook
	c.OnShutdown(func() error {
		return rf.Stop()
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		rf.Next = next
		return rf
	})

	return nil
}

func parseConfig(c *caddy.Controller) (Config, error) {
	cfg := Config{
		Action: ActionConfig{
			Mode: "nxdomain",
			TTL:  3600,
		},
		Debounce:       300 * time.Millisecond,
		MaxStates:      200000,
		CompileTimeout: 30 * time.Second,
	}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "whitelist_dir":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				cfg.WhitelistDir = c.Val()
			case "blacklist_dir":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				cfg.BlacklistDir = c.Val()
			case "action":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				mode := c.Val()
				switch mode {
				case "nxdomain", "nullip", "refuse":
					cfg.Action.Mode = mode
				default:
					return cfg, fmt.Errorf("unknown action %q (must be nxdomain, nullip, or refuse)", mode)
				}
			case "nullip":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				ip := net.ParseIP(c.Val())
				if ip == nil {
					return cfg, fmt.Errorf("invalid nullip %q", c.Val())
				}
				if ip.To4() != nil {
					cfg.Action.NullIPv4 = ip.To4()
				} else {
					cfg.Action.NullIPv6 = ip
				}
			case "nullip6":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				ip := net.ParseIP(c.Val())
				if ip == nil {
					return cfg, fmt.Errorf("invalid nullip6 %q", c.Val())
				}
				cfg.Action.NullIPv6 = ip
			case "debounce":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				d, err := time.ParseDuration(c.Val())
				if err != nil {
					return cfg, fmt.Errorf("invalid debounce %q: %w", c.Val(), err)
				}
				cfg.Debounce = d
			case "max_states":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				var n int
				if _, err := fmt.Sscanf(c.Val(), "%d", &n); err != nil {
					return cfg, fmt.Errorf("invalid max_states %q: %w", c.Val(), err)
				}
				if n <= 0 {
					return cfg, errors.New("max_states must be positive")
				}
				cfg.MaxStates = n
			case "compile_timeout":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				d, err := time.ParseDuration(c.Val())
				if err != nil {
					return cfg, fmt.Errorf("invalid compile_timeout %q: %w", c.Val(), err)
				}
				cfg.CompileTimeout = d
			case "ttl":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				var n uint32
				if _, err := fmt.Sscanf(c.Val(), "%d", &n); err != nil {
					return cfg, fmt.Errorf("invalid ttl %q: %w", c.Val(), err)
				}
				cfg.Action.TTL = n
			default:
				return cfg, fmt.Errorf("unknown directive %q", c.Val())
			}
		}
	}

	return cfg, nil
}
