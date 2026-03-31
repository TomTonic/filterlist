package regfilter

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	rfmetrics "github.com/TomTonic/coredns-regfilter/pkg/metrics"
)

func init() {
	plugin.Register("regfilter", setup)
}

// setup is the caddy setup function registered for the "regfilter" directive.
func setup(c *caddy.Controller) error {
	log.Infof("regfilter %s", readBuildInfo())

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

// parseConfig reads the regfilter stanza from c and returns a validated Config.
//
// The c parameter must be positioned on a regfilter block inside a CoreDNS
// Corefile. The returned Config contains defaults for omitted options and a
// validation error for unsupported directives, invalid IP families, negative
// durations, or configurations that would start without any filter directory.
// Setup uses this as the single translation layer between Corefile syntax and
// the runtime RegFilter configuration.
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
			if err := parseDirective(c, &cfg); err != nil {
				return cfg, err
			}
		}
	}

	if cfg.WhitelistDir == "" && cfg.BlacklistDir == "" {
		return cfg, errors.New("at least one of whitelist_dir or blacklist_dir must be configured")
	}

	return cfg, nil
}

// parseDirective keeps the per-directive parsing rules out of parseConfig.
func parseDirective(c *caddy.Controller, cfg *Config) error {
	switch c.Val() {
	case "whitelist_dir":
		value, err := nextArgValue(c)
		if err != nil {
			return err
		}
		cfg.WhitelistDir = value
	case "blacklist_dir":
		value, err := nextArgValue(c)
		if err != nil {
			return err
		}
		cfg.BlacklistDir = value
	case "action":
		value, err := nextArgValue(c)
		if err != nil {
			return err
		}
		if err := parseActionMode(value, &cfg.Action); err != nil {
			return err
		}
	case "nullip":
		value, err := nextArgValue(c)
		if err != nil {
			return err
		}
		ip, err := parseIPv4(value, "nullip")
		if err != nil {
			return err
		}
		cfg.Action.NullIPv4 = ip
	case "nullip6":
		value, err := nextArgValue(c)
		if err != nil {
			return err
		}
		ip, err := parseIPv6(value, "nullip6")
		if err != nil {
			return err
		}
		cfg.Action.NullIPv6 = ip
	case "debounce":
		duration, err := parsePositiveDuration(c, "debounce")
		if err != nil {
			return err
		}
		cfg.Debounce = duration
	case "max_states":
		value, err := parsePositiveInt(c, "max_states")
		if err != nil {
			return err
		}
		cfg.MaxStates = value
	case "compile_timeout":
		duration, err := parsePositiveDuration(c, "compile_timeout")
		if err != nil {
			return err
		}
		cfg.CompileTimeout = duration
	case "ttl":
		value, err := parseUint32(c, "ttl")
		if err != nil {
			return err
		}
		cfg.Action.TTL = value
	case "debug":
		cfg.Debug = true
	case "invert_whitelist":
		cfg.InvertWhitelist = true
	default:
		return fmt.Errorf("unknown directive %q", c.Val())
	}

	return nil
}

// nextArgValue centralizes the common "directive needs one argument" check.
func nextArgValue(c *caddy.Controller) (string, error) {
	if !c.NextArg() {
		return "", c.ArgErr()
	}

	return c.Val(), nil
}

// parseActionMode validates the blocked-response mode string.
func parseActionMode(value string, action *ActionConfig) error {
	switch value {
	case "nxdomain", "nullip", "refuse":
		action.Mode = value
		return nil
	default:
		return fmt.Errorf("unknown action %q (must be nxdomain, nullip, or refuse)", value)
	}
}

// parseIPv4 enforces that directives expecting an IPv4 sinkhole receive one.
func parseIPv4(value, directive string) (net.IP, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid %s %q: expected IPv4 address", directive, value)
	}

	return ip.To4(), nil
}

// parseIPv6 enforces that directives expecting an IPv6 sinkhole receive one.
func parseIPv6(value, directive string) (net.IP, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid %s %q: expected IPv6 address", directive, value)
	}

	return ip, nil
}

// parsePositiveDuration validates duration knobs shared by debounce settings.
func parsePositiveDuration(c *caddy.Controller, directive string) (time.Duration, error) {
	value, err := nextArgValue(c)
	if err != nil {
		return 0, err
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", directive, value, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be positive", directive)
	}

	return duration, nil
}

// parsePositiveInt validates positive integer limits such as max_states.
func parsePositiveInt(c *caddy.Controller, directive string) (int, error) {
	value, err := nextArgValue(c)
	if err != nil {
		return 0, err
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", directive, value, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", directive)
	}

	return parsed, nil
}

// parseUint32 validates non-negative 32-bit values such as DNS TTLs.
func parseUint32(c *caddy.Controller, directive string) (uint32, error) {
	value, err := nextArgValue(c)
	if err != nil {
		return 0, err
	}

	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", directive, value, err)
	}

	return uint32(parsed), nil
}
