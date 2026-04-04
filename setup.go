package filterlist

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/TomTonic/filterlist/pkg/matcher"
	rfmetrics "github.com/TomTonic/filterlist/pkg/metrics"
)

func init() {
	plugin.Register("filterlist", setup)
}

// setup is the caddy setup function registered for the "filterlist" directive.
func setup(c *caddy.Controller) error {
	log.Infof("filterlist %s", readBuildInfo())

	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error("filterlist", err)
	}
	if cfg.MaxStates == 0 {
		log.Warning("filterlist configured with max_states=0 (uncapped DFA state growth); use with care")
	}

	rf := &Plugin{
		Config:  cfg,
		metrics: rfmetrics.NewRegistry(),
	}

	if err := rf.StartWatcher(); err != nil {
		return plugin.Error("filterlist", err)
	}

	// Register shutdown hook
	c.OnShutdown(func() error {
		return rf.Stop()
	})

	c.OnStartup(func() error {
		if warning := pluginOrderWarning(dnsserver.GetConfig(c).Handlers()); warning != "" {
			log.Warning(warning)
		}
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		rf.Next = next
		return rf
	})

	return nil
}

// pluginOrderWarning explains when the configured handler order makes filterlist
// ineffective because a terminal forward plugin runs earlier in the chain.
func pluginOrderWarning(handlers []plugin.Handler) string {
	filterlistIndex := -1
	forwardIndex := -1

	for index, handler := range handlers {
		switch handler.Name() {
		case "filterlist":
			if filterlistIndex == -1 {
				filterlistIndex = index
			}
		case "forward":
			if forwardIndex == -1 {
				forwardIndex = index
			}
		}
	}

	if filterlistIndex == -1 || forwardIndex == -1 || filterlistIndex < forwardIndex {
		return ""
	}

	return "filterlist is ordered after the 'forward' plugin in the generated CoreDNS plugin chain; forward is typically terminal, so filterlist will not see queries (and not log them). The relevant order comes from plugin.cfg, not Corefile stanza order. Move filterlist before forward in plugin.cfg."
}

// parseConfig reads the filterlist stanza from c and returns a validated Config.
//
// The c parameter must be positioned on a filterlist block inside a CoreDNS
// Corefile. The returned Config contains defaults for omitted options and a
// validation error for unsupported directives, invalid IP families, negative
// durations, or configurations that would start without any filter directory.
// Setup uses this as the single translation layer between Corefile syntax and
// the runtime Plugin configuration.
func parseConfig(c *caddy.Controller) (Config, error) {
	cfg := Config{
		Action: ActionConfig{
			Mode: "nxdomain",
			TTL:  3600,
		},
		Debounce:       300 * time.Millisecond,
		MaxStates:      200000,
		CompileTimeout: 30 * time.Second,
		MatcherMode:    matcher.ModeHybrid,
	}

	for c.Next() {
		for c.NextBlock() {
			if err := parseDirective(c, &cfg); err != nil {
				return cfg, err
			}
		}
	}

	if cfg.AllowlistDir == "" && cfg.DenylistDir == "" {
		return cfg, errors.New("at least one of allowlist_dir or denylist_dir must be configured")
	}

	return cfg, nil
}

// parseDirective keeps the per-directive parsing rules out of parseConfig.
func parseDirective(c *caddy.Controller, cfg *Config) error {
	switch c.Val() {
	case "allowlist_dir":
		value, err := nextArgValue(c)
		if err != nil {
			return err
		}
		cfg.AllowlistDir = value
	case "denylist_dir":
		value, err := nextArgValue(c)
		if err != nil {
			return err
		}
		cfg.DenylistDir = value
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
		value, err := parseNonNegativeInt(c, "max_states")
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
	case "invert_allowlist":
		cfg.InvertAllowlist = true
	case "deny_non_allowlisted":
		enabled, err := parseBool(c, "deny_non_allowlisted")
		if err != nil {
			return err
		}
		cfg.DenyNonAllowlisted = enabled
	case "disable_RFC_checks":
		enabled, err := parseBool(c, "disable_RFC_checks")
		if err != nil {
			return err
		}
		cfg.DisableRFCChecks = enabled
	case "matcher_mode":
		value, err := nextArgValue(c)
		if err != nil {
			return err
		}
		mode, err := matcher.ParseMode(value)
		if err != nil {
			return err
		}
		cfg.MatcherMode = mode
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

// parseNonNegativeInt validates integer limits that allow zero (for uncapped mode).
func parseNonNegativeInt(c *caddy.Controller, directive string) (int, error) {
	value, err := nextArgValue(c)
	if err != nil {
		return 0, err
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", directive, value, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("%s must be >= 0", directive)
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

// parseBool parses a boolean directive argument that accepts the common
// text representations used in Corefile syntax.
//
// The c parameter must be positioned on the directive name; the function
// consumes the next token as the value. The directive parameter names the
// directive in error messages.
//
// Accepted truthy values: "1", "true", "on", "yes".
// Accepted falsy values:  "0", "false", "off", "no".
// Any other value causes a descriptive error that includes the directive name.
//
// parseBool is used for boolean config switches like deny_non_allowlisted and
// disable_RFC_checks that need explicit on/off syntax instead of bare keywords.
func parseBool(c *caddy.Controller, directive string) (bool, error) {
	value, err := nextArgValue(c)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(value) {
	case "1", "true", "on", "yes":
		return true, nil
	case "0", "false", "off", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid %s %q: expected one of: 1, true, on, yes, 0, false, off, no", directive, value)
	}
}
