package filterlist

import (
	"context"
	"strings"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type namedHandler struct{ name string }

func (h namedHandler) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
	return dns.RcodeSuccess, nil
}

func (h namedHandler) Name() string { return h.name }

// TestParseConfigRequiresAtLeastOneFilterDirectory verifies that operators get
// a configuration error instead of a no-op plugin when no filter directory is set.
//
// This test covers the plugin Corefile parsing and validation path.
//
// It asserts that parseConfig rejects a filterlist block without whitelist_dir
// or blacklist_dir.
func TestParseConfigRequiresAtLeastOneFilterDirectory(t *testing.T) {
	c := caddy.NewTestController("dns", `filterlist { action nxdomain }`)

	_, err := parseConfig(c)
	if err == nil {
		t.Fatal("expected parseConfig to reject missing filter directories")
	}
}

// TestParseConfigRejectsWrongNullIPAddressFamilies verifies that administrators
// cannot accidentally assign IPv6 to nullip or IPv4 to nullip6.
//
// This test covers the plugin setup validation for sinkhole address families.
//
// It asserts that parseConfig returns a descriptive error for each invalid
// family mismatch.
func TestParseConfigRejectsWrongNullIPAddressFamilies(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name: "rejects IPv6 for nullip",
			input: `filterlist {
						denylist_dir /tmp/blacklist
						nullip ::
					}`,
			want: "expected IPv4",
		},
		{
			name: "rejects IPv4 for nullip6",
			input: `filterlist {
				denylist_dir /tmp/blacklist
				nullip6 0.0.0.0
			}`,
			want: "expected IPv6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tt.input)
			_, err := parseConfig(c)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseConfig error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

// TestParseConfigAcceptsValidFamiliesAndPositiveDurations verifies that valid
// sinkhole addresses and timing options survive Corefile parsing unchanged.
//
// This test covers the plugin setup happy path for address and duration
// directives.
//
// It asserts that parseConfig stores the provided IPs, limits, and TTL values
// in the resulting Config.
func TestParseConfigAcceptsValidFamiliesAndPositiveDurations(t *testing.T) {
	c := caddy.NewTestController("dns", `filterlist {
		allowlist_dir /tmp/whitelist
		denylist_dir /tmp/blacklist
		action nullip
		nullip 0.0.0.0
		nullip6 ::
		debounce 500ms
		compile_timeout 10s
		max_states 1234
		ttl 42
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	if got := cfg.Action.NullIPv4.String(); got != "0.0.0.0" {
		t.Fatalf("NullIPv4 = %s, want 0.0.0.0", got)
	}
	if got := cfg.Action.NullIPv6.String(); got != "::" {
		t.Fatalf("NullIPv6 = %s, want ::", got)
	}
	if cfg.Debounce <= 0 || cfg.CompileTimeout <= 0 {
		t.Fatal("expected positive debounce and compile timeout")
	}
	if cfg.MaxStates != 1234 {
		t.Fatalf("MaxStates = %d, want 1234", cfg.MaxStates)
	}
	if cfg.Action.TTL != 42 {
		t.Fatalf("TTL = %d, want 42", cfg.Action.TTL)
	}
}

// TestParseConfigMaxStatesAllowsUncapped verifies that administrators can
// explicitly disable DFA state capping by setting max_states to zero.
//
// This test covers the plugin setup parsing path for DFA resource limits.
//
// It asserts that parseConfig accepts max_states 0 and stores it unchanged.
func TestParseConfigMaxStatesAllowsUncapped(t *testing.T) {
	c := caddy.NewTestController("dns", `filterlist {
		denylist_dir /tmp/blacklist
		max_states 0
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	if cfg.MaxStates != 0 {
		t.Fatalf("MaxStates = %d, want 0", cfg.MaxStates)
	}
}

// TestParseConfigRejectsNegativeMaxStates verifies that administrators get a
// validation error when max_states is configured below zero.
//
// This test covers numeric validation in the plugin setup parser.
//
// It asserts that parseConfig rejects negative values for max_states.
func TestParseConfigRejectsNegativeMaxStates(t *testing.T) {
	c := caddy.NewTestController("dns", `filterlist {
		denylist_dir /tmp/blacklist
		max_states -1
	}`)

	_, err := parseConfig(c)
	if err == nil {
		t.Fatal("expected parseConfig error for negative max_states")
	}
}

// TestParseConfigRejectsNonPositiveDurations verifies that administrators get a
// fast validation error for zero or negative timing knobs.
//
// This test covers the plugin setup validation for debounce and compile
// timeout directives.
//
// It asserts that parseConfig rejects non-positive durations instead of
// accepting them silently.
func TestParseConfigRejectsNonPositiveDurations(t *testing.T) {
	tests := []struct {
		name      string
		directive string
	}{
		{name: "rejects zero debounce", directive: "debounce 0s"},
		{name: "rejects negative compile timeout", directive: "compile_timeout -1s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", "filterlist {\ndenylist_dir /tmp/blacklist\n"+tt.directive+"\n}")
			_, err := parseConfig(c)
			if err == nil {
				t.Fatal("expected parseConfig error")
			}
		})
	}
}

// TestParseConfigDebugDirective verifies that operators can enable per-query
// debug output by adding the debug keyword to the filterlist Corefile block.
//
// This test covers the plugin Corefile parsing path for the debug directive.
//
// It asserts that debug=false by default, and debug=true when the keyword is
// present.
func TestParseConfigDebugDirective(t *testing.T) {
	// Without debug
	c := caddy.NewTestController("dns", `filterlist { denylist_dir /tmp/bl }`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	if cfg.Debug {
		t.Error("expected Debug=false by default")
	}

	// With debug
	c = caddy.NewTestController("dns", `filterlist {
		denylist_dir /tmp/bl
		debug
	}`)
	cfg, err = parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	if !cfg.Debug {
		t.Error("expected Debug=true when debug directive is present")
	}
}

// TestParseConfigInvertWhitelistDirective verifies that operators can switch
// whitelist rule selection to use ||domain^ syntax instead of @@ by adding the
// invert_whitelist keyword to the filterlist Corefile block.
//
// This test covers the plugin Corefile parsing path for the invert_whitelist
// directive.
//
// It asserts that InvertWhitelist is false by default and true when the keyword
// is present.
func TestParseConfigInvertWhitelistDirective(t *testing.T) {
	c := caddy.NewTestController("dns", `filterlist { denylist_dir /tmp/bl }`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	if cfg.InvertAllowlist {
		t.Error("expected InvertAllowlist=false by default")
	}

	c = caddy.NewTestController("dns", `filterlist {
		denylist_dir /tmp/bl
		invert_allowlist
	}`)
	cfg, err = parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	if !cfg.InvertAllowlist {
		t.Error("expected InvertAllowlist=true when directive is present")
	}
}

// TestPluginOrderWarning verifies that operators get a clear startup warning
// when filterlist is configured behind forward and would never see live DNS
// queries.
//
// This test covers the CoreDNS handler-order validation helper used during
// plugin startup.
//
// It asserts that the helper warns only when forward appears before filterlist
// in the execution chain.
func TestPluginOrderWarning(t *testing.T) {
	tests := []struct {
		name     string
		handlers []plugin.Handler
		wantWarn bool
	}{
		{
			name: "warns when forward precedes filterlist",
			handlers: []plugin.Handler{
				namedHandler{name: "errors"},
				namedHandler{name: "forward"},
				namedHandler{name: "filterlist"},
			},
			wantWarn: true,
		},
		{
			name: "stays quiet when filterlist precedes forward",
			handlers: []plugin.Handler{
				namedHandler{name: "errors"},
				namedHandler{name: "filterlist"},
				namedHandler{name: "forward"},
			},
			wantWarn: false,
		},
		{
			name: "stays quiet when forward is absent",
			handlers: []plugin.Handler{
				namedHandler{name: "errors"},
				namedHandler{name: "filterlist"},
			},
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pluginOrderWarning(tt.handlers)
			if tt.wantWarn && got == "" {
				t.Fatal("expected warning, got none")
			}
			if !tt.wantWarn && got != "" {
				t.Fatalf("expected no warning, got %q", got)
			}
		})
	}
}
