package plugin

import (
	"strings"
	"testing"

	"github.com/coredns/caddy"
)

// TestParseConfigRequiresAtLeastOneFilterDirectory verifies that operators get
// a configuration error instead of a no-op plugin when no filter directory is set.
//
// This test covers the plugin Corefile parsing and validation path.
//
// It asserts that parseConfig rejects a regfilter block without whitelist_dir
// or blacklist_dir.
func TestParseConfigRequiresAtLeastOneFilterDirectory(t *testing.T) {
	c := caddy.NewTestController("dns", `regfilter { action nxdomain }`)

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
			input: `regfilter {
				blacklist_dir /tmp/blacklist
				nullip ::
			}`,
			want: "expected IPv4",
		},
		{
			name: "rejects IPv4 for nullip6",
			input: `regfilter {
				blacklist_dir /tmp/blacklist
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
	c := caddy.NewTestController("dns", `regfilter {
		whitelist_dir /tmp/whitelist
		blacklist_dir /tmp/blacklist
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
			c := caddy.NewTestController("dns", "regfilter {\nblacklist_dir /tmp/blacklist\n"+tt.directive+"\n}")
			_, err := parseConfig(c)
			if err == nil {
				t.Fatal("expected parseConfig error")
			}
		})
	}
}
