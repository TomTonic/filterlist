# coredns-regfilter

`coredns-regfilter` is a CoreDNS plugin that filters DNS queries against a hybrid matching engine built from allowlist and denylist filter lists. It is designed for DNS-layer blocking of domain-based rules with predictable lookup latency and live reload support.

The plugin loads host-oriented rules from supported filter list formats, splits them into literal domain patterns (stored in a hash-based suffix map) and wildcard patterns (compiled into a minimized DFA), and evaluates each DNS question in this order:

1. Normalize the queried name.
2. Check the allowlist matcher first.
3. Check the denylist matcher second.
4. Forward or block based on the configured action.

That makes whitelist precedence explicit and keeps per-query matching on the hot path inexpensive.

## Features

- **Filter list support**: Parses AdGuard, EasyList, and hosts-style filter lists
- **Hybrid matching**: O(k) suffix map for literal domains, O(n) DFA for wildcards
- **Hot reload**: Watches filter list directories and recompiles matchers on changes
- **Whitelist precedence**: Whitelisted domains are always allowed, even if blacklisted
- **Multiple block actions**: NXDOMAIN, REFUSE, or null IP responses
- **Observability**: Prometheus metrics and structured logging
- **CLI tool**: Offline validation, matching, and DOT graph export

-## How It Works

- Filter files are read from dedicated allowlist and denylist directories.
- Supported rules are split into literal domains (suffix map) and wildcards (DFA).
- The active matchers are swapped atomically after a successful recompilation.
- Filesystem changes trigger debounced recompilation, so updates can be applied without restarting CoreDNS.

This project intentionally focuses on DNS-relevant host matching. Browser-only rule semantics such as cosmetic filtering, request-type modifiers, or path-based matching are out of scope.

## Quick Start

### Build

To use `regfilter` in production, build a custom CoreDNS binary that includes this plugin.

1. Clone the CoreDNS repository and enter it.
2. Add the `coredns-regfilter` module as a dependency.
3. Register `regfilter` in `plugin.cfg` **before** `forward` so it is inserted earlier in the CoreDNS plugin chain.
4. Regenerate the generated plugin glue.
5. Build CoreDNS.

Example:

```bash
git clone https://github.com/coredns/coredns.git
cd coredns

go get github.com/TomTonic/coredns-regfilter@latest
```

Then edit `plugin.cfg` and add this line before `forward`:

```txt
regfilter:github.com/TomTonic/coredns-regfilter
```

The important order is the CoreDNS plugin chain generated from `plugin.cfg`, not the order in which Go downloads modules and not the stanza order in the Corefile. `go get` only makes the module available to the build. `regfilter` must be listed before `forward` in `plugin.cfg` so the generated handler chain reaches `regfilter` before `forward` answers the query.

After updating `plugin.cfg`, regenerate and build:

```bash
go generate
go build
```

This produces a `coredns` binary that includes the `regfilter` plugin.

### Build the CLI Helper

```bash
go build -o build/regfilter-check ./cmd/regfilter-check
```

This produces the helper CLI at `./build/regfilter-check`. The CLI is optional and useful for validating lists and debugging rule behavior outside of CoreDNS.

### Corefile Configuration

```
. {
  prometheus :9153

  regfilter {
    allowlist_dir /etc/coredns/allowlist.d
    denylist_dir /etc/coredns/denylist.d
    action nxdomain
    debounce 300ms
    max_states 200000
  }

  forward . 8.8.8.8
}
```

In that configuration:

- `prometheus` exposes the metrics described below.
- `regfilter` evaluates queries before they are forwarded upstream.
- `allowlist_dir` takes precedence over `denylist_dir` when the same domain matches both sets.

### CLI Tool

```bash
# Validate filter lists
./build/regfilter-check validate --allowlist testdata/filterlists/allowlist --denylist testdata/filterlists/denylist

# Check a specific domain
./build/regfilter-check match --denylist testdata/filterlists/denylist --name ads.example.com

# Export DFA as DOT graph
./build/regfilter-check dump-dot --denylist testdata/filterlists/denylist --out allowlist.dot,denylist.dot
```

The CLI is useful for validating large lists before deploying them into CoreDNS, checking whether a particular name matches, and inspecting the generated automata when you need to troubleshoot rule behavior.

## Supported Filter Syntax

| Syntax | Example | Description |
|--------|---------|-------------|
| Domain filter | `\|\|example.com^` | Block domain and all subdomains |
| Exception | `@@\|\|example.com^` | Allow rule (used for allowlist entries; excluded from denylist) |
| Wildcard | `\|\|*.ads.example.com^` | Block subdomain pattern (compiled into DFA) |
| Hosts entry | `0.0.0.0 example.com` | Block via hosts format |

The supported subset is intentionally conservative. If a rule cannot be reduced to a domain-level decision at DNS time, it is skipped rather than partially interpreted.

## ABP, EasyList, and AdGuard Compatibility

This project intentionally implements a strict, DNS-oriented subset of Adblock Plus, EasyList, and AdGuard syntax. The parser is designed to extract host-based network rules that can be matched at the DNS layer. It does not attempt full browser-side filter semantics.

### Supported subset

| Rule family | Accepted examples | Behavior in `coredns-regfilter` |
|-------------|-------------------|----------------------------------|
| Basic host-based blocking rules | `\|\|example.com^`, `\|\|sub.example.com^` | Parsed into blocking domain patterns |
| Exception rules | `@@\|\|example.com^`, `@@example.com` | Parsed into allow rules; allowlist wins over denylist |
| Host wildcards | `\|\|*.ads.example.com^`, `\|\|ads*.example.com^` | Preserved as wildcard domain patterns |
| Hosts file entries | `0.0.0.0 example.com`, `127.0.0.1 example.com` | Parsed as blocking rules |
| Selected no-op modifiers | `\|\|example.com^$important`, `\|\|example.com^$document`, `\|\|example.com^$all`, `\|\|example.com^$third-party` | Domain part is kept; modifier semantics are ignored |

### Skipped and logged

| Rule family | Real-world examples | Why it is unsupported |
|-------------|---------------------|------------------------|
| Cosmetic rules | `##.banner`, `example.com#@#.sponsor`, `example.com#?#div:has(.ad)` | These are browser DOM rules, not DNS host rules |
| Scriptlet and JS rules | `#%#//scriptlet('abort-on-property-read', 'alert')` | Requires browser runtime behavior |
| HTML filtering rules | `$$script[tag-content="banner"]` | Operates on HTML bodies, not DNS names |
| Path and URL rules | `\|\|example.com/path^`, `/ads/banner` | Cannot be reduced to a pure domain decision |
| Semantics-changing network modifiers | `\|\|example.com^$script`, `\|\|example.com^$domain=foo.com`, `@@\|\|example.com^$xmlhttprequest` | Request context is unavailable in DNS matching |
| Genericblock and generichide exceptions | `@@\|\|example.com^$genericblock`, `@@\|\|example.com^$generichide` | Browser filter-engine concepts, not DNS policy |

### Real-world examples covered by tests

The repository includes stricter regression tests against:

- `testdata/filterlists/Adguard_filter_example.txt`
- `testdata/filterlists/easylistgermany_example.txt`

Those tests assert that:

- supported host-based network rules are parsed from large real-world lists;
- unsupported ABP and EasyList rule families are logged as unsupported instead of being treated as comments;
- real exception rules that fit the supported subset are recognized as allow rules;
- rules that depend on browser request context remain intentionally excluded.

### Unsupported (logged and skipped)

- Non-network rules (`##`, `#@#`, `#?#`, `#$#`, `#%#`, `$$`)
- Advanced modifiers with browser request semantics (`$script`, `$domain=`, `$xmlhttprequest`)
- Path-only rules without hostnames

## Configuration Reference

| Directive | Default | Description |
|-----------|---------|-------------|
| `allowlist_dir` | (none) | Directory containing allowlist filter files |
| `denylist_dir` | (none) | Directory containing denylist filter files |
| `action` | `nxdomain` | Block action: `nxdomain`, `nullip`, `refuse` |
| `nullip` | `0.0.0.0` | IPv4 address for `nullip` action |
| `nullip6` | `::` | IPv6 address for `nullip` action |
| `debounce` | `300ms` | Debounce duration for file change events |
| `max_states` | `200000` | Maximum wildcard DFA states (limits memory) |
| `compile_timeout` | `30s` | Maximum compile duration |
| `ttl` | `3600` | TTL for blocked responses (nullip) |
| `debug` | `false` | Log per-query match details (list, name, rule source, pattern) |
| `invert_allowlist` | `false` | Use `\|\|domain^` instead of `@@\|\|domain^` for allowlist entries |

### Configuration Notes

- At least one of `allowlist_dir` or `denylist_dir` must be configured.
- Allowlist and denylist files use the same filter syntax. The `@@` exception prefix controls which rules are compiled for each directory:
  - **Denylist directories** always exclude `@@`-prefixed rules. Downloaded AdGuard and EasyList files work without conversion — exception rules embedded in those lists are automatically skipped.
  - **Allowlist directories** by default compile only `@@`-prefixed rules (AdGuard semantics: `@@` = allow). Write `@@||safe.example.com^` to allowlist a domain.
  - With `invert_allowlist`, allowlist directories compile non-`@@` rules instead, so you can write `||safe.example.com^` to allowlist a domain.
- Startup stays fail-open if configured directories are unreadable, empty, or contain only unsupported rules.
- Every initial load and hot-reload writes a detailed compile summary to the CoreDNS log, including directory, outcome, rule count, state count, duration, and any error.
- `action nxdomain` returns NXDOMAIN for blocked queries.
- `action refuse` returns REFUSED for blocked queries.
- `action nullip` returns synthetic `A` and `AAAA` answers for address lookups, and falls back to NXDOMAIN for other query types.
- `nullip` configures the IPv4 sinkhole address.
- `nullip6` configures the IPv6 sinkhole address.
- `ttl` is only relevant for `nullip` answers.
- `debounce`, `max_states`, and `compile_timeout` are operational safeguards for large or volatile filter sets.
- `debug` enables per-query log lines showing the matching list (allowlist or denylist), the queried name, the source file and line number, and the original rule pattern. Useful for verifying that rules behave as expected. The output appears at the `[INFO]` level in the CoreDNS log.

## Query Flow

1. Normalize query name (lowercase, remove trailing dot)
2. Check allowlist matcher → if match, **allow** (forward to next plugin)
3. Check denylist matcher → if match, **block** according to action
4. No match → forward to next plugin

## Metrics

All metrics are exported with the `coredns_regfilter_` prefix through the CoreDNS Prometheus endpoint.

### Counters and Gauges

| Metric | Type | Description |
|--------|------|-------------|
| `coredns_regfilter_allowlist_checks_total` | Counter | Number of queries evaluated against the allowlist matcher |
| `coredns_regfilter_denylist_checks_total` | Counter | Number of queries evaluated against the denylist matcher |
| `coredns_regfilter_allowlist_hits_total` | Counter | Number of queries accepted because the allowlist matched |
| `coredns_regfilter_denylist_hits_total` | Counter | Number of queries blocked because the denylist matched |
| `coredns_regfilter_compile_errors_total` | Counter | Number of failed filter load or compile runs |
| `coredns_regfilter_allowlist_rules` | Gauge | Current number of supported allowlist rules loaded into the active snapshot |
| `coredns_regfilter_denylist_rules` | Gauge | Current number of supported denylist rules loaded into the active snapshot |
| `coredns_regfilter_last_compile_timestamp_seconds` | Gauge | Unix timestamp of the most recent successful compilation |
| `coredns_regfilter_last_compile_duration_seconds` | Gauge | Duration in seconds of the most recent successful compilation |

### Histograms and Summaries

| Metric | Type | Description |
|--------|------|-------------|
| `coredns_regfilter_compile_duration_seconds` | Histogram | Distribution of matcher compilation durations across reloads |
| `coredns_regfilter_match_duration_seconds` | Summary | Distribution of query matching latency, labeled by result |

### `match_duration_seconds` Labels

The `coredns_regfilter_match_duration_seconds` summary uses a `result` label with the following values:

| Label value | Meaning |
|-------------|---------|
| `accept` | The query matched the allowlist and was passed to the next plugin |
| `reject` | The query matched the denylist and was blocked |
| `pass` | No rule matched and the query was forwarded unchanged |

### Interpreting the Metrics

- Use `allowlist_checks_total` and `denylist_checks_total` as the denominator when you want match ratios per automaton.
- Use `allowlist_hits_total` and `denylist_hits_total` to understand policy decisions over time.
- Use `compile_duration_seconds` and `last_compile_duration_seconds` to spot slow reloads.
- Use `last_compile_timestamp_seconds` to verify that file changes are being picked up.
- Use `match_duration_seconds` to watch lookup overhead on the request path.
- The `allowlist_rules` and `denylist_rules` gauges reflect the currently active parsed rule counts after reload, which is more useful operationally than just counting raw source lines.

Typical Prometheus ratios look like this:

```promql
rate(coredns_regfilter_allowlist_hits_total[5m])
/
rate(coredns_regfilter_allowlist_checks_total[5m])
```

```promql
rate(coredns_regfilter_denylist_hits_total[5m])
/
rate(coredns_regfilter_denylist_checks_total[5m])
```

## Development

```bash
# Run tests
go test ./... -count=1

# Run tests with race detector
go test ./... -race -count=1

# Run linter
golangci-lint run ./...

# Generate coverage report
go test ./... -race -coverprofile=coverage.out -covermode=atomic
go tool cover -html=coverage.out -o coverage.html

# Run benchmarks
go test -bench=. -benchmem ./pkg/automaton ./pkg/filterlist
```

## Architecture

See [DESIGN.md](docs/DESIGN.md) for detailed architecture documentation.

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
