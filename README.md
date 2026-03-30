# coredns-regfilter

`coredns-regfilter` is a CoreDNS plugin that filters DNS queries against compiled deterministic finite automata (DFAs) built from whitelist and blacklist filter lists. It is designed for DNS-layer blocking of domain-based rules with predictable lookup latency and live reload support.

The plugin loads host-oriented rules from supported filter list formats, compiles them into DFAs, and evaluates each DNS question in this order:

1. Normalize the queried name.
2. Check the whitelist DFA first.
3. Check the blacklist DFA second.
4. Forward or block based on the configured action.

That makes whitelist precedence explicit and keeps per-query matching on the hot path inexpensive.

## Features

- **Filter list support**: Parses AdGuard, EasyList, and hosts-style filter lists
- **DFA-based matching**: O(n) matching per query via compiled, minimized DFAs
- **Hot reload**: Watches filter list directories and recompiles DFAs on changes
- **Whitelist precedence**: Whitelisted domains are always allowed, even if blacklisted
- **Multiple block actions**: NXDOMAIN, REFUSE, or null IP responses
- **Observability**: Prometheus metrics and structured logging
- **CLI tool**: Offline validation, matching, and DOT graph export

## How It Works

- Filter files are read from dedicated whitelist and blacklist directories.
- Supported rules are normalized into domain patterns and compiled into DFAs.
- The active DFAs are swapped atomically after a successful recompilation.
- Filesystem changes trigger debounced recompilation, so updates can be applied without restarting CoreDNS.

This project intentionally focuses on DNS-relevant host matching. Browser-only rule semantics such as cosmetic filtering, request-type modifiers, or path-based matching are out of scope.

## Quick Start

### Build

```bash
go build -o build/regfilter-check ./cmd/regfilter-check
```

This produces the helper CLI at `./build/regfilter-check`. If you are integrating the plugin into a custom CoreDNS build, make sure the `regfilter` plugin is included in that binary.

### Corefile Configuration

```
. {
    prometheus :9153

    regfilter {
        whitelist_dir /etc/coredns/whitelist.d
        blacklist_dir /etc/coredns/blacklist.d
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
- `whitelist_dir` takes precedence over `blacklist_dir` when the same domain matches both sets.

### CLI Tool

```bash
# Validate filter lists
./build/regfilter-check validate --whitelist testdata/filterlists/whitelist --blacklist testdata/filterlists/blacklist

# Check a specific domain
./build/regfilter-check match --blacklist testdata/filterlists/blacklist --name ads.example.com

# Export DFA as DOT graph
./build/regfilter-check dump-dot --blacklist testdata/filterlists/blacklist --out whitelist.dot,blacklist.dot
```

The CLI is useful for validating large lists before deploying them into CoreDNS, checking whether a particular name matches, and inspecting the generated automata when you need to troubleshoot rule behavior.

## Supported Filter Syntax

| Syntax | Example | Description |
|--------|---------|-------------|
| Domain filter | `\|\|example.com^` | Block exact domain |
| Exception | `@@\|\|example.com^` | Whitelist domain |
| Wildcard | `\|\|*.ads.example.com^` | Block subdomain pattern |
| Hosts entry | `0.0.0.0 example.com` | Block via hosts format |

The supported subset is intentionally conservative. If a rule cannot be reduced to a domain-level decision at DNS time, it is skipped rather than partially interpreted.

## ABP, EasyList, and AdGuard Compatibility

This project intentionally implements a strict, DNS-oriented subset of Adblock Plus, EasyList, and AdGuard syntax. The parser is designed to extract host-based network rules that can be compiled into DFAs for domain matching. It does not attempt full browser-side filter semantics.

### Supported subset

| Rule family | Accepted examples | Behavior in `coredns-regfilter` |
|-------------|-------------------|----------------------------------|
| Basic host-based blocking rules | `\|\|example.com^`, `\|\|sub.example.com^` | Parsed into blocking domain patterns |
| Exception rules | `@@\|\|example.com^`, `@@example.com` | Parsed into allow rules; whitelist wins over blacklist |
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
| `whitelist_dir` | (none) | Directory containing whitelist filter files |
| `blacklist_dir` | (none) | Directory containing blacklist filter files |
| `action` | `nxdomain` | Block action: `nxdomain`, `nullip`, `refuse` |
| `nullip` | `0.0.0.0` | IPv4 address for `nullip` action |
| `nullip6` | `::` | IPv6 address for `nullip` action |
| `debounce` | `300ms` | Debounce duration for file change events |
| `max_states` | `200000` | Maximum DFA states (limits memory) |
| `compile_timeout` | `30s` | Maximum compile duration |
| `ttl` | `3600` | TTL for blocked responses (nullip) |

### Configuration Notes

- At least one of `whitelist_dir` or `blacklist_dir` should point to a directory with readable filter files.
- `action nxdomain` returns NXDOMAIN for blocked queries.
- `action refuse` returns REFUSED for blocked queries.
- `action nullip` returns synthetic `A` and `AAAA` answers for address lookups, and falls back to NXDOMAIN for other query types.
- `nullip` configures the IPv4 sinkhole address.
- `nullip6` configures the IPv6 sinkhole address.
- `ttl` is only relevant for `nullip` answers.
- `debounce`, `max_states`, and `compile_timeout` are operational safeguards for large or volatile filter sets.

## Query Flow

1. Normalize query name (lowercase, remove trailing dot)
2. Check whitelist DFA → if match, **allow** (forward to next plugin)
3. Check blacklist DFA → if match, **block** according to action
4. No match → forward to next plugin

## Metrics

All metrics are exported with the `coredns_regfilter_` prefix through the CoreDNS Prometheus endpoint.

### Counters and Gauges

| Metric | Type | Description |
|--------|------|-------------|
| `coredns_regfilter_whitelist_checks_total` | Counter | Number of queries evaluated against the whitelist DFA |
| `coredns_regfilter_blacklist_checks_total` | Counter | Number of queries evaluated against the blacklist DFA |
| `coredns_regfilter_whitelist_hits_total` | Counter | Number of queries accepted because the whitelist DFA matched |
| `coredns_regfilter_blacklist_hits_total` | Counter | Number of queries blocked because the blacklist DFA matched |
| `coredns_regfilter_compile_errors_total` | Counter | Counter reserved for DFA compile failures |
| `coredns_regfilter_whitelist_rules` | Gauge | Current size of the compiled whitelist automaton, updated on reload |
| `coredns_regfilter_blacklist_rules` | Gauge | Current size of the compiled blacklist automaton, updated on reload |
| `coredns_regfilter_last_compile_timestamp_seconds` | Gauge | Unix timestamp of the most recent successful compilation |
| `coredns_regfilter_last_compile_duration_seconds` | Gauge | Duration in seconds of the most recent successful compilation |

### Histograms and Summaries

| Metric | Type | Description |
|--------|------|-------------|
| `coredns_regfilter_compile_duration_seconds` | Histogram | Distribution of DFA compilation durations across reloads |
| `coredns_regfilter_match_duration_seconds` | Summary | Distribution of query matching latency, labeled by result |

### `match_duration_seconds` Labels

The `coredns_regfilter_match_duration_seconds` summary uses a `result` label with the following values:

| Label value | Meaning |
|-------------|---------|
| `accept` | The query matched the whitelist and was passed to the next plugin |
| `reject` | The query matched the blacklist and was blocked |
| `pass` | No rule matched and the query was forwarded unchanged |

### Interpreting the Metrics

- Use `whitelist_checks_total` and `blacklist_checks_total` as the denominator when you want match ratios per automaton.
- Use `whitelist_hits_total` and `blacklist_hits_total` to understand policy decisions over time.
- Use `compile_duration_seconds` and `last_compile_duration_seconds` to spot slow reloads.
- Use `last_compile_timestamp_seconds` to verify that file changes are being picked up.
- Use `match_duration_seconds` to watch lookup overhead on the request path.
- The `whitelist_rules` and `blacklist_rules` gauges reflect the currently compiled automata after reload, which is more useful operationally than just counting raw source lines.

Typical Prometheus ratios look like this:

```promql
rate(coredns_regfilter_whitelist_hits_total[5m])
/
rate(coredns_regfilter_whitelist_checks_total[5m])
```

```promql
rate(coredns_regfilter_blacklist_hits_total[5m])
/
rate(coredns_regfilter_blacklist_checks_total[5m])
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
