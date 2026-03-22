# coredns-regfilter

A CoreDNS plugin that filters DNS queries using compiled DFA (Deterministic Finite Automaton) matching against whitelist and blacklist filter lists.

## Features

- **Filter list support**: Parses AdGuard, EasyList, and hosts-style filter lists
- **DFA-based matching**: O(n) matching per query via compiled, minimized DFAs
- **Hot reload**: Watches filter list directories and recompiles DFAs on changes
- **Whitelist precedence**: Whitelisted domains are always allowed, even if blacklisted
- **Multiple block actions**: NXDOMAIN, REFUSE, or null IP responses
- **Observability**: Prometheus metrics and structured logging
- **CLI tool**: Offline validation, matching, and DOT graph export

## Quick Start

### Build

```bash
make build
```

### Corefile Configuration

```
. {
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

### CLI Tool

```bash
# Validate filter lists
./build/regfilter-check validate --whitelist testdata/filterlists/whitelist --blacklist testdata/filterlists/blacklist

# Check a specific domain
./build/regfilter-check match --blacklist testdata/filterlists/blacklist --name ads.example.com

# Export DFA as DOT graph
./build/regfilter-check dump-dot --blacklist testdata/filterlists/blacklist --out whitelist.dot,blacklist.dot
```

## Supported Filter Syntax

| Syntax | Example | Description |
|--------|---------|-------------|
| Domain filter | `\|\|example.com^` | Block exact domain |
| Exception | `@@\|\|example.com^` | Whitelist domain |
| Wildcard | `\|\|*.ads.example.com^` | Block subdomain pattern |
| Hosts entry | `0.0.0.0 example.com` | Block via hosts format |

### Unsupported (logged and skipped)

- CSS selectors (`##`, `#@#`)
- Scriptlets and advanced modifiers (`$script`, `$domain=`)
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

## Query Flow

1. Normalize query name (lowercase, remove trailing dot)
2. Check whitelist DFA → if match, **allow** (forward to next plugin)
3. Check blacklist DFA → if match, **block** according to action
4. No match → forward to next plugin

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `coredns_regfilter_whitelist_hits_total` | Counter | Whitelist matches |
| `coredns_regfilter_blacklist_hits_total` | Counter | Blacklist matches |
| `coredns_regfilter_compile_errors_total` | Counter | Compile failures |
| `coredns_regfilter_compile_duration_seconds` | Histogram | Compile time |
| `coredns_regfilter_whitelist_rules_total` | Gauge | Current whitelist rule count |
| `coredns_regfilter_blacklist_rules_total` | Gauge | Current blacklist rule count |

## Development

```bash
# Run tests
make test

# Run tests with race detector
make test-race

# Run linter
make lint

# Generate coverage report
make cover

# Run benchmarks
make bench
```

## Architecture

See [DESIGN.md](docs/DESIGN.md) for detailed architecture documentation.

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
