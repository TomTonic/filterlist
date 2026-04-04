# Design Document

## Overview

`filterlist` is a CoreDNS plugin for DNS-layer domain filtering. It
loads supported host-based rules from whitelist and blacklist directories,
compiles them into a matching structure, and evaluates DNS queries against
that structure on the request path.

By default the matcher uses a hybrid structure and splits rules at compile time:

- **Literal domain patterns** (typically 99%+ of real-world rules) are stored
  in a hash-based suffix map for O(k) lookup, where k is the number of DNS
  labels in the query name.
- **Wildcard patterns** (those containing `*`) are compiled into a minimized
  deterministic finite automaton (DFA) for O(n) matching, where n is the query
  name length.

This split keeps compilation fast and memory bounded for lists that are
dominated by literal entries, while retaining full wildcard support through the
DFA path.

When `matcher_mode dfa` is enabled, the plugin compiles every rule into a
single DFA instead. Literal domain rules are expanded into an exact-match DFA
pattern and a subdomain DFA pattern (`*.example.com`) so the pure-DFA mode
preserves the same `||domain^` semantics as the default suffix-map path.

The design goal is not to implement a full browser filter engine. The plugin
focuses on the subset of AdGuard, EasyList, and hosts-style syntax that can be
reduced to a pure domain decision at DNS time.

The most important properties are:

- predictable matching on the request path (O(k) for literals, O(n) for wildcards);
- atomic hot reloads without locking the hot path;
- fail-open behavior when a reload fails or a directory is temporarily broken;
- enough source metadata to explain matches in logs and offline tooling.

## Architectural Focus

This document focuses on the runtime system behavior:

- how the plugin is inserted into the CoreDNS handler chain;
- how rules flow from files into compiled snapshots;
- how whitelist and blacklist semantics are derived from directory context;
- how reload failures, empty lists, and debug output are handled.

The internal construction details of the suffix map and DFA still matter, but
they are implementation mechanisms rather than the primary architectural story.

## Package Architecture

The matching subsystem is organized into three packages with strict dependency
directions:

```text
pkg/matcher          (compositor)
    ├── pkg/suffixmap    (literal domain lookup, no external deps)
    └── pkg/automaton    (wildcard DFA, no external deps)
```

- **`pkg/automaton`** is a self-contained DFA compiler and matcher. It accepts
  `automaton.Pattern` values (expression string + rule ID), builds a Thompson
  NFA, runs subset construction, optionally applies Hopcroft minimization, and
  produces an array-based DFA. It has no dependency on filter list parsing or
  the suffix map.

- **`pkg/suffixmap`** is a hash-based lookup structure for literal domain
  patterns implementing `||domain^` semantics: a stored entry `example.com`
  matches both `example.com` and any subdomain like `sub.example.com`. It has
  no dependency on the automaton or filter list parsing.

- **`pkg/matcher`** is the compositor that callers use. It receives parsed
  `listparser.Rule` values and either:
  - in `matcher_mode hybrid`, classifies them as literal or wildcard, delegates
    to `suffixmap.New` and `automaton.Compile`, and combines the results behind
    a single `Matcher.Match` method;
  - in `matcher_mode dfa`, expands literal suffix rules into DFA-safe patterns
    and compiles the full set through `automaton.Compile`.

The watcher, plugin handler, and CLI tool all depend on `pkg/matcher` only.
They do not import `pkg/automaton` or `pkg/suffixmap` directly.

## Runtime Architecture

```text
query
       |
       v
filterlist ServeDNS
       |
       +--> whitelist snapshot -> match? yes -> next plugin
       |
       +--> deny_non_allowlisted (if enabled) -> block
       |
       +--> RFC / IDNA precheck (if disable_RFC_checks=false) -> block
       |
       +--> blacklist snapshot -> match? yes -> blocked response
       |
       +--> no match -> next plugin

watcher
       |
       +--> fsnotify + debounce
       |
       +--> LoadDirectory
       |
       +--> rule selection
       |      - blacklist: keep deny rules only
       |      - whitelist: keep allow rules by default
       |      - whitelist + invert_whitelist: keep deny-style rules
       |
      +--> CompileRules  (hybrid: literals → suffix map, wildcards → DFA; dfa: all rules → DFA)
       |
       +--> Snapshot{Matcher, rule count, state count, sources, patterns}
       |
       +--> atomic swap of active whitelist / blacklist snapshots
```

Two details are easy to miss but central to the design:

- `filterlist` only sees queries if it appears early enough in the generated CoreDNS plugin chain, and in practice it must run before terminal plugins such as `forward`.
- The runtime does not swap raw matchers alone; it swaps a snapshot that also carries rule count, source file references, and original patterns for logging and diagnostics.

## CoreDNS Integration

The plugin is configured from a Corefile stanza, but the effective execution
order comes from the generated CoreDNS plugin chain derived from `plugin.cfg`.

That distinction matters because:

- Corefile stanza order does not control which plugin runs first;
- `filterlist` must be inserted before `forward` in the generated chain;
- if `forward` runs first, `filterlist` may initialize successfully but never see live queries, so it cannot filter or emit per-query debug logs.

The plugin emits a startup warning when it detects that `forward` appears
before `filterlist` in the constructed handler chain.

## Compatibility

This plugin is intended to follow CoreDNS plugin development guidelines and
relevant DNS name standards to ensure interoperability. In particular, the
project follows the CoreDNS plugin guidance and documentation:

- https://coredns.io/2017/03/01/how-to-add-plugins-to-coredns/
- https://github.com/coredns/coredns/blob/master/plugin.md#documentation

The implementation also adheres to Internet standards for domain names and
internationalized domain names (IDNA), so parsed and emitted names remain
interoperable with DNS servers and clients. Relevant references include:

- DNS names and message format — RFC 1035
  (https://datatracker.ietf.org/doc/html/rfc1035)
- IDNA / Internationalized Domain Names — RFC 5890–5894 (for example:
  https://datatracker.ietf.org/doc/html/rfc5890)

Parser and normalization behavior (including Punycode/IDNA conversion) should
conform to these standards; any deliberate deviation must be documented and
justified.

When `disable_RFC_checks` is `off` (the default), the denylist phase applies
an RFC 1035 + IDNA Lookup-profile query-name precheck. The precheck uses a
single ASCII scan with nested label loops and two counters (current label
length and total name length) to enforce the 63/253 byte limits and LDH label
rules. It only performs an IDNA round-trip when the scan observes an ACE label
prefix (`xn--`). The check runs after the `deny_non_allowlisted` check and
before denylist matcher lookups.

When `deny_non_allowlisted` is `on`, the denylist phase blocks every allowlist
miss before the RFC precheck and the denylist matcher are consulted.

## Rule Ingestion and Selection

### File Loading

The watcher loads directories non-recursively through `blockloader`.

- supported files are parsed and aggregated;
- unreadable files are logged and skipped;
- unreadable directories cause the directory compile to fail;
- extension filtering happens before parsing.

`blockloader` delegates file parsing to `listparser.ParseFile`, which produces
canonical `listparser.Rule` values.

### Canonical Rule Model

Each parsed rule carries:

- `Pattern`: canonical domain pattern used for automaton compilation;
- `Source`: `path:line` for diagnostics and debug logging;
- `IsAllow`: whether the source rule was an exception rule (`@@...`).

This is important because allow-versus-block semantics are not determined only
by the text of the rule. They are also shaped by the directory being compiled.

### Directory-Specific Semantics

After parsing and before matcher compilation, the watcher filters rules based on
which directory is being compiled.

Blacklist directory:

- only non-allow rules are compiled;
- `@@` exception rules are excluded automatically;
- downloaded AdGuard or EasyList lists work without conversion.

Whitelist directory, default behavior:

- only `@@` exception rules are compiled;
- this follows AdGuard-style semantics where `@@` means allow.

Whitelist directory, `invert_whitelist` enabled:

- non-`@@` rules are compiled instead;
- this allows simpler `||domain^` syntax in whitelist files.

This rule-selection step is a real architectural stage and should be thought of
as part of the compile pipeline, not as a parser detail.

## Compilation Pipeline

For each directory, the watcher executes this pipeline:

1. load and parse all supported files;
2. filter the resulting rules for whitelist or blacklist semantics;
3. compile the selected rules with `matcher.CompileRules`;
4. build a snapshot containing the Matcher, rule count, state count, sources, and patterns;
5. publish the new snapshot atomically if compilation succeeded.

The matcher pipeline depends on `matcher_mode`:

- In `hybrid` mode:

  - Patterns without `*` are lowercased and stored in a hash-based suffix map.
    The suffix map implements `||domain^` semantics: a stored entry `example.com`
    matches both `example.com` itself and any subdomain such as `sub.example.com`.
    Lookup cost is O(k) where k is the number of DNS labels.

  - Patterns containing `*` are compiled through the automaton package:
    Thompson-style NFA construction, subset construction, optional Hopcroft
    minimization, and a cache-friendly array-based DFA for O(n) matching.

- In `dfa` mode:

  - Patterns containing `*` are compiled unchanged.
  - Literal patterns are expanded into two DFA patterns: the exact host itself
    and a `*.`-prefixed variant that covers subdomains without changing the
    original filter semantics.
  - This can reduce request-path lookup time, but it substantially increases
    compile work during startup and hot reloads because every literal rule now
    participates in the automaton pipeline.

That internal pipeline is useful to know, but the externally visible contract
is simpler: a directory compile either yields a new immutable snapshot or the
previous active snapshot remains in place.

## Hot Reload and Failure Model

The watcher listens for filesystem changes, debounces them, and recompiles only
the affected directory snapshot.

```text
fsnotify event -> debounce -> load/parse -> rule selection -> compile -> atomic swap
```

The reload model is intentionally fail-open:

- if a reload fails, the last successful snapshot for that directory stays active;
- if a directory becomes empty or yields no supported rules, that directory's
       active matcher becomes empty for the next successful snapshot;
- startup does not fail just because a configured directory is empty or contains
       only unsupported rules;
- startup fails only when the watcher infrastructure itself cannot be started.

This makes the operational tradeoff explicit: preserve service continuity and
prefer stale-but-known-good policy over blocking DNS because of transient list
problems.

## Query Path

The request path is intentionally short:

1. normalize the queried name to lowercase without the trailing root dot;
2. match against the active whitelist matcher (suffix map first, then DFA);
3. if matched, allow the query to continue to the next plugin;
4. if `strict_name_validation` is enabled, reject names failing RFC/IDNA checks;
5. if `deny_non_allowlisted` is enabled, reject every non-allowlisted name;
6. otherwise match against the active blacklist matcher;
7. if matched, synthesize the configured blocked response;
8. otherwise forward unchanged to the next plugin.

The plugin stores the currently active matcher snapshots in atomic state, so
the hot path performs no lock acquisition.

## Response Modes

Blacklist hits can produce three behaviors:

- `nxdomain`: return NXDOMAIN;
- `refuse`: return REFUSED;
- `nullip`: return synthetic `A` and `AAAA` answers for address lookups and
       NXDOMAIN for other query types.

Whitelist hits never synthesize an answer. They simply permit the query to
continue to the next plugin.

## Debugging and Match Attribution

The design now treats operator visibility as part of the runtime model, not as
an afterthought.

For that reason, the active snapshots retain:

- source file and line information;
- canonical pattern strings.

When `debug` is enabled:

- blacklist matches log the matching list, normalized name, source, and pattern;
- whitelist matches log the same information;
- unmatched queries log `no match`.

This is why the snapshot contains more than just the matcher pointer.

## Resource Limits

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `max_states` | 200000 | Bounds wildcard DFA size to limit memory growth |
| `compile_timeout` | `30s` | Bounds per-directory compile time |
| `debounce` | `300ms` | Coalesces bursts of file changes |
| parser max line length | `8192` bytes | Bounds per-line parse memory and rejects oversized lines |
| parser max lines per file | `200000` | Bounds per-file parse workload and rejects oversized files |

These limits are operational safeguards. They are not intended to make every
pathological filter list safe, but they keep failure modes bounded and visible.

Setting `max_states=0` disables wildcard DFA state capping. The plugin allows
this mode for advanced scenarios and logs a startup warning because memory use
can grow significantly on wildcard-heavy lists.

## Performance Characteristics

- literal matching is O(k) in the number of DNS labels (hash lookups);
- wildcard matching is O(n) in the query name length (DFA traversal);
- the hot path uses immutable snapshots and atomic reads only;
- compile cost for literals is O(m) where m is the number of literal rules;
- compile cost for wildcards depends on the pattern set and DFA minimization;
- memory is dominated by the suffix map entries for literals and the DFA state
  count for wildcards, plus the retained source metadata.

Because real-world filter lists are typically 99%+ literal domain entries,
the suffix map handles the bulk of matching with hash-based lookup. Only the
small wildcard fraction goes through the DFA path. This hybrid approach
combines fast compilation with predictable runtime performance.

### Measured Reference Scenario

The repository contains two realistic upstream-style sample lists in
`testdata/filterlists/Adguard_filter_example.txt` and
`testdata/filterlists/easylistgermany_example.txt`.

Measured together as one blacklist directory on the current development
machine (`linux/amd64`, Go `1.26.1`, AMD Ryzen 9 7900), with blacklist rule
selection applied and `max_states=0` to observe the uncapped compile:

- parsed blacklist rules: 160798
- of those, about 99.8% are literal domain entries and about 0.2% are wildcards
- the literal entries are stored in a hash-based suffix map (fast, bounded memory)
- only the wildcard fraction is compiled through the DFA pipeline

With the hybrid matching approach, the DFA compilation operates on hundreds of
wildcard patterns rather than 160k+ rules. The suffix map handles the literal
bulk in linear time with negligible memory overhead compared to the original
pure-DFA approach.

The original pure-DFA measurement (before the hybrid split) produced:

- compiled DFA states: 2273841
- end-to-end parse plus compile wall-clock time: 4m18.67s
- peak resident memory during that run: 9964356 KiB (about 9.5 GiB)

The hybrid matcher eliminates this bottleneck for typical lists. Two practical
conclusions from the original measurement remain relevant:

- pathological wildcard-heavy lists can still produce large DFAs;
- the `max_states` limit is an important safeguard for the DFA path.

For reproducible benchmarking in the repository, see
`BenchmarkCompileRealisticBlacklist` and
`BenchmarkParseAndCompileRealisticBlacklist` in `realworld_bench_test.go`.

## Metrics and Logging

All metrics are exported with the `coredns_filterlist_` prefix.

### Query Metrics

| Metric | Type | Meaning |
|--------|------|---------|
| `whitelist_checks_total` | Counter | Queries evaluated against the whitelist matcher |
| `blacklist_checks_total` | Counter | Queries evaluated against the blacklist matcher |
| `whitelist_hits_total` | Counter | Queries accepted because the whitelist matched |
| `blacklist_hits_total` | Counter | Queries blocked because the blacklist matched |
| `match_duration_seconds{result=...}` | Summary | End-to-end plugin matching duration |

`match_duration_seconds` uses these `result` labels:

- `accept`: whitelist matched and query continued;
- `reject`: blacklist matched and query was blocked;
- `pass`: no rule matched and query continued unchanged.

### Compile and State Metrics

| Metric | Type | Meaning |
|--------|------|---------|
| `compile_errors_total` | Counter | Failed directory load or compile runs |
| `compile_duration_seconds` | Histogram | Distribution of successful directory compile durations |
| `last_compile_timestamp_seconds` | Gauge | Timestamp of the most recent successful compile |
| `last_compile_duration_seconds` | Gauge | Duration of the most recent successful compile |
| `whitelist_rules` | Gauge | Current number of compiled whitelist rules |
| `blacklist_rules` | Gauge | Current number of compiled blacklist rules |

The rule gauges count compiled rules, not DFA states.

In addition to metrics, every compile attempt emits a structured summary log
that includes label, directory, outcome, rule count, state count, duration, and
any error.

## Non-Goals

The current design explicitly does not attempt to support:

- browser-side cosmetic rules;
- request-type or first-party/third-party semantics;
- URL path filtering;
- full ABP or AdGuard modifier semantics;
- recursive directory trees or remote list fetching inside the plugin.

Those features would require a different execution model than pure DNS name
matching and would change the core architecture substantially.
