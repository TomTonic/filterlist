# Design Document

## Overview

coredns-regfilter is a CoreDNS plugin that provides domain-level DNS filtering
using compiled Deterministic Finite Automata (DFA). It watches two directories
(whitelist and blacklist), parses filter lists in common formats, compiles them
into minimized DFAs, and uses those DFAs for O(n) matching on every DNS query.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌───────────┐     ┌──────────┐
│ Filter Files │────▶│ blockloader  │────▶│ filterlist │────▶│  Rules   │
│ (directory)  │     │ LoadDirectory│     │ ParseFile  │     │ []Rule   │
└─────────────┘     └──────────────┘     └───────────┘     └────┬─────┘
                                                                 │
                                                                 ▼
                                                          ┌──────────────┐
                                                          │  automaton   │
                                                          │ CompileRules │
                                                          └──────┬───────┘
                                                                 │
                    ┌──────────────┐                              ▼
                    │   watcher    │                       ┌──────────────┐
                    │  (fsnotify)  │──── OnUpdate ───────▶ │  DFA (min)   │
                    └──────────────┘                       └──────┬───────┘
                                                                 │
                                                          atomic.Value
                                                                 │
                                                                 ▼
                                                          ┌──────────────┐
                                                          │   plugin     │
                                                          │  ServeDNS    │
                                                          └──────────────┘
```

## Compilation Pipeline

### 1. Parsing (filterlist)

Input formats:
- **AdGuard/EasyList**: `||domain^`, `@@||domain^`, `||*.domain^`
- **Hosts**: `0.0.0.0 domain`, `127.0.0.1 domain`

Output: `[]Rule` where each Rule has a canonical pattern string.

Canonical pattern language:
- Literal characters: `a-z`, `0-9`, `-`, `.`
- Wildcard: `*` matches zero or more DNS characters
- Patterns are implicitly fully anchored

### 2. NFA Construction (automaton — Thompson)

Each pattern is converted to an NFA using Thompson's construction:
- Literal character `c` → two states with transition on `c`
- Wildcard `*` → self-loop state on all DNS alphabet characters

### 3. NFA Combination

All per-rule NFAs are merged into a single NFA:
- New start state
- ε-transitions from new start to each sub-NFA's start

### 4. Subset Construction (NFA → DFA)

Classic powerset/subset construction:
- Each DFA state corresponds to a set of NFA states
- ε-closure computed for each state set
- Accept states carry rule IDs for attribution

### 5. Hopcroft Minimization

Minimizes the DFA to the smallest equivalent DFA:
- Initial partition: accept states (grouped by rule IDs) vs non-accept
- Iterative refinement based on transition signatures
- Preserves rule attribution through partition representatives

### 6. Matching

DFA matching is O(n) where n is the input length:
- Follow transitions character by character
- If no transition exists, reject immediately
- If final state is accept, return matched rule IDs

## Hot Reload Pipeline

```
fsnotify event → debounce (300ms) → LoadDirectory → CompileRules → atomic.Value swap
```

Safety invariants:
- If compile fails, keep previous DFA
- Only one compile pipeline runs at a time per directory
- DFA swap is atomic (no locks in hot path)

## DNS Query Flow

```
DNS Query → normalize(qname)
  → whitelist DFA match? → YES → forward to next plugin
  → blacklist DFA match? → YES → respond blocked (NXDOMAIN/REFUSE/nullip)
  → forward to next plugin
```

## Supported Pattern Alphabet

Restricted to DNS characters for safety and efficiency:
- `a-z` (26 lowercase letters)
- `0-9` (10 digits)
- `-` (hyphen)
- `.` (dot)

Total: 38 characters. This keeps the DFA transition tables small.

## Resource Limits

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `max_states` | 200,000 | Prevents state explosion from pathological patterns |
| `compile_timeout` | 30s | Prevents unbounded compile time |
| `debounce` | 300ms | Prevents rapid recompilation |

## Performance Characteristics

- **Matching**: O(n) per query, where n is domain name length
- **Compilation**: O(rules × alphabet) for NFA/DFA construction
- **Memory**: Proportional to DFA state count × alphabet size
- **Hot path**: No locks (atomic.Value for DFA pointer)

## Metrics

All metrics use the `coredns_regfilter_` prefix and are exposed via Prometheus.
