# Corefile Examples

These examples cover the most common `filterlist` deployment patterns. At least one of `allowlist_dir` or `denylist_dir` must be configured. If both are present, the allowlist is evaluated first and takes precedence over the denylist.

## Basic Setup — NXDOMAIN for blocked domains

```txt
. {
    filterlist {
        allowlist_dir /etc/coredns/allowlist.d
        denylist_dir /etc/coredns/denylist.d
        action nxdomain
    }
    forward . 8.8.8.8
}
```

Use this when you want blocked domains to resolve as NXDOMAIN while allowing explicitly whitelisted names to pass through.

## Observability with Prometheus

```txt
. {
    prometheus :9153

    filterlist {
        allowlist_dir /etc/coredns/allowlist.d
        denylist_dir /etc/coredns/denylist.d
        action nxdomain
    }

    forward . 8.8.8.8
}
```

This exposes the `coredns_filterlist_*` metrics on the CoreDNS Prometheus endpoint.

## Null IP Response

Returns `0.0.0.0` for A queries and `::` for AAAA queries on blocked domains.

```txt
. {
    filterlist {
        denylist_dir /etc/coredns/denylist.d
        action nullip
        nullip 0.0.0.0
        nullip6 ::
        ttl 300
    }
    forward . 8.8.8.8 8.8.4.4
}
```

For non-`A` and non-`AAAA` blocked queries, the plugin falls back to NXDOMAIN.

## REFUSE Response

```txt
. {
    filterlist {
        denylist_dir /etc/coredns/denylist.d
        action refuse
    }
    forward . 1.1.1.1
}
```

Use this when blocked queries should be rejected explicitly rather than answered with synthetic data.

## Whitelist Precedence

```txt
. {
    filterlist {
        allowlist_dir /etc/coredns/allowlist.d
        denylist_dir /etc/coredns/denylist.d
        action refuse
    }
    forward . 1.1.1.1
}
```

If the same domain matches both automata, the whitelist match wins and the query is forwarded.

## Custom Compile Limits

For very large filter lists, increase compile limits:

```txt
. {
    filterlist {
        denylist_dir /etc/coredns/denylist.d
        action nxdomain
        max_states 500000
        compile_timeout 60s
        debounce 1s
    }
    forward . 8.8.8.8
}
```

## Fully Compiled DFA Mode

Use `matcher_mode dfa` when you want the lowest request-path lookup cost and
can afford slower startup and reload compiles.

```txt
. {
    filterlist {
        denylist_dir /etc/coredns/denylist.d
        action nxdomain
        matcher_mode dfa
        max_states 500000
        compile_timeout 60s
    }
    forward . 8.8.8.8
}
```

On the repository's `BenchmarkSequenceMapVsDFA` benchmark with the bundled
realistic denylist samples, pure DFA mode reduced lookup cost from about
125-135 ns/domain to about 93-95 ns/domain, but increased compile time from
about 0.34 s to about 7.1 s. Keep the default `matcher_mode hybrid` unless
you explicitly prefer lower steady-state lookup cost over reload speed.

## Whitelist Only Mode

Use only a whitelist — all non-whitelisted domains will be forwarded normally.

```txt
. {
    filterlist {
        allowlist_dir /etc/coredns/allowlist.d
    }
    forward . 8.8.8.8
}
```

With no blacklist configured, the block action is never used because unmatched queries continue to the next plugin.

## Debug Mode

Enable per-query log output to trace which rule matched a query:

```txt
. {
    filterlist {
        allowlist_dir /etc/coredns/allowlist.d
        denylist_dir /etc/coredns/denylist.d
        action nxdomain
        debug
    }
    forward . 8.8.8.8
}
```

With `debug` enabled, every DNS query produces a log line at `[INFO]` level showing the matching list, the queried domain, the source file and line, and the original rule pattern. Example output:

```
[INFO] plugin/filterlist: denylist match name=ads.example.com rule=deny.txt:3 (ads.example.com)
[INFO] plugin/filterlist: allowlist match name=safe.example.com rule=allow.txt:1 (safe.example.com)
[INFO] plugin/filterlist: no match name=clean.example.com
```

Offline list validation is available with the CLI tool:

```bash
./build/filterlist-check validate --list /etc/coredns/denylist.d
```

## Inverted Allowlist Syntax

By default, allowlist files use the `@@` exception prefix from AdGuard syntax (`@@||safe.example.com^`). Enable `invert_allowlist` to use the simpler `||domain^` syntax instead:

```txt
. {
    filterlist {
        allowlist_dir /etc/coredns/allowlist.d
        denylist_dir /etc/coredns/denylist.d
        action nxdomain
        invert_allowlist
    }
    forward . 8.8.8.8
}
```

With `invert_allowlist`, allowlist files contain plain blocking-style rules like `||safe.example.com^` and those are compiled into the allowlist DFA. Without it, only `@@`-prefixed rules are used as allowlist entries.

Denylist directories are unaffected by this flag — they always exclude `@@` exception rules so that downloaded AdGuard and EasyList files work without conversion.

## RFC / IDNA Name Validation (default: on)

By default the plugin blocks queries whose names violate RFC 1035 LDH syntax or
the IDNA Lookup profile (RFCs 5890–5894). This precheck runs inside the
denylist phase, after `deny_non_allowlisted` and before the denylist matcher.

For environments that intentionally serve non-standard names (for example,
SRV-style names with underscores or legacy hosts with digits at label
boundaries), the check can be disabled:

```txt
. {
    filterlist {
        allowlist_dir /etc/coredns/allowlist.d
        denylist_dir /etc/coredns/denylist.d
        action nxdomain
        disable_RFC_checks on
    }
    forward . 8.8.8.8
}
```

Leave `disable_RFC_checks` unset (or set it to `off`) to keep the check active.

## Deny by Default — Block Non-Allowlisted Names

Enable `deny_non_allowlisted on` to block every query that is not explicitly
matched by the allowlist. This gives a deny-by-default posture: only domains
that appear in the allowlist files will resolve; everything else is blocked
before the denylist matcher is consulted.

```txt
. {
    filterlist {
        allowlist_dir /etc/coredns/trusted.d
        action nxdomain
        deny_non_allowlisted on
    }
    forward . 8.8.8.8
}
```

Combined with RFC name validation (both on by default), the full hardened
configuration looks like this:

```txt
. {
    filterlist {
        allowlist_dir /etc/coredns/trusted.d
        action nxdomain
        deny_non_allowlisted on
        # disable_RFC_checks defaults to off, so RFC checks are active
    }
    forward . 8.8.8.8
}
```
