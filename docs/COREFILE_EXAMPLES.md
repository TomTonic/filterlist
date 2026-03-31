# Corefile Examples

These examples cover the most common `regfilter` deployment patterns. At least one of `whitelist_dir` or `blacklist_dir` must be configured. If both are present, the whitelist is evaluated first and takes precedence over the blacklist.

## Basic Setup — NXDOMAIN for blocked domains

```txt
. {
    regfilter {
        whitelist_dir /etc/coredns/whitelist.d
        blacklist_dir /etc/coredns/blacklist.d
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

    regfilter {
        whitelist_dir /etc/coredns/whitelist.d
        blacklist_dir /etc/coredns/blacklist.d
        action nxdomain
    }

    forward . 8.8.8.8
}
```

This exposes the `coredns_regfilter_*` metrics on the CoreDNS Prometheus endpoint.

## Null IP Response

Returns `0.0.0.0` for A queries and `::` for AAAA queries on blocked domains.

```txt
. {
    regfilter {
        blacklist_dir /etc/coredns/blacklist.d
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
    regfilter {
        blacklist_dir /etc/coredns/blacklist.d
        action refuse
    }
    forward . 1.1.1.1
}
```

Use this when blocked queries should be rejected explicitly rather than answered with synthetic data.

## Whitelist Precedence

```txt
. {
    regfilter {
        whitelist_dir /etc/coredns/whitelist.d
        blacklist_dir /etc/coredns/blacklist.d
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
    regfilter {
        blacklist_dir /etc/coredns/blacklist.d
        action nxdomain
        max_states 500000
        compile_timeout 60s
        debounce 1s
    }
    forward . 8.8.8.8
}
```

## Whitelist Only Mode

Use only a whitelist — all non-whitelisted domains will be forwarded normally.

```txt
. {
    regfilter {
        whitelist_dir /etc/coredns/whitelist.d
    }
    forward . 8.8.8.8
}
```

With no blacklist configured, the block action is never used because unmatched queries continue to the next plugin.

## Debug Mode

Enable per-query log output to trace which rule matched a query:

```txt
. {
    regfilter {
        whitelist_dir /etc/coredns/whitelist.d
        blacklist_dir /etc/coredns/blacklist.d
        action nxdomain
        debug
    }
    forward . 8.8.8.8
}
```

With `debug` enabled, every DNS query produces a log line at `[INFO]` level showing the matching list, the queried domain, the source file and line, and the original rule pattern. Example output:

```
[INFO] plugin/regfilter: blacklist match name=ads.example.com rule=deny.txt:3 (ads.example.com)
[INFO] plugin/regfilter: whitelist match name=safe.example.com rule=allow.txt:1 (safe.example.com)
[INFO] plugin/regfilter: no match name=clean.example.com
```

The same rule tracing is available offline with the CLI tool:

```bash
./build/regfilter-check match --blacklist /etc/coredns/blacklist.d --name ads.example.com
```

## Inverted Whitelist Syntax

By default, whitelist files use the `@@` exception prefix from AdGuard syntax (`@@||safe.example.com^`). Enable `invert_whitelist` to use the simpler `||domain^` syntax instead:

```txt
. {
    regfilter {
        whitelist_dir /etc/coredns/whitelist.d
        blacklist_dir /etc/coredns/blacklist.d
        action nxdomain
        invert_whitelist
    }
    forward . 8.8.8.8
}
```

With `invert_whitelist`, whitelist files contain plain blocking-style rules like `||safe.example.com^` and those are compiled into the whitelist DFA. Without it, only `@@`-prefixed rules are used as whitelist entries.

Blacklist directories are unaffected by this flag — they always exclude `@@` exception rules so that downloaded AdGuard and EasyList files work without conversion.
