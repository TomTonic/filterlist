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

The same rule tracing is available offline with the CLI tool:

```bash
./build/filterlist-check match --denylist /etc/coredns/denylist.d --name ads.example.com
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
