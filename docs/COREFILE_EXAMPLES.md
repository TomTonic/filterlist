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
