# Corefile Examples

## Basic Setup — NXDOMAIN for blocked domains

```
. {
    regfilter {
        whitelist_dir /etc/coredns/whitelist.d
        blacklist_dir /etc/coredns/blacklist.d
        action nxdomain
    }
    forward . 8.8.8.8
}
```

## Null IP Response

Returns `0.0.0.0` for A queries and `::` for AAAA queries on blocked domains.

```
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

## REFUSE Response

```
. {
    regfilter {
        blacklist_dir /etc/coredns/blacklist.d
        action refuse
    }
    forward . 1.1.1.1
}
```

## Custom Compile Limits

For very large filter lists, increase compile limits:

```
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

```
. {
    regfilter {
        whitelist_dir /etc/coredns/whitelist.d
        action nxdomain
    }
    forward . 8.8.8.8
}
```
