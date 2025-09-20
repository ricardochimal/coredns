# aaaa_filter

## Name

aaaa_filter - filters AAAA queries based on IPv6 prefixes.

## Description

The aaaa_filter plugin allows you to control which IPv6 addresses are returned to clients by filtering AAAA queries based on allowed IPv6 prefixes. This is useful for:

- Blocking specific IPv6 address ranges
- Allowing only certain IPv6 prefixes to pass through
- Implementing IPv6 address filtering policies

## Syntax

```
aaaa_filter [PREFIX...] {
    prefix PREFIX...
    block_all
}
```

- `PREFIX` is an IPv6 prefix in CIDR notation (e.g., `2001:db8::/32`) or a single IPv6 address
- `prefix PREFIX...` specifies additional IPv6 prefixes to allow
- `block_all` blocks all AAAA queries (returns NXDOMAIN)

## Examples

### Allow only specific IPv6 prefixes

```
example.org {
    aaaa_filter 2001:db8::/32 2001:db8:1::/64
    forward . 8.8.8.8
}
```

combined with the `dns64` plugin you can support a configuration that allows local network communications to be IPv6 but external communication be IPv4

```
. {
    aaaa_filter 2001:db8::/32 2001:db8:1::/64

    dns64 {
        prefix 64:ff9b::/96
        allow_ipv4
    }

    forward . 8.8.8.8
}
```

### Block all AAAA queries

```
example.org {
    aaaa_filter block_all
    forward . 8.8.8.8
}
```

### Mixed configuration

```
example.org {
    aaaa_filter 2001:db8::/32 {
        prefix 2001:db8:1::/64
    }
    forward . 8.8.8.8
}
```

## Behavior

- Only AAAA queries are processed by this plugin
- Other query types pass through unchanged
- If no prefixes are configured, all AAAA responses are allowed
- If `block_all` is set, all AAAA queries return NXDOMAIN
- AAAA records that don't match any allowed prefix are filtered out
- If all AAAA records are filtered out, the query returns NXDOMAIN
- Non-AAAA records (A, CNAME, etc.) are passed through unchanged

## Metrics

The plugin exports the following Prometheus metrics:

- `coredns_aaaa_filter_queries_blocked_total{server, reason}` - Counter of blocked AAAA queries
  - `reason` can be: `block_all`, `prefix_filter`, `no_matching_prefix`

## See Also

- [CoreDNS documentation](https://coredns.io/plugins/)
- [IPv6 CIDR notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#IPv6_CIDR_blocks)
