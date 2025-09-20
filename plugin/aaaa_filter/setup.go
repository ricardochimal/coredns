package aaaa_filter

import (
	"fmt"
	"net"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("aaaa_filter", setup) }

func setup(c *caddy.Controller) error {
	filter, err := parseAAAAFilter(c)
	if err != nil {
		return plugin.Error("aaaa_filter", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		filter.Next = next
		return filter
	})

	return nil
}

func parseAAAAFilter(c *caddy.Controller) (*AAAAFilter, error) {
	filter := &AAAAFilter{}

	for c.Next() {
		args := c.RemainingArgs()

		// Handle "block_all" directive
		if len(args) > 0 && args[0] == "block_all" {
			filter.BlockAll = true
			if len(args) > 1 {
				return nil, c.ArgErr()
			}
			continue
		}

		// Parse IPv6 prefixes
		for _, arg := range args {
			if _, ipNet, err := net.ParseCIDR(arg); err == nil {
				if ipNet.IP.To16() != nil && ipNet.IP.To4() == nil {
					filter.Prefixes = append(filter.Prefixes, ipNet)
				} else {
					return nil, fmt.Errorf("invalid IPv6 prefix: %s", arg)
				}
			} else {
				// Try parsing as a single IP and convert to /128
				if ip := net.ParseIP(arg); ip != nil {
					if ip.To16() != nil && ip.To4() == nil {
						_, ipNet, _ := net.ParseCIDR(ip.String() + "/128")
						filter.Prefixes = append(filter.Prefixes, ipNet)
					} else {
						return nil, fmt.Errorf("invalid IPv6 address: %s", arg)
					}
				} else {
					return nil, fmt.Errorf("invalid IPv6 prefix or address: %s", arg)
				}
			}
		}

		// Parse any additional configuration blocks
		for c.NextBlock() {
			switch c.Val() {
			case "block_all":
				if c.NextArg() {
					return nil, c.ArgErr()
				}
				filter.BlockAll = true
			case "prefix":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.ArgErr()
				}
				for _, arg := range args {
					if _, ipNet, err := net.ParseCIDR(arg); err == nil {
						if ipNet.IP.To16() != nil && ipNet.IP.To4() == nil {
							filter.Prefixes = append(filter.Prefixes, ipNet)
						} else {
							return nil, fmt.Errorf("invalid IPv6 prefix: %s", arg)
						}
					} else {
						return nil, fmt.Errorf("invalid IPv6 prefix: %s", arg)
					}
				}
			default:
				return nil, c.Errf("unknown directive: %s", c.Val())
			}
		}
	}

	return filter, nil
}
