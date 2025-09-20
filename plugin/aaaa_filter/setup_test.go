package aaaa_filter

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name:    "Valid IPv6 prefix",
			config:  "aaaa_filter 2001:db8::/32",
			wantErr: false,
		},
		{
			name:    "Multiple IPv6 prefixes",
			config:  "aaaa_filter 2001:db8::/32 2001:db8:1::/64",
			wantErr: false,
		},
		{
			name:    "Block all",
			config:  "aaaa_filter block_all",
			wantErr: false,
		},
		{
			name:    "Invalid IPv4 prefix",
			config:  "aaaa_filter 192.168.1.0/24",
			wantErr: true,
		},
		{
			name:    "Invalid prefix format",
			config:  "aaaa_filter invalid_prefix",
			wantErr: true,
		},
		{
			name:    "Empty configuration",
			config:  "aaaa_filter",
			wantErr: false,
		},
		{
			name: "Block configuration",
			config: `aaaa_filter {
    prefix 2001:db8::/32
    prefix 2001:db8:1::/64
}`,
			wantErr: false,
		},
		{
			name: "Mixed configuration",
			config: `aaaa_filter 2001:db8::/32 {
    prefix 2001:db8:1::/64
}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tt.config)
			_, err := parseAAAAFilter(c)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseAAAAFilter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
