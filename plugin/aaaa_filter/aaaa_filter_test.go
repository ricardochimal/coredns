package aaaa_filter

import (
	"context"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestAAAAFilter(t *testing.T) {
	next := plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		// Create a response with AAAA record
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess

		if r.Question[0].Qtype == dns.TypeAAAA {
			aaaa := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: net.ParseIP("2001:db8:1::1"), // This should match 2001:db8::/32
			}
			resp.Answer = append(resp.Answer, aaaa)
		}

		w.WriteMsg(resp)
		return dns.RcodeSuccess, nil
	})

	tests := []struct {
		name           string
		query          string
		qtype          uint16
		prefixes       []string
		blockAll       bool
		expectedRcode  int
		expectedAnswer int
	}{
		{
			name:           "Allow matching prefix",
			query:          "example.com.",
			qtype:          dns.TypeAAAA,
			prefixes:       []string{"2001:db8::/32"},
			expectedRcode:  dns.RcodeSuccess,
			expectedAnswer: 1,
		},
		{
			name:           "Block non-matching prefix",
			query:          "example.com.",
			qtype:          dns.TypeAAAA,
			prefixes:       []string{"2001:db9::/32"}, // Different prefix
			expectedRcode:  dns.RcodeNameError,
			expectedAnswer: 0,
		},
		{
			name:          "Block all AAAA queries",
			query:         "example.com.",
			qtype:         dns.TypeAAAA,
			blockAll:      true,
			expectedRcode: dns.RcodeNameError,
		},
		{
			name:          "Pass through non-AAAA queries",
			query:         "example.com.",
			qtype:         dns.TypeA,
			prefixes:      []string{"2001:db8::/32"},
			expectedRcode: dns.RcodeSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &AAAAFilter{
				Next:     next,
				BlockAll: tt.blockAll,
			}

			for _, prefixStr := range tt.prefixes {
				_, ipNet, err := net.ParseCIDR(prefixStr)
				if err != nil {
					t.Fatalf("Failed to parse prefix %s: %v", prefixStr, err)
				}
				filter.Prefixes = append(filter.Prefixes, ipNet)
			}

			req := new(dns.Msg)
			req.SetQuestion(tt.query, tt.qtype)

			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			// Test the filter
			rc, err := filter.ServeDNS(context.TODO(), rec, req)

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if rc != tt.expectedRcode {
				t.Errorf("Expected Rcode %d, got %d", tt.expectedRcode, rc)
			}

			if tt.expectedAnswer >= 0 && len(rec.Msg.Answer) != tt.expectedAnswer {
				t.Errorf("Expected %d answers, got %d", tt.expectedAnswer, len(rec.Msg.Answer))
			}
		})
	}
}

func TestIsAllowedPrefix(t *testing.T) {
	filter := &AAAAFilter{
		Prefixes: []*net.IPNet{
			mustParseCIDR("2001:db8::/32"),
			mustParseCIDR("2001:db8:1::/64"),
		},
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"2001:db8::1", true},   // Matches 2001:db8::/32
		{"2001:db8:1::1", true}, // Matches 2001:db8:1::/64
		{"2001:db8:2::1", true}, // Matches 2001:db8::/32
		{"2001:db9::1", false},  // Doesn't match any prefix
		{"::1", false},          // Doesn't match any prefix
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := filter.isAllowedPrefix(ip)
			if result != tt.expected {
				t.Errorf("Expected %v for IP %s, got %v", tt.expected, tt.ip, result)
			}
		})
	}
}

func Test2001Prefix(t *testing.T) {
	// Create a mock next handler that returns various AAAA records
	next := plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess

		if r.Question[0].Qtype == dns.TypeAAAA {
			// Add multiple AAAA records with different prefixes
			aaaaRecords := []string{
				"2001:db8::1",  // Should match 2001::/8
				"2001:4860::1", // Should match 2001::/8 (Google IPv6)
				"2001:470::1",  // Should match 2001::/8 (Hurricane Electric)
				"2001:67c::1",  // Should match 2001::/8 (some other 2001 prefix)
				"2002::1",      // Should NOT match 2001::/8 (6to4)
				"2607::1",      // Should NOT match 2001::/8 (different prefix)
				"::1",          // Should NOT match 2001::/8 (localhost)
			}

			for _, ipStr := range aaaaRecords {
				aaaa := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					AAAA: net.ParseIP(ipStr),
				}
				resp.Answer = append(resp.Answer, aaaa)
			}
		}

		w.WriteMsg(resp)
		return dns.RcodeSuccess, nil
	})

	tests := []struct {
		name          string
		prefix        string
		expectedCount int
		expectedRcode int
		description   string
	}{
		{
			name:          "2001::/16 prefix - should allow all 2001 addresses",
			prefix:        "2001::/16",
			expectedCount: 4, // Only 2001:* addresses should pass
			expectedRcode: dns.RcodeSuccess,
			description:   "Should allow 2001:db8::1, 2001:4860::1, 2001:470::1, 2001:67c::1",
		},
		{
			name:          "2001:db8::/32 prefix - should allow only db8 addresses",
			prefix:        "2001:db8::/32",
			expectedCount: 1, // Only 2001:db8::1 should pass
			expectedRcode: dns.RcodeSuccess,
			description:   "Should allow only 2001:db8::1",
		},
		{
			name:          "2001:4860::/32 prefix - should allow only Google addresses",
			prefix:        "2001:4860::/32",
			expectedCount: 1, // Only 2001:4860::1 should pass
			expectedRcode: dns.RcodeSuccess,
			description:   "Should allow only 2001:4860::1",
		},
		{
			name:          "2002::/16 prefix - should allow only 2002 addresses",
			prefix:        "2002::/16",
			expectedCount: 1, // Only 2002::1 should pass
			expectedRcode: dns.RcodeSuccess,
			description:   "Should allow only 2002::1 since we're filtering for 2002",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &AAAAFilter{
				Next: next,
			}

			_, ipNet, err := net.ParseCIDR(tt.prefix)
			if err != nil {
				t.Fatalf("Failed to parse prefix %s: %v", tt.prefix, err)
			}
			filter.Prefixes = append(filter.Prefixes, ipNet)

			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeAAAA)

			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			// Test the filter
			rc, err := filter.ServeDNS(context.TODO(), rec, req)

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if rc != tt.expectedRcode {
				t.Errorf("Expected Rcode %d, got %d", tt.expectedRcode, rc)
			}

			if len(rec.Msg.Answer) != tt.expectedCount {
				t.Errorf("Expected %d AAAA records, got %d. %s", tt.expectedCount, len(rec.Msg.Answer), tt.description)

				for i, rr := range rec.Msg.Answer {
					if aaaa, ok := rr.(*dns.AAAA); ok {
						t.Logf("  Record %d: %s", i+1, aaaa.AAAA.String())
					}
				}
			}
		})
	}
}

func Test2001PrefixEdgeCases(t *testing.T) {
	filter := &AAAAFilter{
		Prefixes: []*net.IPNet{
			mustParseCIDR("2001::/16"),
		},
	}

	tests := []struct {
		ip       string
		expected bool
		desc     string
	}{
		{"2001::1", true, "2001::/16 should match 2001::1"},
		{"2001:ffff::1", true, "2001::/16 should match 2001:ffff::1"},
		{"2001:db8::1", true, "2001::/16 should match 2001:db8::1"},
		{"2001:4860:4860::8888", true, "2001::/16 should match Google DNS"},
		{"2001:470:1f0b:1f0b::1", true, "2001::/16 should match Hurricane Electric"},
		{"2000::1", false, "2001::/16 should NOT match 2000::1"},
		{"2002::1", false, "2001::/16 should NOT match 2002::1"},
		{"2607::1", false, "2001::/16 should NOT match 2607::1"},
		{"::1", false, "2001::/16 should NOT match localhost"},
		{"fe80::1", false, "2001::/16 should NOT match link-local"},
		{"ff02::1", false, "2001::/16 should NOT match multicast"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := filter.isAllowedPrefix(ip)
			if result != tt.expected {
				t.Errorf("%s: Expected %v for IP %s, got %v", tt.desc, tt.expected, tt.ip, result)
			}
		})
	}
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return ipNet
}
