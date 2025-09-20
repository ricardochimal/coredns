// Package aaaa_filter implements a plugin that filters AAAA queries based on IPv6 prefixes.
//
// This plugin allows only specified IPv6 prefixes to pass through and blocks the rest.
// It's useful for controlling which IPv6 addresses are returned to clients.
package aaaa_filter

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/nonwriter"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// AAAAFilter performs AAAA query filtering based on IPv6 prefixes.
type AAAAFilter struct {
	Next     plugin.Handler
	Prefixes []*net.IPNet // Allowed IPv6 prefixes
	BlockAll bool         // If true, block all AAAA queries
}

// ServeDNS implements the plugin.Handler interface.
func (f *AAAAFilter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	// Only process AAAA queries
	if state.QType() != dns.TypeAAAA {
		return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
	}

	// If BlockAll is true, return NXDOMAIN for all AAAA queries
	if f.BlockAll {
		QueriesBlockedCount.WithLabelValues(metrics.WithServer(ctx), "block_all").Inc()
		return f.returnNXDOMAIN(ctx, w, r)
	}

	// If we have no prefixes configured, allow all AAAA responses
	if len(f.Prefixes) == 0 {
		return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
	}

	// Use a non-writer to capture the response
	nw := nonwriter.New(w)

	// Pass the request to the next plugin in the chain
	rc, err := plugin.NextOrFailure(f.Name(), f.Next, ctx, nw, r)
	if err != nil {
		return rc, err
	}

	// Filter the response
	filtered := f.filterResponse(nw.Msg)
	if filtered == nil {
		return f.returnNXDOMAIN(ctx, w, r)
	}

	// Write the filtered response
	w.WriteMsg(filtered)
	return filtered.Rcode, nil
}

// Name implements the Handler interface.
func (f *AAAAFilter) Name() string { return "aaaa_filter" }

// filterResponse filters AAAA records in the response based on allowed prefixes.
func (f *AAAAFilter) filterResponse(res *dns.Msg) *dns.Msg {
	if res == nil {
		return res
	}

	// Create a new response message
	response := new(dns.Msg)
	response.SetReply(res)
	response.Authoritative = res.Authoritative
	response.Rcode = res.Rcode
	response.Truncated = res.Truncated

	var filteredAnswers []dns.RR
	var blockedCount int

	// Process each AAAA record in the original response
	for _, rr := range res.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			aaaa := rr.(*dns.AAAA)
			if f.isAllowedPrefix(aaaa.AAAA) {
				filteredAnswers = append(filteredAnswers, rr)
			} else {
				blockedCount++
			}
		} else {
			// Keep non-AAAA records as-is
			filteredAnswers = append(filteredAnswers, rr)
		}
	}

	// Process additional and authority sections similarly
	var filteredExtra []dns.RR
	for _, rr := range res.Extra {
		if rr.Header().Rrtype == dns.TypeAAAA {
			aaaa := rr.(*dns.AAAA)
			if f.isAllowedPrefix(aaaa.AAAA) {
				filteredExtra = append(filteredExtra, rr)
			}
		} else {
			filteredExtra = append(filteredExtra, rr)
		}
	}

	var filteredNs []dns.RR
	for _, rr := range res.Ns {
		if rr.Header().Rrtype == dns.TypeAAAA {
			aaaa := rr.(*dns.AAAA)
			if f.isAllowedPrefix(aaaa.AAAA) {
				filteredNs = append(filteredNs, rr)
			}
		} else {
			filteredNs = append(filteredNs, rr)
		}
	}

	// Update metrics
	if blockedCount > 0 {
		QueriesBlockedCount.WithLabelValues("", "prefix_filter").Add(float64(blockedCount))
	}

	// If no AAAA records remain after filtering, return NXDOMAIN
	if len(filteredAnswers) == 0 && len(res.Question) > 0 && res.Question[0].Qtype == dns.TypeAAAA {
		QueriesBlockedCount.WithLabelValues("", "no_matching_prefix").Inc()
		response.Rcode = dns.RcodeNameError
		response.Answer = nil
		response.Extra = nil
		response.Ns = nil
		return response
	}

	// Set the filtered records
	response.Answer = filteredAnswers
	response.Extra = filteredExtra
	response.Ns = filteredNs

	return response
}

// isAllowedPrefix checks if the given IPv6 address matches any of the allowed prefixes.
func (f *AAAAFilter) isAllowedPrefix(ip net.IP) bool {
	for _, prefix := range f.Prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// returnNXDOMAIN returns a NXDOMAIN response for the query.
func (f *AAAAFilter) returnNXDOMAIN(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	response := new(dns.Msg)
	response.SetReply(r)
	response.Authoritative = true
	response.Rcode = dns.RcodeNameError

	w.WriteMsg(response)
	return dns.RcodeNameError, nil
}
