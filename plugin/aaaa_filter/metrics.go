package aaaa_filter

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

// Variables declared for monitoring.
var (
	// QueriesBlockedCount is the number of AAAA queries blocked by the filter.
	QueriesBlockedCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "aaaa_filter",
		Name:      "queries_blocked_total",
		Help:      "Counter of AAAA queries blocked by the aaaa_filter plugin.",
	}, []string{"server", "reason"})
)

func init() {
	prometheus.MustRegister(QueriesBlockedCount)
}
