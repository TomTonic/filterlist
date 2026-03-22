// Package metrics provides Prometheus metrics helpers for the regfilter plugin.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Registry holds all Prometheus metrics for the regfilter plugin.
type Registry struct {
	WhitelistHits   prometheus.Counter
	BlacklistHits   prometheus.Counter
	CompileErrors   prometheus.Counter
	CompileDuration prometheus.Histogram
	WhitelistRules  prometheus.Gauge
	BlacklistRules  prometheus.Gauge
}

// NewRegistry creates and registers all metrics with the default registerer.
func NewRegistry() *Registry {
	return NewRegistryWith(prometheus.DefaultRegisterer)
}

// NewRegistryWith creates and registers all metrics with a custom registerer.
func NewRegistryWith(reg prometheus.Registerer) *Registry {
	r := &Registry{
		WhitelistHits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "whitelist_hits_total",
			Help:      "Total number of queries matched by whitelist DFA.",
		}),
		BlacklistHits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "blacklist_hits_total",
			Help:      "Total number of queries matched by blacklist DFA.",
		}),
		CompileErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "compile_errors_total",
			Help:      "Total number of DFA compile errors.",
		}),
		CompileDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "compile_duration_seconds",
			Help:      "Duration of DFA compilation in seconds.",
			Buckets:   prometheus.ExponentialBuckets(0.01, 2, 12),
		}),
		WhitelistRules: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "whitelist_rules_total",
			Help:      "Current number of rules in the whitelist DFA.",
		}),
		BlacklistRules: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "blacklist_rules_total",
			Help:      "Current number of rules in the blacklist DFA.",
		}),
	}

	reg.MustRegister(
		r.WhitelistHits,
		r.BlacklistHits,
		r.CompileErrors,
		r.CompileDuration,
		r.WhitelistRules,
		r.BlacklistRules,
	)

	return r
}
