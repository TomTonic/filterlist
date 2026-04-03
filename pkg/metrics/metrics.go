// Package metrics provides Prometheus metrics helpers for the regfilter plugin.
package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Registry groups the Prometheus collectors used by regfilter.
//
// Each field exposes one metric family for query decisions, compile results,
// or current ruleset size. Callers usually create one Registry per process or
// per Prometheus registerer and then share it across handler instances.
type Registry struct {
	AllowlistChecks            prometheus.Counter
	DenylistChecks             prometheus.Counter
	AllowlistHits              prometheus.Counter
	DenylistHits               prometheus.Counter
	CompileErrors              prometheus.Counter
	CompileDuration            prometheus.Histogram
	AllowlistRules             prometheus.Gauge
	DenylistRules              prometheus.Gauge
	LastCompileTimestamp       prometheus.Gauge
	LastCompileDurationSeconds prometheus.Gauge
	MatchDuration              *prometheus.SummaryVec
}

// NewRegistry creates a regfilter metric set on prometheus.DefaultRegisterer.
//
// The returned Registry reuses already-registered collectors when another
// regfilter instance has already published the same metric names. Use this in
// CoreDNS plugin setup paths where multiple server blocks may instantiate the
// plugin within the same process.
func NewRegistry() *Registry {
	return NewRegistryWith(prometheus.DefaultRegisterer)
}

// NewRegistryWith creates a regfilter metric set on reg.
//
// The reg parameter selects the Prometheus registerer that should own the
// metrics. When reg already contains collectors with the same metric
// descriptors, the existing collectors are reused instead of causing a panic.
// This keeps repeated setup calls safe while preserving shared metric series.
func NewRegistryWith(reg prometheus.Registerer) *Registry {
	r := &Registry{
		AllowlistChecks: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "allowlist_checks_total",
			Help:      "Total number of queries checked against the allowlist DFA.",
		}),
		DenylistChecks: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "denylist_checks_total",
			Help:      "Total number of queries checked against the denylist DFA.",
		}),
		AllowlistHits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "allowlist_hits_total",
			Help:      "Total number of queries matched by allowlist DFA.",
		}),
		DenylistHits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "denylist_hits_total",
			Help:      "Total number of queries matched by denylist DFA.",
		}),
		CompileErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "compile_errors_total",
			Help:      "Total number of failed filter load or compile runs.",
		}),
		CompileDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "compile_duration_seconds",
			Help:      "Duration of DFA compilation in seconds.",
			Buckets:   prometheus.ExponentialBuckets(0.01, 2, 12),
		}),
		AllowlistRules: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "allowlist_rules",
			Help:      "Current number of compiled allowlist rules.",
		}),
		DenylistRules: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "denylist_rules",
			Help:      "Current number of compiled denylist rules.",
		}),
		LastCompileTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "last_compile_timestamp_seconds",
			Help:      "Unix timestamp of the last successful DFA compilation.",
		}),
		LastCompileDurationSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "regfilter",
			Name:      "last_compile_duration_seconds",
			Help:      "Duration of the most recent DFA compilation in seconds.",
		}),
		MatchDuration: prometheus.NewSummaryVec(prometheus.SummaryOpts{
			Namespace:  "coredns",
			Subsystem:  "regfilter",
			Name:       "match_duration_seconds",
			Help:       "Duration of DNS query matching in seconds, by result.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		}, []string{"result"}),
	}

	r.AllowlistChecks = registerCounter(reg, r.AllowlistChecks)
	r.DenylistChecks = registerCounter(reg, r.DenylistChecks)
	r.AllowlistHits = registerCounter(reg, r.AllowlistHits)
	r.DenylistHits = registerCounter(reg, r.DenylistHits)
	r.CompileErrors = registerCounter(reg, r.CompileErrors)
	r.CompileDuration = registerHistogram(reg, r.CompileDuration)
	r.AllowlistRules = registerGauge(reg, r.AllowlistRules)
	r.DenylistRules = registerGauge(reg, r.DenylistRules)
	r.LastCompileTimestamp = registerGauge(reg, r.LastCompileTimestamp)
	r.LastCompileDurationSeconds = registerGauge(reg, r.LastCompileDurationSeconds)
	r.MatchDuration = registerSummaryVec(reg, r.MatchDuration)

	return r
}

// registerCounter registers a Counter or reuses an existing one with the same descriptor.
func registerCounter(reg prometheus.Registerer, collector prometheus.Counter) prometheus.Counter {
	if err := reg.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Counter); ok {
				return existing
			}
		}
	}

	return collector
}

// registerGauge registers a Gauge or reuses an existing one with the same descriptor.
func registerGauge(reg prometheus.Registerer, collector prometheus.Gauge) prometheus.Gauge {
	if err := reg.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Gauge); ok {
				return existing
			}
		}
	}

	return collector
}

// registerHistogram registers a Histogram or reuses an existing one with the same descriptor.
func registerHistogram(reg prometheus.Registerer, collector prometheus.Histogram) prometheus.Histogram {
	if err := reg.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Histogram); ok {
				return existing
			}
		}
	}

	return collector
}

// registerSummaryVec registers a SummaryVec or reuses an existing one with the same descriptor.
func registerSummaryVec(reg prometheus.Registerer, collector *prometheus.SummaryVec) *prometheus.SummaryVec {
	if err := reg.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.SummaryVec); ok {
				return existing
			}
		}
	}

	return collector
}
