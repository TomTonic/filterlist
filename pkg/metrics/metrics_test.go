package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestNewRegistryWith verifies that plugin code gets a fully populated metric bundle for a custom registerer in the metrics package by asserting that every collector field is initialized.
func TestNewRegistryWith(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewRegistryWith(reg)

	if r.WhitelistChecks == nil {
		t.Fatal("WhitelistChecks is nil")
	}
	if r.BlacklistChecks == nil {
		t.Fatal("BlacklistChecks is nil")
	}
	if r.WhitelistHits == nil {
		t.Fatal("WhitelistHits is nil")
	}
	if r.BlacklistHits == nil {
		t.Fatal("BlacklistHits is nil")
	}
	if r.CompileErrors == nil {
		t.Fatal("CompileErrors is nil")
	}
	if r.CompileDuration == nil {
		t.Fatal("CompileDuration is nil")
	}
	if r.WhitelistRules == nil {
		t.Fatal("WhitelistRules is nil")
	}
	if r.BlacklistRules == nil {
		t.Fatal("BlacklistRules is nil")
	}
	if r.LastCompileTimestamp == nil {
		t.Fatal("LastCompileTimestamp is nil")
	}
	if r.LastCompileDurationSeconds == nil {
		t.Fatal("LastCompileDurationSeconds is nil")
	}
	if r.MatchDuration == nil {
		t.Fatal("MatchDuration is nil")
	}
}

// TestNewRegistryWithReusesExistingCollectors verifies that repeated metric setup stays safe for multi-instance use in the metrics package by asserting that duplicate registrations reuse the original collectors instead of creating conflicting ones.
func TestNewRegistryWithReusesExistingCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	first := NewRegistryWith(reg)
	second := NewRegistryWith(reg)

	if first.WhitelistChecks != second.WhitelistChecks {
		t.Fatal("WhitelistChecks collector was not reused")
	}
	if first.BlacklistRules != second.BlacklistRules {
		t.Fatal("BlacklistRules collector was not reused")
	}
	if first.MatchDuration != second.MatchDuration {
		t.Fatal("MatchDuration collector was not reused")
	}
}

// TestLastCompileMetrics verifies that operators can observe the latest successful reload in the metrics package by asserting that timestamp and duration gauges accept and expose written values.
func TestLastCompileMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewRegistryWith(reg)

	r.LastCompileTimestamp.SetToCurrentTime()
	r.LastCompileDurationSeconds.Set(1.5)

	var m dto.Metric
	if err := r.LastCompileDurationSeconds.Write(&m); err != nil {
		t.Fatal(err)
	}
	if got := m.GetGauge().GetValue(); got != 1.5 {
		t.Errorf("LastCompileDurationSeconds = %v, want 1.5", got)
	}

	var ts dto.Metric
	if err := r.LastCompileTimestamp.Write(&ts); err != nil {
		t.Fatal(err)
	}
	if got := ts.GetGauge().GetValue(); got <= 0 {
		t.Errorf("LastCompileTimestamp = %v, want > 0", got)
	}
}

// TestMatchDurationLabels verifies that operators can break down query latency by result type in the metrics package by asserting that accept, reject, and pass labels each record observations.
func TestMatchDurationLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewRegistryWith(reg)

	for _, label := range []string{"accept", "reject", "pass"} {
		r.MatchDuration.WithLabelValues(label).Observe(0.001)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, f := range families {
		if f.GetName() == "coredns_regfilter_match_duration_seconds" {
			found = true
			if len(f.GetMetric()) != 3 {
				t.Errorf("expected 3 metric series (accept/reject/pass), got %d", len(f.GetMetric()))
			}
			for _, m := range f.GetMetric() {
				if m.GetSummary().GetSampleCount() != 1 {
					t.Errorf("expected 1 observation for label %v, got %d",
						m.GetLabel(), m.GetSummary().GetSampleCount())
				}
			}
		}
	}
	if !found {
		t.Error("match_duration_seconds metric not found in gathered families")
	}
}

// TestCompileDurationHistogram verifies that operators can inspect compile latency distribution in the metrics package by asserting that histogram observations are gathered with the expected sample count.
func TestCompileDurationHistogram(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewRegistryWith(reg)

	r.CompileDuration.Observe(0.5)
	r.CompileDuration.Observe(1.0)

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range families {
		if f.GetName() == "coredns_regfilter_compile_duration_seconds" {
			m := f.GetMetric()
			if len(m) != 1 {
				t.Fatalf("expected 1 series, got %d", len(m))
			}
			if got := m[0].GetHistogram().GetSampleCount(); got != 2 {
				t.Errorf("expected 2 observations, got %d", got)
			}
			return
		}
	}
	t.Error("compile_duration_seconds not found")
}
