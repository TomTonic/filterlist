package filterlist_test

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TomTonic/filterlist/pkg/automaton"
	"github.com/TomTonic/filterlist/pkg/matcher"
	"github.com/TomTonic/rtcompare"
)

var benchmarkMatchCount int

// BenchmarkSequenceMapVsDFA compiles the realistic denylist rule set and then
// benchmarks matching a deterministic pseudo-random sequence of domains drawn
// from the provided Cloudflare CSV. It reports separate benchmark runs for the
// hybrid suffix-map+DFA matcher and for a pure-automaton matcher.
//
// Sequence sizes can be controlled with the environment variable
// BENCH_SEQ_SIZE (single integer). If unset, the benchmark runs a small set of
// sizes to explore scaling.
func BenchmarkSequenceMapVsDFA(b *testing.B) {
	// Locate CSV in repository testdata directory.
	_, filename, _, _ := runtime.Caller(0)
	csvPath := filepath.Join(filepath.Dir(filename), "testdata", "cloudflare-radar_top-1000000-domains_20260327-20260403.csv")

	domains := loadDomainsFromCSV(b, csvPath)

	// Allow overriding a single sequence size via env var.
	sizes := []int{2_000, 20_000, 200_000}
	if v := os.Getenv("BENCH_SEQ_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sizes = []int{n}
		}
	}

	// Compile hybrid matcher (suffix map + DFA) and measure time.
	b.Logf("compiling hybrid matcher (rules -> suffixmap + dfa)")
	t0 := time.Now()
	rules := loadRealisticDenylistRules(b)
	hybrid, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}
	compileHybrid := time.Since(t0)

	// Compile pure automaton (force all patterns through automaton) and measure.
	b.Logf("compiling pure automaton (all patterns through automaton)")
	t1 := time.Now()
	patterns := loadRealisticDenylistPatterns(b)
	pure, err := automaton.Compile(patterns, automaton.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
	if err != nil {
		b.Fatalf("automaton.Compile error: %v", err)
	}
	compilePure := time.Since(t1)

	b.Logf("compile: hybrid=%s pure=%s", compileHybrid, compilePure)

	// For each configured sequence size build a deterministic sequence using DPRNG.
	for _, seqLen := range sizes {
		// Build deterministic sequence (not timed).
		dprng := rtcompare.NewDPRNG(uint64(seqLen * 123456789)) // Seed based on length for reproducibility across runs.
		seq := make([]string, 0, seqLen)
		for i := 0; i < seqLen; i++ {
			idx := dprng.UInt32N(uint32(len(domains)))
			seq = append(seq, domains[int(idx)])
		}

		// Pre-warm: compute match counts once (not timed) to report hit rates.
		hybridHits := 0
		pureHits := 0
		for _, d := range seq {
			if hit, _ := hybrid.Match(d); hit {
				hybridHits++
			}
			if hit, _ := pure.Match(d); hit {
				pureHits++
			}
		}

		b.Logf("seq=%d hybrid_hits=%d(%.2f%%) pure_hits=%d(%.2f%%)", seqLen, hybridHits, float64(hybridHits)/float64(seqLen)*100.0, pureHits, float64(pureHits)/float64(seqLen)*100.0)

		hybridMean, hybridMedian := measurePerDomainCost(seq, func(domain string) bool {
			hit, _ := hybrid.Match(domain)
			return hit
		})
		pureMean, pureMedian := measurePerDomainCost(seq, func(domain string) bool {
			hit, _ := pure.Match(domain)
			return hit
		})
		totalCompile := compileHybrid + compilePure

		// Benchmark hybrid matcher over the deterministic sequence.
		b.Run(fmt.Sprintf("seq=%d/hybrid", seqLen), func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(seqLen), "domains")
			b.ReportMetric(float64(hybridHits)/float64(seqLen)*100.0, "hit_rate_pct")
			b.ReportMetric(float64(compileHybrid.Nanoseconds()), "compile_ns")
			b.ReportMetric(float64(totalCompile.Nanoseconds()), "total_compile_ns")
			b.ReportMetric(hybridMean, "mean_ns/domain")
			b.ReportMetric(hybridMedian, "median_ns/domain")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				matches := 0
				for _, d := range seq {
					if hit, _ := hybrid.Match(d); hit {
						matches++
					}
				}
				benchmarkMatchCount = matches
			}
		})

		// Benchmark pure DFA matcher over the deterministic sequence.
		b.Run(fmt.Sprintf("seq=%d/pure", seqLen), func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(seqLen), "domains")
			b.ReportMetric(float64(pureHits)/float64(seqLen)*100.0, "hit_rate_pct")
			b.ReportMetric(float64(compilePure.Nanoseconds()), "compile_ns")
			b.ReportMetric(float64(totalCompile.Nanoseconds()), "total_compile_ns")
			b.ReportMetric(pureMean, "mean_ns/domain")
			b.ReportMetric(pureMedian, "median_ns/domain")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				matches := 0
				for _, d := range seq {
					if hit, _ := pure.Match(d); hit {
						matches++
					}
				}
				benchmarkMatchCount = matches
			}
		})

		// Combined measurement: report compile cost and per-domain lookup cost.
		fmt.Printf(
			"BenchmarkSequenceMapVsDFA seq=%d compile_hybrid=%s compile_pure=%s total_compile=%s hybrid_mean_ns_per_domain=%.2f hybrid_median_ns_per_domain=%.2f pure_mean_ns_per_domain=%.2f pure_median_ns_per_domain=%.2f\n",
			seqLen,
			compileHybrid,
			compilePure,
			totalCompile,
			hybridMean,
			hybridMedian,
			pureMean,
			pureMedian,
		)
	}
}

func measurePerDomainCost(seq []string, match func(string) bool) (meanNS, medianNS float64) {
	const samples = 9

	perDomain := make([]float64, 0, samples)
	for range samples {
		matches := 0
		start := time.Now()
		for _, domain := range seq {
			if match(domain) {
				matches++
			}
		}
		elapsed := time.Since(start)
		benchmarkMatchCount = matches
		perDomain = append(perDomain, float64(elapsed.Nanoseconds())/float64(len(seq)))
	}

	meanNS = meanFloat64(perDomain)
	medianNS = medianFloat64(perDomain)
	return meanNS, medianNS
}

func meanFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	var total float64
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func medianFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

// loadDomainsFromCSV reads the first column from a CSV and returns a slice of
// domain names. It skips an initial header row if present.
func loadDomainsFromCSV(tb testing.TB, path string) []string {
	tb.Helper()
	f, err := os.Open(path)
	if err != nil {
		tb.Skipf("CSV file not found (%s): %v", path, err)
	}
	defer f.Close()

	// Use the csv.Reader for robust parsing; stream rows to avoid large
	// temporary allocations for huge files.
	r := csv.NewReader(bufio.NewReader(f))
	var domains []string
	first := true
	for {
		rec, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			tb.Fatalf("error reading csv: %v", err)
		}
		if len(rec) == 0 {
			continue
		}
		val := strings.TrimSpace(rec[0])
		if val == "" {
			continue
		}
		// Skip header line if it looks like a header on the first row.
		if first {
			first = false
			low := strings.ToLower(val)
			if strings.Contains(low, "domain") || strings.Contains(low, "rank") {
				continue
			}
		}
		domains = append(domains, val)
	}

	if len(domains) == 0 {
		tb.Skipf("no domains found in CSV %s", path)
	}
	return domains
}
