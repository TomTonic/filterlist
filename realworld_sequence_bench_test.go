package filterlist_test

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TomTonic/filterlist/pkg/matcher"
	"github.com/TomTonic/rtcompare"
)

// BenchmarkSequenceMapVsDFA compiles the realistic denylist rule set and then
// benchmarks matching a deterministic pseudo-random sequence of domains drawn
// from the provided Cloudflare CSV. It reports separate benchmark runs for the
// matcher package in hybrid mode and in full-DFA mode.
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
	sizes := []int{50_000, 100_000, 200_000}
	if v := os.Getenv("BENCH_SEQ_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sizes = []int{n}
		}
	}

	// Compile hybrid matcher and measure time.
	b.Logf("compiling matcher in hybrid mode")
	t0 := time.Now()
	rules := loadRealisticDenylistRules(b)
	hybrid, err := matcher.CompileRules(rules, matcher.CompileOptions{
		MaxStates: realisticBenchmarkMaxStates,
		Mode:      matcher.ModeHybrid,
	})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}
	compileHybrid := time.Since(t0)

	// Compile matcher in full-DFA mode and measure time.
	b.Logf("compiling matcher in dfa mode")
	t1 := time.Now()
	pure, err := matcher.CompileRules(rules, matcher.CompileOptions{
		MaxStates: realisticBenchmarkMaxStates,
		Mode:      matcher.ModeDFA,
	})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}
	compilePure := time.Since(t1)
	totalCompile := compileHybrid + compilePure

	b.Logf("compile: hybrid=%s pure=%s", compileHybrid, compilePure)

	timesHybrid := make([]float64, 0, 100_000)
	timesPure := make([]float64, 0, 100_000)
	oldGCPercent := debug.SetGCPercent(-1) // Disable GC during benchmarking to avoid noise; we'll trigger manually between runs.
	defer debug.SetGCPercent(oldGCPercent)

	for _, seqLen := range sizes {
		timesHybrid = timesHybrid[:0]
		timesPure = timesPure[:0]

		if seqLen <= 0 {
			b.Fatalf("sequence length must be positive, got %d", seqLen)
		}
		if len(domains) > math.MaxUint32 {
			b.Fatalf("domain count %d exceeds DPRNG limit", len(domains))
		}

		hybridHits := 0
		hybridMatches := 0
		pureHits := 0
		pureMatches := 0
		seed := uint64(seqLen)*123456789 + 11 //nolint:gosec // seqLen is validated > 0 just above and only used in benchmark seeding
		domainCount := uint32(len(domains))   //nolint:gosec // len(domains) is bounded against math.MaxUint32 just above

		runtime.GC()
		runtime.GC()
		runtime.GC()
		debug.SetGCPercent(-1)

		// Benchmark hybrid matcher over the deterministic sequence.
		b.Run(fmt.Sprintf("seq=%d/hybrid", seqLen), func(b *testing.B) {
			b.ReportAllocs()
			dprng := rtcompare.NewDPRNG(seed) // DPRNG is deterministic in sequence and has constant memory and execution time
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t1 := rtcompare.SampleTime()
				for range seqLen {
					idx := dprng.UInt32N(domainCount)
					d := domains[int(idx)]
					if hit, _ := hybrid.Match(d); hit {
						hybridHits++
					}
					hybridMatches++
				}
				t2 := rtcompare.SampleTime()
				timesHybrid = append(timesHybrid, float64(rtcompare.DiffTimeStamps(t1, t2))/float64(seqLen))
			}
		})

		debug.SetGCPercent(oldGCPercent)
		runtime.GC()
		runtime.GC()
		runtime.GC()
		debug.SetGCPercent(-1)

		// Benchmark matcher in full-DFA mode over the deterministic sequence.
		b.Run(fmt.Sprintf("seq=%d/pure", seqLen), func(b *testing.B) {
			b.ReportAllocs()
			dprng := rtcompare.NewDPRNG(seed) // DPRNG is deterministic in sequence and has constant memory and execution time
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t1 := rtcompare.SampleTime()
				for range seqLen {
					idx := dprng.UInt32N(domainCount)
					d := domains[int(idx)]
					if hit, _ := pure.Match(d); hit {
						pureHits++
					}
					pureMatches++
				}
				t2 := rtcompare.SampleTime()
				timesPure = append(timesPure, float64(rtcompare.DiffTimeStamps(t1, t2))/float64(seqLen))
			}
		})

		debug.SetGCPercent(oldGCPercent)
		runtime.GC()

		hybridMedian := rtcompare.QuickMedian(timesHybrid)
		pureMedian := rtcompare.QuickMedian(timesPure)

		fmt.Printf(
			"\nBenchmarkSequenceMapVsDFA seq = %d, hybrid: %d iterations, pure: %d iterations\n",
			seqLen,
			hybridMatches,
			pureMatches,
		)

		// Combined measurement: report compile cost and per-domain lookup cost.
		fmt.Printf(
			"compile_hybrid = %s\ncompile_pure   = %s\ntotal_compile  = %s\n",
			compileHybrid,
			compilePure,
			totalCompile,
		)

		fmt.Printf(
			"hybrid: median_per_domain = %.2fns\npure:   median_per_domain = %.2fns\n\n",
			hybridMedian,
			pureMedian,
		)

		// Compare distributions using bootstrap (precision controls bootstrap repetitions)
		speedups := []float64{0.05} // assume 5% speedup
		results, err := rtcompare.CompareSamplesDefault(timesPure, timesHybrid, speedups)
		if err != nil {
			panic(err)
		}
		for _, r := range results {
			fmt.Printf("Speedup ≥ %.0f%% → Confidence %.2f%%\n", r.RelativeSpeedupSampleAvsSampleB*100, r.Confidence*100)
		}
	}
}

// loadDomainsFromCSV reads the first column from a CSV and returns a slice of
// domain names. It skips an initial header row if present.
func loadDomainsFromCSV(tb testing.TB, path string) []string {
	tb.Helper()
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath) //nolint:gosec // benchmark fixture path is derived from runtime.Caller and cleaned locally
	if err != nil {
		tb.Skipf("CSV file not found (%s): %v", cleanPath, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			tb.Fatalf("close csv %s: %v", cleanPath, closeErr)
		}
	}()

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
		tb.Skipf("no domains found in CSV %s", cleanPath)
	}
	return domains
}
