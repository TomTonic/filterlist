// Package benchfixture provides the realistic inputs shared by the
// repository's runtime comparisons: the bundled denylist samples, the
// Cloudflare top-domain list, and a deterministic query sequence over it.
//
// The comparisons themselves live next to the code they measure (the
// filterlist package for matcher modes, pkg/automaton for the DFA's runtime
// layout) and run through rtcompare's multiproc package, which starts every
// comparison in several processes and pools them. They take minutes, so they
// only run when the environment variable named by [EnvVar] is set.
//
// The package deliberately imports neither pkg/matcher nor pkg/automaton, so
// that the internal tests of both can use it without an import cycle.
package benchfixture

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/TomTonic/filterlist/pkg/listparser"
	"github.com/TomTonic/rtcompare"
)

// EnvVar is the environment variable that enables the multi-process runtime
// comparisons. Any non-empty value enables them.
const EnvVar = "FILTERLIST_PERF"

// SequenceEnvVar overrides the length of the query sequence, see
// [SequenceLength].
const SequenceEnvVar = "BENCH_SEQ_SIZE"

// DefaultSequenceLength is the number of pseudo-random draws from the domain
// list after which a query sequence repeats.
const DefaultSequenceLength = 100_000

// SequenceSeed is the seed every comparison draws its query sequence from, so
// that all candidates of all comparisons see the same queries.
const SequenceSeed uint64 = 0x5eed_f11e

const topDomainsFile = "cloudflare-radar_top-1000000-domains_20260327-20260403.csv"

// Enabled reports whether the runtime comparisons were requested through
// [EnvVar].
//
// Typical usage is the first line of a comparison test:
//
//	if !benchfixture.Enabled() {
//		t.Skipf("set %s=1 to run", benchfixture.EnvVar)
//	}
func Enabled() bool {
	return os.Getenv(EnvVar) != ""
}

// TestdataDir returns the absolute path of the repository's testdata
// directory. It is derived from this source file's location, so it works
// regardless of the working directory of the test binary.
func TestdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

// DenylistRules parses the two bundled sample filter lists
// (testdata/filterlists) and returns their deny rules in file order; allow
// rules (@@) are dropped. The rule index is the rule ID the matcher assigns.
//
// It returns an error if a list cannot be read or parsed. Callers compile
// the result with matcher.CompileRules, or turn it into reversed automaton
// patterns with [ReversedPattern].
func DenylistRules() ([]listparser.Rule, error) {
	dir := filepath.Join(TestdataDir(), "filterlists")
	var rules []listparser.Rule
	for _, name := range []string{"Adguard_filter_example.txt", "easylistgermany_example.txt"} {
		parsed, err := listparser.ParseFile(filepath.Join(dir, name), nil)
		if err != nil {
			return nil, fmt.Errorf("benchfixture: parse %s: %w", name, err)
		}
		for _, r := range parsed {
			if !r.IsAllow {
				rules = append(rules, r)
			}
		}
	}
	return rules, nil
}

// ReversedPattern lowercases and byte-reverses a rule pattern, the form in
// which the matcher compiles every DFA pattern so that
// automaton.DFA.MatchDomain can walk a query name backwards. It must stay in
// step with the matcher's own conversion; DNS patterns are ASCII, so
// reversing bytes is reversing characters.
func ReversedPattern(pattern string) string {
	b := []byte(strings.ToLower(pattern))
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// TopDomains returns the domain names of the bundled Cloudflare Radar top
// one million list, in rank order, without the header row.
//
// It returns an error if the file is missing, unreadable, or contains no
// domains. The result is the query population for [Sequence].
func TopDomains() ([]string, error) {
	path := filepath.Join(TestdataDir(), topDomainsFile)
	f, err := os.Open(path) //nolint:gosec // fixed fixture path below the repository's testdata directory
	if err != nil {
		return nil, fmt.Errorf("benchfixture: %w", err)
	}
	defer func() { _ = f.Close() }()
	return readDomains(f)
}

// readDomains reads the first column of a CSV stream, skipping a header row;
// split from TopDomains so the parsing can be tested without the large file.
func readDomains(r io.Reader) ([]string, error) {
	cr := csv.NewReader(bufio.NewReader(r))
	var domains []string
	first := true
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("benchfixture: read domains: %w", err)
		}
		val := strings.TrimSpace(rec[0])
		if val == "" {
			continue
		}
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
		return nil, errors.New("benchfixture: no domains found")
	}
	return domains, nil
}

// SequenceLength returns the query sequence length requested through
// [SequenceEnvVar], or [DefaultSequenceLength] if it is unset or not a
// positive integer.
func SequenceLength() int {
	if n, err := strconv.Atoi(os.Getenv(SequenceEnvVar)); err == nil && n > 0 {
		return n
	}
	return DefaultSequenceLength
}

// Sequence returns length deterministic pseudo-random indices into a domain
// list of domainCount entries, drawn uniformly from seed.
//
// A comparison's candidates walk the same sequence cyclically, so that they
// answer the same queries in the same proportions. It returns an error if
// length or domainCount is not positive or domainCount exceeds the uint32
// range.
func Sequence(length, domainCount int, seed uint64) ([]uint32, error) {
	if length <= 0 || domainCount <= 0 || domainCount > math.MaxUint32 {
		return nil, fmt.Errorf("benchfixture: invalid sequence length %d or domain count %d", length, domainCount)
	}
	rng := rtcompare.NewDPRNG(seed)
	count := uint32(domainCount) //nolint:gosec // bounded against math.MaxUint32 above
	seq := make([]uint32, length)
	for i := range seq {
		seq[i] = rng.Uint32N(count)
	}
	return seq, nil
}

// Queries materializes a sequence into the query strings it selects, copied
// in sequence order into one contiguous buffer.
//
// A DNS server reads each query name from the packet it just received, so the
// name is in cache when the matcher sees it. Looking the names up in place in
// the one-million-entry domain list instead would charge every lookup a cache
// miss on the string, larger than most of the differences being measured,
// and the same for every candidate, which shrinks those differences. Walking
// the contiguous buffer in order lets the hardware prefetcher bring each name
// in ahead of its lookup, as the packet would.
//
// Every entry of seq must be a valid index into domains, as [Sequence]
// guarantees for a domain count of len(domains).
func Queries(domains []string, seq []uint32) []string {
	size := 0
	for _, i := range seq {
		size += len(domains[i])
	}
	buf := make([]byte, 0, size)
	for _, i := range seq {
		buf = append(buf, domains[i]...)
	}
	all := string(buf)
	queries := make([]string, len(seq))
	off := 0
	for k, i := range seq {
		n := len(domains[i])
		queries[k] = all[off : off+n]
		off += n
	}
	return queries
}

// Walker hands out queries in order, wrapping around at the end.
//
// Both candidates of a comparison must share one Walker. Each batch then
// continues where the previous batch of either candidate stopped, so no
// candidate ever looks up names the other one has just brought into the
// cache, and both cover the whole sequence over a run, however few lookups a
// calibrated batch performs. With one Walker per candidate, whichever trails
// the other finds the names, and the matcher states they lead to, still in
// cache: identical code measured that way came out more than four times
// apart, and the A/A validation cannot see it, because it compares a
// candidate with itself and so with its own Walker.
type Walker struct {
	queries []string
	pos     int
}

// NewWalker returns a Walker over queries, typically the result of [Queries].
// queries must not be empty.
func NewWalker(queries []string) *Walker {
	return &Walker{queries: queries}
}

// Next returns the next query. It is small enough to be inlined into a
// candidate's batch loop, where its cost is the same for every candidate.
func (w *Walker) Next() string {
	q := w.queries[w.pos]
	w.pos++
	if w.pos == len(w.queries) {
		w.pos = 0
	}
	return q
}
