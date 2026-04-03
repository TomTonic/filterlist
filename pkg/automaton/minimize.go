package automaton

import (
	"runtime"
	"slices"
	"sync"
)

// ---- Hopcroft Minimization ----
//
// Hopcroft's algorithm merges distinguishably-equivalent states in the
// intermediate DFA to produce a minimal DFA. Two states are equivalent when
// they share the same accept status, the same rule-ID set, and identical
// transition signatures (each outgoing edge reaches the same equivalence
// class).
//
// The implementation uses iterative partition refinement:
//  1. Start with one partition per distinct (accept, ruleIDs) combination,
//     plus one partition for all non-accept states.
//  2. Split each partition when two members differ in which partition their
//     outgoing edges reach.
//  3. Repeat until no further splits occur.
//  4. Build a new intermediate DFA with one state per partition.
//
// Preserving distinct rule-ID sets in the initial partition ensures that
// minimization never merges accept states that would lose attribution
// information. This guarantee is critical for the filterlist use case where
// every match must report which rule(s) triggered it.

// ruleIDsFingerprint is a cheap hash of a rule-ID slice used to narrow
// candidate buckets before performing a full slice comparison in
// [initialPartitions].
type ruleIDsFingerprint struct {
	hash   uint64
	length int
}

// acceptPartitionBucket groups accept states that share the same rule-ID set
// during initial partition construction.
type acceptPartitionBucket struct {
	ruleIDs []uint32
	states  []int
}

// hopcroftMinimize merges equivalent states in md to produce a minimal
// intermediate DFA.
//
// The md parameter is consumed and should not be used after this call.
// Returns a new [intermediateDFA] with potentially fewer states but
// identical matching behavior and rule attribution.
func hopcroftMinimize(md *intermediateDFA) *intermediateDFA {
	n := md.stateCount()
	if n <= 1 {
		return md
	}

	// Initial partition: split by (accept, ruleIDs).
	partitions := initialPartitions(md)

	// stateToPartition maps each state to its current partition index.
	stateToPartition := make([]uint32, n)
	numWorkers := runtime.GOMAXPROCS(0)

	// updateMapping refreshes stateToPartition from the current partitions.
	updateMapping := func() {
		for pi, p := range partitions {
			p32 := uint32(pi) //nolint:gosec // pi is a range index, always ≥0
			for _, s := range p {
				stateToPartition[s] = p32
			}
		}
	}
	updateMapping()

	// Iterative refinement: split partitions until stable.
	// When there are enough partitions, each refinement iteration is
	// parallelised: workers process disjoint chunks of the partition list,
	// collecting their results locally, which are merged afterward.
	changed := true
	for changed {
		changed = false

		if len(partitions) >= numWorkers*4 && numWorkers > 1 {
			chunkSize := (len(partitions) + numWorkers - 1) / numWorkers
			type workerResult struct {
				parts   [][]int
				changed bool
			}
			results := make([]workerResult, numWorkers)
			var wg sync.WaitGroup
			for w := range numWorkers {
				lo := w * chunkSize
				if lo >= len(partitions) {
					break
				}
				hi := min(lo+chunkSize, len(partitions))
				wg.Add(1)
				go func(w, lo, hi int) {
					defer wg.Done()
					local := make([][]int, 0, hi-lo+(hi-lo)/4)
					lc := false
					for _, p := range partitions[lo:hi] {
						if len(p) <= 1 {
							local = append(local, p)
							continue
						}
						split := splitPartition(md, p, stateToPartition)
						if len(split) > 1 {
							lc = true
						}
						local = append(local, split...)
					}
					results[w] = workerResult{local, lc}
				}(w, lo, hi)
			}
			wg.Wait()

			total := 0
			for _, r := range results {
				total += len(r.parts)
				if r.changed {
					changed = true
				}
			}
			newPartitions := make([][]int, 0, total)
			for _, r := range results {
				newPartitions = append(newPartitions, r.parts...)
			}
			partitions = newPartitions
		} else {
			newPartitions := make([][]int, 0, len(partitions)+len(partitions)/4)
			for _, p := range partitions {
				if len(p) <= 1 {
					newPartitions = append(newPartitions, p)
					continue
				}
				var split [][]int
				if len(p) > 100000 {
					split = splitPartitionParallel(md, p, stateToPartition)
				} else {
					split = splitPartition(md, p, stateToPartition)
				}
				if len(split) > 1 {
					changed = true
				}
				newPartitions = append(newPartitions, split...)
			}
			partitions = newPartitions
		}
		updateMapping()
	}

	// Build the minimized intermediate DFA (one state per partition).
	minMD := &intermediateDFA{
		trans:   make([]uint32, len(partitions)*AlphabetSize),
		accept:  make([]bool, len(partitions)),
		ruleIDs: make(map[int][]uint32, len(md.ruleIDs)),
	}
	// Initialize all transition slots to noTransitionState.
	for i := range minMD.trans {
		minMD.trans[i] = noTransitionState
	}
	for pi, p := range partitions {
		rep := p[0] // any representative state will do
		minMD.accept[pi] = md.accept[rep]
		if rids := md.ruleIDs[rep]; len(rids) > 0 {
			minMD.ruleIDs[pi] = rids
		}
		repTrans := md.stateTrans(rep)
		piTrans := minMD.stateTrans(pi)
		for idx, target := range repTrans {
			if target != noTransitionState {
				piTrans[idx] = stateToPartition[target]
			}
		}
	}
	minMD.start = int(stateToPartition[md.start])

	return minMD
}

// initialPartitions separates states into starting groups: one group for all
// non-accept states, and one group per distinct rule-ID set among accept
// states. This ensures that states with different rule attribution are never
// merged.
func initialPartitions(md *intermediateDFA) [][]int {
	n := md.stateCount()
	nonAccept := make([]int, 0, n)
	bucketIndexByFingerprint := make(map[ruleIDsFingerprint][]int)
	acceptBuckets := make([]acceptPartitionBucket, 0)

	for i := range n {
		if !md.accept[i] {
			nonAccept = append(nonAccept, i)
			continue
		}

		rids := md.ruleIDs[i]
		fingerprint := fingerprintRuleIDs(rids)
		bucketIndexes := bucketIndexByFingerprint[fingerprint]
		matched := false
		for _, bucketIndex := range bucketIndexes {
			if !slices.Equal(acceptBuckets[bucketIndex].ruleIDs, rids) {
				continue
			}
			acceptBuckets[bucketIndex].states = append(acceptBuckets[bucketIndex].states, i)
			matched = true
			break
		}
		if matched {
			continue
		}

		bucketIndexByFingerprint[fingerprint] = append(bucketIndexByFingerprint[fingerprint], len(acceptBuckets))
		acceptBuckets = append(acceptBuckets, acceptPartitionBucket{
			ruleIDs: slices.Clone(rids),
			states:  []int{i},
		})
	}

	partitions := make([][]int, 0, len(acceptBuckets)+1)
	if len(nonAccept) > 0 {
		partitions = append(partitions, nonAccept)
	}
	for _, bucket := range acceptBuckets {
		partitions = append(partitions, bucket.states)
	}
	return partitions
}

// fingerprintRuleIDs computes a fast FNV-1a hash of a rule-ID slice to
// narrow bucket lookups before full slice comparison in [initialPartitions].
func fingerprintRuleIDs(ids []uint32) ruleIDsFingerprint {
	hash := uint64(1469598103934665603) // FNV offset basis
	for _, id := range ids {
		hash ^= uint64(id)
		hash *= 1099511628211 // FNV prime
	}
	return ruleIDsFingerprint{hash: hash, length: len(ids)}
}

// sigHashGroup associates a representative state with its group index in the
// result slice. Used by [splitPartition] for hash-based partition grouping.
type sigHashGroup struct {
	rep      int
	groupIdx int
}

// splitPartition refines one partition by grouping states that share the same
// transition signature (which partition each outgoing edge reaches).
//
// It uses a two-tier map: a primary map[uint64]sigHashGroup stores one entry
// per hash inline (no slice allocation), and a rare-collision overflow map
// handles the exceptional case where different signatures hash to the same
// uint64. This eliminates millions of small []sigHashGroup allocations.
func splitPartition(md *intermediateDFA, partition []int, stateToPartition []uint32) [][]int {
	primary := make(map[uint64]sigHashGroup, min(len(partition), 256))
	var overflow map[uint64][]sigHashGroup
	result := make([][]int, 0, 2)

	for _, s := range partition {
		sTrans := md.stateTrans(s)
		h := transitionSigHash(sTrans, stateToPartition)

		// Fast path: check primary (single entry per hash, no alloc).
		if e, exists := primary[h]; exists {
			if transitionsEqual(sTrans, md.stateTrans(e.rep), stateToPartition) {
				result[e.groupIdx] = append(result[e.groupIdx], s)
				continue
			}
			// Hash collision — promote to overflow.
			if overflow == nil {
				overflow = make(map[uint64][]sigHashGroup)
			}
			gi := len(result)
			result = append(result, []int{s})
			overflow[h] = []sigHashGroup{e, {rep: s, groupIdx: gi}}
			delete(primary, h)
			continue
		}

		// Check overflow for previously promoted hashes.
		if ov, hasOv := overflow[h]; hasOv {
			matched := false
			for _, e := range ov {
				if transitionsEqual(sTrans, md.stateTrans(e.rep), stateToPartition) {
					result[e.groupIdx] = append(result[e.groupIdx], s)
					matched = true
					break
				}
			}
			if !matched {
				gi := len(result)
				result = append(result, []int{s})
				overflow[h] = append(ov, sigHashGroup{rep: s, groupIdx: gi})
			}
			continue
		}

		// New hash — insert into primary (inline value, no slice alloc).
		gi := len(result)
		result = append(result, []int{s})
		primary[h] = sigHashGroup{rep: s, groupIdx: gi}
	}

	return result
}

// splitPartitionParallel handles very large partitions by computing
// transition signature hashes in parallel before grouping sequentially.
// The hash phase distributes well across cores (no shared writes), while
// the grouping phase uses a single-threaded map to avoid synchronisation.
func splitPartitionParallel(md *intermediateDFA, partition []int, stateToPartition []uint32) [][]int {
	n := len(partition)
	numWorkers := runtime.GOMAXPROCS(0)

	// Phase 1: compute hashes in parallel.
	hashes := make([]uint64, n)
	chunkSize := (n + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup
	for w := range numWorkers {
		lo := w * chunkSize
		if lo >= n {
			break
		}
		hi := min(lo+chunkSize, n)
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				hashes[i] = transitionSigHash(md.stateTrans(partition[i]), stateToPartition)
			}
		}(lo, hi)
	}
	wg.Wait()

	// Phase 2: group by hash sequentially.
	groups := make(map[uint64][]sigHashGroup, 256)
	result := make([][]int, 0, 128)
	for i, s := range partition {
		h := hashes[i]
		entries := groups[h]

		matched := false
		for _, e := range entries {
			if transitionsEqual(md.stateTrans(s), md.stateTrans(e.rep), stateToPartition) {
				result[e.groupIdx] = append(result[e.groupIdx], s)
				matched = true
				break
			}
		}
		if !matched {
			gi := len(result)
			result = append(result, []int{s})
			groups[h] = append(entries, sigHashGroup{rep: s, groupIdx: gi})
		}
	}
	return result
}

// transitionSigHash computes a 64-bit FNV-1a fingerprint of one state's
// transition slice. The hash is position-sensitive: different orderings
// of the same partition IDs produce different hashes.
func transitionSigHash(trans []uint32, stateToPartition []uint32) uint64 {
	h := uint64(14695981039346656037) // FNV offset basis
	for _, target := range trans {
		if target == noTransitionState {
			h ^= uint64(noTransitionState)
		} else {
			h ^= uint64(stateToPartition[target])
		}
		h *= 1099511628211 // FNV prime
	}
	return h
}

// transitionsEqual checks whether two states have identical transition
// signatures without materializing a full signature array.
// When both slices refer to the same raw target on a given slot the comparison
// short-circuits without consulting stateToPartition.
func transitionsEqual(a, b []uint32, stateToPartition []uint32) bool {
	for i := range AlphabetSize {
		ta, tb := a[i], b[i]
		if ta == tb {
			continue
		}
		if ta == noTransitionState || tb == noTransitionState {
			return false
		}
		if stateToPartition[ta] != stateToPartition[tb] {
			return false
		}
	}
	return true
}
