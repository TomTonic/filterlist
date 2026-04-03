package automaton

import "slices"

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

// transitionSignature records which partition each outgoing edge reaches,
// keyed by alphabet slot. Two states in the same partition whose signatures
// differ must be split into separate partitions.
type transitionSignature [AlphabetSize]uint32

// noTransSig is a [transitionSignature] with every slot set to
// [noTransitionState], used as the baseline for states with no outgoing
// edges.
var noTransSig transitionSignature

func init() {
	for i := range noTransSig {
		noTransSig[i] = noTransitionState
	}
}

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
	n := len(md.states)
	if n <= 1 {
		return md
	}

	// Initial partition: split by (accept, ruleIDs).
	partitions := initialPartitions(md)

	// stateToPartition maps each state to its current partition index.
	stateToPartition := make([]uint32, n)
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
	changed := true
	for changed {
		changed = false
		newPartitions := make([][]int, 0, len(partitions)+len(partitions)/4)
		for _, p := range partitions {
			if len(p) <= 1 {
				newPartitions = append(newPartitions, p)
				continue
			}
			split := splitPartition(md, p, stateToPartition)
			if len(split) > 1 {
				changed = true
			}
			newPartitions = append(newPartitions, split...)
		}
		partitions = newPartitions
		updateMapping()
	}

	// Build the minimized intermediate DFA (one state per partition).
	minMD := &intermediateDFA{}
	minMD.states = make([]intermediateDFAState, len(partitions))
	for pi, p := range partitions {
		rep := p[0] // any representative state will do
		minMD.states[pi] = newIntermediateDFAState(md.states[rep].accept, md.states[rep].ruleIDs)
		for idx, target := range md.states[rep].trans {
			if target != noTransitionState {
				minMD.states[pi].trans[idx] = stateToPartition[target]
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
	nonAccept := make([]int, 0, len(md.states))
	bucketIndexByFingerprint := make(map[ruleIDsFingerprint][]int)
	acceptBuckets := make([]acceptPartitionBucket, 0)

	for i := range md.states {
		s := &md.states[i]
		if !s.accept {
			nonAccept = append(nonAccept, i)
			continue
		}

		fingerprint := fingerprintRuleIDs(s.ruleIDs)
		bucketIndexes := bucketIndexByFingerprint[fingerprint]
		matched := false
		for _, bucketIndex := range bucketIndexes {
			if !slices.Equal(acceptBuckets[bucketIndex].ruleIDs, s.ruleIDs) {
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
			ruleIDs: slices.Clone(s.ruleIDs),
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

// splitPartition refines one partition by grouping states that share the same
// transition signature (which partition each outgoing edge reaches).
func splitPartition(md *intermediateDFA, partition []int, stateToPartition []uint32) [][]int {
	groupIndexes := make(map[transitionSignature]int, len(partition))
	result := make([][]int, 0, 2)
	for _, s := range partition {
		key := transitionSig(md, s, stateToPartition)
		groupIndex, exists := groupIndexes[key]
		if !exists {
			groupIndex = len(result)
			groupIndexes[key] = groupIndex
			result = append(result, nil)
		}
		result[groupIndex] = append(result[groupIndex], s)
	}

	return result
}

// transitionSig builds the transition signature for one state by recording
// which partition each outgoing edge reaches.
func transitionSig(md *intermediateDFA, state int, stateToPartition []uint32) transitionSignature {
	sig := noTransSig
	for idx, target := range md.states[state].trans {
		if target != noTransitionState {
			sig[idx] = stateToPartition[target]
		}
	}
	return sig
}
