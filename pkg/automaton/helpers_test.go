package automaton

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

func scaledHeavyTestCount(regular, underRace int) int {
	if raceEnabled {
		return underRace
	}

	return regular
}
