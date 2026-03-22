package filterlist

import "testing"

func FuzzParseLine(f *testing.F) {
	// Seed corpus
	seeds := []string{
		"||example.com^",
		"@@||safe.example.com^",
		"0.0.0.0 ads.example.com",
		"127.0.0.1 tracker.com",
		"example.com##.ad-banner",
		"||ads*.google.com^",
		"||*.tracking.example.com^",
		"! comment",
		"# hosts comment",
		"[Adblock Plus 2.0]",
		"||example.com^$script",
		"/ads/banner",
		"",
		"   ",
		"@@example.com",
		"ads",
		"||example.com/path^",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		// ParseLine should never panic regardless of input
		_, _ = ParseLine(line)
	})
}
