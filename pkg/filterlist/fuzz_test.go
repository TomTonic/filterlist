package filterlist

import "testing"

// FuzzParseLine verifies that users cannot crash the parser by feeding it
// malformed or unexpected filter list lines.
//
// This fuzz test covers the filterlist package line parser under adversarial
// input.
//
// It asserts that ParseLine never panics across seeded and generated inputs.
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
		"||example.com^$badfilter",
		"||example.com^$match-case",
		"||example.com^$popup",
		"# comment with ## inside",
		"/ads/banner",
		"",
		"   ",
		"@@example.com",
		"ads",
		"||example.com/path^",
		"||münchen.de^",
		"0.0.0.0 bücher.example.com",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, line string) {
		// ParseLine should never panic regardless of input
		_, _ = ParseLine(line)
	})
}
