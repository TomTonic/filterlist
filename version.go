package regfilter

import (
	"runtime/debug"
	"strings"
)

// buildInfo captures VCS metadata embedded by the Go toolchain.
type buildInfo struct {
	version  string
	revision string
	time     string
	modified bool
}

// readBuildInfo extracts VCS revision, time, and dirty flag from runtime build info.
func readBuildInfo() buildInfo {
	bi := buildInfo{version: "(devel)"}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		bi.version = "(unknown)"
		return bi
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		bi.version = info.Main.Version
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			bi.revision = s.Value
		case "vcs.time":
			bi.time = s.Value
		case "vcs.modified":
			bi.modified = s.Value == "true"
		}
	}
	return bi
}

// String renders build metadata for startup logging and diagnostics.
func (b buildInfo) String() string {
	var parts []string
	parts = append(parts, b.version)
	if b.revision != "" {
		rev := b.revision
		if len(rev) > 12 {
			rev = rev[:12]
		}
		parts = append(parts, "rev "+rev)
	}
	if b.time != "" {
		parts = append(parts, b.time)
	}
	if b.modified {
		parts = append(parts, "dirty")
	}
	return strings.Join(parts, " ")
}
