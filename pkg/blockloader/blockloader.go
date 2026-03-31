// Package blockloader reads all filter list files from a directory and
// aggregates them into a unified slice of filterlist.Rule objects.
package blockloader

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/TomTonic/coredns-regfilter/pkg/filterlist"
)

// LoadDirectory loads supported filter list files from dir and aggregates them.
//
// The dir parameter must point at a single directory and is scanned
// non-recursively. The logger parameter may be nil and receives warnings for
// unreadable files or skipped parse issues. LoadDirectory returns the combined
// rule slice for all supported files, or an error when the directory itself
// cannot be read. Callers typically use it during startup and hot reloads
// before compiling the resulting rules into DFAs.
func LoadDirectory(dir string, logger filterlist.Logger) ([]filterlist.Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("blockloader: read directory %s: %w", dir, err)
	}

	var (
		allRules     []filterlist.Rule
		totalFiles   int
		totalSkipped int
	)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !isFilterFile(name) {
			continue
		}

		totalFiles++
		fullPath := filepath.Join(dir, name)

		rules, err := filterlist.ParseFile(fullPath, logger)
		if err != nil {
			if logger != nil {
				logger.Warnf("blockloader: error reading %s: %v", fullPath, err)
			}
			continue
		}

		allRules = append(allRules, rules...)
	}

	if logger != nil {
		logger.Warnf("blockloader: loaded %d files, %d rules from %s (skipped %d)",
			totalFiles, len(allRules), dir, totalSkipped)
	}

	return allRules, nil
}

// isFilterFile returns true if the file name looks like a filter list file.
// We accept common extensions and extensionless files.
func isFilterFile(name string) bool {
	ext := filepath.Ext(name)
	switch ext {
	case ".txt", ".list", ".hosts", ".conf", ".block", "":
		return true
	}
	return false
}
