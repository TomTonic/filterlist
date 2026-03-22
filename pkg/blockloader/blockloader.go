// Package blockloader reads all filter list files from a directory and
// aggregates them into a unified slice of filterlist.Rule objects.
package blockloader

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tomtonic/coredns-regfilter/pkg/filterlist"
)

// LoadDirectory reads all filter list files from dir (non-recursively) and
// returns the aggregated rules. IO errors are returned; parse errors within
// files are logged and skipped.
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
