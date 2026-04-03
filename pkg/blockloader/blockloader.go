// Package blockloader reads all filter list files from a directory and
// aggregates them into a unified slice of listparser.Rule objects.
package blockloader

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/TomTonic/filterlist/pkg/listparser"
)

// LoadDirectory loads supported filter list files from dir and aggregates them.
//
// The dir parameter must point at a single directory and is scanned
// non-recursively. The logger parameter may be nil and receives warnings for
// unreadable files or skipped parse issues. LoadDirectory returns the combined
// rule slice for all supported files, or an error when the directory itself
// cannot be read. Callers typically use it during startup and hot reloads
// before compiling the resulting rules into DFAs.
func LoadDirectory(dir string, logger listparser.Logger) ([]listparser.Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("blockloader: read directory %s: %w", dir, err)
	}

	var (
		allRules    []listparser.Rule
		loadedFiles int
		skippedExts int
		failedFiles int
	)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !isFilterFile(name) {
			skippedExts++
			if logger != nil {
				logger.Infof("blockloader: %s: skipped, unsupported extension %q",
					filepath.Join(dir, name), filepath.Ext(name))
			}
			continue
		}

		fullPath := filepath.Join(dir, name)

		rules, err := listparser.ParseFile(fullPath, logger)
		if err != nil {
			failedFiles++
			if logger != nil {
				logger.Warnf("blockloader: error reading %s: %v", fullPath, err)
			}
			continue
		}

		loadedFiles++
		if logger != nil {
			logger.Infof("blockloader: %s: %d rules", fullPath, len(rules))
		}
		allRules = append(allRules, rules...)
	}

	if logger != nil {
		logger.Infof("blockloader: %s: %d rules from %d files (%d skipped, %d failed)",
			dir, len(allRules), loadedFiles, skippedExts, failedFiles)
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
