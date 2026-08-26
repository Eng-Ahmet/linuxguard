package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Scanner struct {
	monitoredPaths []string
	excludedPaths  []string
}

func NewScanner(monitoredPaths, excludedPaths []string) *Scanner {
	cleanMonitored := make([]string, 0, len(monitoredPaths))
	for _, p := range monitoredPaths {
		if abs, err := filepath.Abs(p); err == nil {
			cleanMonitored = append(cleanMonitored, abs)
		} else {
			cleanMonitored = append(cleanMonitored, p)
		}
	}

	cleanExcluded := make([]string, 0, len(excludedPaths))
	for _, p := range excludedPaths {
		if abs, err := filepath.Abs(p); err == nil {
			cleanExcluded = append(cleanExcluded, abs)
		} else {
			cleanExcluded = append(cleanExcluded, p)
		}
	}

	return &Scanner{
		monitoredPaths: cleanMonitored,
		excludedPaths:  cleanExcluded,
	}
}

func (s *Scanner) IsExcluded(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	for _, excl := range s.excludedPaths {
		if absPath == excl || strings.HasPrefix(absPath, excl+"/") {
			return true
		}
	}
	return false
}

// ScanDirectories traverses configured paths up to maxDepth and yields FileInfoMetadata for each valid regular file.
func (s *Scanner) ScanDirectories(maxDepth int) ([]*FileInfoMetadata, error) {
	var results []*FileInfoMetadata

	for _, root := range s.monitoredPaths {
		if s.IsExcluded(root) {
			continue
		}

		stat, err := os.Lstat(root)
		if err != nil {
			continue
		}

		if !stat.IsDir() {
			if meta, err := GetFileMetadata(root); err == nil {
				results = append(results, meta)
			}
			continue
		}

		err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip unreadable paths
			}

			if s.IsExcluded(path) {
				if info.IsDir() && path != root {
					return filepath.SkipDir
				}
				return nil
			}

			// Symlink safety: do not follow symlinks recursively
			if info.Mode()&os.ModeSymlink != 0 {
				return nil
			}

			// Enforce max depth if set (> 0)
			if maxDepth > 0 {
				rel, err := filepath.Rel(root, path)
				if err == nil {
					depth := len(strings.Split(rel, string(filepath.Separator)))
					if info.IsDir() && depth > maxDepth {
						return filepath.SkipDir
					}
				}
			}

			if !info.IsDir() {
				meta, err := GetFileMetadata(path)
				if err == nil {
					results = append(results, meta)
				}
			}

			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("error during walk of %s: %w", root, err)
		}
	}

	return results, nil
}
