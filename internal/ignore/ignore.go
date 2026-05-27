// Package ignore provides file-matching logic for .secretignore and default exclusion rules.
package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Matcher decides whether a file path should be ignored during scanning.
type Matcher struct {
	patterns []pattern
	defaults []string
}

type pattern struct {
	glob     string
	negation bool
}

// DefaultIgnoreDirs contains directories always ignored by default.
var DefaultIgnoreDirs = []string{
	".git",
	"node_modules",
	"dist",
	"build",
	"vendor",
	"__pycache__",
	".venv",
	".tox",
	".mypy_cache",
	".pytest_cache",
}

// New creates a Matcher with default ignore patterns.
func New() *Matcher {
	return &Matcher{
		defaults: DefaultIgnoreDirs,
	}
}

// LoadFile reads a .secretignore file and adds its patterns to the matcher.
func (m *Matcher) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // ignore file is optional
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m.AddPattern(line)
	}
	return scanner.Err()
}

// AddPattern adds a single ignore pattern. Prefix with ! for negation.
func (m *Matcher) AddPattern(p string) {
	neg := false
	if strings.HasPrefix(p, "!") {
		neg = true
		p = strings.TrimPrefix(p, "!")
	}
	m.patterns = append(m.patterns, pattern{glob: p, negation: neg})
}

// ShouldIgnore returns true if the given path should be skipped.
// relPath should be relative to the scan root.
func (m *Matcher) ShouldIgnore(relPath string) bool {
	// Normalize separators.
	relPath = filepath.ToSlash(relPath)

	// Check default directory ignores.
	for _, d := range m.defaults {
		dirPrefix := d + "/"
		if relPath == d || strings.HasPrefix(relPath, dirPrefix) {
			return true
		}
		// Also check if any path segment matches.
		if containsSegment(relPath, d) {
			return true
		}
	}

	// Apply user patterns in order — last match wins for negation.
	ignored := false
	for _, p := range m.patterns {
		if matchGlob(relPath, p.glob) {
			if p.negation {
				ignored = false
			} else {
				ignored = true
			}
		}
	}
	return ignored
}

// ShouldIgnoreDir is like ShouldIgnore but specifically for directories.
func (m *Matcher) ShouldIgnoreDir(relPath string) bool {
	relPath = filepath.ToSlash(relPath)

	for _, d := range m.defaults {
		if relPath == d || strings.HasSuffix(relPath, "/"+d) || strings.Contains(relPath, "/"+d+"/") {
			return true
		}
	}

	for _, p := range m.patterns {
		dirGlob := strings.TrimSuffix(p.glob, "/")
		if matchGlob(relPath, dirGlob) || matchGlob(relPath+"/", p.glob) {
			if p.negation {
				return false
			}
			return true
		}
	}
	return false
}

// matchGlob performs glob matching with support for ** patterns.
func matchGlob(path, pattern string) bool {
	// Handle ** for recursive directory matching.
	if strings.Contains(pattern, "**") {
		// Replace ** with a wildcard that matches path separators.
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := parts[0]
			suffix := parts[1]
			suffix = strings.TrimPrefix(suffix, "/")
			if prefix == "" {
				// Pattern like **/foo — match foo anywhere.
				base := filepath.Base(path)
				if matched, _ := filepath.Match(suffix, base); matched {
					return true
				}
				// Also try matching the full path.
				segments := strings.Split(path, "/")
				for i := range segments {
					subpath := strings.Join(segments[i:], "/")
					if matched, _ := filepath.Match(suffix, subpath); matched {
						return true
					}
				}
			}
			return false
		}
	}

	// Try matching against basename for simple patterns.
	base := filepath.Base(path)
	if matched, _ := filepath.Match(pattern, base); matched {
		return true
	}

	// Try matching against full path.
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}

	// Handle directory patterns (e.g., "dist/").
	if strings.HasSuffix(pattern, "/") {
		dirPattern := strings.TrimSuffix(pattern, "/")
		if matched, _ := filepath.Match(dirPattern, base); matched {
			return true
		}
		if strings.HasPrefix(path, dirPattern+"/") || path == dirPattern {
			return true
		}
	}

	return false
}

func containsSegment(path, segment string) bool {
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if p == segment {
			return true
		}
	}
	return false
}
