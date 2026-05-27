// Package files implements recursive filesystem scanning with worker pools.
package files

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/secretscan/secretscan/internal/config"
	"github.com/secretscan/secretscan/internal/detectors"
	"github.com/secretscan/secretscan/internal/ignore"
	"github.com/secretscan/secretscan/internal/models"
	"github.com/secretscan/secretscan/internal/util"
)

// Scanner scans the filesystem for secrets.
type Scanner struct {
	cfg      *config.Config
	registry *detectors.Registry
	matcher  *ignore.Matcher
	verbose  bool
}

// New creates a new filesystem scanner.
func New(cfg *config.Config, registry *detectors.Registry, matcher *ignore.Matcher) *Scanner {
	return &Scanner{
		cfg:      cfg,
		registry: registry,
		matcher:  matcher,
		verbose:  cfg.Verbose,
	}
}

// Scan scans the given root directory and returns findings.
func (s *Scanner) Scan(ctx context.Context, root string) ([]models.Finding, int, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid path: %w", err)
	}

	info, err := os.Stat(root)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot access path: %w", err)
	}
	if !info.IsDir() {
		return nil, 0, fmt.Errorf("path is not a directory: %s", root)
	}

	// Collect files to scan.
	var filePaths []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		relPath, _ := filepath.Rel(root, path)
		if relPath == "." {
			return nil
		}

		if d.IsDir() {
			if s.matcher.ShouldIgnoreDir(relPath) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		if s.matcher.ShouldIgnore(relPath) {
			return nil
		}

		// Skip binary files by extension.
		if util.IsBinaryExtension(path) {
			return nil
		}

		// Check file size.
		if info, err := d.Info(); err == nil {
			if s.cfg.MaxFileSize > 0 && info.Size() > s.cfg.MaxFileSize {
				return nil
			}
		}

		// Check included extensions if specified.
		if len(s.cfg.IncludeExts) > 0 {
			ext := filepath.Ext(path)
			found := false
			for _, e := range s.cfg.IncludeExts {
				if ext == e || ext == "."+e {
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}

		filePaths = append(filePaths, path)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	// Scan files using worker pool.
	workers := s.cfg.MaxWorkers
	if workers <= 0 {
		workers = 8
	}

	jobs := make(chan string, len(filePaths))
	var mu sync.Mutex
	var allFindings []models.Finding
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				findings := s.scanFile(path, root)
				if len(findings) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					mu.Unlock()
				}
			}
		}()
	}

	for _, fp := range filePaths {
		jobs <- fp
	}
	close(jobs)
	wg.Wait()

	return allFindings, len(filePaths), nil
}

func (s *Scanner) scanFile(path, root string) []models.Finding {
	// Double check for binary content.
	isBin, err := util.IsBinaryContent(path)
	if err != nil || isBin {
		return nil
	}

	relPath, _ := filepath.Rel(root, path)
	var findings []models.Finding

	err = util.ReadLines(path, s.cfg.MaxFileSize, func(lineNum int, line string) error {
		line = util.NormalizeLine(line)
		if len(line) == 0 {
			return nil
		}

		results := s.registry.DetectAll(line, lineNum, relPath)
		findings = append(findings, results...)
		return nil
	})

	if err != nil {
		// Log but don't fail the scan for individual file errors.
		if s.verbose {
			fmt.Fprintf(os.Stderr, "warning: error reading %s: %v\n", relPath, err)
		}
	}

	return findings
}
