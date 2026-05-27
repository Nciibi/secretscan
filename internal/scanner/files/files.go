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
	filePaths := s.collectFiles(ctx, root)
	return s.scanPaths(ctx, root, filePaths)
}

// ScanFiles scans only the specified files (for incremental --since scanning).
func (s *Scanner) ScanFiles(ctx context.Context, root string, relPaths []string) ([]models.Finding, int, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid path: %w", err)
	}

	var filePaths []string
	for _, rel := range relPaths {
		abs := filepath.Join(root, rel)
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			continue
		}
		if s.matcher.ShouldIgnore(rel) || util.IsBinaryExtension(abs) {
			continue
		}
		if s.cfg.MaxFileSize > 0 && info.Size() > s.cfg.MaxFileSize {
			continue
		}
		filePaths = append(filePaths, abs)
	}
	return s.scanPaths(ctx, root, filePaths)
}

func (s *Scanner) collectFiles(ctx context.Context, root string) []string {
	var filePaths []string
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
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

		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		if s.matcher.ShouldIgnore(relPath) {
			return nil
		}

		if util.IsBinaryExtension(path) {
			return nil
		}

		if info, err := d.Info(); err == nil {
			if s.cfg.MaxFileSize > 0 && info.Size() > s.cfg.MaxFileSize {
				return nil
			}
		}

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
	return filePaths
}

func (s *Scanner) scanPaths(ctx context.Context, root string, filePaths []string) ([]models.Finding, int, error) {
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
		// Store line content for baseline fingerprinting.
		for i := range results {
			results[i].LineContent = line
		}
		findings = append(findings, results...)
		return nil
	})

	if err != nil {
		if s.verbose {
			fmt.Fprintf(os.Stderr, "warning: error reading %s: %v\n", relPath, err)
		}
	}

	return findings
}
