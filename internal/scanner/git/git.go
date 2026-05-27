// Package git implements Git history scanning for leaked secrets.
package git

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/secretscan/secretscan/internal/config"
	"github.com/secretscan/secretscan/internal/detectors"
	"github.com/secretscan/secretscan/internal/models"
)

// Scanner scans Git history for secrets.
type Scanner struct {
	cfg      *config.Config
	registry *detectors.Registry
}

// New creates a new Git history scanner.
func New(cfg *config.Config, registry *detectors.Registry) *Scanner {
	return &Scanner{cfg: cfg, registry: registry}
}

// Scan scans the Git history of the repository at root.
func (s *Scanner) Scan(ctx context.Context, root string) ([]models.Finding, int, error) {
	repo, err := git.PlainOpen(root)
	if err != nil {
		return nil, 0, fmt.Errorf("not a git repository: %w", err)
	}

	ref, err := repo.Head()
	if err != nil {
		return nil, 0, fmt.Errorf("cannot get HEAD: %w", err)
	}

	commitIter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil, 0, fmt.Errorf("cannot read log: %w", err)
	}

	var allFindings []models.Finding
	seen := make(map[string]bool)
	commitCount := 0

	err = commitIter.ForEach(func(c *object.Commit) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		commitCount++
		findings := s.scanCommit(c, seen)
		allFindings = append(allFindings, findings...)
		return nil
	})
	if err != nil {
		return allFindings, commitCount, err
	}

	return allFindings, commitCount, nil
}

func (s *Scanner) scanCommit(c *object.Commit, seen map[string]bool) []models.Finding {
	tree, err := c.Tree()
	if err != nil {
		return nil
	}

	// Get parent for diffing.
	var parentTree *object.Tree
	if c.NumParents() > 0 {
		parent, err := c.Parent(0)
		if err == nil {
			parentTree, _ = parent.Tree()
		}
	}

	if parentTree == nil {
		// First commit: scan all files.
		return s.scanTree(c, tree, seen)
	}

	// Diff against parent.
	changes, err := parentTree.Diff(tree)
	if err != nil {
		return nil
	}

	return s.scanChanges(c, changes, seen)
}

func (s *Scanner) scanTree(c *object.Commit, tree *object.Tree, seen map[string]bool) []models.Finding {
	var findings []models.Finding

	tree.Files().ForEach(func(f *object.File) error {
		if f.Size > s.cfg.MaxFileSize {
			return nil
		}

		isBin, _ := f.IsBinary()
		if isBin {
			return nil
		}

		content, err := f.Contents()
		if err != nil {
			return nil
		}

		lines := strings.Split(content, "\n")
		for i, line := range lines {
			results := s.registry.DetectAll(line, i+1, f.Name)
			for _, r := range results {
				r.Source = models.SourceGitHistory
				r.CommitHash = c.Hash.String()[:8]
				r.CommitMessage = firstLine(c.Message)
				r.CommitAuthor = c.Author.Name

				id := r.ID() + ":" + r.CommitHash
				if !seen[id] {
					seen[id] = true
					findings = append(findings, r)
				}
			}
		}
		return nil
	})

	return findings
}

func (s *Scanner) scanChanges(c *object.Commit, changes object.Changes, seen map[string]bool) []models.Finding {
	var findings []models.Finding

	for _, change := range changes {
		patch, err := change.Patch()
		if err != nil {
			continue
		}

		for _, fp := range patch.FilePatches() {
			_, to := fp.Files()
			if to == nil {
				continue // file was deleted
			}

			fileName := to.Path()
			for _, chunk := range fp.Chunks() {
				if chunk.Type() != 1 { // 1 = Add
					continue
				}

				lines := strings.Split(chunk.Content(), "\n")
				for i, line := range lines {
					results := s.registry.DetectAll(line, i+1, fileName)
					for _, r := range results {
						r.Source = models.SourceGitHistory
						r.CommitHash = c.Hash.String()[:8]
						r.CommitMessage = firstLine(c.Message)
						r.CommitAuthor = c.Author.Name

						id := r.ID()
						if !seen[id] {
							seen[id] = true
							findings = append(findings, r)
						}
					}
				}
			}
		}
	}

	return findings
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
