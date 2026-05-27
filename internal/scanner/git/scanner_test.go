package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/secretscan/secretscan/internal/config"
	"github.com/secretscan/secretscan/internal/detectors"
)

func TestGitScanner(t *testing.T) {
	// Create a temporary directory.
	tmpDir, err := os.MkdirTemp("", "git_scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Init a git repo.
	repo, err := git.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get worktree: %v", err)
	}

	// Create a safe commit.
	safeFile := filepath.Join(tmpDir, "safe.txt")
	os.WriteFile(safeFile, []byte("Hello, world!"), 0644)
	wt.Add("safe.txt")
	commitOpts := &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
	}
	_, err = wt.Commit("Initial safe commit", commitOpts)
	if err != nil {
		t.Fatalf("Failed to create commit: %v", err)
	}

	// Create a commit with a secret.
	secretFile := filepath.Join(tmpDir, "secret.env")
	os.WriteFile(secretFile, []byte("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABRACAD\n"), 0644)
	wt.Add("secret.env")
	_, err = wt.Commit("Add secret file", commitOpts)
	if err != nil {
		t.Fatalf("Failed to create commit: %v", err)
	}

	// Set up the scanner.
	cfg := config.DefaultConfig()
	registry := detectors.NewRegistry(4.0)
	scanner := New(cfg, registry)

	// Run the scanner.
	findings, scannedCommits, err := scanner.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scanner returned error: %v", err)
	}

	// Assertions.
	if scannedCommits != 2 {
		t.Errorf("Expected 2 commits scanned, got %d", scannedCommits)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected exactly 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Detector != "aws-key" {
		t.Errorf("Expected detector 'aws-key', got '%s'", finding.Detector)
	}
	if finding.File != "secret.env" {
		t.Errorf("Expected finding in 'secret.env', got '%s'", finding.File)
	}
	if finding.Source != "git-history" {
		t.Errorf("Expected source 'git-history', got '%s'", finding.Source)
	}
}
