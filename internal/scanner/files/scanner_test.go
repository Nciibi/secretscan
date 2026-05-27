package files

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/secretscan/secretscan/internal/config"
	"github.com/secretscan/secretscan/internal/detectors"
	"github.com/secretscan/secretscan/internal/ignore"
)

func TestFilesScanner(t *testing.T) {
	// Create a temporary directory.
	tmpDir, err := os.MkdirTemp("", "scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write a file with a known secret (AWS key).
	testFile := filepath.Join(tmpDir, "config.env")
	err = os.WriteFile(testFile, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABRACAD\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Write a safe file.
	safeFile := filepath.Join(tmpDir, "safe.txt")
	err = os.WriteFile(safeFile, []byte("This is a safe file with no secrets.\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to write safe file: %v", err)
	}

	// Set up the scanner.
	cfg := config.DefaultConfig()
	registry := detectors.NewRegistry(4.0)
	matcher := ignore.New()
	scanner := New(cfg, registry, matcher)

	// Run the scanner.
	findings, scannedFiles, err := scanner.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scanner returned error: %v", err)
	}

	// Assertions.
	if scannedFiles != 2 {
		t.Errorf("Expected 2 files scanned, got %d", scannedFiles)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected exactly 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Detector != "aws-key" {
		t.Errorf("Expected detector 'aws-key', got '%s'", finding.Detector)
	}
	if filepath.Base(finding.File) != "config.env" {
		t.Errorf("Expected finding in 'config.env', got '%s'", finding.File)
	}
}
