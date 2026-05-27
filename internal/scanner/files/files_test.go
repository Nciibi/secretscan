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

func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// File with a secret.
	secretFile := filepath.Join(dir, "config.env")
	os.WriteFile(secretFile, []byte(`# Config
DB_HOST=localhost
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DB_PORT=5432
`), 0644)

	// Clean file.
	cleanFile := filepath.Join(dir, "main.go")
	os.WriteFile(cleanFile, []byte(`package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
`), 0644)

	// Nested directory.
	subDir := filepath.Join(dir, "src")
	os.MkdirAll(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "app.py"), []byte(`
import os
password = "SuperS3cr3tP@ss"
`), 0644)

	// File in ignored directory.
	nodeDir := filepath.Join(dir, "node_modules", "pkg")
	os.MkdirAll(nodeDir, 0755)
	os.WriteFile(filepath.Join(nodeDir, "index.js"), []byte(`
const key = "sk_live_REALKEY123456789012345678";
`), 0644)

	return dir
}

func TestScanFindsSecrets(t *testing.T) {
	dir := setupTestDir(t)

	cfg := config.DefaultConfig()
	registry := detectors.NewRegistry(4.0)
	matcher := ignore.New()

	s := New(cfg, registry, matcher)
	findings, scanned, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if scanned == 0 {
		t.Error("should have scanned files")
	}

	if len(findings) == 0 {
		t.Error("expected at least one finding")
	}

	// Check that we found the AWS key.
	foundAWS := false
	for _, f := range findings {
		if f.Type == "AWS Access Key" {
			foundAWS = true
		}
	}
	if !foundAWS {
		t.Error("should have found the AWS key")
	}
}

func TestScanIgnoresNodeModules(t *testing.T) {
	dir := setupTestDir(t)

	cfg := config.DefaultConfig()
	registry := detectors.NewRegistry(4.0)
	matcher := ignore.New()

	s := New(cfg, registry, matcher)
	findings, _, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, f := range findings {
		if filepath.Base(f.File) == "index.js" {
			t.Error("should not find secrets in node_modules")
		}
	}
}

func TestScanCancellation(t *testing.T) {
	dir := setupTestDir(t)

	cfg := config.DefaultConfig()
	registry := detectors.NewRegistry(4.0)
	matcher := ignore.New()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := New(cfg, registry, matcher)
	_, _, err := s.Scan(ctx, dir)
	// Should not panic or error badly.
	_ = err
}

func TestScanInvalidPath(t *testing.T) {
	cfg := config.DefaultConfig()
	registry := detectors.NewRegistry(4.0)
	matcher := ignore.New()

	s := New(cfg, registry, matcher)
	_, _, err := s.Scan(context.Background(), "/nonexistent/path")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func BenchmarkScan(b *testing.B) {
	dir := b.TempDir()

	// Create many files.
	for i := 0; i < 100; i++ {
		name := filepath.Join(dir, filepath.Base(b.Name())+"_"+string(rune('a'+i%26))+".go")
		os.WriteFile(name, []byte(`package main
import "fmt"
func main() { fmt.Println("hello") }
`), 0644)
	}

	cfg := config.DefaultConfig()
	registry := detectors.NewRegistry(4.0)
	matcher := ignore.New()
	s := New(cfg, registry, matcher)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Scan(context.Background(), dir)
	}
}
