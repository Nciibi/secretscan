package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxFileSize != DefaultMaxFileSize {
		t.Errorf("default max file size should be %d, got %d", DefaultMaxFileSize, cfg.MaxFileSize)
	}
	if cfg.MaxWorkers != DefaultMaxWorkers {
		t.Errorf("default workers should be %d, got %d", DefaultMaxWorkers, cfg.MaxWorkers)
	}
	if cfg.OutputFormat != "text" {
		t.Errorf("default format should be text, got %s", cfg.OutputFormat)
	}
	if len(cfg.ExcludePaths) == 0 {
		t.Error("should have default exclude paths")
	}
}

func TestLoadMissing(t *testing.T) {
	cfg, err := Load("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("loading missing config should use defaults, got error: %v", err)
	}
	if cfg.MaxWorkers != DefaultMaxWorkers {
		t.Error("missing config should use defaults")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secretscan.yaml")

	content := `max_file_size: 5242880
max_workers: 4
output_format: json
entropy_threshold: 4.5
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.MaxFileSize != 5242880 {
		t.Errorf("expected 5MB, got %d", cfg.MaxFileSize)
	}
	if cfg.MaxWorkers != 4 {
		t.Errorf("expected 4 workers, got %d", cfg.MaxWorkers)
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("expected json format, got %s", cfg.OutputFormat)
	}
}

func TestGenerateDefault(t *testing.T) {
	dir := t.TempDir()

	if err := GenerateDefault(dir); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, DefaultConfigFile)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("config file should have been created")
	}
}

func TestGenerateIgnoreFile(t *testing.T) {
	dir := t.TempDir()

	if err := GenerateIgnoreFile(dir); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, DefaultIgnoreFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("ignore file should not be empty")
	}
}

func TestNormalize(t *testing.T) {
	cfg := &Config{}
	cfg.normalize()

	if cfg.MaxFileSize != DefaultMaxFileSize {
		t.Error("should normalize max file size")
	}
	if cfg.MaxWorkers != DefaultMaxWorkers {
		t.Error("should normalize workers")
	}
}
