// Package config handles loading and validating configuration for secretscan.
package config

import (
	"os"
	"path/filepath"

	"github.com/secretscan/secretscan/internal/models"
	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigFile  = ".secretscan.yaml"
	DefaultIgnoreFile  = ".secretignore"
	DefaultMaxFileSize = 10 * 1024 * 1024 // 10 MB
	DefaultMaxWorkers  = 8
	DefaultEntropy     = 4.0
)

// Config represents the full secretscan configuration.
type Config struct {
	MaxFileSize    int64    `yaml:"max_file_size"`
	IncludeExts    []string `yaml:"include_extensions,omitempty"`
	ExcludePaths   []string `yaml:"exclude_paths,omitempty"`
	CustomPatterns []models.DetectorPattern `yaml:"custom_patterns,omitempty"`
	EntropyThreshold float64 `yaml:"entropy_threshold"`
	OutputFormat   string   `yaml:"output_format"` // "text", "json", "sarif"
	ScanMode       string   `yaml:"scan_mode"`     // "filesystem", "git", "all"
	MaxWorkers     int      `yaml:"max_workers"`
	IncludeGit     bool     `yaml:"include_git_history"`
	IgnoreFile     string   `yaml:"ignore_file"`
	Verbose        bool     `yaml:"verbose"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		MaxFileSize:      DefaultMaxFileSize,
		EntropyThreshold: DefaultEntropy,
		OutputFormat:     "text",
		ScanMode:         "filesystem",
		MaxWorkers:       DefaultMaxWorkers,
		IncludeGit:       false,
		IgnoreFile:       DefaultIgnoreFile,
		ExcludePaths: []string{
			".git",
			"node_modules",
			"dist",
			"build",
			"vendor",
			"__pycache__",
			".venv",
			".tox",
		},
	}
}

// Load reads a config file from the given path and merges it with defaults.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		path = DefaultConfigFile
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // use defaults if no config file
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.normalize()
	return cfg, nil
}

// normalize ensures config values are within valid ranges.
func (c *Config) normalize() {
	if c.MaxFileSize <= 0 {
		c.MaxFileSize = DefaultMaxFileSize
	}
	if c.MaxWorkers <= 0 {
		c.MaxWorkers = DefaultMaxWorkers
	}
	if c.EntropyThreshold <= 0 {
		c.EntropyThreshold = DefaultEntropy
	}
	if c.OutputFormat == "" {
		c.OutputFormat = "text"
	}
	if c.ScanMode == "" {
		c.ScanMode = "filesystem"
	}
}

// GenerateDefault writes a default config file to disk.
func GenerateDefault(dir string) error {
	cfg := DefaultConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, DefaultConfigFile)
	return os.WriteFile(path, data, 0644)
}

// GenerateIgnoreFile writes a default .secretignore file to disk.
func GenerateIgnoreFile(dir string) error {
	content := `# secretscan ignore file
# Patterns follow .gitignore syntax

# Dependencies
node_modules/
vendor/
.venv/

# Build outputs
dist/
build/
out/
target/

# Binary and media files
*.exe
*.dll
*.so
*.dylib
*.png
*.jpg
*.jpeg
*.gif
*.svg
*.ico
*.mp3
*.mp4
*.zip
*.tar.gz
*.pdf

# IDE and editor files
.idea/
.vscode/
*.swp
*.swo

# OS files
.DS_Store
Thumbs.db

# Lock files (rarely contain secrets)
package-lock.json
yarn.lock
go.sum
Gemfile.lock
poetry.lock
Cargo.lock

# Test fixtures (add paths to your test data here)
# testdata/
# fixtures/
`
	path := filepath.Join(dir, DefaultIgnoreFile)
	return os.WriteFile(path, []byte(content), 0644)
}
