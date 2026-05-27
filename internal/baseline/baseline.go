// Package baseline provides suppression of known findings via a baseline file.
// Teams can snapshot current findings and only alert on NEW secrets going forward.
package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/secretscan/secretscan/internal/models"
)

const DefaultFile = ".secretscan-baseline.json"

// Entry represents a single suppressed finding in the baseline.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	Detector    string `json:"detector"`
	File        string `json:"file"`
	Line        int    `json:"line"`
}

// File represents the on-disk baseline format.
type File struct {
	Version     int     `json:"version"`
	GeneratedAt string  `json:"generated_at"`
	Findings    []Entry `json:"findings"`
}

// Fingerprint computes a stable hash for a finding.
// Uses sha256(detector_id + ":" + relative_file_path + ":" + matched_line_content).
func Fingerprint(f models.Finding) string {
	input := f.Detector + ":" + f.File + ":" + f.LineContent
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)
}

// Load reads a baseline file from disk. Returns nil if file does not exist.
func Load(path string) (*File, error) {
	if path == "" {
		path = DefaultFile
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading baseline: %w", err)
	}
	var bf File
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	return &bf, nil
}

// Save writes a baseline file from the given findings.
func Save(path string, findings []models.Finding) error {
	if path == "" {
		path = DefaultFile
	}

	entries := make([]Entry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, Entry{
			Fingerprint: Fingerprint(f),
			Detector:    f.Detector,
			File:        f.File,
			Line:        f.Line,
		})
	}

	bf := File{
		Version:     1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:    entries,
	}

	data, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// Filter removes findings that match the baseline and returns the remaining
// findings plus a count of how many were suppressed.
func Filter(findings []models.Finding, bf *File) ([]models.Finding, int) {
	if bf == nil || len(bf.Findings) == 0 {
		return findings, 0
	}

	known := make(map[string]bool, len(bf.Findings))
	for _, e := range bf.Findings {
		known[e.Fingerprint] = true
	}

	var kept []models.Finding
	suppressed := 0
	for _, f := range findings {
		fp := Fingerprint(f)
		if known[fp] {
			suppressed++
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}
