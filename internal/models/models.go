// Package models defines the core data structures used throughout secretscan.
package models

import "fmt"

// Severity represents the severity level of a detected secret.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// SeverityWeight returns a numeric weight for sorting (higher = more severe).
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Source indicates where a finding was discovered.
type Source string

const (
	SourceFilesystem Source = "filesystem"
	SourceGitHistory Source = "git-history"
)

// Finding represents a single detected secret leak.
type Finding struct {
	Type       string   `json:"type"`
	Severity   Severity `json:"severity"`
	Confidence int      `json:"confidence"` // 0–100
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Column     int      `json:"column"`
	Preview    string   `json:"preview"`
	Reason     string   `json:"reason"`
	Detector   string   `json:"detector"`
	Source     Source   `json:"source"`

	// Git-specific fields (populated only for git-history findings).
	CommitHash    string `json:"commit_hash,omitempty"`
	CommitMessage string `json:"commit_message,omitempty"`
	CommitAuthor  string `json:"commit_author,omitempty"`
}

// ID returns a deduplication key for this finding.
func (f Finding) ID() string {
	return fmt.Sprintf("%s:%s:%d:%s", f.File, f.Type, f.Line, f.Preview)
}

// ScanResult aggregates all findings from a scan.
type ScanResult struct {
	Findings  []Finding `json:"findings"`
	ScannedFiles int    `json:"scanned_files"`
	ScannedCommits int  `json:"scanned_commits,omitempty"`
	Duration  string    `json:"duration"`
	ScanPath  string    `json:"scan_path"`
	ScanMode  string    `json:"scan_mode"`
}

// HasFindings returns true if any findings were detected.
func (r ScanResult) HasFindings() bool {
	return len(r.Findings) > 0
}

// CountBySeverity returns a map of severity -> count.
func (r ScanResult) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// DetectorPattern defines a custom regex pattern for detection.
type DetectorPattern struct {
	Name     string   `yaml:"name" json:"name"`
	Pattern  string   `yaml:"pattern" json:"pattern"`
	Severity Severity `yaml:"severity" json:"severity"`
	Keywords []string `yaml:"keywords,omitempty" json:"keywords,omitempty"`
}
