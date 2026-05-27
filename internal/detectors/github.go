package detectors

import (
	"regexp"

	"github.com/secretscan/secretscan/internal/models"
)

// GitHubTokenDetector detects GitHub personal access tokens and fine-grained tokens.
type GitHubTokenDetector struct {
	BaseDetector
	fineGrainedPattern *regexp.Regexp
}

func NewGitHubTokenDetector() *GitHubTokenDetector {
	return &GitHubTokenDetector{
		BaseDetector: BaseDetector{
			name:     "github-token",
			typeName: "GitHub Token",
			severity: models.SeverityCritical,
			// Classic PAT: ghp_, fine-grained: github_pat_, OAuth: gho_, app: ghs_, refresh: ghr_
			pattern: regexp.MustCompile(`(?:^|[^A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9_]{36,255})(?:[^A-Za-z0-9_]|$)`),
		},
		fineGrainedPattern: regexp.MustCompile(`(?:^|[^A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{22,255})(?:[^A-Za-z0-9_]|$)`),
	}
}

func (d *GitHubTokenDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	var findings []models.Finding

	// Classic tokens.
	findings = append(findings, d.baseDetect(line, lineNum, filePath)...)

	// Fine-grained PATs.
	if matches := d.fineGrainedPattern.FindAllStringSubmatchIndex(line, -1); matches != nil {
		for _, loc := range matches {
			if len(loc) < 4 {
				continue
			}
			matched := line[loc[2]:loc[3]]
			confidence := computeConfidence(true, true, 0, true)
			findings = append(findings, models.Finding{
				Type:         "GitHub Fine-Grained Token",
				Severity:     models.SeverityCritical,
				Confidence:   confidence,
				File:         filePath,
				Line:         lineNum,
				Column:       loc[2] + 1,
				Preview:      truncateContext(line, loc[2], loc[3]),
				Reason:       "Matched GitHub fine-grained PAT pattern (github_pat_ prefix)",
				Detector:     d.name,
				Source:       models.SourceFilesystem,
				MatchedValue: matched,
			})
		}
	}

	return findings
}
