package detectors

import (
	"regexp"

	"github.com/secretscan/secretscan/internal/models"
)

// AWSKeyDetector detects AWS access key IDs and secret access keys.
type AWSKeyDetector struct {
	BaseDetector
	secretPattern *regexp.Regexp
}

func NewAWSKeyDetector() *AWSKeyDetector {
	return &AWSKeyDetector{
		BaseDetector: BaseDetector{
			name:     "aws-key",
			typeName: "AWS Access Key",
			severity: models.SeverityCritical,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)`),
		},
		secretPattern: regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
	}
}

func (d *AWSKeyDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	var findings []models.Finding

	// Detect access key IDs (AKIA prefix).
	findings = append(findings, d.baseDetect(line, lineNum, filePath)...)

	// Detect secret access keys via context.
	if isFalsePositive(line) {
		return findings
	}

	if matches := d.secretPattern.FindAllStringSubmatchIndex(line, -1); matches != nil {
		for _, loc := range matches {
			if len(loc) >= 4 {
				matched := line[loc[2]:loc[3]]
				confidence := computeConfidence(true, true, 0, len(matched) == 40)
				if confidence >= 25 {
					findings = append(findings, models.Finding{
						Type:       "AWS Secret Key",
						Severity:   models.SeverityCritical,
						Confidence: confidence,
						File:       filePath,
						Line:       lineNum,
						Column:     loc[2] + 1,
						Preview:    truncateContext(line, loc[2], loc[3]),
						Reason:     "Matched AWS secret access key pattern with context keyword",
						Detector:   d.name,
						Source:     models.SourceFilesystem,
					})
				}
			}
		}
	}

	return findings
}
